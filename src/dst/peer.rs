//! The wire under a frame-aware peer: what either end of HTTP/2 does whatever
//! it is asked to play. Frames in and out, both directions' windows checked
//! and credited, SETTINGS applied and acknowledged, PINGs answered, and the
//! program's header blocks decoded with one table for the connection.
//!
//! A `Dialogue` plays a script, so it can neither credit a window as it reads
//! nor answer a PING. The peers built on this can; what they ask, and when,
//! is theirs (see the server's and the client's `dst_peer`).
//!
//! Nothing here trusts the program: DATA past a window it was given, a frame
//! larger than allowed, a frame inside a header block or a block that does
//! not decode is a failure, after which the peer resets the connection.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Duration;

use runtime::bytes::BytesMut;
use runtime_core::deterministic_testing::{ActorCx, ReadReply, WriteReply};

use super::{
    DATA, FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM, GOAWAY, HEADERS, PING, RST_STREAM, SETTINGS,
    WINDOW_UPDATE, frame, frame_at,
};
use crate::shared::hpack::{Decoder, Header};

pub(crate) const CONTINUATION: u8 = 0x9;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// §6.5.2.
pub(crate) const MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub(crate) const INITIAL_WINDOW_SIZE: u16 = 0x4;
const MAX_FRAME_SIZE: u16 = 0x5;

/// §6.9.2 and §4.2: what holds until a SETTINGS says otherwise.
const DEFAULT_WINDOW: i64 = 65_535;
const DEFAULT_FRAME: usize = 16_384;

/// §3.4.
pub(crate) const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The wire's own timer; a peer's tags must stay below it.
pub(crate) const CREDIT: u64 = 1 << 32;

/// §7.
pub(crate) const CANCEL: u32 = 0x8;

/// What the program sent that the peer on top acts on; the wire handles the
/// rest itself.
#[derive(Debug)]
pub(crate) enum In {
    /// A whole header block, decoded.
    Headers {
        id: u32,
        end: bool,
        status: Option<u16>,
        method: Option<String>,
        path: Option<String>,
    },
    Data {
        id: u32,
        payload: Vec<u8>,
        end: bool,
    },
    Reset {
        id: u32,
        code: u32,
    },
    GoAway {
        last: u32,
        code: u32,
    },
}

/// How the peer gives back what the program sent it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Credit {
    /// Each round of WINDOW_UPDATEs held back by a delay drawn from here, in
    /// milliseconds.
    pub(crate) delay: (u64, u64),
    /// A stream is credited once this much is owed on it, so less often than
    /// every frame. Held under half the initial window, or a stream could
    /// stall waiting for a credit that never comes.
    pub(crate) batch: u32,
}

/// One direction's windows (§6.9).
#[derive(Debug)]
pub(crate) struct Windows {
    pub(crate) conn: i64,
    pub(crate) initial: i64,
    streams: HashMap<u32, i64>,
}

impl Windows {
    fn new() -> Self {
        Self {
            conn: DEFAULT_WINDOW,
            initial: DEFAULT_WINDOW,
            streams: HashMap::new(),
        }
    }

    fn stream(&mut self, id: u32) -> &mut i64 {
        let initial = self.initial;
        self.streams.entry(id).or_insert(initial)
    }

    /// §6.9.2: a new initial window moves every stream's by the difference,
    /// below zero included.
    fn resize(&mut self, initial: i64) {
        let delta = initial - self.initial;
        self.initial = initial;
        for window in self.streams.values_mut() {
            *window += delta;
        }
    }

    fn available(&mut self, id: u32) -> i64 {
        (*self.stream(id)).min(self.conn)
    }
}

/// A body still going out: its bytes, how far it got, and whether its last
/// frame ends the stream.
struct Outgoing {
    bytes: Vec<u8>,
    at: usize,
    end: bool,
}

pub(crate) struct Wire {
    inbox: Vec<u8>,
    outbox: VecDeque<u8>,
    /// Still to check the client preface: the peer plays a server.
    preface: bool,
    decoder: Decoder,
    /// A header block awaiting its CONTINUATION: its stream, its flags, and
    /// the fragments so far.
    block: Option<(u32, u8, Vec<u8>)>,
    /// What the program may send us, which it must keep to.
    pub(crate) recv: Windows,
    /// What we may send the program.
    pub(crate) send: Windows,
    max_frame: usize,
    /// One per SETTINGS of ours not yet acknowledged. A lowered initial window
    /// applies once the program has it, a raised one at once, so that the
    /// check is never stricter than the program's view.
    lowered: VecDeque<Option<i64>>,
    owed: BTreeMap<u32, u32>,
    owed_conn: u32,
    /// Streams whose own credit is no longer given: cancelled, or ended.
    held: HashSet<u32>,
    /// Streams credited a byte at a time, a peer metering a response out.
    pub(crate) metered: HashSet<u32>,
    pub(crate) credit: Credit,
    credit_armed: bool,
    outgoing: BTreeMap<u32, Outgoing>,
    /// The DATA frames the peer sends, drawn from this range.
    frame_sizes: (usize, usize),
    pub(crate) failure: Option<String>,
    reset_reported: bool,
    /// We sent FIN: reads see EOF once everything before it is read.
    pub(crate) closed: bool,
    short_writes: f64,
    write_latency: Option<Duration>,
}

impl Wire {
    pub(crate) fn new(server: bool, credit: Credit) -> Self {
        Self {
            inbox: Vec::new(),
            outbox: VecDeque::new(),
            preface: server,
            decoder: Decoder::new(4096),
            block: None,
            recv: Windows::new(),
            send: Windows::new(),
            max_frame: DEFAULT_FRAME,
            lowered: VecDeque::new(),
            owed: BTreeMap::new(),
            owed_conn: 0,
            held: HashSet::new(),
            metered: HashSet::new(),
            credit,
            credit_armed: false,
            outgoing: BTreeMap::new(),
            frame_sizes: (1, DEFAULT_FRAME),
            failure: None,
            reset_reported: false,
            closed: false,
            short_writes: 0.0,
            write_latency: None,
        }
    }

    /// Sends of the program's taken only in part at these odds, and each
    /// held back by up to `latency`.
    pub(crate) fn hostile(mut self, short_writes: f64, latency: Option<Duration>) -> Self {
        self.short_writes = short_writes;
        self.write_latency = latency;
        self
    }

    pub(crate) fn fail(&mut self, why: String) {
        self.failure.get_or_insert(why);
    }

    /// Bytes that are not a frame: the client preface.
    pub(crate) fn raw(&mut self, bytes: &[u8]) {
        self.outbox.extend(bytes);
    }

    pub(crate) fn frame(&mut self, kind: u8, flags: u8, id: u32, payload: &[u8]) {
        self.outbox.extend(frame(kind, flags, id, payload));
    }

    /// One SETTINGS frame; an initial window among `pairs` is accounted for
    /// as [`lowered`](Self::lowered) says.
    pub(crate) fn settings(&mut self, pairs: &[(u16, u32)]) {
        let mut payload = Vec::new();
        let mut lowered = None;
        for &(id, value) in pairs {
            payload.extend(id.to_be_bytes());
            payload.extend(value.to_be_bytes());
            if id == INITIAL_WINDOW_SIZE {
                let value = i64::from(value);
                if value >= self.recv.initial {
                    self.recv.resize(value);
                } else {
                    lowered = Some(value);
                }
            }
        }
        self.lowered.push_back(lowered);
        self.frame(SETTINGS, 0, 0, &payload);
    }

    /// Raise the connection's receive window by `increment`.
    pub(crate) fn widen(&mut self, increment: u32) {
        self.recv.conn += i64::from(increment);
        self.frame(WINDOW_UPDATE, 0, 0, &increment.to_be_bytes());
    }

    pub(crate) fn headers(&mut self, id: u32, block: &[u8], end: bool) {
        let flags = FLAG_END_HEADERS | if end { FLAG_END_STREAM } else { 0 };
        self.recv.stream(id);
        self.send.stream(id);
        self.frame(HEADERS, flags, id, block);
    }

    /// Queue a body, sent as the windows allow.
    pub(crate) fn body(&mut self, id: u32, bytes: Vec<u8>, end: bool, cx: &mut ActorCx) {
        self.outgoing.insert(id, Outgoing { bytes, at: 0, end });
        self.pump(cx);
    }

    /// Bytes of `id`'s body not yet sent.
    pub(crate) fn unsent(&self, id: u32) -> usize {
        self.outgoing
            .get(&id)
            .map_or(0, |out| out.bytes.len() - out.at)
    }

    /// §6.4: and nothing more on it from us, its credit with it.
    pub(crate) fn reset(&mut self, id: u32, code: u32) {
        self.outgoing.remove(&id);
        self.held.insert(id);
        self.owed.remove(&id);
        self.frame(RST_STREAM, 0, id, &code.to_be_bytes());
    }

    pub(crate) fn goaway(&mut self, last: u32, code: u32) {
        let mut payload = last.to_be_bytes().to_vec();
        payload.extend(code.to_be_bytes());
        self.frame(GOAWAY, 0, 0, &payload);
    }

    /// Send what the windows let through, a frame per stream in turn.
    pub(crate) fn pump(&mut self, cx: &mut ActorCx) {
        loop {
            let mut progress = false;
            let ids: Vec<u32> = self.outgoing.keys().copied().collect();
            for id in ids {
                let available = self.send.available(id).max(0) as usize;
                let size = cx.between(self.frame_sizes.0 as u64, self.frame_sizes.1 as u64);
                let Some(out) = self.outgoing.get_mut(&id) else {
                    continue;
                };
                let left = out.bytes.len() - out.at;
                let n = left.min(available).min(self.max_frame).min(size as usize);
                if n == 0 && left > 0 {
                    continue;
                }
                let last = n == left;
                let flags = if last && out.end { FLAG_END_STREAM } else { 0 };
                let chunk = frame(DATA, flags, id, &out.bytes[out.at..out.at + n]);
                out.at += n;
                self.outbox.extend(chunk);
                self.send.conn -= n as i64;
                *self.send.stream(id) -= n as i64;
                if last {
                    self.outgoing.remove(&id);
                }
                progress = true;
            }
            if !progress {
                return;
            }
        }
    }

    /// Everything whole the program sent, the wire's own frames handled.
    pub(crate) fn take(&mut self, cx: &mut ActorCx) -> Vec<In> {
        let mut events = Vec::new();
        if self.preface {
            let n = self.inbox.len().min(PREFACE.len());
            if self.inbox[..n] != PREFACE[..n] {
                self.fail("not the client preface".into());
                return events;
            }
            if n < PREFACE.len() {
                return events;
            }
            self.inbox.drain(..n);
            self.preface = false;
        }
        let mut at = 0;
        while self.failure.is_none()
            && let Some((frame, len)) = frame_at(&self.inbox[at..])
        {
            at += len;
            let (kind, flags, id) = (frame.kind, frame.flags, frame.stream_id);
            let payload = frame.payload.to_vec();
            if payload.len() > DEFAULT_FRAME {
                self.fail(format!(
                    "a {}-byte frame, past the 16 KiB allowed",
                    payload.len()
                ));
                break;
            }
            if self.block.is_some() && kind != CONTINUATION {
                self.fail(format!("frame type {kind} inside a header block"));
                break;
            }
            match kind {
                DATA => self.data(id, flags, &payload, &mut events),
                HEADERS => {
                    let Some(fragment) = unpadded(flags, &payload).map(|p| {
                        let skip = if flags & FLAG_PRIORITY != 0 { 5 } else { 0 };
                        p.get(skip..).unwrap_or_default().to_vec()
                    }) else {
                        self.fail(format!("bad padding on stream {id}"));
                        break;
                    };
                    self.recv.stream(id);
                    self.send.stream(id);
                    self.block = Some((id, flags, fragment));
                    if flags & FLAG_END_HEADERS != 0 {
                        self.decode(&mut events);
                    }
                }
                CONTINUATION => {
                    match &mut self.block {
                        Some((open, _, fragments)) if *open == id => {
                            fragments.extend_from_slice(&payload);
                        }
                        _ => {
                            self.fail(format!("a CONTINUATION on stream {id} out of place"));
                            break;
                        }
                    }
                    if flags & FLAG_END_HEADERS != 0 {
                        self.decode(&mut events);
                    }
                }
                RST_STREAM => {
                    self.outgoing.remove(&id);
                    self.held.insert(id);
                    self.owed.remove(&id);
                    events.push(In::Reset {
                        id,
                        code: word(&payload, 0),
                    });
                }
                SETTINGS if flags & FLAG_ACK != 0 => {
                    if let Some(Some(lowered)) = self.lowered.pop_front() {
                        self.recv.resize(lowered);
                    }
                }
                SETTINGS => {
                    for pair in payload.as_chunks::<6>().0 {
                        let value = u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]);
                        match u16::from_be_bytes([pair[0], pair[1]]) {
                            INITIAL_WINDOW_SIZE => self.send.resize(i64::from(value)),
                            MAX_FRAME_SIZE => self.max_frame = value as usize,
                            _ => {}
                        }
                    }
                    self.frame(SETTINGS, FLAG_ACK, 0, &[]);
                }
                PING if flags & FLAG_ACK == 0 => self.frame(PING, FLAG_ACK, 0, &payload),
                GOAWAY => events.push(In::GoAway {
                    last: word(&payload, 0) & 0x7fff_ffff,
                    code: word(&payload, 4),
                }),
                WINDOW_UPDATE => {
                    let increment = i64::from(word(&payload, 0) & 0x7fff_ffff);
                    match id {
                        0 => self.send.conn += increment,
                        id => *self.send.stream(id) += increment,
                    }
                }
                // PRIORITY, a PING's ACK, and what §5.5 says to ignore.
                _ => {}
            }
        }
        self.inbox.drain(..at);
        self.pump(cx);
        self.schedule(cx);
        events
    }

    fn data(&mut self, id: u32, flags: u8, payload: &[u8], events: &mut Vec<In>) {
        // §6.9.1: padding counts against the windows too.
        let len = payload.len() as i64;
        self.recv.conn -= len;
        *self.recv.stream(id) -= len;
        if self.recv.conn < 0 {
            self.fail(format!("DATA on stream {id} past the connection's window"));
            return;
        }
        if *self.recv.stream(id) < 0 {
            self.fail(format!("DATA on stream {id} past its window"));
            return;
        }
        let Some(body) = unpadded(flags, payload) else {
            self.fail(format!("bad padding on stream {id}"));
            return;
        };
        let end = flags & FLAG_END_STREAM != 0;
        self.owed_conn += len as u32;
        if end {
            self.held.insert(id);
            self.owed.remove(&id);
        } else if !self.held.contains(&id) {
            *self.owed.entry(id).or_default() += len as u32;
        }
        events.push(In::Data {
            id,
            payload: body.to_vec(),
            end,
        });
    }

    fn decode(&mut self, events: &mut Vec<In>) {
        let Some((id, flags, block)) = self.block.take() else {
            return;
        };
        let mut buf = BytesMut::from(&block[..]);
        let mut cursor = std::io::Cursor::new(&mut buf);
        let (mut status, mut method, mut path) = (None, None, None);
        let decoded = self.decoder.decode(&mut cursor, |header| match header {
            Header::Status(s) => status = Some(s.as_u16()),
            Header::Method(m) => method = Some(m.as_str().to_owned()),
            Header::Path(p) => path = Some(p.as_str().to_owned()),
            _ => {}
        });
        if let Err(error) = decoded {
            self.fail(format!(
                "stream {id}'s header block does not decode: {error:?}"
            ));
            return;
        }
        events.push(In::Headers {
            id,
            end: flags & FLAG_END_STREAM != 0,
            status,
            method,
            path,
        });
    }

    /// Arm the credit timer if anything is owed.
    fn schedule(&mut self, cx: &mut ActorCx) {
        if self.credit_armed || (self.owed_conn == 0 && self.owed.is_empty()) {
            return;
        }
        let (lo, hi) = self.credit.delay;
        let delay = Duration::from_millis(cx.between(lo, hi));
        cx.timer(delay, CREDIT);
        self.credit_armed = true;
    }

    /// The credit timer fired: give back what is owed, as the policy says.
    pub(crate) fn on_credit(&mut self, cx: &mut ActorCx) {
        self.credit_armed = false;
        if self.failure.is_some() {
            return;
        }
        if self.owed_conn > 0 {
            let owed = std::mem::take(&mut self.owed_conn);
            self.widen(owed);
        }
        // A lowered initial window lowers the batch with it, or a stream could
        // never owe enough to be credited again.
        let batch = self.credit.batch.min((self.recv.initial / 2).max(1) as u32);
        let mut updates = Vec::new();
        for (&id, owed) in &mut self.owed {
            let n = match self.metered.contains(&id) {
                true => 1.min(*owed),
                false if *owed >= batch => *owed,
                false => 0,
            };
            if n > 0 {
                *owed -= n;
                updates.push((id, n));
            }
        }
        self.owed.retain(|_, owed| *owed > 0);
        for (id, n) in updates {
            *self.recv.stream(id) += i64::from(n);
            self.frame(WINDOW_UPDATE, 0, id, &n.to_be_bytes());
        }
        // A metered stream keeps the timer going; a batch not yet reached
        // waits for more DATA, which arms it again.
        if self.owed.keys().any(|id| self.metered.contains(id)) {
            self.schedule(cx);
        }
    }

    /// What a read of at most `max` bytes gets.
    pub(crate) fn read(&mut self, max: usize, cx: &mut ActorCx) -> ReadReply {
        if !self.outbox.is_empty() && self.failure.is_none() {
            let n = (cx.between(1, max as u64) as usize).min(self.outbox.len());
            return ReadReply::Data(self.outbox.drain(..n).collect());
        }
        if self.failure.is_some() {
            return match std::mem::replace(&mut self.reset_reported, true) {
                false => ReadReply::Error(libc::ECONNRESET),
                true => ReadReply::Eof,
            };
        }
        match self.closed {
            true => ReadReply::Eof,
            false => ReadReply::Pending,
        }
    }

    /// Take what the program writes, or part of it; [`take`](Self::take)
    /// then makes frames of it.
    pub(crate) fn accept(&mut self, bytes: &[u8], cx: &mut ActorCx) -> WriteReply {
        if self.failure.is_some() {
            return match std::mem::replace(&mut self.reset_reported, true) {
                false => WriteReply::Error(libc::ECONNRESET),
                true => WriteReply::Error(libc::EPIPE),
            };
        }
        let chance = (cx.random() >> 11) as f64 / (1u64 << 53) as f64;
        let taken = match bytes.len() > 1 && chance < self.short_writes {
            true => cx.between(1, bytes.len() as u64 - 1) as usize,
            false => bytes.len(),
        };
        self.inbox.extend_from_slice(&bytes[..taken]);
        match self.write_latency {
            None => WriteReply::Accepted(taken),
            Some(max) => {
                let after = Duration::from_nanos(cx.between(0, max.as_nanos() as u64));
                WriteReply::AcceptedAfter(taken, after)
            }
        }
    }
}

/// A frame's payload without its padding (§6.1), if the padding fits.
fn unpadded(flags: u8, payload: &[u8]) -> Option<&[u8]> {
    if flags & FLAG_PADDED == 0 {
        return Some(payload);
    }
    let (&pad, rest) = payload.split_first()?;
    rest.len().checked_sub(pad as usize).map(|end| &rest[..end])
}

fn word(payload: &[u8], at: usize) -> u32 {
    payload
        .get(at..at + 4)
        .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// A header block of literals the peer sends: never indexed (§6.2.3), so the
/// program's decoder table is left alone, after `head`, static entries.
pub(crate) fn block(head: &[u8], path: Option<&str>) -> Vec<u8> {
    let mut out = head.to_vec();
    if let Some(path) = path {
        // `:path` is static entry 4; its value in a 7-bit length.
        assert!(path.len() < 127, "a path that fits a one-byte length");
        out.push(0x14);
        out.push(path.len() as u8);
        out.extend_from_slice(path.as_bytes());
    }
    out
}
