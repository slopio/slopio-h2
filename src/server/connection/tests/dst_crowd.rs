//! A crowd of healthy clients sharing one worker with a few that are ailing.
//!
//! Nothing here needs malice: a client whose software hung, a host that
//! dropped off the network, a link too slow to carry a header, a program
//! stuck in a loop. Whatever goes wrong with a few peers must not put the
//! server, or the clients it is serving well, at risk: that is what
//! `FLUSH_TIMEOUT`, the partial-header deadline, the flood budgets and the
//! empty-ring backoff are for. Each seed draws dozens of healthy clients,
//! calm ones (the `dst` dialogues without their faults), and among them a few
//! of these:
//!
//! - a **stuck reader**, whose reading side hung after asking for a large
//!   answer while its upload keeps flowing, so that its connection is stuck
//!   in a send while what it sends piles up in the buffer ring every
//!   connection shares;
//! - a **vanished** peer, which asks for a large answer and drops off the
//!   network;
//! - a **trickle**, a link so slow that a header block arrives a byte at a
//!   time;
//! - a **chatty** peer, software stuck sending PINGs by the thousand.
//!
//! What must hold whatever the seed: every healthy client is answered in
//! full, within [`BOUND`] of arriving; every connection ends, the ailing ones
//! on the server's deadlines or budgets; nothing is left open, owed or in
//! flight.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::rc::Rc;
use std::time::Duration;

use runtime_core::deterministic_testing::{
    AcceptEvent, Actor, ActorCx, Dialogue, DialogueReport, FakeRingHandle, Faults, FdKind,
    ReadReply, Scripted, WriteReply, mint,
};
use runtime_core::io_driver::operations::sockets::multi_accept::MultiAccept;
use runtime_core::runtime::{RuntimeInner, spawn};
use runtime_streams::StreamExt;

use super::{GET_BLOCK, PREFACE, echo};
use crate::dst::peer::block;
use crate::dst::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, HEADERS, PING, Rng, SETTINGS, Slot, WINDOW_UPDATE,
    explore, frame, judge, leftovers, profile, ring,
};
use crate::server::connection::Connection;
use crate::server::{Limits, Stream};
use crate::shared::transport::PlainMessages;

// A ring a single connection can empty, as a busy worker's would be.
runtime_core::define_buf_ring!(
    CrowdRing,
    bgid = 0,
    buffer_size = 1024,
    ring_size = 32,
    pool_size = 64
);

const SEEDS: u64 = 32;

const HEALTHY: (usize, usize) = (16, 48);
const AILING: (usize, usize) = (1, 4);

/// How long a healthy client may take from arriving to its last answer.
const BOUND: Duration = Duration::from_secs(1);

/// What an ailing client asks for: more than any send buffer holds.
const LARGE: usize = 1 << 20;

/// `/` is the echo; `/<n>` is `n` bytes, for the ailing clients not to read.
async fn serve(stream: Stream) {
    let n: Option<usize> = stream
        .path()
        .and_then(|p| p.strip_prefix('/')?.parse().ok());
    let Some(n) = n else {
        return echo(stream).await;
    };
    stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
    let body = vec![b'y'; n];
    let (body, last) = body.split_at(n.saturating_sub(16_384));
    for chunk in body.chunks(16_384) {
        stream.write_data(chunk).await;
    }
    stream.write_data_final(last).await;
}

/// A healthy client's dialogue, and when it finished, counted from its
/// arrival.
struct Timed {
    inner: Dialogue,
    report: Rc<RefCell<DialogueReport>>,
    opened: Duration,
    took: Rc<Cell<Option<Duration>>>,
}

impl Timed {
    fn clock(&self, cx: &ActorCx) {
        let report = self.report.borrow();
        if self.took.get().is_none() && report.done == report.total {
            self.took.set(Some(cx.now() - self.opened));
        }
    }
}

impl Actor for Timed {
    fn on_open(&mut self, cx: &mut ActorCx) {
        self.opened = cx.now();
        self.inner.on_open(cx);
        self.clock(cx);
    }

    fn read(&mut self, max: usize, cx: &mut ActorCx) -> ReadReply {
        let reply = self.inner.read(max, cx);
        self.clock(cx);
        reply
    }

    fn write(&mut self, bytes: &[u8], cx: &mut ActorCx) -> WriteReply {
        let reply = self.inner.write(bytes, cx);
        self.clock(cx);
        reply
    }

    fn on_closed(&mut self, cx: &mut ActorCx) {
        self.inner.on_closed(cx);
    }

    fn on_timer(&mut self, tag: u64, cx: &mut ActorCx) {
        self.inner.on_timer(tag, cx);
        self.clock(cx);
    }
}

/// The stuck reader's timer, and what it sends each time.
const FEED: u64 = 1;
const FEED_EVERY: Duration = Duration::from_millis(30);
const FEED_BYTES: usize = 30 * 1024;

/// A client whose reading side hung after asking for [`LARGE`], while its
/// upload goes on: a body 30 KiB every 30 ms, a fresh POST each 60 KiB to stay
/// inside the default window, until the server lets it go. Not finer: each tick offers it the server's stalled
/// send again, which is what a run spends its time on.
struct StuckReader {
    outbox: VecDeque<u8>,
    /// Room in a send buffer nobody drains.
    room: usize,
    stream: u32,
    sent: usize,
    closed: bool,
}

impl StuckReader {
    fn new(room: usize) -> Self {
        let mut outbox: VecDeque<u8> = PREFACE.iter().copied().collect();
        outbox.extend(frame(SETTINGS, 0, 0, &[]));
        outbox.extend(frame(WINDOW_UPDATE, 0, 0, &(1u32 << 30).to_be_bytes()));
        let path = format!("/{LARGE}");
        let flags = FLAG_END_HEADERS | FLAG_END_STREAM;
        outbox.extend(frame(HEADERS, flags, 1, &block(&[0x82, 0x86], Some(&path))));
        outbox.extend(frame(
            HEADERS,
            FLAG_END_HEADERS,
            3,
            &block(&[0x83, 0x86], Some("/")),
        ));
        Self {
            outbox,
            room,
            stream: 3,
            sent: 0,
            closed: false,
        }
    }
}

impl Actor for StuckReader {
    fn on_open(&mut self, cx: &mut ActorCx) {
        cx.timer(FEED_EVERY, FEED);
    }

    fn read(&mut self, max: usize, cx: &mut ActorCx) -> ReadReply {
        if self.outbox.is_empty() {
            return ReadReply::Pending;
        }
        let n = (cx.between(1, max as u64) as usize).min(self.outbox.len());
        ReadReply::Data(self.outbox.drain(..n).collect())
    }

    fn write(&mut self, bytes: &[u8], _: &mut ActorCx) -> WriteReply {
        let taken = bytes.len().min(self.room);
        self.room -= taken;
        match taken {
            0 => WriteReply::Pending,
            n => WriteReply::Accepted(n),
        }
    }

    fn on_closed(&mut self, _: &mut ActorCx) {
        self.closed = true;
    }

    fn on_timer(&mut self, _: u64, cx: &mut ActorCx) {
        if self.closed {
            return;
        }
        let end = self.sent + FEED_BYTES >= 60 * 1024;
        let flags = if end { FLAG_END_STREAM } else { 0 };
        self.outbox
            .extend(frame(DATA, flags, self.stream, &[b'x'; FEED_BYTES]));
        self.sent += FEED_BYTES;
        if end {
            self.stream += 2;
            self.sent = 0;
            let head = block(&[0x83, 0x86], Some("/"));
            self.outbox
                .extend(frame(HEADERS, FLAG_END_HEADERS, self.stream, &head));
        }
        cx.timer(FEED_EVERY, FEED);
    }
}

/// What ails a client.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Ailing {
    StuckReader,
    Vanished,
    Trickle,
    Chatty,
}

fn opening() -> Vec<u8> {
    let mut bytes = PREFACE.to_vec();
    bytes.extend(frame(SETTINGS, 0, 0, &[]));
    bytes
}

fn attach_ailing(kind: Ailing, rng: &mut Rng, fd: i32, handle: &FakeRingHandle) {
    match kind {
        Ailing::StuckReader => handle.attach(fd, StuckReader::new(rng.upto((0, 4096)))),
        Ailing::Vanished => {
            let path = format!("/{LARGE}");
            let flags = FLAG_END_HEADERS | FLAG_END_STREAM;
            let mut bytes = opening();
            bytes.extend(frame(HEADERS, flags, 1, &block(&[0x82, 0x86], Some(&path))));
            let (peer, _) = Dialogue::new()
                .send(bytes)
                .wait(rng.millis(0, 20))
                .vanish()
                .build();
            handle.attach(fd, peer);
        }
        Ailing::Trickle => {
            // A header block with a field long enough to trickle past
            // `PARTIAL_TIMEOUT`, a byte every half second.
            let mut fields = GET_BLOCK.to_vec();
            fields.extend([0x10, 5]);
            fields.extend(b"x-pad");
            fields.push(40);
            fields.extend([b'a'; 40]);
            let headers = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &fields);
            let mut dialogue = Dialogue::new().send(opening());
            for byte in headers {
                dialogue = dialogue.wait(Duration::from_millis(500)).send(vec![byte]);
            }
            handle.attach(fd, dialogue.close().build().0);
        }
        Ailing::Chatty => {
            let mut bytes = opening();
            for i in 0..20_000u64 {
                bytes.extend(frame(PING, 0, 0, &i.to_be_bytes()));
            }
            let (peer, _) = Dialogue::new()
                .send(bytes)
                .wait(Duration::from_secs(60))
                .close()
                .build();
            handle.attach(fd, peer);
        }
    }
}

struct Healthy {
    fd: i32,
    report: Rc<RefCell<DialogueReport>>,
    took: Rc<Cell<Option<Duration>>>,
}

#[derive(Debug, PartialEq, Eq)]
struct Summary {
    ailing: Vec<Ailing>,
    /// The slowest healthy client.
    slowest: Duration,
    elapsed: Duration,
}

fn run(seed: u64, journal: Option<&Slot>) -> Result<Summary, String> {
    let mut rng = Rng(seed);
    let mut calm = profile(&mut rng);
    calm.faults = Faults::default();
    let (fake, handle) = ring(seed, &calm, journal);

    let healthy_count = rng.upto(HEALTHY);
    let mut kinds: Vec<Option<Ailing>> = vec![None; healthy_count];
    let mut ailing = Vec::new();
    for _ in 0..rng.upto(AILING) {
        let kind = match rng.between(0, 3) {
            0 => Ailing::StuckReader,
            1 => Ailing::Vanished,
            2 => Ailing::Trickle,
            _ => Ailing::Chatty,
        };
        ailing.push(kind);
        let at = rng.upto((0, kinds.len()));
        kinds.insert(at, Some(kind));
    }

    let mut healthy = Vec::new();
    let mut arrivals: Vec<Scripted> = Vec::new();
    for kind in kinds {
        let fd = mint(FdKind::Socket);
        match kind {
            Some(kind) => attach_ailing(kind, &mut rng, fd, &handle),
            None => {
                let (inner, report) = super::dst::dialogue(&mut rng, &calm).build();
                let took = Rc::new(Cell::new(None));
                let timed = Timed {
                    inner,
                    report: report.clone(),
                    opened: Duration::ZERO,
                    took: took.clone(),
                };
                handle.attach(fd, timed);
                healthy.push(Healthy { fd, report, took });
            }
        }
        // Each arrival counts from the one before it.
        arrivals.push(AcceptEvent::On(fd).after(rng.millis(0, 10)));
    }
    let count = arrivals.len();

    let script = handle.clone();
    RuntimeInner::simulated(fake).block_on::<CrowdRing, _>(
        async move {
            let mut listener = MultiAccept::new(0).expect("bind");
            let arrivals = arrivals.into_iter().map(|arrival| vec![arrival]);
            script.on_multishot_accept(listener.socket().fd(), arrivals);
            let mut connections = Vec::with_capacity(count);
            while connections.len() < count {
                match listener.next().await {
                    Some(Ok(socket)) => {
                        let transport = PlainMessages::<CrowdRing, false>::new(socket);
                        let connection = Connection::new(transport, None, Limits::default(), serve);
                        connections.push(spawn(connection.run()));
                    }
                    Some(Err(_)) => continue,
                    None => break,
                }
            }
            drop(listener);
            for connection in connections {
                connection.await;
            }
        },
        None,
        |run| run(),
    );

    let mut failures = String::new();
    let mut slowest = Duration::ZERO;
    for client in &healthy {
        let report = client.report.borrow();
        if let Some(failure) = &report.failure {
            let _ = writeln!(failures, "fd {}: {failure}", client.fd);
        }
        match client.took.get() {
            None => {
                let _ = writeln!(
                    failures,
                    "fd {}: played {} of {} steps",
                    client.fd, report.done, report.total
                );
            }
            Some(took) if took > BOUND => {
                let _ = writeln!(
                    failures,
                    "fd {}: answered in {took:?}, past {BOUND:?}",
                    client.fd
                );
            }
            Some(took) => slowest = slowest.max(took),
        }
    }
    leftovers(&handle, &mut failures);
    if !failures.is_empty() {
        return Err(format!("ailing: {ailing:?}\n{failures}"));
    }
    ailing.sort();
    Ok(Summary {
        ailing,
        slowest,
        elapsed: handle.clock().expect("virtual time").elapsed(),
    })
}

#[test]
fn a_few_ailing_peers_do_not_hold_up_the_healthy_many() {
    let mut seen: BTreeMap<Ailing, usize> = BTreeMap::new();
    let mut slowest = Duration::ZERO;
    explore("server_dst_crowd", SEEDS, run, |_, summary: Summary| {
        for kind in summary.ailing {
            *seen.entry(kind).or_default() += 1;
        }
        slowest = slowest.max(summary.slowest);
    });
    eprintln!("ailing clients met: {seen:?}; slowest healthy client {slowest:?}");
}

#[test]
fn a_seed_replays_the_same_run() {
    for seed in crate::dst::seeds(SEEDS).take(4) {
        assert_eq!(judge(seed, run), judge(seed, run), "seed {seed}");
    }
}
