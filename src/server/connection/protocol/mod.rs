use std::net::SocketAddr;
use std::rc::Rc;

use crate::server::connection::{
    CONNECTION_INITIAL_WINDOW_SIZE, CONNECTION_RECV_WINDOW,
    shared_with_streams::{LiveStreams, StreamToken, retire_if_closed},
};
use crate::server::handler;
use crate::server::stream::{Lifecycle, StreamState};
use crate::server::{Handler, Incoming, Limits, Stream};
use crate::shared::codec::{
    frames::{
        FrameHandler, FrameKind, SettingsIter,
        encode::{
            encode_goaway, encode_ping, encode_rst_stream, encode_settings, encode_settings_ack,
            encode_window_update,
        },
        headers::Headers,
        stream_id::StreamId,
    },
    types::{
        CANCEL, DecodeError, ENHANCE_YOUR_CALM, FLOW_CONTROL_ERROR, NO_ERROR, PROTOCOL_ERROR,
        REFUSED_STREAM, STREAM_CLOSED, Setting, StreamViolation,
    },
};
use crate::shared::connection::{STREAM_ID, SharedConnection, settings::Settings};
use std::time::SystemTime;

/// How far stream errors — ours or the peer's — may run ahead of the streams
/// the connection has finished before it is closed as abusive. Bounds Rapid
/// Reset (CVE-2023-44487).
///
/// Measured against completed streams, not as a lifetime ceiling: honest
/// long-lived connections cancel constantly, and an attacker buying budget
/// would have to complete a real request for every extra reset.
pub(super) const FAULT_LIMIT: u32 = 100;

/// Control frames a peer may send in a row without making progress on a
/// request. PING and SETTINGS each force a frame back (CVE-2019-9512,
/// CVE-2019-9515). A burst, cleared by progress, not a lifetime total.
///
/// Known cost: a download crediting back half a §6.9.2 default window at a
/// time spends one unit per 32 KiB and trips this past ~300 MB.
pub(super) const CONTROL_FRAME_BURST: u32 = 10_000;

/// Frames a peer may send in a row that a conforming one has no reason to
/// send at all. Stricter than `CONTROL_FRAME_BURST` because these have no
/// honest case at volume. Cleared by progress, so an RFC 7540 client sending
/// a PRIORITY per request stays under it.
pub(super) const ODD_FRAME_BURST: u32 = 100;

enum FrameWorth {
    Progress,
    Control,
    Odd,
}

impl FrameWorth {
    /// Every kind but DATA, which [`Self::of_data`] judges.
    fn of(kind: FrameKind, length: u32) -> Self {
        match kind {
            // An empty fragment never reaches `max_header_block_size` (CVE-2024-27316).
            FrameKind::Headers | FrameKind::Continuation if length > 0 => Self::Progress,
            FrameKind::Headers | FrameKind::Continuation => Self::Odd,
            // PRIORITY is validated and ignored (CVE-2019-9513).
            FrameKind::Priority => Self::Odd,
            // §4.1: an unknown type MUST be ignored, which makes it free to send and
            // not free to receive.
            FrameKind::Unknown(_) => Self::Odd,
            _ => Self::Control,
        }
    }

    /// By its body, not its length: padding costs the peer no credit it does
    /// not get straight back, so a padded frame with nothing in it must not
    /// clear the budgets. Empty DATA without END_STREAM is not progress, and
    /// flow control accounts nothing for it either (CVE-2019-9518). Only on a
    /// live stream: DATA on a gone one is dropped, and calling it progress let
    /// a peer clear both budgets for free.
    fn of_data(body: usize, end_stream: bool, stream_live: bool) -> Self {
        match (body > 0 || end_stream, stream_live) {
            (true, true) => Self::Progress,
            (true, false) => Self::Control,
            (false, _) => Self::Odd,
        }
    }
}

pub struct Protocol<H: Handler> {
    peer_settings: Settings,
    shared: Rc<SharedConnection>,
    streams: Streams<H>,
    greeting: Greeting,
    phase: Phase,
    faults: u32,
    control_frames: u32,
    odd_frames: u32,
    pings_sent: u64,
}

/// §3.4. Apart from `Phase`: the peer can close its half before its preface,
/// and must still get no GOAWAY.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Greeting {
    /// An invalid preface is met with silence, not a GOAWAY.
    AwaitingPreface,
    /// The client's SETTINGS must be the first frame after its preface.
    AwaitingSettings,
    Greeted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    /// Reading and writing.
    Open,
    /// §6.8: a GOAWAY(NO_ERROR) went one way or the other; the streams in
    /// flight finish. `until` is ours: a shutdown bounds the drain, a peer's
    /// GOAWAY does not.
    Draining { until: Option<SystemTime> },
    /// The peer closed its half of the transport: nothing more will be read,
    /// and the transport must not be asked again. Streams waiting on the peer
    /// are reset at once; `HALF_CLOSED_TICKS` bounds the rest.
    HalfClosed { since: SystemTime },
    /// Nothing left but to flush and close.
    Closing,
}

struct Streams<H: Handler> {
    handler: H,
    limits: Limits,
    last_client_stream_id: STREAM_ID,
    goaway_stream_id: Option<STREAM_ID>,
    streams: Rc<LiveStreams>,
}

enum Rejected {
    /// §5.1: a frame the peer sent before it could see our RST_STREAM is
    /// dropped silently.
    Ignored,
    Refused(u32),
    Violation(StreamViolation),
    Fatal(u32, &'static str),
}

impl<H: Handler> Streams<H> {
    fn create(
        &mut self,
        settings: &Settings,
        shared: &Rc<SharedConnection>,
        headers: Box<Headers>,
    ) -> Result<(), Rejected> {
        let id = headers.stream_id();
        let raw: STREAM_ID = id.into();

        if !id.is_client_initiated() {
            return Err(Rejected::Fatal(
                PROTOCOL_ERROR,
                "HEADERS with server-initiated stream id",
            ));
        }

        // Not idle and not in the map: the stream is gone. A connection error
        // (§5.1, §5.1.1) unless we reset it ourselves, in which case trailers
        // already in flight are ignored (§5.1). HPACK is already in sync.
        if raw <= self.last_client_stream_id {
            return Err(match shared.take_reset(raw) {
                true => Rejected::Ignored,
                false => Rejected::Fatal(STREAM_CLOSED, "HEADERS on closed stream"),
            });
        }

        self.spend(raw);

        if self.goaway_stream_id.is_some_and(|last| raw > last) {
            return Err(Rejected::Refused(REFUSED_STREAM));
        }

        if is_malformed_request(&headers) {
            return Err(Rejected::Violation(StreamViolation::MalformedRequest));
        }

        if !self.admits() {
            return Err(Rejected::Refused(REFUSED_STREAM));
        }

        let stream = StreamState::create(settings, self.limits.stream_window, headers)
            .map_err(Rejected::Violation)?;
        let stream = Rc::new(stream);
        let token = StreamToken::new(
            id,
            Rc::clone(&stream),
            Rc::clone(shared),
            Rc::downgrade(&self.streams),
        );
        // The handler only reads the head here; the stream reaches its task
        // on the first poll, once it is in the map.
        let Some(task) = handler::start(&self.handler, Incoming::new(Stream::new(token))) else {
            // It panicked choosing, and the stream went with the unwind,
            // answered and never in the map.
            return Ok(());
        };
        self.streams.insert(raw, stream, task.into_handle());
        Ok(())
    }

    /// An id is spent as soon as we have seen it, stream or no stream: that
    /// is what tells a closed stream apart from an idle one.
    fn spend(&mut self, id: STREAM_ID) {
        self.last_client_stream_id = id.max(self.last_client_stream_id);
    }

    /// §5.1.2: the map only holds live streams, so its length is the current
    /// count.
    fn admits(&self) -> bool {
        self.streams.len() < self.limits.max_concurrent_streams as usize
    }

    fn body_is_starving(&self, id: STREAM_ID) -> bool {
        self.streams
            .get(id)
            .is_some_and(|stream| stream.body_is_starving(self.limits.body_min_rate))
    }

    fn recv_data(
        &mut self,
        shared: &SharedConnection,
        id: STREAM_ID,
        payload: &[u8],
        padded_len: u32,
        end_stream: bool,
    ) -> Result<u32, Rejected> {
        // §5.1: an idle stream only accepts HEADERS and PRIORITY.
        if id > self.last_client_stream_id {
            return Err(Rejected::Fatal(PROTOCOL_ERROR, "DATA on idle stream"));
        }

        // Not idle and not in the map: closed. After our RST_STREAM this is a
        // body in flight, ignored per §5.1 — answering each frame with a reset
        // made this a reflector. Otherwise the peer closed it itself: counted.
        let Some(stream) = self.streams.get(id) else {
            return Err(match shared.was_reset(id) {
                true => Rejected::Ignored,
                false => Rejected::Violation(StreamViolation::DataAfterEndStream),
            });
        };

        // Flow control is accounted before the content is judged. §6.9.1 makes
        // an overrun a connection error.
        if stream.recv_window(padded_len).is_err() {
            return Err(Rejected::Fatal(
                FLOW_CONTROL_ERROR,
                "stream receive window exceeded",
            ));
        }

        stream
            .recv_data(payload, end_stream)
            .map_err(Rejected::Violation)
    }

    /// `kill` takes the handle by value, so the entry has to come out first.
    /// Safe because the task is not running now — we are — so it holds no
    /// borrow and `write_frame` left no half-written frame behind.
    /// Returns the state the stream was in.
    fn remove(&mut self, id: STREAM_ID, shared: &SharedConnection) -> Option<Lifecycle> {
        let (stream, handle) = self.streams.remove(id)?;
        // Its task is about to be killed: it must not try to write.
        let before = stream.retire();
        handle.kill();
        // Body bytes the task never consumed still hold connection credit.
        shared.release_stream_credit(stream.take_unreleased());
        Some(before)
    }

    /// Connection credit after the window was spent. Bounded by
    /// `MAX_CONCURRENT_STREAMS`, and only walked when a writer can have been
    /// waiting, so a stream gone holds nothing to wake.
    fn wake_senders(&self) {
        let _ = self.streams.try_for_each(|stream| {
            stream.wake_sender();
            Ok::<(), ()>(())
        });
    }

    /// §6.9.2. The first overflow stops the walk: the connection is over.
    fn adjust_send_windows(&self, delta: i32) -> Result<(), ()> {
        self.streams
            .try_for_each(|stream| stream.adjust_send(delta))
    }

    /// An id absent from the map closed and was removed; the peer may have sent
    /// before receiving our RST_STREAM, which is legal.
    fn credit_send(&self, id: STREAM_ID, increment: u32) -> Result<(), Rejected> {
        // §5.1: an idle stream only accepts HEADERS and PRIORITY.
        if id > self.last_client_stream_id {
            return Err(Rejected::Fatal(
                PROTOCOL_ERROR,
                "WINDOW_UPDATE on idle stream",
            ));
        }

        let Some(stream) = self.streams.get(id) else {
            return Ok(());
        };
        stream
            .credit_send(increment)
            .map_err(|()| Rejected::Violation(StreamViolation::StreamWindowOverflow))
    }
}

impl<H: Handler> Streams<H> {
    /// Safe for the same reason [`Streams::remove`] is: the one task running
    /// is the connection's, so no stream task holds a borrow or a
    /// half-written frame.
    fn kill_all(&mut self) {
        for (stream, handle) in self.streams.take_all() {
            stream.retire();
            handle.kill();
        }
    }
}

impl<H: Handler> Drop for Streams<H> {
    /// A handle merely dropped detaches its task rather than stopping it: it
    /// parks on the bounded output, is never woken or dropped, and leaks the
    /// whole connection state. So streams are killed here.
    fn drop(&mut self) {
        self.kill_all();
    }
}

impl<H: Handler> Protocol<H> {
    pub(super) fn new(handler: H, peer: Option<SocketAddr>, limits: Limits) -> Self {
        // §6.5.2 defaults, until the peer's SETTINGS says otherwise.
        let peer_settings = Settings::default();
        let shared = SharedConnection::new(
            peer_settings.header_table_size,
            peer_settings.max_frame_size,
            CONNECTION_RECV_WINDOW,
            peer,
        );
        Self {
            peer_settings,
            shared: Rc::new(shared),
            streams: Streams {
                handler,
                limits,
                last_client_stream_id: 0,
                goaway_stream_id: None,
                streams: Rc::new(LiveStreams::new()),
            },
            greeting: Greeting::AwaitingPreface,
            phase: Phase::Open,
            faults: 0,
            control_frames: 0,
            odd_frames: 0,
            pings_sent: 0,
        }
    }

    pub(super) fn shared(&self) -> &SharedConnection {
        &self.shared
    }

    pub(super) fn has_live_streams(&self) -> bool {
        self.streams.streams.len() > 0
    }

    /// §6.8 GOAWAY rather than a silent close.
    pub(super) fn time_out(&mut self, reason: &'static str) {
        self.fail_connection(NO_ERROR, reason);
    }

    /// §6.7. Any frame from the peer answers it; the opaque is not checked.
    pub(super) fn ping(&mut self) {
        self.pings_sent += 1;
        let opaque = self.pings_sent.to_be_bytes();
        self.shared
            .write_frame(|out| encode_ping(out, opaque, false));
    }

    pub(super) fn phase(&self) -> Phase {
        self.phase
    }

    pub(super) fn is_done(&self) -> bool {
        matches!(
            self.phase,
            Phase::Draining { .. } | Phase::HalfClosed { .. }
        ) && !self.has_live_streams()
    }

    pub(super) fn shared_handle(&self) -> Rc<SharedConnection> {
        self.shared.clone()
    }

    /// §6.8: the server is stopping. GOAWAY(NO_ERROR) names the last stream
    /// taken, anything above it is refused and may be retried elsewhere, and
    /// what is in flight has until `until` to finish.
    pub(super) fn shut_down(&mut self, until: SystemTime) {
        match self.phase {
            // §3.4: no GOAWAY before the preface, and nothing to wait for.
            Phase::Open if self.greeting == Greeting::AwaitingPreface => {
                self.fail_connection(NO_ERROR, "shutting down");
            }
            Phase::Open => {
                let last = self.streams.last_client_stream_id;
                self.streams.goaway_stream_id = Some(last);
                self.shared.write_frame(|out| {
                    encode_goaway(out, StreamId::from(last), NO_ERROR, b"shutting down");
                });
                self.phase = Phase::Draining { until: Some(until) };
            }
            // The peer already said it opens nothing more.
            Phase::Draining { .. } => self.phase = Phase::Draining { until: Some(until) },
            // Bounded already, and a GOAWAY changes nothing for either.
            Phase::HalfClosed { .. } | Phase::Closing => {}
        }
    }

    /// The connection is over: whatever its streams were doing stops here,
    /// not when the connection is dropped. Resets nothing, since the GOAWAY
    /// already speaks for them.
    pub(super) fn end_streams(&mut self) {
        self.streams.kill_all();
    }

    pub(super) fn peer_closed(&mut self) {
        if self.phase == Phase::Closing {
            return;
        }
        self.phase = Phase::HalfClosed {
            since: runtime::runtime::now(),
        };
        self.shared.close_credit();
        self.reset_stalled();
    }

    /// A stream whose body was still coming would have its handler read the
    /// end of input as the end of the body, acting on a truncated one. A writer
    /// out of credit can never finish. CANCEL, and not counted as faults.
    pub(super) fn reset_stalled(&mut self) {
        if !matches!(self.phase, Phase::HalfClosed { .. }) {
            return;
        }
        let credit = self.shared.window.available_send();
        let mut stalled = Vec::new();
        let _ = self.streams.streams.try_for_each(|stream| {
            if !stream.input_ended() || stream.is_stalled_on_credit(credit) {
                stalled.push(stream.id());
            }
            Ok::<(), ()>(())
        });
        for id in stalled {
            self.reset_stream(id, CANCEL);
        }
    }

    /// §5.4.1. Idempotent: the first error is the one the peer hears about.
    fn fail_connection(&mut self, error_code: u32, reason: &'static str) {
        if self.phase == Phase::Closing {
            return;
        }
        self.phase = Phase::Closing;

        // §6.8: anything arriving above `last` from now on is refused.
        let last = self.streams.last_client_stream_id;
        self.streams.goaway_stream_id = Some(last);

        // §3.4: an invalid client preface is answered with nothing at all. It is
        // the only error that can reach us before `on_preface`.
        if self.greeting == Greeting::AwaitingPreface {
            return;
        }

        self.shared.write_frame(|out| {
            encode_goaway(out, StreamId::from(last), error_code, reason.as_bytes());
        });
    }

    /// §5.4.2. Counted against `FAULT_LIMIT`.
    fn fail_stream(&mut self, stream_id: StreamId, violation: StreamViolation) {
        self.reset_stream(stream_id, violation.code());
        self.count_fault("too many stream errors");
    }

    /// Sends RST_STREAM either way: REFUSED_STREAM answers an id that was never
    /// opened.
    fn reset_stream(&mut self, stream_id: StreamId, error_code: u32) {
        let raw: STREAM_ID = stream_id.into();
        // §5.1: a stream the peer had not finished with may still have a body or
        // trailers coming, to be ignored. Only a live stream says for certain that
        // its input ended; an idle id has sent nothing to tolerate.
        let peer_done = self
            .streams
            .remove(raw, &self.shared)
            .is_some_and(Lifecycle::input_ended);
        if !peer_done && raw <= self.streams.last_client_stream_id {
            self.shared.note_reset(raw);
        }
        self.shared
            .write_frame(|out| encode_rst_stream(out, stream_id, error_code));
    }

    /// §5.4.1 for a peer that is not making requests. An odd frame spends both
    /// budgets, so the strict one runs out first.
    fn count_frame(&mut self, worth: FrameWorth) {
        match worth {
            FrameWorth::Progress => {
                self.control_frames = 0;
                self.odd_frames = 0;
            }
            FrameWorth::Control => self.control_frames += 1,
            FrameWorth::Odd => {
                self.control_frames += 1;
                self.odd_frames += 1;
            }
        }

        if self.odd_frames > ODD_FRAME_BURST {
            self.fail_connection(ENHANCE_YOUR_CALM, "too many pointless frames");
        } else if self.control_frames > CONTROL_FRAME_BURST {
            self.fail_connection(ENHANCE_YOUR_CALM, "too many control frames");
        }
    }

    /// Event-driven checks never see a stream that sends no DATA, or a writer
    /// parked on a peer that credits nothing — the shapes an attacker picks.
    /// Bounded by `MAX_CONCURRENT_STREAMS`.
    pub(super) fn sweep_starving_streams(&mut self) {
        // Collected first: resetting inside `try_for_each` would re-enter the
        // borrow it is contracted not to.
        let mut starving: Vec<StreamId> = Vec::new();
        let min_rate = self.streams.limits.body_min_rate;
        let _ = self.streams.streams.try_for_each(|stream| {
            if stream.body_is_starving(min_rate) || stream.output_is_starving() {
                starving.push(stream.id());
            }
            Ok::<(), ()>(())
        });

        for id in starving {
            self.reset_stream(id, ENHANCE_YOUR_CALM);
            self.count_fault("too many starved streams");
        }
    }

    fn count_fault(&mut self, reason: &'static str) {
        self.faults += 1;
        // Against completed streams, not a flat ceiling: see `FAULT_LIMIT`.
        if self.faults > FAULT_LIMIT.saturating_add(self.shared.completed_streams()) {
            self.fail_connection(ENHANCE_YOUR_CALM, reason);
        }
    }

    /// HEADERS on a live stream: its trailers (§8.1).
    fn on_trailers(&mut self, stream: Rc<StreamState>, headers: Box<Headers>) {
        let id = headers.stream_id();
        match stream.recv_trailers(headers) {
            // §8.1: trailers carry END_STREAM.
            Ok(()) => retire_if_closed(&self.streams.streams, &self.shared, id.into()),
            Err(violation) => self.fail_stream(id, violation),
        }
    }

    fn reject(&mut self, stream_id: StreamId, rejected: Rejected) {
        match rejected {
            Rejected::Ignored => {}
            Rejected::Refused(code) => self.reset_stream(stream_id, code),
            Rejected::Violation(violation) => self.fail_stream(stream_id, violation),
            Rejected::Fatal(code, reason) => self.fail_connection(code, reason),
        }
    }
}

/// §8.1.2.1/.3/.6: `:method` and `:scheme` are required, `:path` non-empty,
/// and no `:status` (a response pseudo-header).
fn is_malformed_request(headers: &Headers) -> bool {
    let p = headers.pseudo();
    p.status.is_some()
        || p.method.is_none()
        || p.scheme.is_none()
        || p.path.as_deref().is_none_or(str::is_empty)
}

impl<H: Handler> FrameHandler for Protocol<H> {
    /// `payload` borrows the decoder's buffer: valid only for the duration of
    /// the call. §6.9.1: `padded_len` includes the pad-length byte and padding.
    fn on_data(
        &mut self,
        stream_id: StreamId,
        payload: &[u8],
        padded_len: usize,
        end_stream: bool,
    ) {
        // Bounded by max_frame_size, itself below 2^24.
        let padded_len = padded_len as u32;
        let raw: STREAM_ID = stream_id.into();

        // Once per piece of a frame cut by a read, each with a body.
        let stream_live = self.streams.streams.get(raw).is_some();
        self.count_frame(FrameWorth::of_data(payload.len(), end_stream, stream_live));

        // Debited before anything is decided: the peer spent that credit whatever
        // we make of the frame, or our accounting drifts from its own.
        if self.shared.window.recv(padded_len).is_err() {
            return self.fail_connection(FLOW_CONTROL_ERROR, "connection receive window exceeded");
        }

        let received = self
            .streams
            .recv_data(&self.shared, raw, payload, padded_len, end_stream);

        // Padding never reaches an application, so it goes back now; otherwise the
        // window shrinks by it for good until the connection stalls.
        let padding = padded_len - payload.len() as u32;
        let spent = match received {
            Ok(consumed) => padding + consumed,
            Err(_) => padded_len,
        };
        self.shared.release_stream_credit(spent);

        if received.is_ok()
            && !end_stream
            && spent > 0
            && let Some(stream) = self.streams.streams.get(raw)
            && let Some(increment) = stream.release_recv(spent)
        {
            self.shared
                .write_frame(|out| encode_window_update(out, stream_id, increment));
        }

        // Either the peer's half closing or the task's token may retire the
        // stream last.
        if received.is_ok() && end_stream {
            retire_if_closed(&self.streams.streams, &self.shared, raw);
        }

        // Only while the body is still coming. A stream starved of DATA entirely
        // never reaches here: the sweep collects it.
        if received.is_ok() && !end_stream && self.streams.body_is_starving(raw) {
            self.reset_stream(stream_id, ENHANCE_YOUR_CALM);
            return self.count_fault("too many starved bodies");
        }

        if let Err(rejected) = received {
            self.reject(stream_id, rejected);
        }
    }

    fn on_headers(&mut self, headers: Box<Headers>) {
        let id = headers.stream_id();
        let raw: STREAM_ID = id.into();

        // §5.3.1: a stream MUST NOT depend on itself.
        if let Some(dep) = headers.stream_dep()
            && dep.dependency_id == id
        {
            return self.fail_stream(id, StreamViolation::HeadersSelfDependency);
        }

        // Truncated list: HPACK stays in sync, but the content must not reach the
        // handler, as a request or as trailers. Counted: the whole block was
        // decoded, and `FrameWorth` cleared both burst budgets for it.
        if headers.is_over_size() {
            self.streams.spend(raw);
            self.reset_stream(id, REFUSED_STREAM);
            return self.count_fault("too many over-sized header lists");
        }

        // §8.1: an id already live takes these HEADERS as its trailers.
        if let Some(stream) = self.streams.streams.get(raw) {
            return self.on_trailers(stream, headers);
        }

        if let Err(rejected) = self
            .streams
            .create(&self.peer_settings, &self.shared, headers)
        {
            // §5.1.2: a refusal is a request frame that made no progress, so it is
            // counted — otherwise a peer that fills the map and keeps asking holds
            // the burst budgets at zero, since `FrameWorth` calls the block progress.
            // Trailers that raced our reset are `Ignored`, and uncounted.
            let refused = matches!(rejected, Rejected::Refused(_));
            self.reject(id, rejected);
            if refused {
                self.count_fault("too many refused streams");
            }
        }
    }

    /// The decoder has already refused a non-zero stream id, an ACK with a
    /// payload, and a length that is not a multiple of 6.
    fn on_settings(&mut self, ack: bool, settings: SettingsIter<'_>) {
        // Acknowledging an ACK back would loop forever.
        if ack {
            return;
        }

        let initial_window_before = self.peer_settings.initial_window_size;

        for setting in settings {
            if let Err(invalid) = self.peer_settings.apply(setting) {
                return self.fail_connection(invalid.code, invalid.message);
            }
        }

        // Takes effect with the frame (RFC 7541 §4.2).
        self.shared
            .set_header_table_size(self.peer_settings.header_table_size);
        self.shared
            .set_max_frame_size(self.peer_settings.max_frame_size);

        // §6.9.2: one walk, from the value before the frame to the value after it.
        // Both are within 2^31-1, so the difference fits an i32.
        let delta = self.peer_settings.initial_window_size as i32 - initial_window_before as i32;
        if delta != 0 && self.streams.adjust_send_windows(delta).is_err() {
            return self.fail_connection(FLOW_CONTROL_ERROR, "stream send window exceeds 2^31-1");
        }

        // §6.5.3: the ACK must not overtake frames already queued, hence last.
        self.shared.write_frame(encode_settings_ack);
    }

    /// The decoder has already masked the reserved bit and refused a zero
    /// increment (§6.9.1), so `increment` is guaranteed in `1..=2^31-1`.
    fn on_window_update(&mut self, stream_id: StreamId, increment: u32) {
        if stream_id.is_zero() {
            match self.shared.window.credit_send(increment) {
                // §6.9.1: going past 2^31-1 is a connection error.
                Err(()) => {
                    return self.fail_connection(
                        FLOW_CONTROL_ERROR,
                        "connection send window exceeds 2^31-1",
                    );
                }
                Ok(true) => self.streams.wake_senders(),
                Ok(false) => {}
            }
            return;
        }

        let raw: STREAM_ID = stream_id.into();

        if let Err(rejected) = self.streams.credit_send(raw, increment) {
            self.reject(stream_id, rejected);
        }
    }

    /// Counted against `FAULT_LIMIT`, which is what bounds Rapid Reset:
    /// open-and-cancel in a loop never trips `MAX_CONCURRENT_STREAMS`.
    fn on_rst_stream(&mut self, stream_id: StreamId, _error_code: u32) {
        let raw: STREAM_ID = stream_id.into();

        // §6.4: an idle stream cannot be reset, there is nothing to reset.
        if raw > self.streams.last_client_stream_id {
            return self.fail_connection(PROTOCOL_ERROR, "RST_STREAM on idle stream");
        }

        self.streams.remove(raw, &self.shared);
        self.count_fault("too many stream resets");
    }

    /// §6.7. The decoder has already enforced stream 0 and the 8-byte length.
    fn on_ping(&mut self, ack: bool, opaque: [u8; 8]) {
        if ack {
            return;
        }
        self.shared
            .write_frame(|out| encode_ping(out, opaque, true));
    }

    /// §6.8: `NO_ERROR` drains, anything else closes.
    fn on_goaway(&mut self, _last_stream_id: StreamId, error_code: u32, _debug_data: &[u8]) {
        self.phase = match (self.phase, error_code) {
            (Phase::Open, NO_ERROR) => Phase::Draining { until: None },
            (phase, NO_ERROR) => phase,
            _ => Phase::Closing,
        };
    }

    /// After a `DecodeError::Connection` the decoder poisons itself and emits
    /// nothing more; noting that the connection is over is on us.
    fn on_error(&mut self, err: DecodeError) {
        match err {
            DecodeError::Connection { code, message } => self.fail_connection(code, message),
            DecodeError::Stream {
                stream_id,
                violation,
                ..
            } => {
                // §5.1: a HEADERS frame opens its stream whatever we make of the block,
                // so the body behind it is on a closed stream, not an idle one.
                if violation == StreamViolation::MalformedMessage && stream_id.is_client_initiated()
                {
                    self.streams.spend(stream_id.into());
                }
                // Every one is counted: one behind each HEADERS is MadeYouReset
                // (CVE-2025-8671), a handler spawned and killed per round while every
                // HEADERS clears the burst budgets.
                self.fail_stream(stream_id, violation)
            }
        }
    }

    /// §3.4: the first frame after the client preface must be its SETTINGS, and
    /// not an ACK.
    fn on_frame(&mut self, kind: FrameKind, _stream_id: StreamId, length: u32, flags: u8) {
        // DATA is counted in `on_data`, where its padding is off.
        if kind != FrameKind::Data {
            self.count_frame(FrameWorth::of(kind, length));
        }

        if self.greeting != Greeting::AwaitingSettings {
            return;
        }
        self.greeting = Greeting::Greeted;
        // §6.5: ACK is 0x1.
        if kind != FrameKind::Settings || flags & 0x1 != 0 {
            self.fail_connection(PROTOCOL_ERROR, "client preface not followed by SETTINGS");
        }
    }

    /// §3.4: the server preface must be the first thing we write. The decoder
    /// calls this before dispatching any frame.
    fn on_preface(&mut self) {
        let limits = self.streams.limits;
        self.shared.write_frame(|out| {
            encode_settings(
                out,
                &[
                    Setting::MaxConcurrentStreams(limits.max_concurrent_streams),
                    Setting::EnablePush(0),
                    Setting::MaxHeaderListSize(limits.max_header_list_size),
                    // §6.9.2: every `StreamWindow` starts its ledger at this number, and no
                    // stream exists before this frame is out.
                    Setting::InitialWindowSize(limits.stream_window),
                ],
            );
        });

        // §6.9.2: the connection window starts at 65535 and SETTINGS never
        // touches it. Frame and credit go together, so the ledger never says more
        // than the wire.
        let gap = CONNECTION_RECV_WINDOW - CONNECTION_INITIAL_WINDOW_SIZE;
        self.shared
            .write_frame(|out| encode_window_update(out, StreamId::ZERO, gap));
        self.shared.window.announce_recv(gap);

        self.greeting = Greeting::AwaitingSettings;
    }
}
