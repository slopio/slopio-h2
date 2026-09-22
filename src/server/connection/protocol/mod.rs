use std::rc::Rc;

use crate::server::connection::{
    CONNECTION_INITIAL_WINDOW_SIZE, CONNECTION_RECV_WINDOW, MAX_CONCURRENT_STREAMS,
    STREAM_RECV_WINDOW,
    shared_with_streams::{LiveStreams, StreamToken, retire_if_closed},
};
use crate::server::stream::StreamState;
use crate::server::{Handler, Stream};
use crate::shared::codec::{
    frames::{
        DECODE_MAX_HEADER_LIST_SIZE, FrameHandler, FrameKind, SettingsIter,
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

/// How far a connection's stream errors — ours to report or the peer's to
/// send — may run *ahead of the streams it has finished* before it is closed
/// as abusive.
///
/// One counter for both kinds: a malformed request and a CANCEL are different
/// faults, but a peer that piles up either is the same problem, and Rapid
/// Reset (CVE-2023-44487) is exactly the second kind.
///
/// Measured against completed streams rather than as a lifetime ceiling,
/// because the ceiling could not tell the attack from its most ordinary
/// neighbour. Cancelling is what a deadline, a user navigating away, or the
/// loser of two hedged calls looks like, and a gRPC connection that lives for
/// hours does it constantly — a hundred over a lifetime is nothing, and the
/// connection died for it.
///
/// What Rapid Reset actually is, is cancelling *instead of* finishing: the
/// attack's whole point is to make the server do the work of a request
/// without paying for a response. So a stream that ran to its end earns the
/// room to cancel one more. An honest peer finishes far more than it
/// abandons and never approaches this; an attacker that tried to buy budget
/// would have to complete a real request for every extra reset, which is the
/// work it was trying not to do.
pub(super) const FAULT_LIMIT: u32 = 100;

/// Control frames a peer may send in a row without making any progress on a
/// request. PING and SETTINGS each force a frame straight back
/// (CVE-2019-9512, CVE-2019-9515) and every one of them costs a decode, so a
/// peer sending nothing else spends our output and our CPU while asking for
/// nothing.
///
/// A burst rather than a lifetime total, unlike `FAULT_LIMIT`: a request
/// frame that carries something clears it, so a connection doing real work
/// never approaches it. An upload is a stream of DATA and clears it
/// constantly; a flood reaches this in milliseconds; a keepalive PING every
/// 10s on a wholly idle connection would need a day.
///
/// The exception, and the cost of the rule, is a *download*: the peer
/// receives DATA and answers WINDOW_UPDATE, so nothing it sends is progress.
/// A client leaving its stream window at the §6.9.2 default and crediting it
/// back half a window at a time spends one unit per 32 KiB and trips this
/// somewhere past 300 MB. The clients that matter announce a large window
/// instead of a chatty one, so it is a bound on the conservative client
/// rather than a common case — but the budget cannot tell it from a flood,
/// which is the strongest argument for the rate this wants to become.
pub(super) const CONTROL_FRAME_BURST: u32 = 10_000;

/// Frames a peer may send in a row that a conforming one has no reason to
/// send at all.
///
/// Far stricter than `CONTROL_FRAME_BURST` because the two bound different
/// things. A PING is a keepalive and a WINDOW_UPDATE is how a download
/// proceeds: legal, purposeful, and legitimately voluminous, so their budget
/// has to be generous enough for the honest case — which is what leaves it
/// too generous for frames that have no honest case. An empty CONTINUATION
/// fragment is not a keepalive. Nothing a well-behaved peer does produces
/// one, so a hundred in a row with no request between them is already a peer
/// worth closing on, and a hundred is the same number `FAULT_LIMIT` allows
/// for the same reason.
///
/// A burst cleared by progress, like the other, which is what keeps the one
/// real user of these out of it: a client still speaking the RFC 7540
/// priority scheme sends a PRIORITY frame per request, and the request
/// clears the count.
pub(super) const ODD_FRAME_BURST: u32 = 100;

/// What a frame is worth to the connection, read off its type, length and
/// flags — which is all `on_frame` has, and all the budgets need.
enum FrameWorth {
    /// Advances a request. Clears both budgets.
    Progress,
    /// Legal, purposeful and floodable: a keepalive PING, the SETTINGS of a
    /// preface, the WINDOW_UPDATEs of a download — and the body still in
    /// flight on a stream we reset, which is legal and advances nothing.
    Control,
    /// Legal and purposeless — a frame that costs us a decode and a dispatch
    /// and carries the peer nothing.
    Odd,
}

impl FrameWorth {
    /// `stream_live` is whether the frame's stream is one we are serving,
    /// and only DATA asks: it is the one frame whose worth depends on it.
    fn of(kind: FrameKind, length: u32, flags: u8, stream_live: bool) -> Self {
        match kind {
            // §6.1: END_STREAM is 0x1. A zero-length DATA frame that ends
            // the body is progress — `write_data` emits exactly that — and
            // one that does not says nothing, while flow control accounts
            // nothing for it either (CVE-2019-9518).
            //
            // Only on a stream that is still live. DATA on one that is gone
            // is dropped, so calling it progress let a peer clear both
            // budgets for free: one byte on a finished stream after every
            // few thousand PINGs, and the PING flood never ended.
            FrameKind::Data if length > 0 || flags & 0x1 != 0 => match stream_live {
                true => Self::Progress,
                false => Self::Control,
            },
            // A fragment carrying nothing adds nothing to the header block
            // `MAX_HEADER_BLOCK_SIZE` bounds, so that cap never sees one
            // however many arrive (CVE-2024-27316).
            FrameKind::Headers | FrameKind::Continuation if length > 0 => Self::Progress,
            FrameKind::Data | FrameKind::Headers | FrameKind::Continuation => Self::Odd,
            // RFC 9218 deprecated the RFC 7540 priority scheme and we
            // implement neither: the decoder validates a PRIORITY frame and
            // emits nothing at all (CVE-2019-9513).
            FrameKind::Priority => Self::Odd,
            // §4.1: an unknown type MUST be ignored, which is what makes it
            // free to send and not free to receive.
            FrameKind::Unknown(_) => Self::Odd,
            _ => Self::Control,
        }
    }
}
use runtime::spawn;

/// The connection's side of the protocol: what every frame does to it.
pub struct Protocol<H: Handler> {
    peer_settings: Settings,
    shared: Rc<SharedConnection>,
    streams: Streams<H>,
    /// Armed by `on_preface`, consumed by the next `on_frame`: §3.4 makes
    /// the client's SETTINGS the first frame after its preface.
    expect_settings: bool,
    /// Set by `on_preface`. Decides whether a connection error may be
    /// answered on the wire at all: §3.4 wants an invalid preface met with
    /// silence, not a GOAWAY.
    preface_seen: bool,
    /// Where the connection is in its life, which is what decides what the
    /// loop waits for, which deadlines apply, and when it is over.
    phase: Phase,
    /// Stream errors so far, against `FAULT_LIMIT`.
    faults: u32,
    /// Control frames since the last request frame, against
    /// `CONTROL_FRAME_BURST`.
    control_frames: u32,
    /// Purposeless frames since the last request frame, against
    /// `ODD_FRAME_BURST`.
    odd_frames: u32,
    /// Keepalive PINGs sent, which is what their opaques count.
    pings_sent: u64,
}

/// Where a connection is in its life.
///
/// Every way a connection ends used to be a way out of the loop — a `return`
/// here, a `break` there — and the loop knew only one way to be alive. So a
/// peer that said goodbye, or half-closed, had its requests in flight killed
/// with the connection, where §6.8 has them finish. The phases are what the
/// loop now asks instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    /// Reading and writing: the ordinary life of a connection.
    Open,
    /// The peer sent GOAWAY(NO_ERROR): it is leaving, and its streams in
    /// flight are to finish (§6.8). Read as in `Open` — their bodies, their
    /// WINDOW_UPDATEs and their resets still come — and over when the last
    /// of them is.
    Draining,
    /// The peer closed its half of the transport: nothing more will be
    /// read, and the transport must not be asked again. What is left is
    /// writing, until the streams are done or `HALF_CLOSED_TICKS` is up.
    /// A stream waiting on the peer — for its body, or for credit — waits
    /// on nothing and is reset at once; the time bound is for handlers still
    /// working, since the peer cannot answer a PING any more.
    HalfClosed { since: SystemTime },
    /// Nothing left but to flush and close: a connection error we answered,
    /// a deadline that ran out, or a peer that left on an error of its own.
    Closing,
}

struct Streams<H: Handler> {
    /// Cloned once per stream, at the spawn below.
    handler: H,
    last_client_stream_id: STREAM_ID,
    goaway_stream_id: Option<STREAM_ID>,
    /// Shared with every stream task, so one can take itself out when it
    /// ends rather than wait to be found.
    streams: Rc<LiveStreams>,
}

enum Rejected {
    /// A frame the peer sent before it could see our RST_STREAM: §5.1 has
    /// us drop it without a word.
    Ignored,
    /// Reset the id with this code, nothing else is wrong.
    Refused(u32),
    /// A stream error to report on the id.
    Violation(StreamViolation),
    /// The id itself breaks the protocol: the connection must go.
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

        // Not idle and not in the map: the stream existed and is gone. If the
        // peer closed it, or never opened it in this order, that is its fault
        // and the connection's end (§5.1, §5.1.1). But it may be one we reset
        // ourselves — an early response, a violation — with trailers the peer
        // had already sent, and §5.1 has whoever sends RST_STREAM ignore
        // what was in flight, as DATA in the same place is. HPACK is already
        // in sync: the decoder ran the block before we saw it.
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

        let stream = Rc::new(StreamState::create(settings, headers).map_err(Rejected::Violation)?);
        let token = StreamToken::new(
            id,
            Rc::clone(&stream),
            Rc::clone(shared),
            Rc::downgrade(&self.streams),
        );
        // The handler is invoked by the task's first poll, not here. Called
        // on this line instead, it would run — and could drop its stream —
        // before the `insert` below, so a stream could end while the map had
        // never heard of it. Deferring makes "in the map before the handler
        // can touch it" an ordering the code enforces rather than one the
        // handler has to respect.
        let handler = self.handler.clone();
        let handle = spawn(async move { handler.handle(Stream::new(token)).await });
        self.streams.insert(raw, stream, handle);
        Ok(())
    }

    /// An id is spent as soon as we have seen it, stream or no stream: that
    /// is what later tells a closed stream apart from an idle one.
    fn spend(&mut self, id: STREAM_ID) {
        self.last_client_stream_id = id.max(self.last_client_stream_id);
    }

    /// §5.1.2: the map only holds live streams, so its length is the current
    /// count.
    fn admits(&self) -> bool {
        self.streams.len() < MAX_CONCURRENT_STREAMS as usize
    }

    /// Hands one DATA payload to its stream. `payload` is already stripped of
    /// its padding; `padded_len` is what flow control accounts for. `Ok` is
    /// the payload buffered: only its padding is lost. On `Err` nothing was
    /// consumed.
    /// Whether the stream under `id` is being fed too slowly to be a body.
    /// A stream that has already gone answers `false`: there is nothing left
    /// to reset.
    fn body_is_starving(&self, id: STREAM_ID) -> bool {
        self.streams
            .get(id)
            .is_some_and(|stream| stream.body_is_starving())
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

        // Not idle and not in the map: the stream existed and is closed.
        // After our RST_STREAM that is a body in flight, and §5.1 has us
        // ignore it — answering each frame with a reset of its own is what
        // made this a reflector. Otherwise the peer closed the stream itself,
        // by END_STREAM or RST_STREAM, and sent DATA anyway: its fault, and
        // counted. The reset that answers it is remembered like any other,
        // so the rest of that frame, and whatever followed it, is ignored
        // rather than counted again.
        let Some(stream) = self.streams.get(id) else {
            return Err(match shared.was_reset(id) {
                true => Rejected::Ignored,
                false => Rejected::Violation(StreamViolation::DataAfterEndStream),
            });
        };

        // Flow control is accounted before the content is judged, as at the
        // connection level. §6.9.1 makes an overrun a connection error.
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

    /// Every way out of the map. `kill` takes the handle by value, so the
    /// entry has to come out first; the task's future is dropped on the
    /// scheduler's next pass, which cancels whatever it had in flight. Safe
    /// because the task is not running now — we are — so it holds no borrow
    /// and `write_frame` left no half-written frame behind.
    ///
    /// `None` when the id was never opened, which `reset_stream` still has
    /// to answer: REFUSED_STREAM is sent for streams that never existed.
    fn remove(&mut self, id: STREAM_ID, shared: &SharedConnection) -> Option<Rc<StreamState>> {
        let (stream, handle) = self.streams.remove(id)?;
        // Out of the table and its task about to be killed: what it would
        // have written reaches nobody, and it must not try.
        stream.note_retired();
        handle.kill();
        // Body bytes the task never consumed still hold connection credit.
        shared.release_stream_credit(stream.take_unreleased());
        Some(stream)
    }

    /// §6.9.2: shifts every live stream's send window. The first overflow
    /// stops the walk — the connection is over, the rest does not matter.
    fn adjust_send_windows(&self, delta: i32) -> Result<(), ()> {
        self.streams
            .try_for_each(|stream| stream.adjust_send(delta))
    }

    /// An id absent from the map is a stream that closed and was removed: the
    /// peer may have sent before receiving our RST_STREAM. That is legal, so
    /// `Ok`.
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

impl<H: Handler> Drop for Streams<H> {
    /// A handle merely *dropped* is a task detached, not stopped: it keeps
    /// its `Rc<SharedConnection>` alive, writes into an output no one will
    /// ever flush again, parks on the high-water mark, and is never woken —
    /// so it is never dropped either, and the whole connection state leaks
    /// with it. The connection therefore kills its streams on the way out.
    ///
    /// Only the bounded output makes this fatal: against a buffer that grew
    /// without limit, an orphaned writer ran to the end of its body and
    /// retired itself.
    ///
    /// Safe for the same reason [`Streams::remove`] is: the one task running
    /// is the connection's, so no stream task holds a borrow or a
    /// half-written frame.
    fn drop(&mut self) {
        for (stream, handle) in self.streams.take_all() {
            stream.note_retired();
            handle.kill();
        }
    }
}

impl<H: Handler> Protocol<H> {
    pub(super) fn new(handler: H) -> Self {
        // §6.5.2 defaults, until the peer's SETTINGS says otherwise — and
        // the encoder and frame size we start from are those same defaults.
        let peer_settings = Settings::default();
        let shared = SharedConnection::new(
            peer_settings.header_table_size,
            peer_settings.max_frame_size,
            CONNECTION_RECV_WINDOW,
        );
        Self {
            peer_settings,
            shared: Rc::new(shared),
            streams: Streams {
                handler,
                last_client_stream_id: 0,
                goaway_stream_id: None,
                streams: Rc::new(LiveStreams::new()),
            },
            expect_settings: false,
            preface_seen: false,
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

    /// Whether any stream is open, which is what separates an idle connection
    /// from one holding state on the peer's behalf.
    pub(super) fn has_live_streams(&self) -> bool {
        self.streams.streams.len() > 0
    }

    /// The peer said nothing for long enough. §6.8 GOAWAY rather than a
    /// silent close, so the peer can tell a deadline from a broken network.
    ///
    /// NO_ERROR and not ENHANCE_YOUR_CALM: reaching the idle deadline is not
    /// misbehaviour, it is the connection having served its purpose, and a
    /// client that reconnects on NO_ERROR is doing the right thing. The peer
    /// that *was* misbehaving — the one holding a half-sent frame — is told
    /// the same thing, because the two are indistinguishable from here and
    /// nothing is gained by guessing. So is a peer that did not answer our
    /// PING, which most likely will never read it.
    pub(super) fn time_out(&mut self, reason: &'static str) {
        self.fail_connection(NO_ERROR, reason);
    }

    /// §6.7: asks the peer whether it is still there.
    ///
    /// The opaque is a count of probes, so no two are alike, but nothing
    /// checks it on the way back: any frame from the peer answers the
    /// question, and the loop takes it as the answer before the ACK is
    /// dispatched.
    pub(super) fn ping(&mut self) {
        self.pings_sent += 1;
        let opaque = self.pings_sent.to_be_bytes();
        self.shared
            .write_frame(|out| encode_ping(out, opaque, false));
    }

    pub(super) fn phase(&self) -> Phase {
        self.phase
    }

    /// Whether a connection that is on its way out has nothing left to wait
    /// for: every stream the peer had in flight is done.
    pub(super) fn is_done(&self) -> bool {
        matches!(self.phase, Phase::Draining | Phase::HalfClosed { .. }) && !self.has_live_streams()
    }

    /// The peer closed its half of the transport.
    ///
    /// From here nothing it could send will arrive — no body, and no credit.
    /// The streams that were waiting on either are ended now (see
    /// [`reset_stalled`](Self::reset_stalled)), and the rest — requests the
    /// peer finished sending, handlers still working on them — are answered
    /// as usual, which is the point of staying.
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

    /// Resets every stream a half-closed peer has left with nothing to wait
    /// for.
    ///
    /// Two kinds. A stream whose body was still coming will never have it,
    /// and its handler would read the end of the input as the end of the
    /// body — acting on a truncated one as if it were whole. And a stream
    /// whose writer is out of credit will never get more, so its response
    /// cannot finish: RST_STREAM tells the peer, which can still read, where
    /// a close would leave it holding a body cut short without a word.
    ///
    /// CANCEL, and not counted as faults: a peer that stops sending is not
    /// misbehaving at us. Nothing to do before the half-close, when either
    /// could still arrive; called again whenever a writer runs dry after it.
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

    /// §5.4.1: a GOAWAY naming the last stream we took up, then no more
    /// reading. Idempotent — the first error is the one the peer hears
    /// about, later ones change nothing.
    fn fail_connection(&mut self, error_code: u32, reason: &'static str) {
        if self.phase == Phase::Closing {
            return;
        }
        self.phase = Phase::Closing;

        // §6.8: anything above `last` was never processed and the peer may
        // retry it elsewhere; anything arriving above it from now on is
        // refused rather than opened.
        let last = self.streams.last_client_stream_id;
        self.streams.goaway_stream_id = Some(last);

        // §3.4: an invalid client preface is answered with nothing at all,
        // not even a GOAWAY. It is the only error that can reach us before
        // `on_preface` — the decoder dispatches nothing else until then.
        if !self.preface_seen {
            return;
        }

        self.shared.write_frame(|out| {
            encode_goaway(out, StreamId::from(last), error_code, reason.as_bytes());
        });
    }

    /// §5.4.2: the peer broke the rules on one stream. The stream is reset
    /// with the violation's code, and the fault is counted — past
    /// `FAULT_LIMIT` the connection goes, since a peer that keeps erring is
    /// not one worth serving.
    fn fail_stream(&mut self, stream_id: StreamId, violation: StreamViolation) {
        self.reset_stream(stream_id, violation.code());
        self.count_fault("too many stream errors");
    }

    /// Kills the stream if it exists, and sends RST_STREAM either way: a
    /// REFUSED_STREAM answers an id that was never opened.
    fn reset_stream(&mut self, stream_id: StreamId, error_code: u32) {
        let raw: STREAM_ID = stream_id.into();
        // One the peer had not finished with may still have a body or
        // trailers coming, which §5.1 has us ignore. So may one that never
        // made it into the map — a request refused before its body arrived —
        // or one already out of it; only a live stream says for certain that
        // its input ended. An idle id has sent nothing to tolerate.
        let peer_done = self
            .streams
            .remove(raw, &self.shared)
            .is_some_and(|stream| stream.input_ended());
        if !peer_done && raw <= self.streams.last_client_stream_id {
            self.shared.note_reset(raw);
        }
        self.shared
            .write_frame(|out| encode_rst_stream(out, stream_id, error_code));
    }

    /// §5.4.1 for a peer that is not making requests.
    ///
    /// Two budgets watch the same stream of frames: a generous one for
    /// control frames, which have honest uses at volume, and a strict one
    /// for frames that have none. An odd frame spends both — it is not
    /// progress either — so the strict budget is simply the one that runs
    /// out first, and its message is the one the peer hears.
    fn count_frame(&mut self, kind: FrameKind, length: u32, flags: u8, stream_live: bool) {
        match FrameWorth::of(kind, length, flags, stream_live) {
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

    /// Resets every stream that is starving in either direction.
    ///
    /// The event-driven checks cannot see the cases that matter most. A body
    /// is judged when DATA arrives, so a stream that never sends any is never
    /// judged; a response is judged where it is written, so a peer that
    /// credits nothing leaves the writer parked and the check unreached. Both
    /// are the shape an attacker picks, and both need something that runs
    /// without the peer's help.
    ///
    /// Bounded by `MAX_CONCURRENT_STREAMS` — 64 — and run a few seconds apart,
    /// against a clock the scheduler already sampled.
    pub(super) fn sweep_starving_streams(&mut self) {
        // Collected first: resetting walks into the map to remove the entry,
        // and doing that inside `try_for_each` would re-enter the borrow it
        // is contracted not to.
        let mut starving: Vec<StreamId> = Vec::new();
        let _ = self.streams.streams.try_for_each(|stream| {
            if stream.body_is_starving() || stream.output_is_starving() {
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
        // Against what this connection has *finished*, not against a flat
        // ceiling. A stream that ran to its end is the work Rapid Reset
        // exists to avoid doing, so a peer that does it has earned the room
        // to cancel one more.
        if self.faults > FAULT_LIMIT.saturating_add(self.shared.completed_streams()) {
            self.fail_connection(ENHANCE_YOUR_CALM, reason);
        }
    }

    /// HEADERS on a live stream: its trailers (§8.1). The stream checks them
    /// and closes its input; a bad set is a stream error, like a bad DATA.
    fn on_trailers(&mut self, stream: Rc<StreamState>, headers: Box<Headers>) {
        let id = headers.stream_id();
        match stream.recv_trailers(headers) {
            // §8.1: trailers carry END_STREAM, so this closes the peer's
            // half exactly as a final DATA frame would.
            Ok(()) => retire_if_closed(&self.streams.streams, &self.shared, id.into()),
            Err(violation) => self.fail_stream(id, violation),
        }
    }

    /// Answers what `Streams` refused: it decides, we are the one that can
    /// write.
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
        || !p.path.as_deref().is_some_and(|path| !path.is_empty())
}

impl<H: Handler> FrameHandler for Protocol<H> {
    /// `payload` borrows the decoder's buffer: valid only for the duration of
    /// the call. §6.9.1: `padded_len` is what flow control accounts for,
    /// pad-length byte and padding included.
    fn on_data(
        &mut self,
        stream_id: StreamId,
        payload: &[u8],
        padded_len: usize,
        end_stream: bool,
    ) {
        // Bounded by max_frame_size, itself below 2^24.
        let padded_len = padded_len as u32;

        // Debited before anything is decided: the peer spent that credit
        // whatever we make of the frame, and skipping it on the paths that
        // fail would drift our accounting away from its own.
        if self.shared.window.recv(padded_len).is_err() {
            return self.fail_connection(FLOW_CONTROL_ERROR, "connection receive window exceeded");
        }

        let raw: STREAM_ID = stream_id.into();
        let received = self
            .streams
            .recv_data(&self.shared, raw, payload, padded_len, end_stream);

        // Padding is accounted by flow control but never reaches an
        // application, so it is spent the moment it lands; on a frame we drop,
        // all of it is. Either way it goes back now — release only what a
        // handler consumes and the window shrinks by the padding for good,
        // until the connection stalls with nothing to show for it. Payload the
        // stream consumed on the spot — a gRPC message filling — goes back
        // with it.
        let padding = padded_len - payload.len() as u32;
        let spent = match received {
            Ok(consumed) => padding + consumed,
            Err(_) => padded_len,
        };
        self.shared.release_stream_credit(spent);

        // The same bytes were debited from the stream's window, and the
        // handler's `consume` only ever returns what it took. Not worth a
        // frame on a stream the peer has just finished with.
        if received.is_ok() && !end_stream && spent > 0 {
            if let Some(stream) = self.streams.streams.get(raw)
                && let Some(increment) = stream.release_recv(spent)
            {
                self.shared
                    .write_frame(|out| encode_window_update(out, stream_id, increment));
            }
        }

        // The peer's half closing is the other half of what retires a
        // stream; the task's token is the first, and either may be last.
        if received.is_ok() && end_stream {
            retire_if_closed(&self.streams.streams, &self.shared, raw);
        }

        // Judged on DATA because that is when the evidence changes, and only
        // while the body is still coming: a peer that has sent END_STREAM owes
        // nothing more, however slowly it got there. A stream that is starved
        // of DATA entirely never reaches here at all — the sweep collects
        // that one, on whatever else the peer sends, the answer to our
        // keepalive PING included.
        if received.is_ok() && !end_stream && self.streams.body_is_starving(raw) {
            self.reset_stream(stream_id, ENHANCE_YOUR_CALM);
            return self.count_fault("too many starved bodies");
        }

        if let Err(rejected) = received {
            self.reject(stream_id, rejected);
        }
    }

    /// Two roles: opening a stream, or carrying the trailers (§8.1) of a live
    /// one.
    fn on_headers(&mut self, headers: Box<Headers>) {
        let id = headers.stream_id();
        let raw: STREAM_ID = id.into();

        // §5.3.1: a stream MUST NOT depend on itself. Checked before the id
        // itself, which the frame never gets to spend.
        if let Some(dep) = headers.stream_dep()
            && dep.dependency_id == id
        {
            return self.fail_stream(id, StreamViolation::HeadersSelfDependency);
        }

        // List truncated during decoding: HPACK state stays in sync, but the
        // content is incomplete and must not reach the handler — neither as a
        // request nor as trailers, hence before the lookup below.
        //
        // Counted, because it is the dearest refusal there is: the whole
        // block was decoded to learn it was too long, and `FrameWorth` saw a
        // full header block and cleared both burst budgets for it.
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
            // §5.1.2: a HEADERS frame that takes the peer past the
            // concurrency limit we advertised is a stream error, and a
            // refusal is a request frame that made no progress however full
            // its header block was. Both make it something the budgets have
            // to see — a peer that fills the map and then keeps asking
            // otherwise holds them at zero for as long as it likes, since
            // `FrameWorth` reads the block and calls it progress.
            //
            // Trailers that raced our reset are `Ignored`, and uncounted:
            // a race rather than a demand.
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
        // An ACK carries timing, not values: its payload is empty, and what
        // it says is that the settings we announced are now in force on the
        // peer's side. Acknowledging it back would loop forever.
        if ack {
            return;
        }

        let initial_window_before = self.peer_settings.initial_window_size;

        for setting in settings {
            if let Err(invalid) = self.peer_settings.apply(setting) {
                return self.fail_connection(invalid.code, invalid.message);
            }
        }

        // What bounds our writers takes effect with the frame: the encoder's
        // table (RFC 7541 §4.2) and the largest payload we may emit.
        self.shared
            .set_header_table_size(self.peer_settings.header_table_size);
        self.shared
            .set_max_frame_size(self.peer_settings.max_frame_size);

        // §6.9.2: a new initial window moves every live stream's send window
        // by the difference — one walk, from the value before the frame to
        // the value after it, however many times the frame repeated the id.
        // Both ends are within 2^31-1, so the difference fits an i32.
        let delta = self.peer_settings.initial_window_size as i32 - initial_window_before as i32;
        if delta != 0 && self.streams.adjust_send_windows(delta).is_err() {
            return self.fail_connection(FLOW_CONTROL_ERROR, "stream send window exceeds 2^31-1");
        }

        // §6.5.3: the values are in force as of now, and the ACK is what tells
        // the peer so. It must not overtake frames already queued, hence the
        // tail of this function rather than anywhere earlier.
        self.shared.write_frame(encode_settings_ack);
    }

    /// The decoder has already masked the reserved bit and refused a zero
    /// increment (§6.9.1), so `increment` is guaranteed in `1..=2^31-1`.
    fn on_window_update(&mut self, stream_id: StreamId, increment: u32) {
        if stream_id.is_zero() {
            // §6.9.1: going past 2^31-1 is a connection error.
            if self.shared.window.credit_send(increment).is_err() {
                return self
                    .fail_connection(FLOW_CONTROL_ERROR, "connection send window exceeds 2^31-1");
            }
            return;
        }

        let raw: STREAM_ID = stream_id.into();

        if let Err(rejected) = self.streams.credit_send(raw, increment) {
            self.reject(stream_id, rejected);
        }
    }

    /// The peer cancels a stream — a navigation abandoned, or a fault it
    /// found on our side. Nothing is written back; the stream just goes.
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

    /// §6.7: a probe is answered with the same opaque data, ACK set. An ACK
    /// is the peer answering a probe of ours, and there is nothing left to do
    /// with it: arriving at all was the answer, and the loop has already
    /// taken it (see [`Protocol::ping`]). The decoder has already enforced
    /// stream 0 and the 8-byte length.
    fn on_ping(&mut self, ack: bool, opaque: [u8; 8]) {
        if ack {
            return;
        }
        self.shared
            .write_frame(|out| encode_ping(out, opaque, true));
    }

    /// The peer is leaving. `NO_ERROR` is a graceful shutdown: what it has in
    /// flight is still to be answered (§6.8), and the connection drains. Any
    /// other code is a fault it found on our side, and a peer that says so
    /// is closing on us whatever we do — nothing is gained by answering it.
    ///
    /// `last_stream_id` names the streams *we* opened that it processed, and
    /// we open none.
    fn on_goaway(&mut self, _last_stream_id: StreamId, error_code: u32, _debug_data: &[u8]) {
        self.phase = match (self.phase, error_code) {
            (Phase::Open, NO_ERROR) => Phase::Draining,
            // Already on the way out, and a second goodbye changes nothing
            // about which way.
            (phase, NO_ERROR) => phase,
            _ => Phase::Closing,
        };
    }

    /// After a `DecodeError::Connection` the decoder poisons itself and emits
    /// nothing more; noting that the connection is over is on us.
    fn on_error(&mut self, err: DecodeError) {
        match err {
            DecodeError::Connection { code, message } => self.fail_connection(code, message),
            // The frame is already discarded; the stream is told why.
            DecodeError::Stream {
                stream_id,
                violation,
                ..
            } => {
                // §5.1: a HEADERS frame opens its stream whatever we make of
                // the block, so the reset closes a stream rather than leaving
                // an idle one — and the body the peer had already sent behind
                // it is a frame on a closed stream, not on an idle one. The
                // other decoder violations are PRIORITY and WINDOW_UPDATE,
                // which open nothing.
                if violation == StreamViolation::MalformedMessage && stream_id.is_client_initiated()
                {
                    self.streams.spend(stream_id.into());
                }
                // Every one is counted, not only the malformed block
                // `FrameWorth` called progress. The others — a WINDOW_UPDATE
                // of zero, a PRIORITY that is the wrong size or depends on
                // itself — are frames no honest peer sends, and one behind
                // each HEADERS is MadeYouReset (CVE-2025-8671): a handler
                // spawned and killed per round, for a frame that costs the
                // peer nothing, while every HEADERS clears the burst budgets.
                self.fail_stream(stream_id, violation)
            }
        }
    }

    /// Every frame comes through here before anything else, which is where
    /// §3.4 is checked: the first frame after the client preface must be its
    /// SETTINGS — and not an ACK, which it cannot legitimately send before
    /// having seen ours.
    fn on_frame(&mut self, kind: FrameKind, stream_id: StreamId, length: u32, flags: u8) {
        // A lookup per DATA frame, and only for DATA: the one frame whose
        // worth depends on its stream.
        let stream_live =
            kind == FrameKind::Data && self.streams.streams.get(stream_id.into()).is_some();
        self.count_frame(kind, length, flags, stream_live);

        if !std::mem::take(&mut self.expect_settings) {
            return;
        }
        // §6.5: ACK is 0x1.
        if kind != FrameKind::Settings || flags & 0x1 != 0 {
            self.fail_connection(PROTOCOL_ERROR, "client preface not followed by SETTINGS");
        }
    }

    /// §3.4: the server preface is a SETTINGS frame, and it must be the first
    /// thing we write. The decoder calls this before dispatching any frame,
    /// so nothing can have been queued ahead of it.
    fn on_preface(&mut self) {
        self.shared.write_frame(|out| {
            // Only what differs from the RFC defaults: an id we omit keeps
            // its default on the peer's side, so the frame size and the
            // HPACK table have nothing to say.
            encode_settings(
                out,
                &[
                    // Enforced by `admits` from the start; announced at last.
                    Setting::MaxConcurrentStreams(MAX_CONCURRENT_STREAMS),
                    // No push. A server may say so, and this one has none.
                    Setting::EnablePush(0),
                    // The decoder drops fields past this; telling the peer
                    // lets it stay under instead of finding out by refusal.
                    Setting::MaxHeaderListSize(DECODE_MAX_HEADER_LIST_SIZE as u32),
                    // §6.9.2: what every stream the peer opens may send
                    // before it needs credit back. Every `StreamWindow` of
                    // ours starts its ledger at the same number, and no
                    // stream exists before this frame is out.
                    Setting::InitialWindowSize(STREAM_RECV_WINDOW),
                ],
            );
        });

        // §6.9.2: the connection window starts at 65535 and SETTINGS never
        // touches it — only a WINDOW_UPDATE on stream 0 does. Frame and
        // credit go together, so the ledger never says more than the wire.
        let gap = CONNECTION_RECV_WINDOW - CONNECTION_INITIAL_WINDOW_SIZE;
        self.shared
            .write_frame(|out| encode_window_update(out, StreamId::ZERO, gap));
        self.shared.window.announce_recv(gap);

        // §3.4: the client's preface ends with a SETTINGS of its own, and it
        // has to be the next frame in.
        self.expect_settings = true;
        self.preface_seen = true;
    }
}
