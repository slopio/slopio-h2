use std::rc::Rc;

use http::{HeaderMap, StatusCode};

use crate::server::connection::{
    CONNECTION_INITIAL_WINDOW_SIZE, CONNECTION_RECV_WINDOW, MAX_CONCURRENT_STREAMS,
    settings::Settings, shared_with_streams::SharedConnection,
};
use crate::server::{STREAM_ID, stream::Stream};
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
        DecodeError, ENHANCE_YOUR_CALM, FLOW_CONTROL_ERROR, PROTOCOL_ERROR, REFUSED_STREAM,
        STREAM_CLOSED, Setting, StreamViolation,
    },
};

/// Stream errors — ours to report or the peer's to send — a connection may
/// accumulate before it is closed as abusive. One counter for both: a
/// malformed request and a CANCEL are different faults, but a peer that
/// piles up either is the same problem, and Rapid Reset (CVE-2023-44487)
/// is exactly the second kind. A lifetime cap, so a long-lived client that
/// legitimately cancels a lot will hit it; a rate is the refinement.
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
    /// preface, the WINDOW_UPDATEs of a download.
    Control,
    /// Legal and purposeless — a frame that costs us a decode and a dispatch
    /// and carries the peer nothing.
    Odd,
}

impl FrameWorth {
    fn of(kind: FrameKind, length: u32, flags: u8) -> Self {
        match kind {
            // §6.1: END_STREAM is 0x1. A zero-length DATA frame that ends
            // the body is progress — `write_data` emits exactly that — and
            // one that does not says nothing, while flow control accounts
            // nothing for it either (CVE-2019-9518).
            FrameKind::Data if length > 0 || flags & 0x1 != 0 => Self::Progress,
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
use runtime::{Handle, spawn};
use rustc_hash::FxHashMap;

/// The connection's side of the protocol: what every frame does to it.
pub struct Protocol {
    peer_settings: Settings,
    shared: Rc<SharedConnection>,
    streams: Streams,
    /// Armed by `on_preface`, consumed by the next `on_frame`: §3.4 makes
    /// the client's SETTINGS the first frame after its preface.
    expect_settings: bool,
    /// Set by `on_preface`. Decides whether a connection error may be
    /// answered on the wire at all: §3.4 wants an invalid preface met with
    /// silence, not a GOAWAY.
    preface_seen: bool,
    /// Set once, by the first connection error. The loop stops reading on
    /// it; whatever is already queued — the GOAWAY, typically — still goes
    /// out.
    closing: bool,
    /// Stream errors so far, against `FAULT_LIMIT`.
    faults: u32,
    /// Control frames since the last request frame, against
    /// `CONTROL_FRAME_BURST`.
    control_frames: u32,
    /// Purposeless frames since the last request frame, against
    /// `ODD_FRAME_BURST`.
    odd_frames: u32,
}

struct Streams {
    last_client_stream_id: STREAM_ID,
    goaway_stream_id: Option<STREAM_ID>,
    streams: FxHashMap<STREAM_ID, (Rc<Stream>, Handle<()>)>,
}

enum Rejected {
    /// Reset the id with this code, nothing else is wrong.
    Refused(u32),
    /// A stream error to report on the id.
    Violation(StreamViolation),
    /// The id itself breaks the protocol: the connection must go.
    Fatal(u32, &'static str),
}

impl Streams {
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

        if raw <= self.last_client_stream_id {
            return Err(Rejected::Fatal(STREAM_CLOSED, "HEADERS on closed stream"));
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

        let stream = Rc::new(Stream::create(settings, headers).map_err(Rejected::Violation)?);
        let handle = spawn(handle_stream(Rc::clone(shared), Rc::clone(&stream), id));
        self.streams.insert(raw, (stream, handle));
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
    fn recv_data(
        &mut self,
        id: STREAM_ID,
        payload: &[u8],
        padded_len: u32,
        end_stream: bool,
    ) -> Result<(), Rejected> {
        // §5.1: an idle stream only accepts HEADERS and PRIORITY.
        if id > self.last_client_stream_id {
            return Err(Rejected::Fatal(PROTOCOL_ERROR, "DATA on idle stream"));
        }

        // Not idle and not in the map: the stream existed and is closed.
        // §5.1 lets a frame on a closed stream be answered STREAM_CLOSED —
        // the peer sent DATA after its own RST_STREAM or END_STREAM, or
        // after ours. That last one is the race `credit_send` tolerates,
        // and the RFC would have us ignore it for a while; but a second
        // RST_STREAM on a stream the peer already closed is a frame it
        // must ignore, so answering costs nothing. `Refused` rather than
        // `Violation`: a body in flight when we reset its stream would
        // otherwise count one fault per frame, and a refused POST or two
        // would trip `FAULT_LIMIT`.
        let Some((stream, _)) = self.streams.get(&id) else {
            return Err(Rejected::Refused(STREAM_CLOSED));
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

    /// Retires the streams whose task finished. Their handle is dropped, not
    /// killed — a done task has nothing left to cancel — and whatever
    /// connection credit they still held goes back.
    fn sweep(&mut self, shared: &SharedConnection) {
        self.streams.retain(|_, (stream, _handle)| {
            if !stream.is_closed() {
                return true;
            }
            release_connection_credit(shared, stream.take_unreleased());
            false
        });
    }

    /// Every way out of the map. `kill` takes the handle by value, so the
    /// entry has to come out first; the task's future is dropped on the
    /// scheduler's next pass, which cancels whatever it had in flight. Safe
    /// because the task is not running now — we are — so it holds no borrow
    /// and `write_frame` left no half-written frame behind.
    ///
    /// `None` when the id was never opened, which `reset_stream` still has
    /// to answer: REFUSED_STREAM is sent for streams that never existed.
    fn remove(&mut self, id: STREAM_ID, shared: &SharedConnection) -> Option<Rc<Stream>> {
        let (stream, handle) = self.streams.remove(&id)?;
        handle.kill();
        // Body bytes the task never consumed still hold connection credit.
        release_connection_credit(shared, stream.take_unreleased());
        Some(stream)
    }

    /// §6.9.2: shifts every live stream's send window. The first overflow
    /// stops the walk — the connection is over, the rest does not matter.
    fn adjust_send_windows(&self, delta: i32) -> Result<(), ()> {
        self.streams
            .values()
            .try_for_each(|(stream, _)| stream.adjust_send(delta))
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

        let Some((stream, _)) = self.streams.get(&id) else {
            return Ok(());
        };
        stream
            .credit_send(increment)
            .map_err(|()| Rejected::Violation(StreamViolation::StreamWindowOverflow))
    }
}

impl Drop for Streams {
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
        for (_, (_, handle)) in self.streams.drain() {
            handle.kill();
        }
    }
}

impl Protocol {
    pub(super) fn new() -> Self {
        // §6.5.2 defaults, until the peer's SETTINGS says otherwise — and
        // the encoder and frame size we start from are those same defaults.
        let peer_settings = Settings::default();
        let shared = SharedConnection::new(
            peer_settings.header_table_size,
            peer_settings.max_frame_size,
        );
        Self {
            peer_settings,
            shared: Rc::new(shared),
            streams: Streams {
                last_client_stream_id: 0,
                goaway_stream_id: None,
                streams: FxHashMap::default(),
            },
            expect_settings: false,
            preface_seen: false,
            closing: false,
            faults: 0,
            control_frames: 0,
            odd_frames: 0,
        }
    }

    pub(super) fn shared(&self) -> &SharedConnection {
        &self.shared
    }

    pub(super) fn is_closing(&self) -> bool {
        self.closing
    }

    /// Takes the finished streams out of the map. Once per turn, after the
    /// tasks have had a chance to run.
    pub(super) fn sweep(&mut self) {
        self.streams.sweep(&self.shared);
    }

    /// §5.4.1: a GOAWAY naming the last stream we took up, then no more
    /// reading. Idempotent — the first error is the one the peer hears
    /// about, later ones change nothing.
    fn fail_connection(&mut self, error_code: u32, reason: &'static str) {
        if self.closing {
            return;
        }
        self.closing = true;

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
        self.streams.remove(stream_id.into(), &self.shared);
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
    fn count_frame(&mut self, kind: FrameKind, length: u32, flags: u8) {
        match FrameWorth::of(kind, length, flags) {
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

    fn count_fault(&mut self, reason: &'static str) {
        self.faults += 1;
        if self.faults > FAULT_LIMIT {
            self.fail_connection(ENHANCE_YOUR_CALM, reason);
        }
    }

    /// HEADERS on a live stream: its trailers (§8.1). The stream checks them
    /// and closes its input; a bad set is a stream error, like a bad DATA.
    fn on_trailers(&mut self, stream: Rc<Stream>, headers: Box<Headers>) {
        let id = headers.stream_id();
        if let Err(violation) = stream.recv_trailers(headers) {
            self.fail_stream(id, violation);
        }
    }

    /// Answers what `Streams` refused: it decides, we are the one that can
    /// write.
    fn reject(&mut self, stream_id: StreamId, rejected: Rejected) {
        match rejected {
            Rejected::Refused(code) => self.reset_stream(stream_id, code),
            Rejected::Violation(violation) => self.fail_stream(stream_id, violation),
            Rejected::Fatal(code, reason) => self.fail_connection(code, reason),
        }
    }
}

/// Hands the peer back connection-level credit for bytes that reached no
/// handler — padding, and whatever a departing stream still held — writing
/// the WINDOW_UPDATE on stream 0 when enough has piled up. The frame goes
/// out beside the ledger entry, never after it.
fn release_connection_credit(shared: &SharedConnection, len: u32) {
    if let Some(increment) = shared.window.release(len) {
        shared.write_frame(|out| encode_window_update(out, StreamId::ZERO, increment));
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

/// Basic behaviour for now: a 200 with no body, whatever the request, and
/// without waiting for its body. The HEADERS carries END_STREAM, which
/// closes our half only — the peer may still be sending, and the stream
/// stays in the map until it is done too.
///
/// A panic here would take the whole process down — the runtime does not
/// catch task panics.
/// The placeholder handler: `200` and a fixed body, whatever the request.
async fn handle_stream(shared: Rc<SharedConnection>, stream: Rc<Stream>, id: StreamId) {
    // The two body contracts, picked by the request's `content-length`.
    let received = match stream.body_is_oneshot() {
        // Small enough to hold: wait for all of it, take it in one piece.
        // No credit goes back while it fills — that is what this form buys.
        true => stream.body().await.map_or(0, |body| body.len()),
        // Too large, or of unknown length: drained as it arrives. Taking
        // bytes is what hands the peer its credit back, so a handler that
        // stops taking is a handler that stops the upload.
        false => {
            let mut total = 0;
            while stream.readable().await {
                let taken = stream.peek(|bytes| bytes.len());
                shared.consume(id, &stream, taken);
                total += taken;
            }
            total
        }
    };

    let body = format!("read {received} bytes\n");
    shared.write_headers(id, StatusCode::OK, &HeaderMap::new(), false);
    shared.write_data(id, &stream, body.as_bytes(), true).await;
    stream.end_output();
}

impl FrameHandler for Protocol {
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
        let received = self.streams.recv_data(raw, payload, padded_len, end_stream);

        // Padding is accounted by flow control but never reaches an
        // application, so it is spent the moment it lands; on a frame we drop,
        // all of it is. Either way it goes back now — release only what a
        // handler consumes and the window shrinks by the padding for good,
        // until the connection stalls with nothing to show for it.
        release_connection_credit(
            &self.shared,
            match received {
                Ok(()) => padded_len - payload.len() as u32,
                Err(_) => padded_len,
            },
        );

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
        if headers.is_over_size() {
            self.streams.spend(raw);
            return self.reset_stream(id, REFUSED_STREAM);
        }

        // §8.1: an id already live takes these HEADERS as its trailers.
        if let Some((stream, _)) = self.streams.streams.get(&raw) {
            let stream = Rc::clone(stream);
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
            // The `Refused` that `recv_data` raises stays uncounted: that
            // one is a body still in flight when we reset its stream, a race
            // rather than a demand, and counting it would cost a fault per
            // frame of a refused POST.
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
    /// is the peer answering a probe of ours; we send none yet, so it is
    /// dropped. The decoder has already enforced stream 0 and the 8-byte
    /// length.
    fn on_ping(&mut self, ack: bool, opaque: [u8; 8]) {
        if ack {
            return;
        }
        self.shared
            .write_frame(|out| encode_ping(out, opaque, true));
    }

    /// The peer is leaving: `NO_ERROR` is a graceful shutdown, anything else
    /// a fault it found on our side. Basic for now — we close too. The
    /// graceful version keeps serving what is in flight and closes once the
    /// map drains.
    fn on_goaway(&mut self, _last_stream_id: StreamId, _error_code: u32, _debug_data: &[u8]) {
        self.closing = true;
    }

    /// After a `DecodeError::Connection` the decoder poisons itself and emits
    /// nothing more; noting that the connection is over is on us.
    fn on_error(&mut self, err: DecodeError) {
        match err {
            DecodeError::Connection { code, message } => self.fail_connection(code, message),
            // The frame is already discarded; the stream is told why.
            DecodeError::Stream {
                stream_id, code, ..
            } => self.reset_stream(stream_id, code),
        }
    }

    /// Every frame comes through here before anything else, which is where
    /// §3.4 is checked: the first frame after the client preface must be its
    /// SETTINGS — and not an ACK, which it cannot legitimately send before
    /// having seen ours.
    fn on_frame(&mut self, kind: FrameKind, _stream_id: StreamId, length: u32, flags: u8) {
        self.count_frame(kind, length, flags);

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
            // its default on the peer's side, so the initial window, the
            // frame size and the HPACK table have nothing to say.
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
