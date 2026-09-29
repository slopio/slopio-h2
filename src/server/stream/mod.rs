use std::cell::{Cell, RefCell};
use std::task::{Poll, Waker};
use std::time::{Duration, SystemTime};

use http::StatusCode;

#[cfg(feature = "grpc")]
use crate::grpc::{GrpcError, GrpcFormat, GrpcFrame, GrpcInput};
use crate::server::connection::shared_with_streams::StreamToken;
use crate::shared::codec::frames::stream_id::StreamId;
use crate::shared::{
    codec::{
        frames::headers::{Headers, content_length},
        types::StreamViolation,
    },
    connection::{input_data::InputData, settings::Settings, stream_window::StreamWindow},
};

mod lifecycle;

pub(crate) use lifecycle::{Farewell, Lifecycle};
use lifecycle::{Inbound, Outbound};

enum Input {
    None,
    Http(InputData),
    #[cfg(feature = "grpc")]
    Grpc(GrpcInput),
}

impl Input {
    fn http(&self) -> Option<&InputData> {
        match self {
            Self::Http(input) => Some(input),
            _ => None,
        }
    }

    fn http_mut(&mut self) -> Option<&mut InputData> {
        match self {
            Self::Http(input) => Some(input),
            _ => None,
        }
    }
}

/// How long a body is given before its rate is judged at all, so a stream is
/// never failed for the time it took to get started.
const BODY_GRACE: Duration = Duration::from_secs(5);

/// Bytes per second below which a request body is not slow but held: a floor
/// against a peer trickling bytes to hold a stream open, not a service level.
const MIN_BODY_RATE: u64 = 256;

/// How long a response may have waited on the peer's credit, in total, before
/// its rate is judged. Only time waiting for credit counts, so a slow handler
/// never fails its own stream.
const SEND_GRACE: Duration = Duration::from_secs(5);

/// Bytes per second below which a peer is not receiving a response, it is
/// holding one: a floor against a peer crediting a byte at a time.
const MIN_SEND_RATE: u64 = 256;

/// Reached only through an `Rc` shared with the stream task, so everything the
/// connection mutates while a frame is being decoded lives behind a `Cell`.
pub struct StreamState {
    created_at: SystemTime,
    header: Box<Headers>,
    trailers: Cell<Option<Box<Headers>>>,
    lifecycle: Cell<Lifecycle>,
    /// Outlives the peer's half: a body stays readable after END_STREAM.
    input: RefCell<Input>,
    #[cfg(feature = "grpc")]
    grpc: Option<GrpcFormat>,
    sent: Cell<u64>,
    send_blocked_since: Cell<Option<SystemTime>>,
    /// Only time the peer made us wait accrues here, so a slow handler is
    /// never judged.
    send_blocked: Cell<Duration>,
    /// Connection credit still held. Whatever is left when the stream goes
    /// must be given back, or the connection window shrinks for good.
    unreleased: Cell<u32>,
    window: StreamWindow,
    waker: RefCell<Option<Waker>>,
}

impl StreamState {
    pub fn create(
        settings: &Settings,
        window: u32,
        header: Box<Headers>,
    ) -> Result<Self, StreamViolation> {
        let content_length =
            content_length(header.fields()).map_err(|()| StreamViolation::MalformedRequest)?;

        let end_stream = header.is_end_stream();
        let lifecycle = Lifecycle::open(content_length, end_stream)?;

        #[cfg(feature = "grpc")]
        let grpc = GrpcFormat::of(&header);

        let input = match content_length {
            _ if end_stream => Input::None,
            Some(0) => Input::None,
            declared => {
                #[cfg(feature = "grpc")]
                let input = match grpc {
                    Some(format) => Input::Grpc(GrpcInput::new(format, header.fields())),
                    None => Input::Http(InputData::new(declared)),
                };
                #[cfg(not(feature = "grpc"))]
                let input = Input::Http(InputData::new(declared));
                input
            }
        };

        Ok(Self {
            created_at: runtime::runtime::now(),
            window: StreamWindow::new(settings, window),
            #[cfg(feature = "grpc")]
            grpc,
            header,
            trailers: Cell::new(None),
            lifecycle: Cell::new(lifecycle),
            input: RefCell::new(input),
            sent: Cell::new(0),
            send_blocked_since: Cell::new(None),
            send_blocked: Cell::new(Duration::ZERO),
            unreleased: Cell::new(0),
            waker: RefCell::new(None),
        })
    }

    /// Floors at zero on a wall clock that stepped backwards, so a clock
    /// adjustment never fails a request.
    pub fn age(&self) -> Duration {
        runtime::runtime::now()
            .duration_since(self.created_at)
            .unwrap_or_default()
    }

    /// A rate and not a deadline: a deadline cannot tell a large upload from
    /// a slow one. Averaged from the stream opening, so a peer cannot bank
    /// credit by starting fast and then stalling.
    ///
    /// Fails open on a clock that stepped backwards.
    pub fn body_is_starving(&self) -> bool {
        // Once the peer owes nothing more, whatever time passes is the
        // handler's.
        let Some(Inbound::Open(body)) = self.lifecycle.get().inbound() else {
            return false;
        };
        let age = self.age();
        if age < BODY_GRACE {
            return false;
        }
        body.received() < MIN_BODY_RATE.saturating_mul(age.as_secs())
    }

    pub fn id(&self) -> crate::shared::codec::frames::stream_id::StreamId {
        self.header.stream_id()
    }

    pub fn path(&self) -> Option<&str> {
        self.header.pseudo().path.as_deref()
    }

    pub fn method(&self) -> Option<&http::Method> {
        self.header.pseudo().method.as_ref()
    }

    pub fn fields(&self) -> &http::HeaderMap {
        self.header.fields()
    }

    /// Called by the connection, never the stream's own task. Returns the
    /// state it was retired from.
    pub(crate) fn retire(&self) -> Lifecycle {
        self.lifecycle.replace(Lifecycle::Retired)
    }

    /// For the token, when the task stops.
    pub(crate) fn on_task_end(&self) -> Farewell {
        let (next, farewell) = self.lifecycle.get().on_task_end();
        self.lifecycle.set(next);
        farewell
    }

    pub fn note_sent(&self, n: usize) {
        if let Some(since) = self.send_blocked_since.take() {
            self.send_blocked
                .set(self.send_blocked.get() + elapsed_since(since));
        }
        self.sent.set(self.sent.get() + n as u64);
    }

    fn note_send_blocked(&self) {
        if self.send_blocked_since.get().is_none() {
            self.send_blocked_since.set(Some(runtime::runtime::now()));
        }
    }

    /// Catches a peer metering a response out with one-byte WINDOW_UPDATEs.
    /// The rate is over time spent waiting for the peer's credit only (see
    /// [`SEND_GRACE`]).
    pub fn output_is_starving(&self) -> bool {
        let waiting = self
            .send_blocked_since
            .get()
            .map_or(Duration::ZERO, elapsed_since);
        let blocked = self.send_blocked.get() + waiting;
        if blocked < SEND_GRACE {
            return false;
        }
        self.sent.get() < MIN_SEND_RATE.saturating_mul(blocked.as_secs())
    }

    pub fn credit_send(&self, increment: u32) -> Result<(), ()> {
        self.window.credit_send(increment)?;
        self.wake();
        Ok(())
    }

    /// Connection credit after the connection window was spent. Only a writer
    /// parked for want of credit that has some of its own was waiting on the
    /// connection's; the rest are left alone, the slot being the body
    /// reader's too.
    pub fn wake_sender(&self) {
        if self.send_blocked_since.get().is_some() && self.available_send() > 0 {
            self.wake();
        }
    }

    /// §6.9.2: the peer's initial window changed.
    pub fn adjust_send(&self, delta: i32) -> Result<(), ()> {
        self.window.adjust_send(delta)?;
        if delta > 0 {
            self.wake();
        }
        Ok(())
    }

    pub fn available_send(&self) -> u32 {
        self.window.available_send()
    }

    /// Both checks, because `send_blocked_since` alone can go stale: a writer
    /// woken by credit that then found the output full is parked on room, not
    /// credit.
    pub fn is_stalled_on_credit(&self, connection_credit: u32) -> bool {
        self.send_blocked_since.get().is_some() && self.available_send().min(connection_credit) == 0
    }

    /// `Err` debits nothing.
    pub fn debit_send(&self, len: u32) -> Result<(), ()> {
        self.window.debit_send(len)
    }

    /// One slot: a stream has one task, and that task waits on one thing at a
    /// time. Whoever wakes it, it re-checks its condition.
    pub fn register_waker(&self, waker: &Waker) {
        let mut slot = self.waker.borrow_mut();
        if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }

    /// Split from `recv_data` because an overrun here is a connection error,
    /// not a stream one.
    pub fn recv_window(&self, padded_len: u32) -> Result<(), ()> {
        self.window.recv(padded_len)
    }

    /// Zeroed on the way out so it can only be given back once.
    pub fn take_unreleased(&self) -> u32 {
        self.unreleased.replace(0)
    }

    fn respond(&self) {
        let lifecycle = self.lifecycle.get();
        if let Lifecycle::Live {
            outbound: Outbound::Idle,
            ..
        } = lifecycle
        {
            self.lifecycle
                .set(lifecycle.with_outbound(Outbound::Streaming));
        }
    }

    pub fn end_output(&self) {
        let lifecycle = self.lifecycle.get();
        self.lifecycle.set(lifecycle.with_outbound(Outbound::Ended));
    }

    /// A head is out and the end is not.
    fn is_streaming(&self) -> bool {
        matches!(
            self.lifecycle.get(),
            Lifecycle::Live {
                outbound: Outbound::Streaming,
                ..
            }
        )
    }

    pub fn input_ended(&self) -> bool {
        self.lifecycle.get().input_ended()
    }

    pub fn is_closed(&self) -> bool {
        self.lifecycle.get().is_closed()
    }

    fn set_inbound(&self, inbound: Inbound) {
        let lifecycle = self.lifecycle.get();
        self.lifecycle.set(lifecycle.with_inbound(inbound));
    }

    /// §8.1. Ends the input exactly as END_STREAM on DATA does, with the same
    /// final check.
    pub fn recv_trailers(&self, headers: Box<Headers>) -> Result<(), StreamViolation> {
        let Some(inbound) = self.lifecycle.get().inbound().filter(|half| half.is_open()) else {
            return Err(StreamViolation::DataAfterEndStream);
        };

        // §8.1: trailers end the message, so they carry END_STREAM; §8.3: no
        // pseudo-header may appear in them.
        if !headers.is_end_stream() || has_pseudo(&headers) {
            return Err(StreamViolation::MalformedTrailers);
        }

        let inbound = inbound.on_trailers()?;
        #[cfg(feature = "grpc")]
        {
            if let Input::Grpc(input) = &mut *self.input.borrow_mut() {
                input.end();
            }
        }

        self.trailers.set(Some(headers));
        self.set_inbound(inbound);
        self.wake();
        Ok(())
    }

    pub fn take_trailers(&self) -> Option<Box<Headers>> {
        self.trailers.take()
    }

    pub fn body_is_oneshot(&self) -> bool {
        self.input
            .borrow()
            .http()
            .is_none_or(|input| !input.wakes_per_frame())
    }

    /// The `content-length` the body is held to, if it declared one.
    pub fn declared_len(&self) -> Option<u64> {
        self.input.borrow().http().and_then(InputData::expected)
    }

    #[cfg(feature = "grpc")]
    pub fn is_grpc(&self) -> bool {
        self.grpc.is_some()
    }

    #[cfg(feature = "grpc")]
    pub fn grpc_format(&self) -> Option<GrpcFormat> {
        self.grpc
    }

    /// A oneshot body, whole: each frame's bytes are credited back as they
    /// land, so an unfinished body holds no window, only its stream's slot,
    /// until the starvation sweep takes that too. `None` for any other.
    pub fn take_oneshot(&self) -> impl Future<Output = Option<Box<[u8]>>> {
        std::future::poll_fn(move |cx| {
            if !self.input_ended() {
                self.register_waker(cx.waker());
                return Poll::Pending;
            }
            let mut input = self.input.borrow_mut();
            if input.http().is_none() {
                return Poll::Ready(None);
            }
            Poll::Ready(match std::mem::replace(&mut *input, Input::None) {
                Input::Http(input) => input.into_oneshot(),
                _ => None,
            })
        })
    }

    pub fn readable(&self) -> impl Future<Output = bool> {
        std::future::poll_fn(move |cx| {
            if self.available_len() > 0 {
                return Poll::Ready(true);
            }
            if self.input_ended() {
                return Poll::Ready(false);
            }
            self.register_waker(cx.waker());
            Poll::Pending
        })
    }

    /// The slice must not be held across the `await` that would let the
    /// connection push more in, hence the closure.
    pub fn peek<R>(&self, with: impl FnOnce(&[u8]) -> R) -> R {
        let input = self.input.borrow();
        with(input.http().map_or(&[][..], InputData::available))
    }

    /// Only the bookkeeping: `SharedConnection::consume` writes the
    /// WINDOW_UPDATE frames.
    pub fn consume(&self, n: usize) -> u32 {
        let mut input = self.input.borrow_mut();
        let Some(input) = input.http_mut() else {
            return 0;
        };
        let n = n.min(input.available().len());
        // A oneshot body was credited as it landed: reading it owes nothing.
        let credited = if input.wakes_per_frame() { n } else { 0 };
        input.consume(n);
        // Cannot underflow: `unreleased` counts the same bytes.
        self.unreleased.set(self.unreleased.get() - credited as u32);
        credited as u32
    }

    /// `Some` is already credited here, so the caller must write the frame
    /// that carries it.
    #[must_use]
    pub fn release_recv(&self, len: u32) -> Option<u32> {
        self.window.release_recv(len)
    }

    fn available_len(&self) -> usize {
        self.input
            .borrow()
            .http()
            .map_or(0, |input| input.available().len())
    }

    /// `payload` is already stripped of padding: flow control accounts for
    /// padding, `content-length` does not.
    ///
    /// `Ok(n)` is how much was consumed on the spot and owes the peer its
    /// credit back now; the caller must write the frames.
    pub fn recv_data(&self, payload: &[u8], end_stream: bool) -> Result<u32, StreamViolation> {
        let Some(inbound @ Inbound::Open(body)) = self.lifecycle.get().inbound() else {
            return Err(StreamViolation::DataAfterEndStream);
        };
        let at = body.received();
        let inbound = inbound.on_data(payload.len() as u64, end_stream)?;

        let (wake, consumed) = match &mut *self.input.borrow_mut() {
            // A declared length of zero, which `on_data` has held the payload
            // to.
            Input::None => (end_stream, 0),
            Input::Http(input) => {
                input
                    .push(at, payload)
                    .map_err(|_| StreamViolation::ContentLengthMismatch)?;
                if input.wakes_per_frame() {
                    (true, 0)
                } else {
                    (end_stream, payload.len() as u32)
                }
            }
            #[cfg(feature = "grpc")]
            Input::Grpc(input) => {
                let wake = input.push(payload);
                if end_stream {
                    input.end();
                }
                // While a whole message waits, the handler is behind and
                // these bytes keep their credit until it takes one.
                let consumed = if input.has_ready() {
                    0
                } else {
                    payload.len() as u32
                };
                (wake || end_stream, consumed)
            }
        };

        // Only now: a payload that was refused never landed. `unreleased` is
        // bounded by the receive window, so it cannot outgrow a u32.
        self.set_inbound(inbound);
        self.unreleased
            .set(self.unreleased.get() + payload.len() as u32 - consumed);
        if wake {
            self.wake();
        }
        Ok(consumed)
    }

    #[cfg(feature = "grpc")]
    pub fn message(&self) -> impl Future<Output = Option<Result<GrpcFrame, GrpcError>>> {
        std::future::poll_fn(move |cx| {
            let taken = match &mut *self.input.borrow_mut() {
                Input::Grpc(input) => input.take(),
                _ => return Poll::Ready(None),
            };
            match taken {
                Some(taken) => Poll::Ready(Some(taken)),
                None if self.input_ended() => Poll::Ready(None),
                None => {
                    self.register_waker(cx.waker());
                    Poll::Pending
                }
            }
        })
    }

    /// Whether a whole message is still waiting to be taken.
    #[cfg(feature = "grpc")]
    pub fn message_waiting(&self) -> bool {
        matches!(&*self.input.borrow(), Input::Grpc(input) if input.has_ready())
    }

    /// Everything held back, zeroed so it can only be given back once, with
    /// the window it goes back to.
    #[cfg(feature = "grpc")]
    #[must_use]
    pub fn take_held(&self) -> (u32, &StreamWindow) {
        (self.unreleased.replace(0), &self.window)
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}

/// A body past the limit a route gave [`Stream::body`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BodyTooLarge;

impl std::fmt::Display for BodyTooLarge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the request body is larger than the route accepts")
    }
}

impl std::error::Error for BodyTooLarge {}

/// Dropping it is what ends the server's half of the exchange (§5.1).
///
/// Not `Clone` and not `Send`: one stream, one task, one thread.
pub struct Stream {
    token: StreamToken,
}

impl Stream {
    pub(crate) fn new(token: StreamToken) -> Self {
        Self { token }
    }

    fn state(&self) -> &StreamState {
        self.token.stream()
    }

    /// §5.1.1: odd, since a client opens it.
    pub fn id(&self) -> StreamId {
        self.token.id()
    }

    pub fn method(&self) -> Option<&http::Method> {
        self.state().method()
    }

    pub fn path(&self) -> Option<&str> {
        self.state().path()
    }

    pub fn fields(&self) -> &http::HeaderMap {
        self.state().fields()
    }

    /// The transport's peer: behind a proxy, the proxy. `None` when the
    /// address could not be read, a peer gone before it was asked.
    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.token.shared().peer()
    }

    /// Whether the body was declared small enough, 16 KiB at most, to be
    /// gathered whole before anything sees it. Nothing a route must act on:
    /// [`Stream::body`] and [`Stream::readable`] both read either kind.
    pub fn body_is_oneshot(&self) -> bool {
        self.state().body_is_oneshot()
    }

    /// The whole body, however the client sent it, or `BodyTooLarge` past
    /// `limit` bytes, what a route typically answers with a `413`. A body
    /// with a `content-length` over `limit` is refused before any of it is
    /// read. Empty when the request has none.
    ///
    /// A small declared body comes as it was gathered, without a copy; any
    /// other is gathered here, its credit given back as it is, so the client
    /// is never left waiting on a window.
    pub async fn body(&self, limit: usize) -> Result<Box<[u8]>, BodyTooLarge> {
        let declared = self.state().declared_len();
        if declared.is_some_and(|len| len > limit as u64) {
            return Err(BodyTooLarge);
        }
        if self.body_is_oneshot() {
            let body = self.state().take_oneshot().await;
            return Ok(body.unwrap_or_default());
        }
        // Bounded by `limit`, which a declared length is under.
        let mut body = Vec::with_capacity(declared.map_or(0, |len| len as usize));
        while self.readable().await {
            let taken = self.peek(|bytes| {
                (body.len() + bytes.len() <= limit).then(|| {
                    body.extend_from_slice(bytes);
                    bytes.len()
                })
            });
            match taken {
                Some(taken) => self.consume(taken),
                None => return Err(BodyTooLarge),
            }
        }
        Ok(body.into_boxed_slice())
    }

    /// The body as it comes, whichever way the client sent it: a small
    /// declared one is seen once whole, as a single piece.
    pub fn readable(&self) -> impl Future<Output = bool> {
        self.state().readable()
    }

    /// The slice must not be held across the `await` that would let the
    /// connection push more in, hence the closure.
    pub fn peek<R>(&self, with: impl FnOnce(&[u8]) -> R) -> R {
        self.state().peek(with)
    }

    /// §6.9.1: a handler that stops consuming stops the upload.
    pub fn consume(&self, n: usize) {
        self.token.shared().consume(self.id(), self.state(), n);
    }

    #[cfg(feature = "grpc")]
    pub fn is_grpc(&self) -> bool {
        self.state().is_grpc()
    }

    #[cfg(feature = "grpc")]
    pub fn grpc_format(&self) -> Option<GrpcFormat> {
        self.state().grpc_format()
    }

    /// Only while a whole message is waiting here do the bytes after it keep
    /// their credit, and taking the last one waiting is what lets go of it.
    #[cfg(feature = "grpc")]
    pub async fn message(&self) -> Option<Result<GrpcFrame, GrpcError>> {
        let taken = self.state().message().await;
        // Once input has ended, held connection credit goes back when the
        // stream retires. While another message waits, the handler is still
        // behind and the window is what holds the peer back: released per
        // message instead, the queue could grow by one each time.
        if let Some(Ok(_)) = &taken
            && !self.state().input_ended()
            && !self.state().message_waiting()
        {
            self.token.shared().release_held(self.id(), self.state());
        }
        taken
    }

    /// §8.1: `None` until the body has ended.
    pub fn trailers(&self) -> Option<http::HeaderMap> {
        self.state()
            .take_trailers()
            .map(|headers| (*headers).into_fields())
    }

    /// Must precede [`write_data`](Self::write_data), or DATA goes out on a
    /// stream the peer has had no head for.
    ///
    /// The `_final` writers take the stream by value so that writing after
    /// the end is a compile error rather than a frame on a closed stream.
    pub fn write_headers(&self, status: StatusCode, fields: &http::HeaderMap) {
        self.token
            .shared()
            .write_response(self.id(), status, fields, false);
        self.state().respond();
    }

    pub fn write_headers_final(self, status: StatusCode, fields: &http::HeaderMap) {
        self.token
            .shared()
            .write_response(self.id(), status, fields, true);
        self.state().end_output();
    }

    /// §6.9.1: waits for credit and output room rather than buffering.
    pub async fn write_data(&self, data: &[u8]) {
        self.token
            .shared()
            .write_data(self.id(), self.state(), data, false)
            .await;
    }

    /// No `_final`: a gRPC response always ends with its trailers, never with
    /// END_STREAM on DATA. See [`crate::grpc::write_message`].
    #[cfg(feature = "grpc")]
    pub async fn write_message<M: prost::Message>(&self, message: &M) {
        crate::grpc::write_message(self.token.shared(), self.id(), self.state(), message, false)
            .await;
    }

    pub async fn write_data_final(self, data: &[u8]) {
        self.token
            .shared()
            .write_data(self.id(), self.state(), data, true)
            .await;
        // After the await: a write dropped half way never wrote the frame
        // that carries the flag.
        self.state().end_output();
    }

    /// §8.1 allows no pseudo-header here, which `HeaderName` guarantees.
    ///
    /// Does nothing on a stream with no response head yet: trailers without a
    /// head are a malformed response, and the handler gets the `500` instead.
    pub fn write_trailers(self, fields: &http::HeaderMap) {
        let state = self.state();
        if !state.is_streaming() {
            return;
        }
        self.token.shared().write_trailers(self.id(), fields);
        state.end_output();
    }
}

/// One waker slot serves both directions, which is sound because a server
/// stream has one task and that task waits on one thing at a time.
impl crate::shared::connection::SendSide for StreamState {
    fn available_send(&self) -> u32 {
        self.available_send()
    }

    fn debit_send(&self, len: u32) -> Result<(), ()> {
        self.debit_send(len)
    }

    /// Only ever called for want of credit (a full output parks elsewhere),
    /// which is what makes it the right place to start timing the wait.
    fn register_send_waker(&self, waker: &Waker) {
        self.note_send_blocked();
        self.register_waker(waker);
    }

    fn note_sent(&self, n: usize) {
        self.note_sent(n);
    }
}

/// Floors at zero on a clock that stepped backwards.
fn elapsed_since(since: SystemTime) -> Duration {
    runtime::runtime::now()
        .duration_since(since)
        .unwrap_or_default()
}

/// §8.3: a pseudo-header field anywhere in a trailer section.
fn has_pseudo(headers: &Headers) -> bool {
    let p = headers.pseudo();
    p.method.is_some()
        || p.scheme.is_some()
        || p.authority.is_some()
        || p.path.is_some()
        || p.protocol.is_some()
        || p.status.is_some()
}
