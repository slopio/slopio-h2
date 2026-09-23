use std::cell::{Cell, RefCell};
use std::task::{Poll, Waker};
use std::time::{Duration, SystemTime};

use http::StatusCode;

use crate::server::connection::shared_with_streams::StreamToken;
use crate::shared::codec::frames::stream_id::StreamId;
#[cfg(feature = "grpc")]
use crate::grpc::{GrpcError, GrpcFormat, GrpcFrame, GrpcInput};
use crate::{
    server::stream::input_data::InputData,
    shared::{
        codec::{
            frames::headers::{Headers, content_length},
            types::StreamViolation,
        },
        connection::{settings::Settings, stream_window::StreamWindow},
    },
};

mod input_data;

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
///
/// The two halves close independently (§5.1); both `no_more_input` and
/// `no_more_output` set is the closed state that lets the connection take the
/// stream out of its map.
pub struct StreamState {
    created_at: SystemTime,
    header: Box<Headers>,
    trailers: Cell<Option<Box<Headers>>>,
    /// Half-closed(remote) once set: DATA or HEADERS after it is a stream
    /// error.
    no_more_input: Cell<bool>,
    /// Says nothing about the peer's half: §5.1 still lets the peer send its
    /// body.
    no_more_output: Cell<bool>,
    input: RefCell<Input>,
    #[cfg(feature = "grpc")]
    grpc: Option<GrpcFormat>,
    /// Padding excluded. Doubles as the write cursor of a pre-allocated
    /// buffer.
    received: Cell<u64>,
    sent: Cell<u64>,
    send_blocked_since: Cell<Option<SystemTime>>,
    /// Only time the peer made us wait accrues here, so a slow handler is
    /// never judged.
    send_blocked: Cell<Duration>,
    /// Connection credit still held. Whatever is left when the stream goes
    /// must be given back, or the connection window shrinks for good.
    unreleased: Cell<u32>,
    /// Not the same as `no_more_output`, which the token sets on the way out
    /// whether or not anything was said.
    responded: Cell<bool>,
    /// Out of the connection's live table: nothing its task writes from here
    /// reaches anyone.
    retired: Cell<bool>,
    window: StreamWindow,
    waker: RefCell<Option<Waker>>,
}

impl StreamState {
    pub fn create(settings: &Settings, header: Box<Headers>) -> Result<Self, StreamViolation> {
        let content_length =
            content_length(header.fields()).map_err(|()| StreamViolation::MalformedRequest)?;

        let end_stream = header.is_end_stream();

        // §8.1.1: with END_STREAM on the HEADERS no DATA can follow, so a
        // declared length that is not zero already fails to add up.
        if end_stream && content_length.is_some_and(|len| len != 0) {
            return Err(StreamViolation::ContentLengthMismatch);
        }

        #[cfg(feature = "grpc")]
        let grpc = GrpcFormat::of(&header);

        let input = match content_length {
            _ if end_stream => Input::None,
            Some(0) => Input::None,
            declared => {
                #[cfg(feature = "grpc")]
                let input = match grpc {
                    Some(format) => Input::Grpc(GrpcInput::new(format, header.fields(), declared)),
                    None => Input::Http(InputData::new(declared)),
                };
                #[cfg(not(feature = "grpc"))]
                let input = Input::Http(InputData::new(declared));
                input
            }
        };

        Ok(Self {
            created_at: runtime::runtime::now(),
            window: StreamWindow::new(settings, crate::server::connection::STREAM_RECV_WINDOW),
            #[cfg(feature = "grpc")]
            grpc,
            header,
            trailers: Cell::new(None),
            no_more_input: Cell::new(end_stream),
            no_more_output: Cell::new(false),
            input: RefCell::new(input),
            received: Cell::new(0),
            sent: Cell::new(0),
            send_blocked_since: Cell::new(None),
            send_blocked: Cell::new(Duration::ZERO),
            unreleased: Cell::new(0),
            responded: Cell::new(false),
            retired: Cell::new(false),
            waker: RefCell::new(None),
        })
    }

    pub fn created_at(&self) -> SystemTime {
        self.created_at
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
        // The peer owes nothing more; whatever time passes is the handler's.
        if self.no_more_input.get() {
            return false;
        }
        let age = self.age();
        if age < BODY_GRACE {
            return false;
        }
        let owed = MIN_BODY_RATE.saturating_mul(age.as_secs());
        self.received.get() < owed
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

    pub fn has_responded(&self) -> bool {
        self.responded.get()
    }

    pub fn note_responded(&self) {
        self.responded.set(true);
    }

    pub fn is_retired(&self) -> bool {
        self.retired.get()
    }

    /// Called by the connection, never the stream's own task.
    pub fn note_retired(&self) {
        self.retired.set(true);
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
            self.send_blocked_since
                .set(Some(runtime::runtime::now()));
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

    pub fn end_output(&self) {
        self.no_more_output.set(true);
    }

    pub fn input_ended(&self) -> bool {
        self.no_more_input.get()
    }

    pub fn output_ended(&self) -> bool {
        self.no_more_output.get()
    }

    /// For a stream we have just reset: RST_STREAM closes both halves (§5.1).
    pub fn abandon_input(&self) {
        self.no_more_input.set(true);
    }

    /// Both halves done, which is what lets the connection remove the stream.
    pub fn is_closed(&self) -> bool {
        self.no_more_output.get() && self.no_more_input.get()
    }

    /// §8.1. Ends the input exactly as END_STREAM on DATA does, with the same
    /// final check.
    pub fn recv_trailers(&self, headers: Box<Headers>) -> Result<(), StreamViolation> {
        if self.no_more_input.get() {
            return Err(StreamViolation::DataAfterEndStream);
        }

        // §8.1: trailers end the message, so they carry END_STREAM; §8.3: no
        // pseudo-header may appear in them.
        if !headers.is_end_stream() || has_pseudo(&headers) {
            return Err(StreamViolation::MalformedTrailers);
        }

        // §8.1.1: the body must add up to exactly what was declared.
        let declared = match &*self.input.borrow() {
            Input::None => None,
            Input::Http(input) => input.expected(),
            #[cfg(feature = "grpc")]
            Input::Grpc(input) => input.declared(),
        };
        if declared.is_some_and(|declared| self.received.get() != declared) {
            return Err(StreamViolation::ContentLengthMismatch);
        }
        #[cfg(feature = "grpc")]
        {
            if let Input::Grpc(input) = &mut *self.input.borrow_mut() {
                input.end();
            }
        }

        self.trailers.set(Some(headers));
        self.no_more_input.set(true);
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

    #[cfg(feature = "grpc")]
    pub fn is_grpc(&self) -> bool {
        self.grpc.is_some()
    }

    #[cfg(feature = "grpc")]
    pub fn grpc_format(&self) -> Option<GrpcFormat> {
        self.grpc
    }

    /// Each frame's bytes are credited back as they land, so an unfinished
    /// body holds no window, only its stream's slot, until the starvation
    /// sweep takes that too.
    pub fn body(&self) -> impl Future<Output = Option<Box<[u8]>>> {
        std::future::poll_fn(move |cx| {
            if !self.no_more_input.get() {
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
            if self.no_more_input.get() {
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
        input.consume(n);
        // Cannot underflow: `unreleased` counts the same bytes.
        self.unreleased.set(self.unreleased.get() - n as u32);
        n as u32
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
        if self.no_more_input.get() {
            return Err(StreamViolation::DataAfterEndStream);
        }

        let mut input = self.input.borrow_mut();
        let declared = match &*input {
            Input::None => Some(0),
            Input::Http(input) => input.expected(),
            #[cfg(feature = "grpc")]
            Input::Grpc(input) => input.declared(),
        };

        // §8.1.1: the body must add up to exactly what was declared.
        let at = self.received.get();
        let received = at + payload.len() as u64;
        if end_stream && declared.is_some_and(|declared| received != declared) {
            return Err(StreamViolation::ContentLengthMismatch);
        }

        // §8.1.1: exceeding the declared length is an error as soon as it
        // happens; for an HTTP body, `push` decides.
        let (wake, consumed) = match &mut *input {
            // A declared length of zero, so any byte is one too many.
            Input::None if !payload.is_empty() => {
                return Err(StreamViolation::ContentLengthMismatch);
            }
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
                if declared.is_some_and(|declared| received > declared) {
                    return Err(StreamViolation::ContentLengthMismatch);
                }
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
        self.received.set(received);
        self.unreleased
            .set(self.unreleased.get() + payload.len() as u32 - consumed);
        if end_stream {
            self.no_more_input.set(true);
        }
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
                None if self.no_more_input.get() => Poll::Ready(None),
                None => {
                    self.register_waker(cx.waker());
                    Poll::Pending
                }
            }
        })
    }

    /// At once rather than accumulated, unlike [`release_recv`]: the peer was
    /// made to wait on exactly this.
    ///
    /// [`release_recv`]: Self::release_recv
    #[cfg(feature = "grpc")]
    #[must_use]
    pub fn release_held(&self) -> (u32, Option<u32>) {
        let held = self.unreleased.replace(0);
        (held, self.window.release_recv_now(held))
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}

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

    pub fn body_is_oneshot(&self) -> bool {
        self.state().body_is_oneshot()
    }

    pub fn body(&self) -> impl Future<Output = Option<Box<[u8]>>> {
        self.state().body()
    }

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
    /// their credit, and taking a message is what lets go of it.
    #[cfg(feature = "grpc")]
    pub async fn message(&self) -> Option<Result<GrpcFrame, GrpcError>> {
        let taken = self.state().message().await;
        // Once input has ended, held connection credit goes back when the
        // stream retires.
        if let Some(Ok(_)) = &taken
            && !self.state().input_ended()
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
        self.state().note_responded();
    }

    pub fn write_headers_final(self, status: StatusCode, fields: &http::HeaderMap) {
        self.token
            .shared()
            .write_response(self.id(), status, fields, true);
        self.state().note_responded();
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
    /// END_STREAM on DATA.
    #[cfg(feature = "grpc")]
    pub async fn write_message<M: prost::Message>(&self, message: &M) {
        self.write_data(&crate::grpc::frame_message(message)).await;
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
        if !state.has_responded() || state.is_retired() {
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
