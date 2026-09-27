use std::cell::{Cell, RefCell};
use std::io;
use std::pin::pin;
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use http::HeaderMap;
use runtime::runtime::time::timeout;

use crate::client::STREAM_RECV_WINDOW;
use crate::client::lifecycle::{Inbound, Lifecycle, Outbound};
use crate::client::shared::ClientShared;
#[cfg(feature = "grpc")]
use crate::grpc::{GrpcError, GrpcFormat, GrpcFrame, GrpcInput, Status};
use crate::shared::codec::frames::{
    encode::encode_window_update, headers::content_length, stream_id::StreamId,
};
use crate::shared::codec::types::{CANCEL, StreamViolation};
use crate::shared::connection::{
    MAX_SLEEP, SendSide, input_data::InputData, settings::Settings, stream_window::StreamWindow,
};

/// A value rather than an `io::Error`: set from the connection loop, where an
/// allocation per reset stream is a cost a peer controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// §6.4.
    Reset(u32),
    Gone(&'static str),
    /// Must map to `ErrorKind::TimedOut`, which retries decide on.
    Expired,
}

impl Failure {
    fn error(self) -> io::Error {
        match self {
            Self::Reset(code) => io::Error::other(format!("stream reset by peer (code {code:#x})")),
            Self::Gone(reason) => io::Error::other(reason),
            Self::Expired => io::Error::new(
                io::ErrorKind::TimedOut,
                "the deadline on this request passed",
            ),
        }
    }
}

/// What a response's body is gathered into, chosen by its head.
enum Input {
    Bytes(InputData),
    /// A gRPC call's messages, gathered straight from the frames that carry
    /// them, each decoded from the buffer it was gathered in.
    #[cfg(feature = "grpc")]
    Messages(GrpcInput),
}

pub(crate) struct StreamState {
    id: StreamId,
    window: StreamWindow,
    lifecycle: Cell<Lifecycle>,
    /// Emptied by the handle, so it says nothing about whether a head came:
    /// that is `lifecycle`'s.
    response: RefCell<Option<http::Response<()>>>,
    /// Made with the head. Bytes: gathered whole when its `content-length`
    /// is small, drained as they arrive otherwise, as the server does with a
    /// request's; no credit goes back until the application takes them.
    /// Messages, for a gRPC call: credited as they land, unless a whole one
    /// is waiting to be taken. `None` before the head, and once a whole body
    /// is taken.
    input: RefCell<Option<Input>>,
    /// Body bytes landed so far: `InputData` judges each push against the
    /// declared length by it.
    landed: Cell<u64>,
    trailers: RefCell<Option<HeaderMap>>,
    /// RFC 9110 §9.3.2: a HEAD response's `content-length` is not a promise
    /// about this stream.
    head_request: bool,
    /// A gRPC call, whose response a `Call` reads message by message.
    #[cfg_attr(not(feature = "grpc"), allow(dead_code))]
    grpc: bool,
    /// Received bytes still holding flow-control credit.
    unreleased: Cell<u32>,
    sent: Cell<u64>,
    recv_waker: RefCell<Option<Waker>>,
    /// A separate slot: both halves can be parked at once, and a single slot
    /// would let one park overwrite the other.
    send_waker: RefCell<Option<Waker>>,
}

impl StreamState {
    /// `settings` are the peer's.
    pub(crate) fn new(
        id: StreamId,
        settings: &Settings,
        end_stream: bool,
        head_request: bool,
        grpc: bool,
    ) -> Self {
        Self {
            id,
            window: StreamWindow::new(settings, STREAM_RECV_WINDOW),
            lifecycle: Cell::new(Lifecycle::new(end_stream)),
            response: RefCell::new(None),
            input: RefCell::new(None),
            landed: Cell::new(0),
            trailers: RefCell::new(None),
            head_request,
            grpc,
            unreleased: Cell::new(0),
            sent: Cell::new(0),
            recv_waker: RefCell::new(None),
            send_waker: RefCell::new(None),
        }
    }

    pub(crate) fn id(&self) -> StreamId {
        self.id
    }

    fn inbound(&self) -> Inbound {
        self.lifecycle.get().inbound
    }

    fn outbound(&self) -> Outbound {
        self.lifecycle.get().outbound
    }

    fn set_inbound(&self, inbound: Inbound) {
        self.lifecycle.set(Lifecycle {
            inbound,
            ..self.lifecycle.get()
        });
    }

    /// §5.1.
    pub(crate) fn is_closed(&self) -> bool {
        self.lifecycle.get().is_closed()
    }

    pub(crate) fn end_output(&self) {
        self.lifecycle.set(Lifecycle {
            outbound: self.outbound().end(),
            ..self.lifecycle.get()
        });
    }

    /// §8.1.2.4. Judged before it is stored, so a failing head never reaches
    /// the application. Informational responses (§8.1) are dropped.
    pub(crate) fn recv_response(
        &self,
        response: http::Response<()>,
        end_stream: bool,
    ) -> Result<(), StreamViolation> {
        if response.status().is_informational() {
            // §8.1: an informational response cannot end the message.
            return match end_stream {
                true => Err(StreamViolation::MalformedResponse),
                false => Ok(()),
            };
        }

        // §8.1.1. Not for a HEAD's response or a 304 (RFC 9110 §8.6): both
        // declare the length of a body they do not carry.
        let declared =
            content_length(response.headers()).map_err(|()| StreamViolation::MalformedResponse)?;
        let bodiless = self.head_request || response.status() == http::StatusCode::NOT_MODIFIED;
        let inbound = self
            .inbound()
            .on_head(declared.filter(|_| !bodiless), end_stream)?;

        // A body known to be empty is a whole one, of nothing.
        let body = match bodiless || end_stream {
            true => Some(0),
            false => declared,
        };
        let input = self
            .messages(&response, end_stream)
            .unwrap_or_else(|| Input::Bytes(InputData::new(body)));
        *self.input.borrow_mut() = Some(input);
        *self.response.borrow_mut() = Some(response);
        self.set_inbound(inbound);
        self.wake_recv();
        Ok(())
    }

    /// No messages in a head that settles the call (§9.1), as its `Call`
    /// reads it, nor in one with no gRPC content-type.
    #[cfg(feature = "grpc")]
    fn messages(&self, response: &http::Response<()>, end_stream: bool) -> Option<Input> {
        let fields = response.headers();
        if !self.grpc || end_stream || Status::settled_by_head(response.status(), fields).is_some()
        {
            return None;
        }
        GrpcFormat::of_response(fields)
            .map(|format| Input::Messages(GrpcInput::new(format, fields)))
    }

    #[cfg(not(feature = "grpc"))]
    fn messages(&self, _: &http::Response<()>, _: bool) -> Option<Input> {
        None
    }

    /// §8.1.
    pub(crate) fn recv_trailers(&self, fields: HeaderMap) -> Result<(), StreamViolation> {
        let inbound = self.inbound().on_trailers()?;
        #[cfg(feature = "grpc")]
        if let Some(Input::Messages(input)) = self.input.borrow_mut().as_mut() {
            input.end();
        }
        *self.trailers.borrow_mut() = Some(fields);
        self.set_inbound(inbound);
        self.wake_recv();
        Ok(())
    }

    pub(crate) fn has_response(&self) -> bool {
        self.inbound().has_response()
    }

    pub(crate) fn input_ended(&self) -> bool {
        self.inbound().is_ended()
    }

    /// The payload is copied, once, into what gathers it: the decoder's
    /// buffer is owed back to the ring the moment this returns. Judged before
    /// anything is kept. A body gathered whole wakes its reader once, when it
    /// is complete.
    ///
    /// `Ok(n)`: how much was consumed on the spot and owes the peer its credit
    /// back now, which is the caller's to give.
    pub(crate) fn recv_data(
        &self,
        payload: &[u8],
        end_stream: bool,
    ) -> Result<u32, StreamViolation> {
        let inbound = self.inbound().on_data(payload.len() as u64, end_stream)?;
        let mut input = self.input.borrow_mut();
        // `on_data` refuses DATA before the head, which is what makes it.
        let input = input.as_mut().ok_or(StreamViolation::MalformedResponse)?;
        let len = payload.len() as u32;

        let (wake, consumed) = match input {
            Input::Bytes(input) => {
                if !payload.is_empty() {
                    // Past what `on_data` checked only for a body known to be
                    // empty whatever its `content-length` said, as a HEAD's.
                    input
                        .push(self.landed.get(), payload)
                        .map_err(|_| StreamViolation::ContentLengthMismatch)?;
                    self.landed.set(self.landed.get() + payload.len() as u64);
                }
                (end_stream || input.wakes_per_frame(), 0)
            }
            #[cfg(feature = "grpc")]
            Input::Messages(input) => {
                let wake = input.push(payload);
                if end_stream {
                    input.end();
                }
                // While a whole message waits, the call is behind, and these
                // bytes keep their credit until it takes one.
                let consumed = if input.has_ready() { 0 } else { len };
                (wake || end_stream, consumed)
            }
        };

        // Bounded by the receive window, so it cannot outgrow a u32.
        self.unreleased.set(self.unreleased.get() + len - consumed);
        self.set_inbound(inbound);
        if wake {
            self.wake_recv();
        }
        Ok(consumed)
    }

    /// §6.9.1. Split from `recv_data` because an overrun here is a connection
    /// error, not a stream one.
    pub(crate) fn recv_window(&self, padded_len: u32) -> Result<(), ()> {
        self.window.recv(padded_len)
    }

    /// For bytes no read will ever release, i.e. padding.
    pub(crate) fn release_recv(&self, len: u32) -> Option<u32> {
        self.window.release_recv(len)
    }

    /// §6.9.1.
    pub(crate) fn credit_send(&self, increment: u32) -> Result<(), ()> {
        self.window.credit_send(increment)?;
        self.wake_send();
        Ok(())
    }

    /// §6.9.2.
    pub(crate) fn adjust_send(&self, delta: i32) -> Result<(), ()> {
        self.window.adjust_send(delta)?;
        if delta > 0 {
            self.wake_send();
        }
        Ok(())
    }

    /// The first failure is the one kept, since it closes both halves.
    pub(crate) fn fail(&self, failure: Failure) {
        self.lifecycle.set(self.lifecycle.get().fail(failure));
        self.wake_recv();
        self.wake_send();
    }

    /// Zeroed on the way out so the credit can only be given back once.
    pub(crate) fn take_unreleased(&self) -> u32 {
        self.unreleased.replace(0)
    }

    /// Zero after the stream has been retired, which keeps a late read from
    /// crediting the peer twice.
    fn release(&self, len: u32) -> u32 {
        let taken = len.min(self.unreleased.get());
        self.unreleased.set(self.unreleased.get() - taken);
        taken
    }

    fn wake_recv(&self) {
        if let Some(waker) = self.recv_waker.borrow_mut().take() {
            waker.wake();
        }
    }

    fn wake_send(&self) {
        if let Some(waker) = self.send_waker.borrow_mut().take() {
            waker.wake();
        }
    }

    fn register_recv_waker(&self, waker: &Waker) {
        let mut slot = self.recv_waker.borrow_mut();
        if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }
}

impl SendSide for StreamState {
    fn available_send(&self) -> u32 {
        self.window.available_send()
    }

    fn debit_send(&self, len: u32) -> Result<(), ()> {
        self.window.debit_send(len)
    }

    fn register_send_waker(&self, waker: &Waker) {
        let mut slot = self.send_waker.borrow_mut();
        if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }

    fn note_sent(&self, n: usize) {
        self.sent.set(self.sent.get() + n as u64);
    }
}

/// A body gathered whole, taken out of its slot.
fn take_whole(input: &mut Option<Input>) -> Option<Box<[u8]>> {
    match input.take() {
        Some(Input::Bytes(gathered)) => gathered.into_oneshot(),
        #[cfg(feature = "grpc")]
        Some(Input::Messages(messages)) => {
            *input = Some(Input::Messages(messages));
            None
        }
        None => None,
    }
}

#[cfg(feature = "grpc")]
fn read_as_messages() -> io::Error {
    io::Error::other("a gRPC call's response is read message by message")
}

/// What [`Stream::body`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum Body {
    /// The whole body, whose length the response declared and small enough
    /// to be gathered: one allocation, moved out.
    Complete(Box<[u8]>),
    /// Any other body: [`Stream::read`] takes it as it arrives.
    Streaming,
}

/// Dropping it closes the stream, with a RST_STREAM if the exchange was not
/// finished (§8.1).
pub struct Stream {
    id: StreamId,
    state: Rc<StreamState>,
    shared: Rc<ClientShared>,
    deadline: Option<SystemTime>,
    closed: Cell<bool>,
}

impl Stream {
    pub(crate) fn new(id: StreamId, state: Rc<StreamState>, shared: Rc<ClientShared>) -> Self {
        Self {
            id,
            state,
            shared,
            deadline: None,
            closed: Cell::new(false),
        }
    }

    /// Enforced only where the application waits, not by the connection loop.
    pub fn with_deadline(mut self, within: Duration) -> Self {
        self.deadline = Some(runtime::runtime::now() + within);
        self
    }

    pub fn id(&self) -> StreamId {
        self.id
    }

    /// §6.9.1.
    pub async fn write(&self, data: &[u8], end_stream: bool) -> io::Result<()> {
        self.within(self.write_body(data, end_stream)).await
    }

    /// As [`Stream::write`], for a buffer handed over rather than lent: from
    /// [`ATTACH_MIN`](crate::client::ATTACH_MIN) bytes up it is sent as it
    /// is, never copied into the connection's output.
    /// `Vec<u8>`, `Box<[u8]>`, `Bytes` and `&'static [u8]` all become one
    /// without a copy.
    pub async fn write_owned(&self, data: impl Into<Bytes>, end_stream: bool) -> io::Result<()> {
        let data = data.into();
        self.within(self.write_owned_body(data, end_stream)).await
    }

    async fn write_body(&self, data: &[u8], end_stream: bool) -> io::Result<()> {
        self.writable()?;
        self.drive_write(
            self.shared
                .core
                .write_data(self.id, &*self.state, data, end_stream),
            end_stream,
        )
        .await
    }

    async fn write_owned_body(&self, data: Bytes, end_stream: bool) -> io::Result<()> {
        self.writable()?;
        self.drive_write(
            self.shared
                .core
                .write_data_owned(self.id, &*self.state, data, end_stream),
            end_stream,
        )
        .await
    }

    async fn drive_write(
        &self,
        writing: impl Future<Output = ()>,
        end_stream: bool,
    ) -> io::Result<()> {
        let mut writing = pin!(writing);
        // A stream reset while the write is parked on flow control is credited
        // by nothing, so the failure must be checked beside it; `fail` wakes
        // the send waker the write registered.
        std::future::poll_fn(|cx| {
            if let Outbound::Failed(failure) = self.state.outbound() {
                return Poll::Ready(Err(failure.error()));
            }
            writing.as_mut().poll(cx).map(Ok)
        })
        .await?;

        if end_stream {
            self.state.end_output();
            self.shared.retire_if_closed(self.id.into());
        }
        Ok(())
    }

    /// Answers once; a second call must error rather than hang.
    pub async fn response(&self) -> io::Result<http::Response<()>> {
        self.within(self.await_response()).await
    }

    async fn await_response(&self) -> io::Result<http::Response<()>> {
        std::future::poll_fn(|cx| {
            if let Some(response) = self.state.response.borrow_mut().take() {
                return Poll::Ready(Ok(response));
            }
            match self.state.inbound() {
                Inbound::Failed(failure) => Poll::Ready(Err(failure.error())),
                Inbound::AwaitingHead => {
                    self.state.register_recv_waker(cx.waker());
                    Poll::Pending
                }
                Inbound::Body(_) | Inbound::Ended => {
                    Poll::Ready(Err(io::Error::other("the response was already taken")))
                }
            }
        })
        .await
    }

    /// The body whole, if the response declared a length of at most
    /// [`InputData::ONESHOT_LIMIT`]: gathered in one allocation as it arrived,
    /// and handed over when complete. Otherwise [`Body::Streaming`], as soon
    /// as the head is in: the body is then [`Stream::read`]'s.
    pub async fn body(&self) -> io::Result<Body> {
        self.within(self.whole_body()).await
    }

    async fn whole_body(&self) -> io::Result<Body> {
        let body = std::future::poll_fn(|cx| {
            let inbound = self.state.inbound();
            if let Inbound::Failed(failure) = inbound {
                return Poll::Ready(Err(failure.error()));
            }
            let mut input = self.state.input.borrow_mut();
            let gathered = match input.as_ref() {
                Some(Input::Bytes(gathered)) => gathered,
                #[cfg(feature = "grpc")]
                Some(Input::Messages(_)) => return Poll::Ready(Err(read_as_messages())),
                None => {
                    return match inbound {
                        Inbound::AwaitingHead => {
                            self.state.register_recv_waker(cx.waker());
                            Poll::Pending
                        }
                        _ => Poll::Ready(Err(io::Error::other("the body was already taken"))),
                    };
                }
            };
            if gathered.wakes_per_frame() {
                return Poll::Ready(Ok(Body::Streaming));
            }
            if inbound != Inbound::Ended {
                self.state.register_recv_waker(cx.waker());
                return Poll::Pending;
            }
            let whole = take_whole(&mut input);
            Poll::Ready(Ok(Body::Complete(whole.unwrap_or_default())))
        })
        .await?;

        if let Body::Complete(bytes) = &body {
            self.release(bytes.len() as u32);
        }
        Ok(body)
    }

    /// Whatever has arrived since the last read, in one piece: its bytes
    /// moved out, not copied. A body gathered whole comes in one read, once
    /// complete. Taking bytes is what returns their credit (§6.9.1), so
    /// nothing is buffered beyond one receive window. Whatever arrived is
    /// delivered before any failure is reported.
    pub async fn read(&self) -> io::Result<Option<Vec<u8>>> {
        self.within(self.next_chunk()).await
    }

    async fn next_chunk(&self) -> io::Result<Option<Vec<u8>>> {
        let chunk = std::future::poll_fn(|cx| {
            let inbound = self.state.inbound();
            let mut input = self.state.input.borrow_mut();
            match input.as_mut() {
                Some(Input::Bytes(gathered)) if gathered.wakes_per_frame() => {
                    let chunk = gathered.take_available();
                    if !chunk.is_empty() {
                        return Poll::Ready(Ok(Some(chunk)));
                    }
                }
                Some(Input::Bytes(_)) if inbound == Inbound::Ended => {
                    let whole = take_whole(&mut input);
                    if let Some(whole) = whole.filter(|whole| !whole.is_empty()) {
                        return Poll::Ready(Ok(Some(whole.into_vec())));
                    }
                }
                #[cfg(feature = "grpc")]
                Some(Input::Messages(_)) => return Poll::Ready(Err(read_as_messages())),
                Some(Input::Bytes(_)) | None => {}
            }
            match inbound {
                Inbound::Failed(failure) => Poll::Ready(Err(failure.error())),
                Inbound::Ended => Poll::Ready(Ok(None)),
                Inbound::AwaitingHead | Inbound::Body(_) => {
                    self.state.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            }
        })
        .await?;

        if let Some(chunk) = &chunk {
            self.release(chunk.len() as u32);
        }
        Ok(chunk)
    }

    /// The next whole message of a gRPC call, decoded from nothing but the
    /// buffer it was gathered in. `None` once the response ends, carrying
    /// messages or not. Messages that arrived are delivered before a failure
    /// is reported.
    #[cfg(feature = "grpc")]
    pub(crate) async fn message(&self) -> io::Result<Option<Result<GrpcFrame, GrpcError>>> {
        self.within(self.next_message()).await
    }

    #[cfg(feature = "grpc")]
    async fn next_message(&self) -> io::Result<Option<Result<GrpcFrame, GrpcError>>> {
        let (taken, drained) = std::future::poll_fn(|cx| {
            let inbound = self.state.inbound();
            match self.state.input.borrow_mut().as_mut() {
                Some(Input::Messages(input)) => {
                    if let Some(taken) = input.take() {
                        return Poll::Ready(Ok((Some(taken), !input.has_ready())));
                    }
                }
                // No messages in it, but it must still end before its
                // trailers can say how the call went. What it carries is
                // dropped, and credited back so it cannot stall.
                Some(Input::Bytes(body)) => {
                    let dropped = body.take_available().len();
                    self.release(dropped as u32);
                }
                None => {}
            }
            match inbound {
                Inbound::Failed(failure) => Poll::Ready(Err(failure.error())),
                Inbound::Ended => Poll::Ready(Ok((None, false))),
                Inbound::AwaitingHead | Inbound::Body(_) => {
                    self.state.register_recv_waker(cx.waker());
                    Poll::Pending
                }
            }
        })
        .await?;

        // Only once none waits: while one does, the call is still behind, and
        // the window is what holds the peer back. Released per message
        // instead, it would let the queue grow by one each time.
        if drained && let Some(Ok(_)) = &taken {
            self.release_held();
        }
        Ok(taken)
    }

    /// At once rather than accumulated: the peer was made to wait on exactly
    /// the bytes the waiting messages held.
    #[cfg(feature = "grpc")]
    fn release_held(&self) {
        let held = self.state.release(u32::MAX);
        self.shared
            .core
            .release_held_credit(self.id, &self.state.window, held);
    }

    /// A gRPC message: see [`crate::grpc::write_message`]. Held to the
    /// deadline, and to the stream's failing, as any write.
    #[cfg(feature = "grpc")]
    pub(crate) async fn write_message<M: prost::Message>(
        &self,
        message: &M,
        end_stream: bool,
    ) -> io::Result<()> {
        self.within(async {
            self.writable()?;
            self.drive_write(
                crate::grpc::write_message(
                    &self.shared.core,
                    self.id,
                    &*self.state,
                    message,
                    end_stream,
                ),
                end_stream,
            )
            .await
        })
        .await
    }

    /// §8.1.
    pub fn trailers(&self) -> Option<HeaderMap> {
        self.state.trailers.borrow_mut().take()
    }

    /// §8.3's no-pseudo-header rule holds by construction: `:` cannot appear
    /// in a `HeaderName`. No window to wait on (§6.9 meters DATA only).
    pub fn send_trailers(&self, fields: &HeaderMap) -> io::Result<()> {
        self.writable()?;

        self.shared.core.write_trailers(self.id, fields);
        self.state.end_output();
        self.shared.retire_if_closed(self.id.into());
        Ok(())
    }

    fn writable(&self) -> io::Result<()> {
        match self.state.outbound() {
            Outbound::Open => Ok(()),
            Outbound::Failed(failure) => Err(failure.error()),
            Outbound::Ended => Err(io::Error::other("the request body already ended")),
        }
    }

    /// An unfinished stream is reset with CANCEL (§8.1). Idempotent.
    pub fn close(&self) {
        if self.closed.replace(true) {
            return;
        }
        self.shared.reset_stream(self.id, CANCEL);
        // Even when that wrote nothing: this may have been the last handle,
        // and the parked loop would not otherwise notice.
        self.shared.core.wake_flusher();
    }

    /// Waited in slices of at most [`MAX_SLEEP`], the longest the runtime's
    /// timewheel holds. `op` must be held across slices, not restarted, so a
    /// half-written body stays half-written.
    async fn within<T>(&self, op: impl Future<Output = io::Result<T>>) -> io::Result<T> {
        let Some(deadline) = self.deadline else {
            return op.await;
        };

        let mut op = pin!(op);
        loop {
            let left = deadline
                .duration_since(runtime::runtime::now())
                .unwrap_or_default();
            if left.is_zero() {
                return Err(self.expire());
            }
            match timeout(left.min(MAX_SLEEP), op.as_mut()).await {
                Ok(done) => return done,
                Err(()) => continue,
            }
        }
    }

    /// Fail before close: [`StreamState::fail`] keeps the first failure, so
    /// waiters report the timeout rather than the cancel.
    fn expire(&self) -> io::Error {
        self.state.fail(Failure::Expired);
        self.close();
        Failure::Expired.error()
    }

    /// §6.9.1: credit goes back on the stream and the connection both.
    fn release(&self, len: u32) {
        let taken = self.state.release(len);
        if taken == 0 {
            return;
        }
        if let Some(increment) = self.state.window.release_recv(taken) {
            self.shared
                .core
                .write_frame(|out| encode_window_update(out, self.id, increment));
        }
        self.shared.core.release_stream_credit(taken);
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.close();
    }
}
