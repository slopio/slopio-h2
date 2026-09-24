use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::pin::pin;
use std::rc::Rc;
use std::task::{Poll, Waker};
use std::time::{Duration, SystemTime};

use http::HeaderMap;
use runtime::runtime::time::timeout;

use crate::client::STREAM_RECV_WINDOW;
use crate::client::lifecycle::{Inbound, Lifecycle, Outbound};
use crate::client::shared::ClientShared;
use crate::shared::codec::frames::{
    encode::encode_window_update, headers::content_length, stream_id::StreamId,
};
use crate::shared::codec::types::{CANCEL, StreamViolation};
use crate::shared::connection::{
    MAX_SLEEP, SendSide, settings::Settings, stream_window::StreamWindow,
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

pub(crate) struct StreamState {
    id: StreamId,
    window: StreamWindow,
    lifecycle: Cell<Lifecycle>,
    /// Emptied by the handle, so it says nothing about whether a head came:
    /// that is `lifecycle`'s.
    response: RefCell<Option<http::Response<()>>>,
    /// Bounded by the receive window: no credit goes back until the
    /// application takes a chunk.
    chunks: RefCell<VecDeque<Vec<u8>>>,
    trailers: RefCell<Option<HeaderMap>>,
    /// RFC 9110 §9.3.2: a HEAD response's `content-length` is not a promise
    /// about this stream.
    head_request: bool,
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
    ) -> Self {
        Self {
            id,
            window: StreamWindow::new(settings, STREAM_RECV_WINDOW),
            lifecycle: Cell::new(Lifecycle::new(end_stream)),
            response: RefCell::new(None),
            chunks: RefCell::new(VecDeque::new()),
            trailers: RefCell::new(None),
            head_request,
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

        *self.response.borrow_mut() = Some(response);
        self.set_inbound(inbound);
        self.wake_recv();
        Ok(())
    }

    /// §8.1.
    pub(crate) fn recv_trailers(&self, fields: HeaderMap) -> Result<(), StreamViolation> {
        let inbound = self.inbound().on_trailers()?;
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

    /// The payload is copied: the decoder's buffer is owed back to the ring
    /// the moment this returns. Judged before anything is kept.
    pub(crate) fn recv_data(
        &self,
        payload: &[u8],
        end_stream: bool,
    ) -> Result<(), StreamViolation> {
        let inbound = self.inbound().on_data(payload.len() as u64, end_stream)?;
        if !payload.is_empty() {
            self.chunks.borrow_mut().push_back(payload.to_vec());
            // Bounded by the receive window, so it cannot outgrow a u32.
            self.unreleased
                .set(self.unreleased.get() + payload.len() as u32);
        }
        self.set_inbound(inbound);
        self.wake_recv();
        Ok(())
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

    async fn write_body(&self, data: &[u8], end_stream: bool) -> io::Result<()> {
        self.writable()?;

        let mut writing = pin!(self.shared.core.write_data(
            self.id,
            &*self.state,
            data,
            end_stream
        ));
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

    /// Taking a chunk is what returns its credit (§6.9.1), so nothing is
    /// buffered beyond one receive window. Whatever arrived is delivered
    /// before any failure is reported.
    pub async fn read(&self) -> io::Result<Option<Vec<u8>>> {
        self.within(self.next_chunk()).await
    }

    async fn next_chunk(&self) -> io::Result<Option<Vec<u8>>> {
        let chunk = std::future::poll_fn(|cx| {
            if let Some(chunk) = self.state.chunks.borrow_mut().pop_front() {
                return Poll::Ready(Ok(Some(chunk)));
            }
            match self.state.inbound() {
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
