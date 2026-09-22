//! One request and the response it is waiting for.
//!
//! Two halves of the same thing. [`StreamState`] is what the connection loop
//! writes into as frames arrive — it lives in the connection's stream map and
//! is reached through an `Rc`, so everything the loop touches is behind a
//! `Cell`. [`Stream`] is what the application holds: the handle that writes a
//! body, takes the response, and closes the stream when it is dropped.
//!
//! They are separate because they are owned by different tasks. The loop must
//! be able to deliver a DATA frame whether or not anyone is currently reading,
//! and the application must be able to let its handle go without the loop
//! losing the map entry it is decoding into.

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
use crate::client::shared::ClientShared;
use crate::shared::codec::frames::{encode::encode_window_update, stream_id::StreamId};
use crate::shared::codec::types::CANCEL;
use crate::shared::connection::{
    DEADLINE_TICK, SendSide, settings::Settings, stream_window::StreamWindow,
};

/// Why a stream ended before it was done.
///
/// Kept as a value rather than an `io::Error` because it is set from the
/// connection loop, where an allocation per reset stream is a cost a peer
/// controls, and read at most once by whoever was waiting.
#[derive(Clone, Copy)]
pub(crate) enum Failure {
    /// §6.4: the peer reset the stream, with this error code.
    Reset(u32),
    /// The stream ended without a reset from the peer: the connection went,
    /// a GOAWAY said this request was never processed (§6.8), or this client
    /// cancelled it.
    Gone(&'static str),
    /// The deadline this request was given ran out, and the stream was
    /// cancelled for it.
    ///
    /// Its own variant rather than a [`Gone`](Self::Gone) with a good message,
    /// because it is the one failure a caller acts on differently: a timeout
    /// is `ErrorKind::TimedOut`, which is what a retry decides on without
    /// reading prose.
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

/// The connection's half of a stream: what frames do to it.
pub(crate) struct StreamState {
    /// §5.1.1: the id this request went out on. Kept here because the map
    /// that holds the state is keyed by it but does not carry it, and a walk
    /// of the live streams sometimes needs to name one.
    id: StreamId,
    window: StreamWindow,
    /// The response head, converted where it arrived because that is where a
    /// malformed one can still be answered with a RST_STREAM. Taken by the
    /// handle, which is why arriving is tracked separately.
    response: RefCell<Option<http::Response<()>>>,
    /// The response head has arrived, whether or not anyone has taken it yet.
    ///
    /// Not the same question as `response.is_some()`, and the difference is
    /// what tells a trailer section from a response: §8.1 makes the second
    /// HEADERS on a stream its trailers, and if this were read off the slot
    /// the head was taken from, an application that had read its response
    /// would have its trailers delivered as a second one.
    response_seen: Cell<bool>,
    /// Body bytes, one entry per DATA frame.
    ///
    /// Bounded without a limit of its own: nothing is credited back to the
    /// peer until the application takes a chunk, so what can pile up here is
    /// exactly the receive window — [`STREAM_RECV_WINDOW`] a stream — and that
    /// is the whole argument for buffering at all rather than pushing back on
    /// the loop.
    chunks: RefCell<VecDeque<Vec<u8>>>,
    /// §8.1: the trailers, if the response had any.
    trailers: RefCell<Option<HeaderMap>>,
    /// The peer's half is done: its END_STREAM arrived, on the response head,
    /// a DATA frame or the trailers.
    no_more_input: Cell<bool>,
    /// Our half is done: the request is written, END_STREAM included.
    no_more_output: Cell<bool>,
    failure: Cell<Option<Failure>>,
    /// Received body bytes still holding flow-control credit — the peer's
    /// until the application reads them.
    unreleased: Cell<u32>,
    /// Request body bytes handed to the peer. Nothing reads it yet; it is the
    /// counter a send-rate check would run on, and the server keeps the same
    /// one.
    sent: Cell<u64>,
    /// Whoever waits for the response, or for body bytes.
    recv_waker: RefCell<Option<Waker>>,
    /// Whoever waits for credit to write a body with. A second slot rather
    /// than the server's one, because both halves of a client stream can be
    /// in flight at once: a request body goes up while the response comes
    /// down, and a single slot would let one park overwrite the other.
    send_waker: RefCell<Option<Waker>>,
}

impl StreamState {
    /// `settings` are the peer's: they credit the send window.
    pub(crate) fn new(id: StreamId, settings: &Settings, end_stream: bool) -> Self {
        Self {
            id,
            window: StreamWindow::new(settings, STREAM_RECV_WINDOW),
            response: RefCell::new(None),
            response_seen: Cell::new(false),
            chunks: RefCell::new(VecDeque::new()),
            trailers: RefCell::new(None),
            no_more_input: Cell::new(false),
            // END_STREAM already on the request head: the stream is born
            // half-closed(local).
            no_more_output: Cell::new(end_stream),
            failure: Cell::new(None),
            unreleased: Cell::new(0),
            sent: Cell::new(0),
            recv_waker: RefCell::new(None),
            send_waker: RefCell::new(None),
        }
    }

    pub(crate) fn id(&self) -> StreamId {
        self.id
    }

    /// Both halves done (§5.1), which is what lets the connection take the
    /// stream out of its map.
    pub(crate) fn is_closed(&self) -> bool {
        self.no_more_input.get() && self.no_more_output.get()
    }

    /// Our half is done: END_STREAM is written. Says nothing about the peer's
    /// — §5.1 leaves us half-closed(local) and still owed a response.
    pub(crate) fn end_output(&self) {
        self.no_more_output.set(true);
    }

    /// §8.1.2.4: the response head. `Err` is a head that is not one — no
    /// `:status`, or a pseudo-header that belongs to a request.
    ///
    /// §8.1 lets any number of informational responses precede the final one;
    /// they are dropped here rather than delivered, so `response()` resolves
    /// on the response the application asked about. Nothing is lost that this
    /// client can currently act on: it never sends `expect: 100-continue`.
    pub(crate) fn recv_response(
        &self,
        response: http::Response<()>,
        end_stream: bool,
    ) -> Result<(), ()> {
        if response.status().is_informational() {
            // §8.1: an informational response cannot end the message.
            return if end_stream { Err(()) } else { Ok(()) };
        }

        *self.response.borrow_mut() = Some(response);
        self.response_seen.set(true);
        if end_stream {
            self.no_more_input.set(true);
        }
        self.wake_recv();
        Ok(())
    }

    /// §8.1: the trailers — a second HEADERS, after the body, carrying
    /// END_STREAM and no pseudo-header. Ends the peer's half exactly as a
    /// final DATA frame does.
    pub(crate) fn recv_trailers(&self, fields: HeaderMap) {
        *self.trailers.borrow_mut() = Some(fields);
        self.no_more_input.set(true);
        self.wake_recv();
    }

    /// Whether a HEADERS frame on this stream is the response or its
    /// trailers.
    pub(crate) fn has_response(&self) -> bool {
        self.response_seen.get()
    }

    /// One DATA payload, already stripped of its padding. The bytes are
    /// copied out of the decoder's buffer, which is owed back to the ring the
    /// moment this returns.
    pub(crate) fn recv_data(&self, payload: &[u8], end_stream: bool) -> Result<(), ()> {
        if self.no_more_input.get() {
            return Err(());
        }
        if !payload.is_empty() {
            self.chunks.borrow_mut().push_back(payload.to_vec());
            // Bounded by the receive window, so it cannot outgrow a u32.
            self.unreleased
                .set(self.unreleased.get() + payload.len() as u32);
        }
        if end_stream {
            self.no_more_input.set(true);
        }
        self.wake_recv();
        Ok(())
    }

    /// §6.9.1: debits the receive window. Split from `recv_data` because an
    /// overrun here is a connection error, not a stream one.
    pub(crate) fn recv_window(&self, padded_len: u32) -> Result<(), ()> {
        self.window.recv(padded_len)
    }

    /// §6.9.1: a WINDOW_UPDATE on this stream. The writer may be waiting on
    /// exactly this; it re-checks the window itself.
    pub(crate) fn credit_send(&self, increment: u32) -> Result<(), ()> {
        self.window.credit_send(increment)?;
        self.wake_send();
        Ok(())
    }

    /// §6.9.2: the peer's initial window changed. Woken only when the change
    /// opens room — a shrink has nothing to offer a waiting writer.
    pub(crate) fn adjust_send(&self, delta: i32) -> Result<(), ()> {
        self.window.adjust_send(delta)?;
        if delta > 0 {
            self.wake_send();
        }
        Ok(())
    }

    /// The stream is over for a reason that is not its END_STREAM. Both
    /// wakers fire: a reader waiting for a response it will never get and a
    /// writer parked on credit that will never come are the same casualty.
    ///
    /// The first failure is the one kept — a stream reset by the peer and
    /// then caught by the connection closing was reset by the peer.
    pub(crate) fn fail(&self, failure: Failure) {
        if self.failure.get().is_none() {
            self.failure.set(Some(failure));
        }
        // Nothing more will arrive and nothing more may be written, which is
        // what stops a reader parking again on the next poll.
        self.no_more_input.set(true);
        self.no_more_output.set(true);
        self.wake_recv();
        self.wake_send();
    }

    /// Connection credit this stream still holds, zeroed on the way out so it
    /// can only be given back once — by the connection retiring the stream,
    /// or by the application reading the bytes, whichever comes first.
    pub(crate) fn take_unreleased(&self) -> u32 {
        self.unreleased.replace(0)
    }

    /// Takes `len` off what this stream still owes, answering how much of it
    /// was actually still owed. Zero after the stream has been retired, which
    /// is what keeps a late read from crediting the peer twice.
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

/// One request on a connection: write its body, read its response, close it.
///
/// The handle is the stream's lifetime as far as the application is
/// concerned. Dropping it closes the stream — with a RST_STREAM if the
/// exchange was not finished, which is what §8.1 expects of a client that
/// abandons a request rather than one that completes it.
///
/// Not `Clone`, and not `Send`: a stream belongs to one task on one thread,
/// like everything else on this runtime.
pub struct Stream {
    id: StreamId,
    state: Rc<StreamState>,
    shared: Rc<ClientShared>,
    /// When this request runs out of time, if it was given a deadline.
    ///
    /// Held by the handle rather than the state, because it is the handle that
    /// waits: the connection loop has no opinion about how long a request may
    /// take, and a deadline it enforced would be a timer per stream armed on
    /// the loop's behalf for something only the application asked for.
    deadline: Option<SystemTime>,
    /// Set by [`Stream::close`], so that the drop that follows does nothing a
    /// second time.
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

    /// Gives this request `within` to finish, from now.
    ///
    /// The deadline covers the whole exchange rather than one call on it —
    /// writing the body, waiting for the head, reading to the end of it — so
    /// what it bounds is the thing a caller actually cares about. When it
    /// passes, the stream is cancelled the way [`close`](Self::close) cancels
    /// it (§8.1: RST_STREAM CANCEL, so the peer stops working and stops
    /// sending), and every call on the handle answers `ErrorKind::TimedOut`
    /// from then on — the one that timed out and the ones after it alike.
    ///
    /// It is enforced where the application waits, which is the whole of it: a
    /// deadline on a handle nobody is awaiting passes unnoticed until the next
    /// call, and a handle nobody awaits *at all* cancels the stream when it is
    /// dropped anyway. What this is not is a bound the connection keeps on the
    /// peer's behalf — see [`Connection::run`].
    ///
    /// Without one, a request waits as long as the exchange takes. That is
    /// often right: a server-streaming call has no natural deadline, and the
    /// keepalive is what notices a peer that has gone rather than one that is
    /// slow.
    ///
    /// [`Connection::run`]: crate::client::Connection::run
    pub fn with_deadline(mut self, within: Duration) -> Self {
        self.deadline = Some(runtime::runtime::now() + within);
        self
    }

    /// The id this request went out on (§5.1.1: odd, and never reused).
    pub fn id(&self) -> StreamId {
        self.id
    }

    /// Writes `data` as the next of the request body, `end_stream` marking it
    /// as the last.
    ///
    /// §6.9.1: the payload is cut into DATA frames by what the stream's send
    /// window, the connection's and the peer's `max_frame_size` allow, and by
    /// the room left in the connection's output. With none of it, this waits
    /// — for a WINDOW_UPDATE, or for the loop to flush — so a body larger
    /// than the peer will take does not have to be held anywhere but where
    /// the caller already has it.
    ///
    /// Resolves once the last byte is *written*, which is not the same as
    /// sent: the connection loop owns the send, and an error there ends the
    /// connection rather than this call.
    pub async fn write(&self, data: &[u8], end_stream: bool) -> io::Result<()> {
        self.within(self.write_body(data, end_stream)).await
    }

    async fn write_body(&self, data: &[u8], end_stream: bool) -> io::Result<()> {
        if let Some(failure) = self.state.failure.get() {
            return Err(failure.error());
        }
        if self.state.no_more_output.get() {
            return Err(io::Error::other("the request body already ended"));
        }

        let mut writing = pin!(self.shared.core.write_data(
            self.id,
            &*self.state,
            data,
            end_stream
        ));
        // The write parks on flow control, and a stream that is reset while
        // parked is credited by nothing — so the failure has to be checked
        // beside it rather than after it. `fail` wakes the send waker the
        // write registered, which is what brings us back here to see it.
        std::future::poll_fn(|cx| {
            if let Some(failure) = self.state.failure.get() {
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

    /// The response head, once the peer has sent it.
    ///
    /// §8.1 lets informational responses precede it; they are dropped, so
    /// this resolves on the response proper. An error is the stream ending
    /// without one — reset by the peer, or carried away by the connection.
    ///
    /// The head is handed over rather than lent, so this answers once. A
    /// second call is an error and not a wait, which is the difference
    /// between a mistake that is reported and one that hangs.
    pub async fn response(&self) -> io::Result<http::Response<()>> {
        self.within(self.await_response()).await
    }

    async fn await_response(&self) -> io::Result<http::Response<()>> {
        std::future::poll_fn(|cx| {
            if let Some(response) = self.state.response.borrow_mut().take() {
                return Poll::Ready(Ok(response));
            }
            if let Some(failure) = self.state.failure.get() {
                return Poll::Ready(Err(failure.error()));
            }
            if self.state.has_response() {
                return Poll::Ready(Err(io::Error::other("the response was already taken")));
            }
            if self.state.no_more_input.get() {
                return Poll::Ready(Err(io::Error::other("the stream ended without a response")));
            }
            self.state.register_recv_waker(cx.waker());
            Poll::Pending
        })
        .await
    }

    /// The next of the response body, or `None` at its end.
    ///
    /// One chunk per DATA frame, in the order they arrived. Taking a chunk is
    /// what hands the peer back the flow-control credit it was holding
    /// (§6.9.1), so an application that stops reading stops the download —
    /// which is the point: nothing is buffered here beyond one receive
    /// window.
    ///
    /// Whatever arrived is delivered before any failure is reported: a body
    /// cut short by a reset is still a body as far as it goes.
    pub async fn read(&self) -> io::Result<Option<Vec<u8>>> {
        self.within(self.next_chunk()).await
    }

    async fn next_chunk(&self) -> io::Result<Option<Vec<u8>>> {
        let chunk = std::future::poll_fn(|cx| {
            if let Some(chunk) = self.state.chunks.borrow_mut().pop_front() {
                return Poll::Ready(Ok(Some(chunk)));
            }
            if let Some(failure) = self.state.failure.get() {
                return Poll::Ready(Err(failure.error()));
            }
            if self.state.no_more_input.get() {
                return Poll::Ready(Ok(None));
            }
            self.state.register_recv_waker(cx.waker());
            Poll::Pending
        })
        .await?;

        if let Some(chunk) = &chunk {
            self.release(chunk.len() as u32);
        }
        Ok(chunk)
    }

    /// §8.1: the trailers, if the response carried any. `None` until the body
    /// has ended, since that is what a trailer section follows.
    pub fn trailers(&self) -> Option<HeaderMap> {
        self.state.trailers.borrow_mut().take()
    }

    /// Ends the request with a trailer section: §8.1's second HEADERS, after
    /// the body, carrying END_STREAM.
    ///
    /// This is what `write(.., true)` would otherwise have done, so it is one
    /// or the other — a request whose body already ended has nothing left to
    /// put trailers on, and says so rather than sending a frame the peer would
    /// answer with a stream error.
    ///
    /// §8.3 forbids a pseudo-header anywhere in a trailer section, which
    /// `HeaderMap` already makes impossible: `:` is not a character a
    /// `HeaderName` may contain. What it does not check is whether the peer
    /// wants trailers at all — a server is free to ignore them, and §8.1 only
    /// asks that a sender not put anything essential there.
    ///
    /// Not `async`: a trailer section is one small frame, written to the
    /// output for the loop to send, with no window to wait on (§6.9 meters
    /// DATA and nothing else).
    pub fn send_trailers(&self, fields: &HeaderMap) -> io::Result<()> {
        if let Some(failure) = self.state.failure.get() {
            return Err(failure.error());
        }
        if self.state.no_more_output.get() {
            return Err(io::Error::other("the request body already ended"));
        }

        self.shared.core.write_trailers(self.id, fields);
        self.state.end_output();
        self.shared.retire_if_closed(self.id.into());
        Ok(())
    }

    /// Ends this stream now.
    ///
    /// A stream that has finished both halves is merely forgotten. One that
    /// has not is reset with CANCEL (§8.1): the peer is told to stop, which
    /// it cannot infer from a client that simply stops reading — its own
    /// half-closed state would keep it sending until the window ran out.
    ///
    /// Idempotent, and what dropping the handle does.
    pub fn close(&self) {
        if self.closed.replace(true) {
            return;
        }
        self.shared.reset_stream(self.id, CANCEL);
        // Even when that wrote nothing: this may have been the last handle on
        // the connection, and the loop is parked waiting to be told something
        // changed. Letting go is the one change nothing else reports.
        self.shared.core.wake_flusher();
    }

    /// Runs `op` under this stream's deadline, if it has one.
    ///
    /// The wait is taken in slices rather than armed once, for a reason that
    /// is the runtime's: it serves [`DEADLINE_TICK`] from a store of its own
    /// and anything else from a timewheel that holds a minute at most, so a
    /// deadline of five minutes has no timer that fits it. Slicing gives
    /// arbitrary deadlines the cheap store for the long stretch and the wheel
    /// only for the last, sub-tick part of the wait — and the precision is the
    /// wheel's, not the tick's, since the final slice is exactly what is left.
    ///
    /// `op` is held across slices rather than restarted: it is polled through
    /// a `Pin`, so a timed-out slice drops the borrow and not the future, and
    /// a half-written body stays half-written.
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
            match timeout(left.min(DEADLINE_TICK), op.as_mut()).await {
                Ok(done) => return done,
                Err(()) => continue,
            }
        }
    }

    /// The deadline passed: the stream is failed with the reason, and then
    /// cancelled.
    ///
    /// In that order, because [`StreamState::fail`] keeps the first failure it
    /// is given and the cancel brings one of its own. This way everything
    /// waiting on the stream — and every later call on the handle — reports
    /// the timeout rather than the reset that carried it out.
    fn expire(&self) -> io::Error {
        self.state.fail(Failure::Expired);
        self.close();
        Failure::Expired.error()
    }

    /// Hands the peer back the credit `len` received bytes were holding, on
    /// this stream and on the connection both — §6.9.1 debited both when they
    /// arrived. Nothing goes out until a worthwhile amount has piled up at
    /// either level.
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
