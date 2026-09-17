use std::cell::{Cell, RefCell};
use std::task::{Poll, Waker};

use http::header;

use crate::{
    server::{
        connection::settings::Settings,
        stream::{input_data::InputData, stream_window::StreamWindow},
    },
    shared::codec::{frames::headers::Headers, types::StreamViolation},
};

mod input_data;
mod stream_window;

/// Reached only through an `Rc` shared with the stream task, so everything the
/// connection mutates while a frame is being decoded lives behind a `Cell`.
///
/// A stream has two halves that close independently (§5.1): the peer's, by
/// its END_STREAM on DATA or trailers, and ours, by the END_STREAM of our
/// response. `no_more_input` and `no_more_output` track them one each;
/// both set is the closed state the sweep retires.
pub struct Stream {
    header: Box<Headers>,
    /// §8.1: the trailers, if the request had any. Written once by the
    /// connection at END_STREAM, taken once by the task after the body. The
    /// decoder's own `Box`, kept as is: 8 bytes per stream for something
    /// almost no request carries.
    trailers: Cell<Option<Box<Headers>>>,
    /// The peer's half is done: its END_STREAM came, on the HEADERS, a DATA
    /// or the trailers. Half-closed(remote) from here on — DATA or HEADERS
    /// after it is a frame on a stream that, from its side, no longer
    /// exists.
    no_more_input: Cell<bool>,
    /// Our half is done: the response is written, END_STREAM included. Says
    /// nothing about the peer's half — the stream is half-closed(local), and
    /// §5.1 still lets the peer send its body.
    no_more_output: Cell<bool>,
    input: RefCell<Option<InputData>>,
    /// Body bytes taken so far, padding excluded. Doubles as the write cursor
    /// of a pre-allocated buffer.
    received: Cell<u64>,
    /// Body bytes taken from the connection window and not yet consumed by
    /// the task — still holding credit. Whatever is left when the stream
    /// goes must be given back, or the connection window shrinks for good.
    unreleased: Cell<u32>,
    window: StreamWindow,
    waker: RefCell<Option<Waker>>,
}

impl Stream {
    /// `settings` are the peer's: they credit the send window.
    pub fn create(settings: &Settings, header: Box<Headers>) -> Result<Self, StreamViolation> {
        let content_length =
            content_length(&header).map_err(|()| StreamViolation::MalformedRequest)?;

        // END_STREAM already on the request: the stream is born
        // half-closed(remote).
        let end_stream = header.is_end_stream();

        // §8.1.1: with END_STREAM on the HEADERS no DATA can follow, so a
        // declared length that is not zero already fails to add up.
        if end_stream && content_length.is_some_and(|len| len != 0) {
            return Err(StreamViolation::ContentLengthMismatch);
        }

        // Nothing is allocated for a request that cannot carry a body, nor
        // for one that declares an empty one.
        let input = match content_length {
            _ if end_stream => None,
            Some(0) => None,
            declared => Some(InputData::new(declared)),
        };

        Ok(Self {
            window: StreamWindow::from(settings),
            header,
            trailers: Cell::new(None),
            no_more_input: Cell::new(end_stream),
            no_more_output: Cell::new(false),
            input: RefCell::new(input),
            received: Cell::new(0),
            unreleased: Cell::new(0),
            waker: RefCell::new(None),
        })
    }

    /// A WINDOW_UPDATE on this stream. The task may be waiting on exactly
    /// this, so it is woken; it re-checks the window itself.
    pub fn credit_send(&self, increment: u32) -> Result<(), ()> {
        self.window.credit_send(increment)?;
        self.wake();
        Ok(())
    }

    /// §6.9.2: the peer's initial window changed. Woken only when the change
    /// opens room — a shrink has nothing to offer a waiting task.
    pub fn adjust_send(&self, delta: i32) -> Result<(), ()> {
        self.window.adjust_send(delta)?;
        if delta > 0 {
            self.wake();
        }
        Ok(())
    }

    /// What a DATA frame may still spend on this stream.
    pub fn available_send(&self) -> u32 {
        self.window.available_send()
    }

    /// Debits the send window for a DATA frame of ours. `Err` is the peer's
    /// credit running short, with nothing debited.
    pub fn debit_send(&self, len: u32) -> Result<(), ()> {
        self.window.debit_send(len)
    }

    /// The task parks here, on whatever it waits for — body bytes, a
    /// WINDOW_UPDATE. One slot: a stream has one task, and that task waits
    /// on one thing at a time. Whoever wakes it, it re-checks its condition.
    pub fn register_waker(&self, waker: &Waker) {
        let mut slot = self.waker.borrow_mut();
        if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }

    /// Debits the receive window. Split from `recv_data` because an overrun
    /// here is a connection error, not a stream one.
    pub fn recv_window(&self, padded_len: u32) -> Result<(), ()> {
        self.window.recv(padded_len)
    }

    /// Connection credit this stream still holds, zeroed on the way out so
    /// it can only be given back once.
    pub fn take_unreleased(&self) -> u32 {
        self.unreleased.replace(0)
    }

    /// The task has written its whole response. Only our half: the stream
    /// leaves the map once the peer's half is closed too.
    pub fn end_output(&self) {
        self.no_more_output.set(true);
    }

    /// Both halves done — what the sweep retires. A task that answered
    /// before the peer finished sending keeps the stream here until its
    /// END_STREAM, or a reset, arrives; §8.1 lets us hurry that along with
    /// a RST_STREAM(NO_ERROR) after a complete response, later.
    pub fn is_closed(&self) -> bool {
        self.no_more_output.get() && self.no_more_input.get()
    }

    /// Takes the second and last HEADERS of a request (§8.1). Ends the input
    /// exactly as END_STREAM on DATA does, with the same final check.
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
        let declared = self.input.borrow().as_ref().and_then(InputData::expected);
        if declared.is_some_and(|declared| self.received.get() != declared) {
            return Err(StreamViolation::ContentLengthMismatch);
        }

        self.trailers.set(Some(headers));
        self.no_more_input.set(true);
        self.wake();
        Ok(())
    }

    /// The trailers, once and only once — the task's to take after the body.
    pub fn take_trailers(&self) -> Option<Box<Headers>> {
        self.trailers.take()
    }

    /// Which of the two body contracts this request falls under, decided by
    /// its `content-length` when the stream was created: `true` for the one
    /// delivered whole by [`Stream::body`], `false` for the one drained
    /// through [`Stream::readable`], [`Stream::peek`] and
    /// [`Stream::consume`]. A request with no body counts as the first, and
    /// `body` answers `None` for it.
    pub fn body_is_oneshot(&self) -> bool {
        self.input
            .borrow()
            .as_ref()
            .is_none_or(|input| !input.wakes_per_frame())
    }

    /// The whole body, once it is whole.
    ///
    /// Resolves at END_STREAM and not before — nothing is handed over in
    /// pieces, so no credit is handed back in pieces either, and the peer
    /// gets no WINDOW_UPDATE until the stream retires. That is what bounds
    /// this form: `BUFFER_ONESHOT_LIMIT` is small enough that every stream
    /// accumulating at once still fits in the connection window, which is
    /// the static assertion in `input_data`.
    ///
    /// `None` when the request carried no body, or when it is large enough
    /// that it has to be drained instead — [`Stream::body_is_oneshot`] is
    /// what tells the two apart beforehand.
    pub fn body(&self) -> impl Future<Output = Option<Box<[u8]>>> {
        std::future::poll_fn(move |cx| {
            // Incomplete: the peer's half is still open, so more is coming.
            if !self.no_more_input.get() {
                self.register_waker(cx.waker());
                return Poll::Pending;
            }
            Poll::Ready(
                self.input
                    .borrow_mut()
                    .take()
                    .and_then(InputData::into_oneshot),
            )
        })
    }

    /// Waits until the body has bytes to take, or has ended.
    ///
    /// `false` is the end: the peer's half is closed and the buffer is
    /// drained, so no further [`Stream::peek`] will ever show anything. A
    /// body that ended with bytes still buffered answers `true` until they
    /// are consumed.
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

    /// Shows what is buffered without consuming it. The slice borrows the
    /// stream's buffer, hence the closure: nothing may hold it across the
    /// `await` that would let the connection push more in.
    pub fn peek<R>(&self, with: impl FnOnce(&[u8]) -> R) -> R {
        let input = self.input.borrow();
        with(input.as_ref().map_or(&[][..], InputData::available))
    }

    /// Takes the `n` leading bytes the handler is done with, and says how
    /// many that was — `n` clamped to what is actually there.
    ///
    /// Only the bookkeeping: the credit those bytes were holding is now owed
    /// back to the peer, and `SharedConnection::consume` is what turns it
    /// into WINDOW_UPDATE frames, being the half that can write.
    pub fn consume(&self, n: usize) -> u32 {
        let mut input = self.input.borrow_mut();
        let Some(input) = input.as_mut() else {
            return 0;
        };
        let n = n.min(input.available().len());
        input.consume(n);
        // Held credit, so bounded by the receive window and by `unreleased`
        // itself, which counts the same bytes.
        self.unreleased.set(self.unreleased.get() - n as u32);
        n as u32
    }

    /// Credit owed back to the peer on *this stream* for consumed bytes.
    /// `Some` is the amount to announce, already credited here, so the
    /// caller must write the frame that carries it.
    #[must_use]
    pub fn release_recv(&self, len: u32) -> Option<u32> {
        self.window.release_recv(len)
    }

    fn available_len(&self) -> usize {
        self.input
            .borrow()
            .as_ref()
            .map_or(0, |input| input.available().len())
    }

    /// Takes one DATA payload, already stripped of its padding.
    ///
    /// The length that matters here is `payload.len()`, never the padded one:
    /// flow control accounts for padding, `content-length` does not.
    pub fn recv_data(&self, payload: &[u8], end_stream: bool) -> Result<(), StreamViolation> {
        if self.no_more_input.get() {
            return Err(StreamViolation::DataAfterEndStream);
        }

        let mut input = self.input.borrow_mut();
        let Some(input) = input.as_mut() else {
            // No buffer at all means a declared length of zero, so any byte
            // is already one too many (§8.1.1).
            if !payload.is_empty() {
                return Err(StreamViolation::ContentLengthMismatch);
            }
            if end_stream {
                self.no_more_input.set(true);
                self.wake();
            }
            return Ok(());
        };

        // §8.1.1: exceeding the declared length is an error as soon as it
        // happens — no reason to take the rest of the body first.
        let at = self.received.get();
        let received = at + payload.len() as u64;
        if input.expected().is_some_and(|declared| received > declared) {
            return Err(StreamViolation::ContentLengthMismatch);
        }

        input.push(at, payload);
        self.received.set(received);
        // Bounded by the receive window, so it cannot outgrow a u32.
        self.unreleased
            .set(self.unreleased.get() + payload.len() as u32);

        if end_stream {
            // §8.1.1: and the body must add up to exactly what was declared.
            if input
                .expected()
                .is_some_and(|declared| received != declared)
            {
                return Err(StreamViolation::ContentLengthMismatch);
            }
            self.no_more_input.set(true);
        }

        // A body held whole is worth waking for only once; a drained one has
        // something to take on every frame.
        if end_stream || input.wakes_per_frame() {
            self.wake();
        }
        Ok(())
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}

/// The declared body length, or `None` when the request declared none.
///
/// RFC 9110 §8.6 gives `content-length` the grammar `1*DIGIT` with no upper
/// bound, and requires recipients to anticipate numerals too large to convert
/// — hence the checked accumulation rather than a parse that could wrap. A
/// repeated field is legal only if every value agrees.
fn content_length(headers: &Headers) -> Result<Option<u64>, ()> {
    let mut declared: Option<u64> = None;

    for value in headers.fields().get_all(header::CONTENT_LENGTH) {
        let digits = value.as_bytes();
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(());
        }

        let mut len: u64 = 0;
        for digit in digits {
            len = len
                .checked_mul(10)
                .and_then(|n| n.checked_add((digit - b'0') as u64))
                .ok_or(())?;
        }

        if declared.is_some_and(|first| first != len) {
            return Err(());
        }
        declared = Some(len);
    }

    Ok(declared)
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
