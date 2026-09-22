use std::cell::{Cell, RefCell};
use std::task::{Poll, Waker};
use std::time::{Duration, SystemTime};

use http::header;

use http::StatusCode;

use crate::server::connection::shared_with_streams::StreamToken;
use crate::shared::codec::frames::stream_id::StreamId;
#[cfg(feature = "grpc")]
use crate::grpc::{GrpcError, GrpcFormat, GrpcFrame, GrpcInput};
use crate::{
    server::stream::input_data::InputData,
    shared::{
        codec::{frames::headers::Headers, types::StreamViolation},
        connection::{settings::Settings, stream_window::StreamWindow},
    },
};

mod input_data;

/// Where a request's body lands, chosen once, at HEADERS.
///
/// Two types and not one with more variants: an HTTP body and a gRPC one have
/// different contracts with the stream task — what is delivered, when the task
/// is woken, when credit goes back — and nothing of [`InputData`] had to
/// change for the other to exist.
enum Input {
    /// END_STREAM on the HEADERS, or a declared length of zero.
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

/// How long a body is given before its rate is judged at all.
///
/// Covers the first round trip and the handler's first poll, so a stream is
/// never failed for the time it took to get started. Five seconds is far more
/// than either needs and costs an attacker five seconds a stream, which is not
/// a budget worth having.
const BODY_GRACE: Duration = Duration::from_secs(5);

/// Bytes per second below which a request body is not slow but held.
///
/// This is a floor, not a service level, and it is set where it is because the
/// honest slow case has to pass it comfortably: 256 B/s is about a fortieth of
/// a 2G link, so any peer actually sending a body clears it by orders of
/// magnitude. What it does not clear is the attack, which sends one byte per
/// frame and per minute to hold a stream open for nothing.
///
/// Read with `BODY_GRACE`, this is what a peer must have sent by the time it
/// is first judged: 1280 bytes at five seconds.
const MIN_BODY_RATE: u64 = 256;

/// How long a response may have waited on the peer's credit, in total, before
/// its rate is judged.
///
/// Time spent waiting for credit and not time since the first byte, which is
/// the difference between judging the peer and judging ourselves: a handler
/// thinks before its first byte and may think between any two after it — an
/// event stream is mostly that — and a clock that ran through those pauses
/// would fail the stream whenever the *handler* was slow. There is no
/// equivalent dead time inbound, which is why [`BODY_GRACE`] can start where
/// it does.
const SEND_GRACE: Duration = Duration::from_secs(5);

/// Bytes per second below which a peer is not receiving a response, it is
/// holding one.
///
/// Set against the same reasoning as [`MIN_BODY_RATE`] and with the same
/// caveat: a floor on how fast we will serve is a service level, not an abuse
/// signal, because nothing at this layer can tell a phone on a bad train line
/// from an attacker — both advertise small windows and drain slowly. So it is
/// pitched as an insult rather than a threshold. The attack it answers credits
/// a byte at a time; 256 B/s is thousands of times more than that and far
/// below anything a real client sustains.
const MIN_SEND_RATE: u64 = 256;

/// Reached only through an `Rc` shared with the stream task, so everything the
/// connection mutates while a frame is being decoded lives behind a `Cell`.
///
/// A stream has two halves that close independently (§5.1): the peer's, by
/// its END_STREAM on DATA or trailers, and ours, by the END_STREAM of our
/// response. `no_more_input` and `no_more_output` track them one each; both
/// set is the closed state that lets the connection take the stream out of
/// its map.
pub struct StreamState {
    /// When the peer's HEADERS opened this stream.
    ///
    /// The runtime's clock, not the OS's: the event loop samples
    /// `SystemTime::now()` once per scheduler pass and the timewheel keeps
    /// it, so every stream opened in that pass reads the same cached value
    /// and opening one costs no clock call of its own. Fresh to within a
    /// pass, which is finer than anything a stream deadline cares about.
    created_at: SystemTime,
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
    input: RefCell<Input>,
    /// What the request's `content-type` made of it, body or no body: a gRPC
    /// call that sends no message is still one, and is answered as one.
    #[cfg(feature = "grpc")]
    grpc: Option<GrpcFormat>,
    /// Body bytes taken so far, padding excluded. Doubles as the write cursor
    /// of a pre-allocated buffer.
    received: Cell<u64>,
    /// Response body bytes handed to the peer.
    ///
    /// Counted where `write_data` writes a frame, which is the point the peer
    /// controls: that loop only advances by what the stream and connection
    /// windows have credited, so this measures the peer's pace and not ours.
    sent: Cell<u64>,
    /// Since when the writer has been parked with no credit from the peer, or
    /// `None` while it is not.
    send_blocked_since: Cell<Option<SystemTime>>,
    /// Every such wait already over, added up.
    ///
    /// With the one above, the clock [`Stream::output_is_starving`] runs on:
    /// only time the peer made us wait. A handler that has produced nothing,
    /// or is between two writes, accrues none and is never judged.
    send_blocked: Cell<Duration>,
    /// Body bytes taken from the connection window and not yet consumed by
    /// the task — still holding credit. Whatever is left when the stream
    /// goes must be given back, or the connection window shrinks for good.
    unreleased: Cell<u32>,
    /// A response head has been written. Not the same as `no_more_output`,
    /// which the token sets on the way out whether or not anything was said:
    /// this is what tells a handler that returned in silence from one that
    /// answered.
    responded: Cell<bool>,
    /// This stream is out of the connection's live table: it finished and was
    /// retired, or the peer reset it, or the connection is going down. Either
    /// way nothing its task writes from here reaches anyone.
    ///
    /// The fact belongs here rather than in the table's membership, which is
    /// where it used to be read from. Whether it is still in that table is the
    /// one thing a stream's own task cannot otherwise know — and asking cost a
    /// `Weak::upgrade`, a hash lookup and an `Rc` round trip on every request,
    /// to answer a question only a cancelled stream ever asks. It measured 3%.
    retired: Cell<bool>,
    window: StreamWindow,
    waker: RefCell<Option<Waker>>,
}

impl StreamState {
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

        // Read whether or not a body follows: a gRPC call that sends no
        // message is still one, and is answered as one.
        #[cfg(feature = "grpc")]
        let grpc = GrpcFormat::of(&header);

        // Nothing is allocated for a request that cannot carry a body, nor
        // for one that declares an empty one. For the others, all there is to
        // go on is the HEADERS.
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
            window: StreamWindow::from(settings),
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

    /// When this stream was opened.
    pub fn created_at(&self) -> SystemTime {
        self.created_at
    }

    /// How long this stream has been open, read off the same cached clock.
    ///
    /// That clock is the wall clock, so it can step backwards under NTP; an
    /// age that would come out negative reads as zero instead. Nothing that
    /// asks a stream its age — a deadline, a slow-request counter — is worth
    /// failing a request over a clock adjustment.
    pub fn age(&self) -> Duration {
        runtime::runtime::now()
            .duration_since(self.created_at)
            .unwrap_or_default()
    }

    /// Whether this stream's body is arriving too slowly to be a body.
    ///
    /// A rate and not a deadline, because a deadline cannot tell a large
    /// upload from a slow one: 100 MB legitimately takes longer than 1 KB, and
    /// any single duration that lets the first through lets a peer hold a
    /// stream for exactly that long with one byte. Bytes over age says the
    /// same thing about both.
    ///
    /// Nothing is judged before `BODY_GRACE`. A stream milliseconds old has no
    /// meaningful rate — the first DATA frame of a perfectly healthy upload
    /// arrives when it arrives — and dividing by an age near zero is how a
    /// defence starts killing the requests it exists to protect.
    ///
    /// `age` is measured from the stream opening, not from the last frame, so
    /// this is an average and not an instantaneous rate: a peer cannot bank
    /// credit by starting fast and then stalling, which is what a
    /// since-last-frame measure would allow. It also means the clock runs
    /// while a handler is thinking, which is why the rate has to be set low
    /// enough to be an insult rather than a service level.
    ///
    /// Fails open on a clock that stepped backwards: [`Stream::age`] floors at
    /// zero, so the comparison reads as infinitely fast rather than as a
    /// stalled peer.
    pub fn body_is_starving(&self) -> bool {
        // END_STREAM came: the peer owes nothing more, so whatever time
        // passes from here is the handler's. The sweep asks every live
        // stream, and a GET is one whose body ended with its HEADERS.
        if self.no_more_input.get() {
            return false;
        }
        let age = self.age();
        if age < BODY_GRACE {
            return false;
        }
        // Multiply rather than divide: `age` is at least `BODY_GRACE` here, so
        // there is no division by zero to guard, and no rounding to argue
        // about.
        let owed = MIN_BODY_RATE.saturating_mul(age.as_secs());
        self.received.get() < owed
    }

    /// The id the peer opened this stream with.
    pub fn id(&self) -> crate::shared::codec::frames::stream_id::StreamId {
        self.header.stream_id()
    }

    /// The request's `:path`.
    pub fn path(&self) -> Option<&str> {
        self.header.pseudo().path.as_deref()
    }

    /// The request's `:method`.
    pub fn method(&self) -> Option<&http::Method> {
        self.header.pseudo().method.as_ref()
    }

    /// Its ordinary fields, pseudo-headers excluded — those are `method`,
    /// `path` and their neighbours (§8.3).
    pub fn fields(&self) -> &http::HeaderMap {
        self.header.fields()
    }

    /// Whether a response head has gone out for this stream.
    pub fn has_responded(&self) -> bool {
        self.responded.get()
    }

    pub fn note_responded(&self) {
        self.responded.set(true);
    }

    /// Whether this stream is out of the connection's live table.
    pub fn is_retired(&self) -> bool {
        self.retired.get()
    }

    /// Called by whoever takes it out, which is the connection and never the
    /// stream's own task.
    pub fn note_retired(&self) {
        self.retired.set(true);
    }

    /// Records `n` response body bytes as having gone to the peer, which
    /// ends whatever wait for credit came before them.
    pub fn note_sent(&self, n: usize) {
        if let Some(since) = self.send_blocked_since.take() {
            self.send_blocked
                .set(self.send_blocked.get() + elapsed_since(since));
        }
        self.sent.set(self.sent.get() + n as u64);
    }

    /// The writer found no credit and is about to park on it.
    fn note_send_blocked(&self) {
        if self.send_blocked_since.get().is_none() {
            self.send_blocked_since
                .set(Some(runtime::runtime::now()));
        }
    }

    /// Whether the peer is taking its response too slowly to be receiving it.
    ///
    /// The mirror of [`Stream::body_is_starving`], and it has to exist
    /// separately because the two measure opposite directions: `received`
    /// counts what arrives, and a peer that metes out a response with
    /// one-byte WINDOW_UPDATEs sends us nothing to count.
    ///
    /// The rate is bytes over the time spent *waiting for the peer's credit*,
    /// not over the life of the response — see [`SEND_GRACE`]. A peer that
    /// credits a byte at a time keeps the writer parked between every two
    /// bytes, so nearly all of its elapsed time counts; a handler pacing its
    /// own output to a peer with credit to spare counts none.
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

    /// Our half is done. Called by the stream's `StreamToken` on the way
    /// out, so it happens however the task ends — returning, reset, or going
    /// down with its connection. Only our half: the stream leaves the map
    /// once the peer's is closed too.
    pub fn end_output(&self) {
        self.no_more_output.set(true);
    }

    /// Receive window this stream wants beyond §6.9.2's 65535, `None` for one
    /// that is content with it.
    ///
    /// Asked once, when the stream opens, and answered by what its body is: an
    /// HTTP body is drained as it arrives and never needs more, a gRPC one is
    /// delivered a whole message at a time and cannot take a message larger
    /// than the window in one go.
    ///
    /// Reported rather than acted on, the stream having no way to write a
    /// frame. Whoever asks must write the WINDOW_UPDATE it is handed.
    #[must_use]
    pub fn window_wanted(&self) -> Option<u32> {
        #[cfg(feature = "grpc")]
        if matches!(*self.input.borrow(), Input::Grpc(_)) {
            let wanted = (GrpcInput::MESSAGE_LIMIT + 5) as u32;
            return wanted
                .checked_sub(crate::shared::connection::stream_window::LOCAL_INITIAL_WINDOW_SIZE)
                .filter(|more| *more > 0)
                .inspect(|more| self.window.grant_recv(*more));
        }
        None
    }

    /// Whether the peer's half is done: its END_STREAM came, or we stopped
    /// expecting one.
    pub fn input_ended(&self) -> bool {
        self.no_more_input.get()
    }

    /// Whether our END_STREAM has gone out: on the head of a response with no
    /// body, on the last of its DATA, or on its trailers.
    pub fn output_ended(&self) -> bool {
        self.no_more_output.get()
    }

    /// Stops expecting anything more from the peer, for a stream we have just
    /// reset: a RST_STREAM closes both halves at once (§5.1), and whatever of
    /// the body is still in flight lands on a stream that is gone.
    pub fn abandon_input(&self) {
        self.no_more_input.set(true);
    }

    /// Both halves done, which is what lets the connection remove the
    /// stream. A task that answered before the peer finished sending keeps
    /// the stream in the map until its END_STREAM, or a reset, arrives;
    /// §8.1 lets us hurry that along with a RST_STREAM(NO_ERROR) after a
    /// complete response, later.
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
        let declared = match &*self.input.borrow() {
            Input::None => None,
            Input::Http(input) => input.expected(),
            #[cfg(feature = "grpc")]
            Input::Grpc(input) => input.declared(),
        };
        if declared.is_some_and(|declared| self.received.get() != declared) {
            return Err(StreamViolation::ContentLengthMismatch);
        }
        // A gRPC client sends no trailers, but one that did has ended its
        // body all the same, and between two messages or not.
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
            .http()
            .is_none_or(|input| !input.wakes_per_frame())
    }

    /// Whether this request is gRPC, and its body therefore a sequence of
    /// messages taken through [`Stream::message`] rather than a body.
    #[cfg(feature = "grpc")]
    pub fn is_grpc(&self) -> bool {
        self.grpc.is_some()
    }

    /// What a gRPC request's messages are serialised as, `None` when the
    /// request is not gRPC.
    #[cfg(feature = "grpc")]
    pub fn grpc_format(&self) -> Option<GrpcFormat> {
        self.grpc
    }

    /// The whole body, once it is whole.
    ///
    /// Resolves at END_STREAM and not before — nothing is handed over in
    /// pieces, so no credit is handed back in pieces either, and the peer
    /// gets no WINDOW_UPDATE until the stream retires. That is what bounds
    /// this form: `InputData::ONESHOT_LIMIT` is small enough that every stream
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
        with(input.http().map_or(&[][..], InputData::available))
    }

    /// Takes the `n` leading bytes the handler is done with, and says how
    /// many that was — `n` clamped to what is actually there.
    ///
    /// Only the bookkeeping: the credit those bytes were holding is now owed
    /// back to the peer, and `SharedConnection::consume` is what turns it
    /// into WINDOW_UPDATE frames, being the half that can write.
    pub fn consume(&self, n: usize) -> u32 {
        let mut input = self.input.borrow_mut();
        let Some(input) = input.http_mut() else {
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
            .http()
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

        // §8.1.1 again: exceeding the declared length is an error as soon as
        // it happens — no reason to take the rest of the body first. Whether a
        // payload fits is for what holds the body to say, and `push` is where
        // an HTTP body says it.
        let wake = match &mut *input {
            // No buffer at all is a declared length of zero, so any byte is
            // one too many.
            Input::None if !payload.is_empty() => {
                return Err(StreamViolation::ContentLengthMismatch);
            }
            Input::None => end_stream,
            Input::Http(input) => {
                input
                    .push(at, payload)
                    .map_err(|_| StreamViolation::ContentLengthMismatch)?;
                // A body held whole is worth waking for only once; a drained
                // one has something to take on every frame.
                end_stream || input.wakes_per_frame()
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
                wake || end_stream
            }
        };

        // Only now: a payload that was refused never landed. Whatever holds
        // it, it holds connection credit until a handler takes it — bounded
        // by the receive window, so it cannot outgrow a u32.
        self.received.set(received);
        self.unreleased
            .set(self.unreleased.get() + payload.len() as u32);
        if end_stream {
            self.no_more_input.set(true);
        }
        if wake {
            self.wake();
        }
        Ok(())
    }

    /// The next gRPC message, once it is whole.
    ///
    /// `None` is the end: the peer's END_STREAM came and every message has
    /// been taken — or the request is not gRPC. `Some(Err(_))` is a body that
    /// stopped being gRPC, told once, after whatever was whole before it.
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

    /// Lets go of the credit a taken gRPC message was holding, `len` being
    /// what it took on the wire. The connection's is the caller's to hand
    /// back; `Some` is the stream's, to announce.
    ///
    /// At once rather than accumulated, unlike [`release_recv`]: the next
    /// message may need the whole window to fit, and credit held back below a
    /// threshold is credit its sender waits for while we wait for the message.
    ///
    /// [`release_recv`]: Self::release_recv
    #[cfg(feature = "grpc")]
    #[must_use]
    pub fn release_message(&self, len: u32) -> Option<u32> {
        self.unreleased.set(self.unreleased.get() - len);
        self.window.release_recv_now(len)
    }

    fn wake(&self) {
        if let Some(waker) = self.waker.borrow_mut().take() {
            waker.wake();
        }
    }
}

/// One request, and the response owed for it: what a handler is handed.
///
/// The mirror of the client's [`Stream`](crate::client::Stream), and owned the
/// same way — it is the handler's for as long as the handler runs, and
/// dropping it is what ends the server's half of the exchange (§5.1). A
/// handler that returns without answering gets a `500` written for it, because
/// the alternative is a peer waiting for a response that will never come.
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

    /// §5.1.1: the id the peer opened this stream with. Odd, since a client
    /// opens it.
    pub fn id(&self) -> StreamId {
        self.token.id()
    }

    /// The request's `:method`.
    pub fn method(&self) -> Option<&http::Method> {
        self.state().method()
    }

    /// The request's `:path`.
    pub fn path(&self) -> Option<&str> {
        self.state().path()
    }

    /// The request's ordinary fields.
    pub fn fields(&self) -> &http::HeaderMap {
        self.state().fields()
    }

    /// Which body contract this request falls under, decided by its
    /// `content-length` when the stream was created: `true` for one delivered
    /// whole by [`Stream::body`], `false` for one drained through
    /// [`Stream::readable`], [`Stream::peek`] and [`Stream::consume`].
    pub fn body_is_oneshot(&self) -> bool {
        self.state().body_is_oneshot()
    }

    /// The whole body, once it is whole. `None` when the request carried none,
    /// or when it is large enough that it has to be drained instead.
    pub fn body(&self) -> impl Future<Output = Option<Box<[u8]>>> {
        self.state().body()
    }

    /// Waits until the body has bytes to take, or has ended. `false` is the
    /// end.
    pub fn readable(&self) -> impl Future<Output = bool> {
        self.state().readable()
    }

    /// Shows what is buffered without consuming it. The slice borrows the
    /// stream's buffer, hence the closure: nothing may hold it across the
    /// `await` that would let the connection push more in.
    pub fn peek<R>(&self, with: impl FnOnce(&[u8]) -> R) -> R {
        self.state().peek(with)
    }

    /// Takes the `n` leading bytes the handler is done with, and hands the
    /// peer back the credit they were holding (§6.9.1). A handler that stops
    /// consuming is a handler that stops the upload, which is the point.
    pub fn consume(&self, n: usize) {
        self.token.shared().consume(self.id(), self.state(), n);
    }

    /// Whether the request is gRPC: a POST with `content-type:
    /// application/grpc`, whether or not it carries a body — one that ends on
    /// its HEADERS is a call with no message, and still a call. Its body is a
    /// sequence of messages, taken through [`message`](Self::message); the
    /// body accessors answer as they do for a request that has none.
    #[cfg(feature = "grpc")]
    pub fn is_grpc(&self) -> bool {
        self.state().is_grpc()
    }

    /// What the request's messages are serialised as — `+proto`, `+json` —
    /// known from its HEADERS, before any message. `None` when the request is
    /// not gRPC.
    #[cfg(feature = "grpc")]
    pub fn grpc_format(&self) -> Option<GrpcFormat> {
        self.state().grpc_format()
    }

    /// The next gRPC message, whole: a [`GrpcFrame`], whose two variants are
    /// what the prefix's Compressed-Flag said. Only the uncompressed one hands
    /// out its bytes; the compressed one knows its encoding and converts.
    ///
    /// `None` is the peer's half-close with nothing left to take. A unary
    /// handler calls this once and expects `None` from a second call; a
    /// client-streaming one loops. `Some(Err(_))` is a body that stopped
    /// being gRPC — a message over the limit, a bad flag, an END_STREAM in the
    /// middle of one — for the handler to answer with a `grpc-status`.
    ///
    /// Taking a message is what gives the peer the credit to send the next.
    #[cfg(feature = "grpc")]
    pub async fn message(&self) -> Option<Result<GrpcFrame, GrpcError>> {
        let taken = self.state().message().await;
        // Nothing to credit a peer that has finished sending, and a unary
        // call — most calls — is one message and a half-close, so the frame
        // would go out on every one of them for nothing. What the message
        // held of the connection window goes back where an HTTP body's does,
        // when the stream retires.
        if let Some(Ok(frame)) = &taken
            && !self.state().input_ended()
        {
            self.token
                .shared()
                .release_message(self.id(), self.state(), frame.wire_len() as u32);
        }
        taken
    }

    /// §8.1: the trailers, if the request carried any. `None` until the body
    /// has ended, since that is what a trailer section follows.
    pub fn trailers(&self) -> Option<http::HeaderMap> {
        self.state()
            .take_trailers()
            .map(|headers| (*headers).into_fields())
    }

    /// Writes the response head, with more of the response to follow. §8.3
    /// puts `:status` before every ordinary field, which is done here rather
    /// than asked of the caller.
    ///
    /// The body follows through [`write_data`](Self::write_data), and calling
    /// that first would put DATA on a stream the peer has had no head for. A
    /// response that is its head and nothing else is
    /// [`write_headers_final`](Self::write_headers_final).
    ///
    /// None of the writers takes an `end_stream` flag. What ends a response is
    /// a method that takes the stream with it — `write_headers_final`,
    /// [`write_data_final`](Self::write_data_final),
    /// [`write_trailers`](Self::write_trailers) — so that writing after the
    /// end is a compile error rather than a frame on a closed stream, and so
    /// that the end is something a handler has to say. One that returns
    /// without saying it has its stream reset, since the peer would otherwise
    /// wait for the rest of a response that is not coming.
    pub fn write_headers(&self, status: StatusCode, fields: &http::HeaderMap) {
        self.token
            .shared()
            .write_response(self.id(), status, fields, false);
        self.state().note_responded();
    }

    /// The whole response in its head: `status`, `fields`, END_STREAM.
    ///
    /// What a gRPC server calls Trailers-Only, with `grpc-status` among the
    /// fields.
    pub fn write_headers_final(self, status: StatusCode, fields: &http::HeaderMap) {
        self.token
            .shared()
            .write_response(self.id(), status, fields, true);
        self.state().note_responded();
        self.state().end_output();
    }

    /// Writes the next of the response body, with more to follow — or
    /// trailers.
    ///
    /// §6.9.1: cut into DATA frames by what the stream's send window, the
    /// connection's and the peer's `max_frame_size` allow, and by the room
    /// left in the output. With none of it this waits, so a body larger than
    /// the peer will take does not have to be held anywhere but where the
    /// caller already has it.
    pub async fn write_data(&self, data: &[u8]) {
        self.token
            .shared()
            .write_data(self.id(), self.state(), data, false)
            .await;
    }

    /// Writes one gRPC message: its five-byte prefix, then the message
    /// encoded as protobuf.
    ///
    /// No `_final` to go with it, and none is missing. A gRPC response ends
    /// with its trailers and never with END_STREAM on a DATA frame, so every
    /// message a handler writes has something after it —
    /// [`write_trailers`](Self::write_trailers) at the very least, carrying
    /// the `grpc-status`.
    ///
    /// Protobuf, whatever the request's [`grpc_format`](Self::grpc_format)
    /// said, and unlike [`decode`] this does not refuse: those are the
    /// handler's own bytes and it picked the method, where a request's bytes
    /// are the peer's and reading them as the wrong thing is a correctness
    /// question. Serving `+json` means framing it with
    /// [`write_data`](Self::write_data) instead — `grpc::frame_message` is
    /// what this one uses.
    ///
    /// [`decode`]: crate::grpc::UncompressedGrpcFrame::decode
    #[cfg(feature = "grpc")]
    pub async fn write_message<M: prost::Message>(&self, message: &M) {
        self.write_data(&crate::grpc::frame_message(message)).await;
    }

    /// Writes the last of the response body, END_STREAM on its last frame.
    pub async fn write_data_final(self, data: &[u8]) {
        self.token
            .shared()
            .write_data(self.id(), self.state(), data, true)
            .await;
        // After the await and not before: a write that is dropped half way
        // never wrote the frame that carries the flag.
        self.state().end_output();
    }

    /// Ends the response with a trailer section (§8.1): a last HEADERS frame,
    /// after the body, carrying END_STREAM.
    ///
    /// For what is only known once the body has been produced — gRPC puts the
    /// outcome of the whole call there, as `grpc-status`.
    ///
    /// `fields` are ordinary fields only, which the type already guarantees —
    /// a `HeaderName` cannot start with `:`, and §8.1 allows no pseudo-header
    /// here.
    ///
    /// Does nothing on a stream with no response head yet: trailers the peer
    /// has had no head for are a malformed response. That leaves the handler
    /// having answered nothing, and it gets the `500` that is owed for that.
    pub fn write_trailers(self, fields: &http::HeaderMap) {
        let state = self.state();
        if !state.has_responded() || state.is_retired() {
            return;
        }
        self.token.shared().write_trailers(self.id(), fields);
        state.end_output();
    }
}

/// What [`SharedConnection::write_data`] needs of a stream: the send window,
/// and where to park a writer that has run out of it.
///
/// One waker slot serves both directions here, which is sound because a
/// server stream has one task and that task waits on one thing at a time —
/// either for body bytes to arrive or for credit to write with, never both.
///
/// [`SharedConnection::write_data`]: crate::shared::connection::SharedConnection::write_data
impl crate::shared::connection::SendSide for StreamState {
    fn available_send(&self) -> u32 {
        self.available_send()
    }

    fn debit_send(&self, len: u32) -> Result<(), ()> {
        self.debit_send(len)
    }

    /// Only ever called for want of credit — a full output parks elsewhere —
    /// so this is also where the wait on the peer starts being timed.
    fn register_send_waker(&self, waker: &Waker) {
        self.note_send_blocked();
        self.register_waker(waker);
    }

    fn note_sent(&self, n: usize) {
        self.note_sent(n);
    }
}

/// Floors at zero on a clock that stepped backwards, as [`StreamState::age`]
/// does.
fn elapsed_since(since: SystemTime) -> Duration {
    runtime::runtime::now()
        .duration_since(since)
        .unwrap_or_default()
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
