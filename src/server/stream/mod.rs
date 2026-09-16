use std::cell::{Cell, RefCell};
use std::task::Waker;

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
pub struct Stream {
    header: Box<Headers>,
    state: Cell<StreamState>,
    input: RefCell<Option<InputData>>,
    /// Body bytes taken so far, padding excluded. Doubles as the write cursor
    /// of a pre-allocated buffer.
    received: Cell<u64>,
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
            state: Cell::new(if end_stream {
                StreamState::InputClosed
            } else {
                StreamState::Normal
            }),
            input: RefCell::new(input),
            received: Cell::new(0),
            waker: RefCell::new(None),
        })
    }

    pub fn credit_send(&self, increment: u32) -> Result<(), ()> {
        self.window.credit_send(increment)
    }

    /// Debits the receive window. Split from `recv_data` because an overrun
    /// here is a connection error, not a stream one.
    pub fn recv_window(&self, padded_len: u32) -> Result<(), ()> {
        self.window.recv(padded_len)
    }

    /// Takes one DATA payload, already stripped of its padding.
    ///
    /// The length that matters here is `payload.len()`, never the padded one:
    /// flow control accounts for padding, `content-length` does not.
    pub fn recv_data(&self, payload: &[u8], end_stream: bool) -> Result<(), StreamViolation> {
        // §5.1: END_STREAM closed the peer's half; anything after it is a
        // frame on a stream that, from its side, no longer exists.
        if self.state.get() == StreamState::InputClosed {
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
                self.state.set(StreamState::InputClosed);
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

        if end_stream {
            // §8.1.1: and the body must add up to exactly what was declared.
            if input
                .expected()
                .is_some_and(|declared| received != declared)
            {
                return Err(StreamViolation::ContentLengthMismatch);
            }
            self.state.set(StreamState::InputClosed);
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StreamState {
    Normal,
    InputClosed,
}
