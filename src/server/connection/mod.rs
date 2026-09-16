use std::rc::Rc;

use crate::server::connection::settings::Settings;
use crate::server::{STREAM_ID, connection::shared_with_streams::SharedConnection, stream::Stream};
use crate::shared::codec::{
    frames::{FrameHandler, FrameKind, SettingsIter, headers::Headers, stream_id::StreamId},
    types::{
        DecodeError, ErrorScope, FLOW_CONTROL_ERROR, PROTOCOL_ERROR, REFUSED_STREAM, STREAM_CLOSED,
        StreamViolation,
    },
};
use runtime::{Handle, spawn};
use rustc_hash::FxHashMap;

pub(crate) mod settings;
mod shared_with_streams;

pub const MAX_CONCURRENT_STREAMS: u32 = 64;

pub struct Connection {
    input: (),
    writer: (),
    peer_settings: Settings,
    shared: Rc<SharedConnection>,
    window: ConnectionWindow,
    streams: Streams,
}

pub const CONNECTION_INITIAL_WINDOW_SIZE: u32 = 65_535;
pub const CONNECTION_RECV_WINDOW: u32 = 1024 * 1024;

pub struct ConnectionWindow {
    to_send: i32,
    to_recv: i32,
    pending_release: u32,
}

impl ConnectionWindow {
    /// §6.9.1: every DATA frame debits this window by its padded length,
    /// whatever becomes of the frame afterwards.
    fn recv(&mut self, padded_len: u32) -> Result<(), ()> {
        let debited = self
            .to_recv
            .checked_sub_unsigned(padded_len)
            .filter(|remaining| *remaining >= 0)
            .ok_or(())?;
        self.to_recv = debited;
        Ok(())
    }

    /// Credit owed back to the peer for bytes no application will ever read.
    /// Accumulated rather than sent, so that a WINDOW_UPDATE goes out once a
    /// worthwhile amount has piled up instead of once per DATA frame.
    fn release(&mut self, len: u32) {
        self.pending_release += len;
    }
}

struct Streams {
    last_client_stream_id: STREAM_ID,
    goaway_stream_id: Option<STREAM_ID>,
    streams: FxHashMap<STREAM_ID, (Rc<Stream>, Handle<()>)>,
}

/// What became of a DATA frame's payload, which decides how much of its flow
/// control is dead on arrival.
enum Received {
    /// Buffered for its stream: only the padding is lost.
    Accepted,
    /// The stream is gone. The frame is legal, but nothing will consume it.
    Discarded,
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
    /// its padding; `padded_len` is what flow control accounts for.
    fn recv_data(
        &mut self,
        id: STREAM_ID,
        payload: &[u8],
        padded_len: u32,
        end_stream: bool,
    ) -> Result<Received, Rejected> {
        // §5.1: an idle stream only accepts HEADERS and PRIORITY.
        if id > self.last_client_stream_id {
            return Err(Rejected::Fatal(PROTOCOL_ERROR, "DATA on idle stream"));
        }

        // Same race as in `credit_send`: the peer emitted before our
        // RST_STREAM reached it. Legal, but the bytes have nowhere to go.
        let Some((stream, _)) = self.streams.get(&id) else {
            return Ok(Received::Discarded);
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
            .map_err(Rejected::Violation)?;
        Ok(Received::Accepted)
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

impl Connection {
    fn new() -> Self {
        unimplemented!()
    }

    async fn flush() {}

    fn fail_connection(&mut self, error_code: u32, reason: &'static str) {
        unimplemented!()
    }

    fn fail_stream(&mut self, stream_id: StreamId, violation: StreamViolation) {
        unimplemented!()
    }

    fn reset_stream(&mut self, stream_id: StreamId, error_code: u32) {
        unimplemented!()
    }

    /// §8.1: trailers must carry END_STREAM and no pseudo-header.
    fn on_trailers(&mut self, stream: Rc<Stream>, headers: Box<Headers>) {
        unimplemented!()
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

/// §8.1.2.1/.3/.6: `:method` and `:scheme` are required, `:path` non-empty,
/// and no `:status` (a response pseudo-header).
fn is_malformed_request(headers: &Headers) -> bool {
    let p = headers.pseudo();
    p.status.is_some()
        || p.method.is_none()
        || p.scheme.is_none()
        || !p.path.as_deref().is_some_and(|path| !path.is_empty())
}

async fn handle_stream(shared: Rc<SharedConnection>, stream: Rc<Stream>, id: StreamId) {
    unimplemented!()
}

impl FrameHandler for Connection {
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
        if self.window.recv(padded_len).is_err() {
            return self.fail_connection(FLOW_CONTROL_ERROR, "connection receive window exceeded");
        }

        let raw: STREAM_ID = stream_id.into();
        let received = self.streams.recv_data(raw, payload, padded_len, end_stream);

        // Padding is accounted by flow control but never reaches an
        // application, so it is spent the moment it lands; on a frame we drop,
        // all of it is. Either way it goes back now — release only what a
        // handler consumes and the window shrinks by the padding for good,
        // until the connection stalls with nothing to show for it.
        self.window.release(match received {
            Ok(Received::Accepted) => padded_len - payload.len() as u32,
            _ => padded_len,
        });

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
            self.reject(id, rejected);
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

        for setting in settings {
            if let Err(invalid) = self.peer_settings.apply(setting) {
                return self.fail_connection(invalid.code, invalid.message);
            }
        }

        // §6.5.3: the values are in force as of now, and the ACK is what tells
        // the peer so. It must not overtake frames already queued, hence the
        // tail of this function rather than anywhere earlier.
        // TODO: queue `encode_settings_ack` once the writer exists.
    }

    /// The decoder has already masked the reserved bit and refused a zero
    /// increment (§6.9.1), so `increment` is guaranteed in `1..=2^31-1`.
    fn on_window_update(&mut self, stream_id: StreamId, increment: u32) {
        if stream_id.is_zero() {
            // §6.9.1: going past 2^31-1 is a connection error.
            let Some(credited) = self.window.to_send.checked_add_unsigned(increment) else {
                return self
                    .fail_connection(FLOW_CONTROL_ERROR, "connection send window exceeds 2^31-1");
            };
            self.window.to_send = credited;
            return;
        }

        let raw: STREAM_ID = stream_id.into();

        if let Err(rejected) = self.streams.credit_send(raw, increment) {
            self.reject(stream_id, rejected);
        }
    }

    fn on_rst_stream(&mut self, stream_id: StreamId, error_code: u32) {
        unimplemented!()
    }

    fn on_ping(&mut self, ack: bool, opaque: [u8; 8]) {
        unimplemented!()
    }

    fn on_goaway(&mut self, last_stream_id: StreamId, error_code: u32, debug_data: &[u8]) {
        unimplemented!()
    }

    /// After a `DecodeError::Connection` the decoder stops emitting events:
    /// tracking that the connection is dead is on us.
    fn on_error(&mut self, err: DecodeError) {
        unimplemented!()
    }

    fn stream_error_scope(&self, violation: StreamViolation) -> ErrorScope {
        unimplemented!()
    }

    fn on_frame(&mut self, kind: FrameKind, stream_id: StreamId, length: u32, flags: u8) {
        unimplemented!()
    }

    /// §3.4: the server preface (a SETTINGS frame) must be queued here,
    /// before the decoder dispatches any following frame.
    fn on_preface(&mut self) {
        unimplemented!()
    }
}
