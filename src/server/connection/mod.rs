use std::rc::Rc;

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

/// §6.9.2: the connection window always starts at 65535, and
/// SETTINGS_INITIAL_WINDOW_SIZE never touches it. Only a WINDOW_UPDATE on
/// stream 0 moves it.
pub const CONNECTION_INITIAL_WINDOW_SIZE: u32 = 65_535;

/// The gap with the initial value must be announced by a WINDOW_UPDATE on
/// stream 0, sent from `on_preface`.
pub const CONNECTION_RECV_WINDOW: u32 = 1024 * 1024;

pub struct ConnectionWindow {
    /// §6.9.1: a DATA frame debits this window *and* its stream's.
    to_send: i32,
    /// Debited by `padded_len`, padding included (§6.9.1).
    to_recv: i32,
    pending_release: u32,
}

struct Streams {
    last_client_stream_id: STREAM_ID,
    streams: FxHashMap<STREAM_ID, (Rc<Stream>, Handle<()>)>,
}

impl Streams {
    fn new_stream(&mut self) {}

    /// An id absent from the map is a stream that closed and was removed: the
    /// peer may have sent before receiving our RST_STREAM. That is legal, so
    /// `Ok`.
    fn credit_send(&self, id: STREAM_ID, increment: u32) -> Result<(), StreamViolation> {
        let Some((stream, _)) = self.streams.get(&id) else {
            return Ok(());
        };
        stream
            .credit_send(increment)
            .map_err(|()| StreamViolation::StreamWindowOverflow)
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

    /// §5.1.2: the map only holds live streams, so its length is the current
    /// count.
    fn admits(&self) -> bool {
        self.streams.streams.len() < MAX_CONCURRENT_STREAMS as usize
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
        unimplemented!()
    }

    /// Two roles: opening a stream, or carrying the trailers (§8.1) of a live
    /// one.
    fn on_headers(&mut self, headers: Box<Headers>) {
        let id = headers.stream_id();
        let raw: STREAM_ID = id.into();

        // §5.3.1: a stream MUST NOT depend on itself.
        if let Some(dep) = headers.stream_dep()
            && dep.dependency_id == id
        {
            return self.fail_stream(id, StreamViolation::HeadersSelfDependency);
        }

        // §5.1.1: client ids are odd; even ones are reserved for the server.
        if !id.is_client_initiated() {
            return self.fail_connection(PROTOCOL_ERROR, "HEADERS with server-initiated stream id");
        }

        // List truncated during decoding: HPACK state stays in sync, but the
        // content is incomplete and must not reach the handler.
        if headers.is_over_size() {
            self.streams.last_client_stream_id = raw.max(self.streams.last_client_stream_id);
            return self.reset_stream(id, REFUSED_STREAM);
        }

        if let Some((stream, _)) = self.streams.streams.get(&raw) {
            let stream = Rc::clone(stream);
            return self.on_trailers(stream, headers);
        }

        // Absent from the map but already used: the stream lived and is gone.
        // `last_client_stream_id` is what tells this apart from "id never
        // used", since the map only holds live streams.
        if raw <= self.streams.last_client_stream_id {
            return self.fail_connection(STREAM_CLOSED, "HEADERS on closed stream");
        }

        // The id is spent as soon as we refuse it: both branches below
        // advance it, but neither opens a stream.
        if is_malformed_request(&headers) {
            self.streams.last_client_stream_id = raw;
            return self.fail_stream(id, StreamViolation::MalformedRequest);
        }

        if !self.admits() {
            self.streams.last_client_stream_id = raw;
            return self.reset_stream(id, REFUSED_STREAM);
        }

        self.streams.last_client_stream_id = raw;

        // The entry stays in the map even with END_STREAM set: the stream is
        // half-closed(remote), not gone — we still need to take its
        // WINDOW_UPDATEs and reject stray DATA.
        let stream = Rc::new(Stream::create(&self.peer_settings, headers));
        let handle = spawn(handle_stream(
            Rc::clone(&self.shared),
            Rc::clone(&stream),
            id,
        ));
        self.streams.streams.insert(raw, (stream, handle));
    }

    fn on_settings(&mut self, ack: bool, settings: SettingsIter<'_>) {
        unimplemented!()
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

        // §5.1: an idle stream only accepts HEADERS and PRIORITY.
        if raw > self.streams.last_client_stream_id {
            return self.fail_connection(PROTOCOL_ERROR, "WINDOW_UPDATE on idle stream");
        }

        // Overflow only kills the stream, not the connection.
        if let Err(violation) = self.streams.credit_send(raw, increment) {
            self.fail_stream(stream_id, violation);
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

pub struct Settings {
    /// 0x01 — max size of the HPACK dynamic table. Default 4096.
    pub header_table_size: u32,
    /// 0x02 — server push. Default true, but a server advertises false.
    pub enable_push: bool,
    /// 0x03 — `None` = unlimited (default). `Some(0)` forbids any new stream.
    pub max_concurrent_streams: Option<u32>,
    /// 0x04 — initial window of every stream. Default 65535, max 2^31-1.
    pub initial_window_size: u32,
    /// 0x05 — max frame payload size. Default 16384, within [2^14, 2^24-1].
    pub max_frame_size: u32,
    /// 0x06 — `None` = unlimited (default). Advisory, not binding.
    pub max_header_list_size: Option<u32>,
    /// 0x08 — RFC 8441, extended CONNECT (WebSocket over h2). Default false.
    pub enable_connect_protocol: bool,
    /// 0x09 — RFC 9218, dropping the RFC 7540 priority scheme. Default false.
    pub no_rfc7540_priorities: bool,
}
