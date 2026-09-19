//! What an inbound frame means to a client.
//!
//! The server's counterpart accepts streams and answers them. This one opened
//! the connection and is waiting to be answered, so the same frames land the
//! other way round: a HEADERS is a *response*, a SETTINGS is the peer telling
//! us its limits rather than us telling it ours, and a stream id that did not
//! come from here is a protocol error rather than a new request.
//!
//! Only the connection-level frames are handled yet. Streams come next.

use crate::shared::codec::{
    frames::{
        FrameHandler, SettingsIter,
        encode::{encode_goaway, encode_ping, encode_settings_ack},
        headers::Headers,
        stream_id::StreamId,
    },
    types::{DecodeError, ErrorScope, PROTOCOL_ERROR, StreamViolation},
};
use crate::shared::connection::{STREAM_ID, output::Output, settings::Settings};
use crate::shared::hpack::Encoder;

/// How far the handshake has got.
///
/// §3.4 makes the client's preface a magic string *and* a SETTINGS frame, and
/// §6.5.3 makes settings a two-step exchange in each direction. A connection is
/// established once both steps have happened both ways, which is two facts and
/// not one — the peer can acknowledge ours before sending its own.
#[derive(Default)]
pub(super) struct Handshake {
    /// The peer sent its SETTINGS. Its limits are known from here.
    pub(super) peer_settings_seen: bool,
    /// The peer acknowledged ours. Our limits are in force from here.
    pub(super) ours_acknowledged: bool,
}

impl Handshake {
    pub(super) fn is_complete(&self) -> bool {
        self.peer_settings_seen && self.ours_acknowledged
    }
}

/// §5.1.1: the first stream a client may open.
const FIRST_CLIENT_STREAM: STREAM_ID = 1;

/// §5.1.1: ids are 31 bits, and one past the last usable odd one is where a
/// client has to stop and open a new connection.
const MAX_STREAM_ID: STREAM_ID = (1 << 31) - 1;

pub(super) struct Protocol {
    /// Frames waiting to go out.
    ///
    /// A plain field, where the server needs a cell: its output is reached
    /// through an `Rc` by every stream task, and this one is owned outright by
    /// the `Connection` that flushes it. That stops being true the day a
    /// request body is written by a task of its own, and the cell can come
    /// back then — putting it in now would be guessing at a shape that does
    /// not exist.
    pub(super) output: Output,
    /// Connection-level by definition: every block on the connection feeds the
    /// same dynamic table, so they have to be encoded in the order they go on
    /// the wire or the peer's decoder drifts.
    pub(super) encoder: Encoder,
    /// §5.1.1: the id the next request will use. Odd, and only ever forward —
    /// a client that reused one would be reopening a stream the peer considers
    /// closed.
    next_stream_id: STREAM_ID,
    /// Streams opened and not yet finished, against the peer's
    /// `max_concurrent_streams`.
    live_streams: u32,
    /// What the server told us it will accept.
    pub(super) peer_settings: Settings,
    pub(super) handshake: Handshake,
    /// Set once this connection is over — a GOAWAY arrived, or we are sending
    /// one. Nothing more is written after it.
    closing: bool,
    /// The last error, kept so `handshake` can report why it gave up rather
    /// than only that it did.
    pub(super) failure: Option<&'static str>,
}

impl Protocol {
    pub(super) fn new() -> Self {
        Self {
            output: Output::new(),
            encoder: Encoder::default(),
            next_stream_id: FIRST_CLIENT_STREAM,
            live_streams: 0,
            peer_settings: Settings::default(),
            handshake: Handshake::default(),
            closing: false,
            failure: None,
        }
    }

    pub(super) fn is_closing(&self) -> bool {
        self.closing
    }

    pub(super) fn write_frame(&mut self, encode: impl FnOnce(&mut Vec<u8>)) {
        self.output.write(encode);
    }

    /// Takes the next stream id, or `None` when there are none left.
    ///
    /// §5.1.1: a client's ids are odd and strictly increasing, so they run out
    /// — and running out is not an error, it is the connection being finished.
    /// A client that has exhausted them opens another one; there is no
    /// recycling, because the peer remembers every id it has seen.
    ///
    /// Also `None` past the peer's `max_concurrent_streams`, which §5.1.2
    /// makes the peer's to set and ours to respect. Opening one anyway earns a
    /// REFUSED_STREAM, and a refusal we could have predicted is worse than a
    /// wait.
    pub(super) fn open_stream(&mut self) -> Option<StreamId> {
        let allowed = self.peer_settings.max_concurrent_streams.unwrap_or(u32::MAX);
        if self.live_streams >= allowed {
            return None;
        }
        if self.next_stream_id > MAX_STREAM_ID {
            return None;
        }

        let id = self.next_stream_id;
        // Odd to odd. The peer is the only one who opens the even ones, and it
        // has told us it will not (§8.2, and we asked for no push).
        self.next_stream_id = self.next_stream_id.saturating_add(2);
        self.live_streams += 1;
        Some(StreamId::from(id))
    }

    /// Ends the connection, saying why. §6.8: a client sends GOAWAY like a
    /// server does — it is not the server's frame, it is the connection's.
    fn fail(&mut self, error_code: u32, reason: &'static str) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.failure = Some(reason);
        self.write_frame(|out| {
            encode_goaway(out, StreamId::ZERO, error_code, reason.as_bytes())
        });
    }
}

impl FrameHandler for Protocol {
    /// §6.5: the peer's limits, or its acknowledgement of ours.
    fn on_settings(&mut self, ack: bool, settings: SettingsIter<'_>) {
        if ack {
            self.handshake.ours_acknowledged = true;
            return;
        }

        for setting in settings {
            if let Err(invalid) = self.peer_settings.apply(setting) {
                return self.fail(invalid.code, invalid.message);
            }
        }

        self.handshake.peer_settings_seen = true;
        // §6.5.3: acknowledged in order, and before anything we send next
        // depends on having read them.
        self.write_frame(encode_settings_ack);
    }

    /// §6.7: a probe is echoed with ACK set. An ACK is the answer to a probe
    /// of ours, and we send none yet.
    fn on_ping(&mut self, ack: bool, opaque: [u8; 8]) {
        if !ack {
            self.write_frame(|out| encode_ping(out, opaque, true));
        }
    }

    /// §6.8: the server is going away. Nothing above `last_stream_id` was
    /// processed — which will matter once there are streams to retry.
    fn on_goaway(&mut self, _last_stream_id: StreamId, _error_code: u32, _debug_data: &[u8]) {
        self.closing = true;
        self.failure.get_or_insert("peer sent GOAWAY");
    }

    /// Credit on stream 0, or on one of ours. Neither has anywhere to go until
    /// this client can open a stream.
    fn on_window_update(&mut self, _stream_id: StreamId, _increment: u32) {}

    /// A response. Nothing here opened a stream yet, so any HEADERS is for one
    /// that does not exist (§5.1).
    fn on_headers(&mut self, _headers: Box<Headers>) {
        self.fail(PROTOCOL_ERROR, "HEADERS on a stream this client never opened");
    }

    /// Same as HEADERS: there is no stream this could belong to.
    fn on_data(&mut self, _stream_id: StreamId, _payload: &[u8], _padded_len: usize, _end: bool) {
        self.fail(PROTOCOL_ERROR, "DATA on a stream this client never opened");
    }

    /// §6.4: a reset for a stream we never opened. Idle streams cannot be
    /// reset, so this is the peer being wrong rather than us losing a request.
    fn on_rst_stream(&mut self, _stream_id: StreamId, _error_code: u32) {
        self.fail(PROTOCOL_ERROR, "RST_STREAM on an idle stream");
    }

    /// Without streams there is nothing a stream-scoped error could name, so
    /// every violation is the connection's.
    fn stream_error_scope(&self, _violation: StreamViolation) -> ErrorScope {
        ErrorScope::Connection
    }

    fn on_error(&mut self, err: DecodeError) {
        match err {
            DecodeError::Connection { code, message } => self.fail(code, message),
            DecodeError::Stream { code, message, .. } => self.fail(code, message),
        }
    }
}
