//! What an inbound frame means to a client.
//!
//! The server's counterpart accepts streams and answers them. This one opened
//! the connection and is waiting to be answered, so the same frames land the
//! other way round: a HEADERS is a *response*, a SETTINGS is the peer telling
//! us its limits rather than us telling it ours, and a stream id that did not
//! come from here is a protocol error rather than a new request.

use std::rc::Rc;

use crate::client::connection::keepalive::Keepalive;
use crate::client::shared::ClientShared;
use crate::shared::codec::{
    frames::{
        FrameHandler, SettingsIter,
        encode::{encode_goaway, encode_ping, encode_settings_ack},
        headers::Headers,
        stream_id::StreamId,
    },
    types::{DecodeError, ENHANCE_YOUR_CALM, FLOW_CONTROL_ERROR, PROTOCOL_ERROR, StreamViolation},
};
use crate::shared::connection::STREAM_ID;

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

pub(super) struct Protocol {
    /// Everything the application reaches too: the send chain, the encoder,
    /// the windows and the live streams.
    pub(super) shared: Rc<ClientShared>,
    pub(super) handshake: Handshake,
    /// §6.7: how long the peer has been silent, and the probe waiting on it.
    /// Driven by the loop, which owns the clock; kept here because the ACK
    /// that answers a probe arrives as a frame.
    pub(super) keepalive: Keepalive,
    /// Set once this connection must stop being read — a connection error has
    /// been answered with a GOAWAY, or the peer sent one and nothing is left
    /// to answer. Distinct from the shared `closing` flag, which only stops
    /// new streams: a peer that says goodbye may still be finishing the
    /// streams it took up.
    closing: bool,
    /// The last error, kept so the handshake and the streams can report why
    /// the connection ended rather than only that it did.
    pub(super) failure: Option<&'static str>,
}

impl Protocol {
    pub(super) fn new(shared: Rc<ClientShared>) -> Self {
        Self {
            shared,
            handshake: Handshake::default(),
            keepalive: Keepalive::default(),
            closing: false,
            failure: None,
        }
    }

    pub(super) fn is_closing(&self) -> bool {
        self.closing
    }

    pub(super) fn write_frame(&mut self, encode: impl FnOnce(&mut Vec<u8>)) {
        self.shared.core.write_frame(encode);
    }

    /// Ends the connection, saying why. §6.8: a client sends GOAWAY like a
    /// server does — it is not the server's frame, it is the connection's.
    ///
    /// The id it names is zero, and that is not a placeholder: a GOAWAY names
    /// the last *peer-initiated* stream the sender processed, and with push
    /// refused the server opens none.
    pub(super) fn fail(&mut self, error_code: u32, reason: &'static str) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.failure = Some(reason);
        self.write_frame(|out| encode_goaway(out, StreamId::ZERO, error_code, reason.as_bytes()));
        // Whatever was in flight is failed by the loop on its way out, which
        // is where it can also say that the transport is gone.
        self.shared.stop_opening();
    }

    /// §5.4.2: the peer broke the rules on one stream. The stream goes, with
    /// a RST_STREAM carrying the violation's code, and the connection lives.
    fn fail_stream(&mut self, stream_id: StreamId, violation: StreamViolation) {
        self.shared.reset_stream(stream_id, violation.code());
    }

    /// Whether `id` is one this client never opened — §5.1's idle state, and
    /// on a client connection that is every id the peer could invent.
    fn is_idle(&self, id: STREAM_ID) -> bool {
        self.shared.is_idle(id)
    }

    /// A HEADERS frame on a live stream: the response, or the trailers that
    /// follow its body (§8.1).
    fn on_response(&mut self, headers: Box<Headers>) {
        let id = headers.stream_id();
        let raw: STREAM_ID = id.into();
        let Some(state) = self.shared.streams.get(raw) else {
            // Closed and already out of the map — a response racing our
            // RST_STREAM. §5.1 asks a peer to tolerate exactly this.
            return;
        };

        // The list was truncated while decoding: HPACK state stays in sync,
        // but what reaches the application would be a response missing
        // fields it was told about. §6.5.2 made that the peer's to avoid —
        // we announce `SETTINGS_MAX_HEADER_LIST_SIZE` — so the stream goes
        // rather than the fields being quietly dropped.
        if headers.is_over_size() {
            self.shared.reset_stream(id, ENHANCE_YOUR_CALM);
            return;
        }

        if state.has_response() {
            // §8.1: trailers end the message, so they carry END_STREAM;
            // §8.3: no pseudo-header may appear in them.
            if !headers.is_end_stream() || has_pseudo(&headers) {
                return self.fail_stream(id, StreamViolation::MalformedTrailers);
            }
            state.recv_trailers((*headers).into_fields());
            self.shared.retire_if_closed(raw);
            return;
        }

        let end_stream = headers.is_end_stream();
        let Some(response) = into_response(headers) else {
            return self.fail_stream(id, StreamViolation::MalformedResponse);
        };
        if state.recv_response(response, end_stream).is_err() {
            return self.fail_stream(id, StreamViolation::MalformedResponse);
        }
        if end_stream {
            self.shared.retire_if_closed(raw);
        }
    }
}

impl FrameHandler for Protocol {
    /// §6.5: the peer's limits, or its acknowledgement of ours.
    fn on_settings(&mut self, ack: bool, settings: SettingsIter<'_>) {
        if ack {
            self.handshake.ours_acknowledged = true;
            return;
        }

        // Applied to a copy and put back whole: a frame that turns out to be
        // invalid halfway through ends the connection anyway, and half a
        // frame's worth of settings must not be what the streams opened
        // before the GOAWAY were sized by.
        let mut peer = self.shared.peer_settings();
        let initial_window_before = peer.initial_window_size;
        for setting in settings {
            if let Err(invalid) = peer.apply(setting) {
                return self.fail(invalid.code, invalid.message);
            }
        }
        // §6.9.2: a new initial window moves every live stream's send window
        // by the difference. Both ends are within 2^31-1, so it fits an i32.
        let delta = peer.initial_window_size as i32 - initial_window_before as i32;
        self.shared.set_peer_settings(peer);
        if delta != 0 && self.shared.adjust_send_windows(delta).is_err() {
            return self.fail(FLOW_CONTROL_ERROR, "stream send window exceeds 2^31-1");
        }

        self.handshake.peer_settings_seen = true;
        // §6.5.3: acknowledged in order, and after anything this frame made
        // us do — the ACK says the values are in force here.
        self.write_frame(encode_settings_ack);
    }

    /// §6.7: a probe is echoed with ACK set, and an ACK is the answer to a
    /// probe of ours — the keepalive's, since it sends the only ones.
    fn on_ping(&mut self, ack: bool, opaque: [u8; 8]) {
        match ack {
            true => self.keepalive.acknowledged(opaque),
            false => self.write_frame(|out| encode_ping(out, opaque, true)),
        }
    }

    /// §6.8: the server is going away. Nothing above `last_stream_id` was
    /// processed, so those requests are failed now — they are safe to retry
    /// on another connection, and that is worth saying immediately rather
    /// than when the socket eventually closes. What is at or below it is
    /// still being answered, so the connection stays open for it.
    fn on_goaway(&mut self, last_stream_id: StreamId, _error_code: u32, _debug_data: &[u8]) {
        self.failure.get_or_insert("peer sent GOAWAY");
        self.shared.stop_opening();
        self.shared.fail_unprocessed(last_stream_id.into());
    }

    /// §6.9: credit, on stream 0 or on one of ours.
    fn on_window_update(&mut self, stream_id: StreamId, increment: u32) {
        if stream_id.is_zero() {
            if self.shared.core.window.credit_send(increment).is_err() {
                return self.fail(FLOW_CONTROL_ERROR, "connection send window exceeds 2^31-1");
            }
            return;
        }

        let raw: STREAM_ID = stream_id.into();
        if self.is_idle(raw) {
            return self.fail(PROTOCOL_ERROR, "WINDOW_UPDATE on idle stream");
        }
        // Absent from the map is a stream that has already gone: the peer may
        // have credited it before our RST_STREAM reached it, which is legal.
        let Some(state) = self.shared.streams.get(raw) else {
            return;
        };
        if state.credit_send(increment).is_err() {
            self.fail_stream(stream_id, StreamViolation::StreamWindowOverflow);
        }
    }

    /// A response, or the trailers after one.
    fn on_headers(&mut self, headers: Box<Headers>) {
        let id = headers.stream_id();

        // §5.1.1 and §8.2: the even ids are the peer's, and it opens one by
        // pushing — which we refused in our SETTINGS. A HEADERS on one is a
        // peer disregarding that.
        if !id.is_client_initiated() {
            return self.fail(PROTOCOL_ERROR, "HEADERS on a server-initiated stream");
        }
        if self.is_idle(id.into()) {
            return self.fail(
                PROTOCOL_ERROR,
                "HEADERS on a stream this client never opened",
            );
        }
        self.on_response(headers);
    }

    /// §6.9.1: `padded_len` is what flow control accounts for, pad-length
    /// byte and padding included; `payload` is what the application gets.
    fn on_data(&mut self, stream_id: StreamId, payload: &[u8], padded_len: usize, end: bool) {
        // Bounded by max_frame_size, itself below 2^24.
        let padded_len = padded_len as u32;

        // Debited before anything is decided: the peer spent that credit
        // whatever we make of the frame, and skipping it on the paths that
        // fail would drift our accounting away from its own.
        if self.shared.core.window.recv(padded_len).is_err() {
            return self.fail(FLOW_CONTROL_ERROR, "connection receive window exceeded");
        }

        let raw: STREAM_ID = stream_id.into();
        if self.is_idle(raw) {
            return self.fail(PROTOCOL_ERROR, "DATA on idle stream");
        }

        let Some(state) = self.shared.streams.get(raw) else {
            // A body still arriving for a stream we have already given up on.
            // Nothing will read it, so all of its credit goes back now.
            self.shared.core.release_stream_credit(padded_len);
            return;
        };

        if state.recv_window(padded_len).is_err() {
            return self.fail(FLOW_CONTROL_ERROR, "stream receive window exceeded");
        }

        let received = state.recv_data(payload, end);

        // Padding is accounted by flow control but never reaches an
        // application, so it is spent the moment it lands; on a frame we
        // drop, all of it is. Either way it goes back now — release only what
        // the application reads and the window shrinks by the padding for
        // good, until the connection stalls with nothing to show for it.
        self.shared.core.release_stream_credit(match received {
            Ok(()) => padded_len - payload.len() as u32,
            Err(()) => padded_len,
        });

        match received {
            // §5.1: the peer's half was already closed by its END_STREAM.
            Err(()) => self.fail_stream(stream_id, StreamViolation::DataAfterEndStream),
            Ok(()) if end => self.shared.retire_if_closed(raw),
            Ok(()) => {}
        }
    }

    /// §6.4: the peer gives up on a stream. Nothing is written back — the
    /// stream just goes, and whoever was waiting on it is told why.
    fn on_rst_stream(&mut self, stream_id: StreamId, error_code: u32) {
        if self.is_idle(stream_id.into()) {
            // §5.1: an idle stream cannot be reset, there is nothing to
            // reset.
            return self.fail(PROTOCOL_ERROR, "RST_STREAM on an idle stream");
        }
        self.shared.peer_reset(stream_id, error_code);
    }

    fn on_error(&mut self, err: DecodeError) {
        match err {
            DecodeError::Connection { code, message } => self.fail(code, message),
            // The frame is already discarded; the stream is told why.
            DecodeError::Stream {
                stream_id, code, ..
            } => self.shared.reset_stream(stream_id, code),
        }
    }
}

/// §8.1.2.4: a response head is `:status` and nothing else pseudo. `None` is
/// a head that is neither.
fn into_response(headers: Box<Headers>) -> Option<http::Response<()>> {
    let pseudo = headers.pseudo();
    let status = pseudo.status?;
    if pseudo.method.is_some()
        || pseudo.scheme.is_some()
        || pseudo.authority.is_some()
        || pseudo.path.is_some()
        || pseudo.protocol.is_some()
    {
        return None;
    }

    let mut response = http::Response::new(());
    *response.status_mut() = status;
    *response.version_mut() = http::Version::HTTP_2;
    *response.headers_mut() = (*headers).into_fields();
    Some(response)
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
