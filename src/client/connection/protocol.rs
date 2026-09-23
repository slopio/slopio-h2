use std::rc::Rc;

use crate::client::connection::keepalive::Keepalive;
use crate::client::shared::ClientShared;
use crate::shared::codec::{
    frames::{
        FrameHandler, FrameKind, SettingsIter,
        encode::{encode_goaway, encode_ping, encode_settings_ack, encode_window_update},
        headers::Headers,
        stream_id::StreamId,
    },
    types::{
        DecodeError, ENHANCE_YOUR_CALM, FLOW_CONTROL_ERROR, PROTOCOL_ERROR, Setting,
        StreamViolation,
    },
};
use crate::shared::connection::STREAM_ID;

/// §6.5.3: two independent facts; the peer can acknowledge ours before
/// sending its own.
#[derive(Default)]
pub(super) struct Handshake {
    /// §3.4: the first frame must be the peer's SETTINGS.
    pub(super) first_frame_seen: bool,
    pub(super) peer_settings_seen: bool,
    pub(super) ours_acknowledged: bool,
}

impl Handshake {
    pub(super) fn is_complete(&self) -> bool {
        self.peer_settings_seen && self.ours_acknowledged
    }
}

pub(super) struct Protocol {
    pub(super) shared: Rc<ClientShared>,
    pub(super) handshake: Handshake,
    pub(super) keepalive: Keepalive,
    /// Set once this connection must stop being read. Distinct from the shared
    /// `closing` flag, which only stops new streams: a peer that says goodbye
    /// may still be finishing the streams it took up.
    closing: bool,
    pub(super) failure: Option<&'static str>,
}

impl Protocol {
    pub(super) fn new(shared: Rc<ClientShared>) -> Self {
        Self {
            shared,
            handshake: Handshake::default(),
            keepalive: Keepalive::new(runtime::runtime::now()),
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

    /// §6.8. The id is zero, not a placeholder: with push refused the server
    /// opens no streams for it to name.
    pub(super) fn fail(&mut self, error_code: u32, reason: &'static str) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.failure = Some(reason);
        self.write_frame(|out| encode_goaway(out, StreamId::ZERO, error_code, reason.as_bytes()));
        // Streams in flight are failed by the loop on its way out.
        self.shared.stop_opening();
    }

    /// §5.4.2: the stream goes, the connection lives.
    fn fail_stream(&mut self, stream_id: StreamId, violation: StreamViolation) {
        self.shared.reject_stream(stream_id, violation);
    }

    /// §5.1 idle: on a client, every id the peer could invent.
    fn is_idle(&self, id: STREAM_ID) -> bool {
        self.shared.is_idle(id)
    }

    fn on_response(&mut self, headers: Box<Headers>) {
        let id = headers.stream_id();
        let raw: STREAM_ID = id.into();
        let Some(state) = self.shared.streams.get(raw) else {
            // A response racing our RST_STREAM; §5.1 asks us to tolerate it.
            return;
        };

        // Truncated while decoding: HPACK state stays in sync, but the
        // application must not see a response with fields silently dropped.
        // §6.5.2: we announced the limit, so the stream goes.
        if headers.is_over_size() {
            self.shared.reset_stream(id, ENHANCE_YOUR_CALM);
            return;
        }

        if state.has_response() {
            // §5.1: nothing more after END_STREAM; a second trailer section
            // must not replace the first.
            if state.input_ended() {
                return self.fail_stream(id, StreamViolation::DataAfterEndStream);
            }
            // §8.1: trailers end the message, so they carry END_STREAM;
            // §8.3: no pseudo-header may appear in them.
            if !headers.is_end_stream() || has_pseudo(&headers) {
                return self.fail_stream(id, StreamViolation::MalformedTrailers);
            }
            if let Err(violation) = state.recv_trailers((*headers).into_fields()) {
                return self.fail_stream(id, violation);
            }
            self.shared.retire_if_closed(raw);
            return;
        }

        let end_stream = headers.is_end_stream();
        let Some(response) = into_response(headers) else {
            return self.fail_stream(id, StreamViolation::MalformedResponse);
        };
        if let Err(violation) = state.recv_response(response, end_stream) {
            return self.fail_stream(id, violation);
        }
        if end_stream {
            self.shared.retire_if_closed(raw);
        }
    }
}

impl FrameHandler for Protocol {
    /// §3.4: the server's first frame must be a non-ACK SETTINGS.
    fn on_frame(&mut self, kind: FrameKind, _stream_id: StreamId, _length: u32, flags: u8) {
        if std::mem::replace(&mut self.handshake.first_frame_seen, true) {
            return;
        }
        // §6.5: ACK is 0x1.
        if kind != FrameKind::Settings || flags & 0x1 != 0 {
            self.fail(PROTOCOL_ERROR, "server preface is not a SETTINGS frame");
        }
    }

    fn on_settings(&mut self, ack: bool, settings: SettingsIter<'_>) {
        if self.closing {
            return;
        }
        if ack {
            self.handshake.ours_acknowledged = true;
            return;
        }

        // Applied to a copy and put back whole: half a frame's worth of
        // settings must never be in force.
        let mut peer = self.shared.peer_settings();
        let initial_window_before = peer.initial_window_size;
        for setting in settings {
            // §6.5.2: a server must not send ENABLE_PUSH = 1.
            if matches!(setting, Setting::EnablePush(1)) {
                return self.fail(PROTOCOL_ERROR, "SETTINGS_ENABLE_PUSH from a server");
            }
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
        // §6.5.3: the ACK must follow applying the values.
        self.write_frame(encode_settings_ack);
    }

    /// §6.7.
    fn on_ping(&mut self, ack: bool, opaque: [u8; 8]) {
        if self.closing {
            return;
        }
        match ack {
            true => self.keepalive.acknowledged(opaque),
            false => self.write_frame(|out| encode_ping(out, opaque, true)),
        }
    }

    /// §6.8: streams above `last_stream_id` were not processed and fail now;
    /// the connection stays open for those at or below it.
    fn on_goaway(&mut self, last_stream_id: StreamId, _error_code: u32, _debug_data: &[u8]) {
        if self.closing {
            return;
        }
        self.failure.get_or_insert("peer sent GOAWAY");
        self.shared.stop_opening();
        self.shared.fail_unprocessed(last_stream_id.into());
    }

    /// §6.9.
    fn on_window_update(&mut self, stream_id: StreamId, increment: u32) {
        if self.closing {
            return;
        }
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
        // Legal: the peer may have credited it before our RST_STREAM arrived.
        let Some(state) = self.shared.streams.get(raw) else {
            return;
        };
        if state.credit_send(increment).is_err() {
            self.fail_stream(stream_id, StreamViolation::StreamWindowOverflow);
        }
    }

    fn on_headers(&mut self, headers: Box<Headers>) {
        if self.closing {
            return;
        }
        let id = headers.stream_id();

        // §5.1.1, §8.2: even ids open only by push, which we refused.
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
        if self.closing {
            return;
        }
        // Bounded by max_frame_size, itself below 2^24.
        let padded_len = padded_len as u32;

        // Debited before anything is decided: the peer spent that credit
        // whatever we make of the frame, or our accounting drifts from its own.
        if self.shared.core.window.recv(padded_len).is_err() {
            return self.fail(FLOW_CONTROL_ERROR, "connection receive window exceeded");
        }

        let raw: STREAM_ID = stream_id.into();
        if self.is_idle(raw) {
            return self.fail(PROTOCOL_ERROR, "DATA on idle stream");
        }

        let Some(state) = self.shared.streams.get(raw) else {
            // Nothing will read it, so all of its credit goes back now.
            self.shared.core.release_stream_credit(padded_len);
            return;
        };

        if state.recv_window(padded_len).is_err() {
            return self.fail(FLOW_CONTROL_ERROR, "stream receive window exceeded");
        }

        let received = state.recv_data(payload, end);

        // Padding (and a dropped frame) never reaches the application, so its
        // credit must go back now or the window shrinks for good and stalls.
        let padding = padded_len - payload.len() as u32;
        self.shared.core.release_stream_credit(match received {
            Ok(()) => padding,
            Err(_) => padded_len,
        });

        // Likewise for the stream's window, except on a stream just finished.
        if received.is_ok()
            && !end
            && padding > 0
            && let Some(increment) = state.release_recv(padding)
        {
            self.shared
                .core
                .write_frame(|out| encode_window_update(out, stream_id, increment));
        }

        match received {
            Err(violation) => self.fail_stream(stream_id, violation),
            Ok(()) if end => self.shared.retire_if_closed(raw),
            Ok(()) => {}
        }
    }

    /// §6.4.
    fn on_rst_stream(&mut self, stream_id: StreamId, error_code: u32) {
        if self.closing {
            return;
        }
        if self.is_idle(stream_id.into()) {
            // §5.1.
            return self.fail(PROTOCOL_ERROR, "RST_STREAM on an idle stream");
        }
        self.shared.peer_reset(stream_id, error_code);
    }

    /// Every frame after a connection error must be ignored, here and in each
    /// handler above: the decoder keeps dispatching the rest of the chunk, and
    /// a response must not reach the application after the connection failed.
    fn on_error(&mut self, err: DecodeError) {
        if self.closing {
            return;
        }
        match err {
            DecodeError::Connection { code, message } => self.fail(code, message),
            DecodeError::Stream {
                stream_id,
                violation,
                ..
            } => self.fail_stream(stream_id, violation),
        }
    }
}

/// §8.1.2.4: a response head is `:status` and nothing else pseudo.
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
