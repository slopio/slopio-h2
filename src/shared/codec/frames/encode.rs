//! Helpers that append serialized HTTP/2 frames to a `Vec<u8>`.
//!
//! Each function writes a complete frame (header + payload) into the
//! caller's buffer; no allocation beyond the buffer's own growth. Designed
//! to feed `ConnectionWriter::append`.
//!
//! The HEADERS block itself is HPACK-encoded by `StreamShared::write_headers`;
//! only the 9-byte frame headers and the control frames live here.

use bytes::BufMut;

use crate::shared::codec::{
    frames::{
        head::{Head, Kind},
        stream_id::StreamId,
    },
    types::Setting,
};

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_ACK: u8 = 0x1;

/// Just the 9-byte DATA frame header (no payload), for callers that stream
/// the payload separately — e.g. writing header + payload back-to-back into
/// a registered send buffer without a staging copy of the payload.
pub fn encode_data_header<T: BufMut>(
    out: &mut T,
    stream_id: StreamId,
    payload_len: usize,
    end_stream: bool,
) {
    let flags = if end_stream { FLAG_END_STREAM } else { 0 };
    Head::new(Kind::Data, flags, stream_id).encode(payload_len, out);
}

/// Just the 9-byte HEADERS frame header (END_HEADERS always set), for callers
/// that stream the HPACK block separately into a send buffer — the HEADERS
/// counterpart of [`encode_data_header`]. Single-frame only (no CONTINUATION).
pub fn encode_headers_header<T: BufMut>(
    out: &mut T,
    stream_id: StreamId,
    block_len: usize,
    end_stream: bool,
) {
    let mut flags = FLAG_END_HEADERS;
    if end_stream {
        flags |= FLAG_END_STREAM;
    }
    Head::new(Kind::Headers, flags, stream_id).encode(block_len, out);
}

/// First fragment of a header block continued in CONTINUATION frames (§6.10):
/// END_HEADERS is deliberately unset, END_STREAM still belongs here.
pub fn encode_headers_fragment_header<T: BufMut>(
    out: &mut T,
    stream_id: StreamId,
    fragment_len: usize,
    end_stream: bool,
) {
    let flags = if end_stream { FLAG_END_STREAM } else { 0 };
    Head::new(Kind::Headers, flags, stream_id).encode(fragment_len, out);
}

/// CONTINUATION frame header (§6.10). `end_headers` closes the block; the
/// frames must follow their HEADERS with nothing interleaved.
pub fn encode_continuation_header<T: BufMut>(
    out: &mut T,
    stream_id: StreamId,
    fragment_len: usize,
    end_headers: bool,
) {
    let flags = if end_headers { FLAG_END_HEADERS } else { 0 };
    Head::new(Kind::Continuation, flags, stream_id).encode(fragment_len, out);
}

/// SETTINGS frame (RFC 9113 §6.5). One entry = 2-byte id + 4-byte value.
pub fn encode_settings(out: &mut Vec<u8>, settings: &[Setting]) {
    let payload_len = settings.len() * 6;
    Head::new(Kind::Settings, 0, StreamId::ZERO).encode(payload_len, out);
    for setting in settings {
        let (id, value) = setting_id_value(*setting);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&value.to_be_bytes());
    }
}

/// SETTINGS frame with the ACK flag set and an empty payload (§6.5.3).
pub fn encode_settings_ack(out: &mut Vec<u8>) {
    Head::new(Kind::Settings, FLAG_ACK, StreamId::ZERO).encode(0, out);
}

/// WINDOW_UPDATE frame (§6.9). `stream_id` may be 0 for connection-level credit.
pub fn encode_window_update(out: &mut Vec<u8>, stream_id: StreamId, increment: u32) {
    Head::new(Kind::WindowUpdate, 0, stream_id).encode(4, out);
    // High bit is reserved (R) per §6.9; callers should not pass values
    // with the MSB set, so masking is left out.
    out.extend_from_slice(&increment.to_be_bytes());
}

/// RST_STREAM frame (§6.4).
pub fn encode_rst_stream(out: &mut Vec<u8>, stream_id: StreamId, error_code: u32) {
    Head::new(Kind::Reset, 0, stream_id).encode(4, out);
    out.extend_from_slice(&error_code.to_be_bytes());
}

/// PING frame (§6.7). `ack` distinguishes a response from a probe.
pub fn encode_ping(out: &mut Vec<u8>, opaque: [u8; 8], ack: bool) {
    let flags = if ack { FLAG_ACK } else { 0 };
    Head::new(Kind::Ping, flags, StreamId::ZERO).encode(8, out);
    out.extend_from_slice(&opaque);
}

/// GOAWAY frame (§6.8). `debug_data` may be empty.
pub fn encode_goaway(
    out: &mut Vec<u8>,
    last_stream_id: StreamId,
    error_code: u32,
    debug_data: &[u8],
) {
    let payload_len = 8 + debug_data.len();
    Head::new(Kind::GoAway, 0, StreamId::ZERO).encode(payload_len, out);
    let last: u32 = last_stream_id.into();
    out.extend_from_slice(&last.to_be_bytes());
    out.extend_from_slice(&error_code.to_be_bytes());
    out.extend_from_slice(debug_data);
}

fn setting_id_value(s: Setting) -> (u16, u32) {
    match s {
        Setting::HeaderTableSize(v) => (0x1, v),
        Setting::EnablePush(v) => (0x2, v),
        Setting::MaxConcurrentStreams(v) => (0x3, v),
        Setting::InitialWindowSize(v) => (0x4, v),
        Setting::MaxFrameSize(v) => (0x5, v),
        Setting::MaxHeaderListSize(v) => (0x6, v),
        Setting::Unknown { id, value } => (id, value),
    }
}
