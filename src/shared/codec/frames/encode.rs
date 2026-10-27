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

pub fn encode_data_header(
    out: &mut Vec<u8>,
    stream_id: StreamId,
    payload_len: usize,
    end_stream: bool,
) {
    let flags = if end_stream { FLAG_END_STREAM } else { 0 };
    Head::new(Kind::Data, flags, stream_id).encode(payload_len, out);
}

/// END_HEADERS always set: single-frame only (no CONTINUATION).
pub fn encode_headers_header(
    out: &mut Vec<u8>,
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

/// §6.10: END_HEADERS deliberately unset; END_STREAM still belongs here.
pub fn encode_headers_fragment_header(
    out: &mut Vec<u8>,
    stream_id: StreamId,
    fragment_len: usize,
    end_stream: bool,
) {
    let flags = if end_stream { FLAG_END_STREAM } else { 0 };
    Head::new(Kind::Headers, flags, stream_id).encode(fragment_len, out);
}

/// §6.10: must follow their HEADERS with nothing interleaved.
pub fn encode_continuation_header(
    out: &mut Vec<u8>,
    stream_id: StreamId,
    fragment_len: usize,
    end_headers: bool,
) {
    let flags = if end_headers { FLAG_END_HEADERS } else { 0 };
    Head::new(Kind::Continuation, flags, stream_id).encode(fragment_len, out);
}

pub fn encode_settings(out: &mut Vec<u8>, settings: &[Setting]) {
    let payload_len = settings.len() * 6;
    Head::new(Kind::Settings, 0, StreamId::ZERO).encode(payload_len, out);
    for setting in settings {
        let (id, value) = setting_id_value(*setting);
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub fn encode_settings_ack(out: &mut Vec<u8>) {
    Head::new(Kind::Settings, FLAG_ACK, StreamId::ZERO).encode(0, out);
}

pub fn encode_window_update(out: &mut Vec<u8>, stream_id: StreamId, increment: u32) {
    Head::new(Kind::WindowUpdate, 0, stream_id).encode(4, out);
    // §6.9: high bit is reserved; callers must not set it, it is not masked.
    out.extend_from_slice(&increment.to_be_bytes());
}

pub fn encode_rst_stream(out: &mut Vec<u8>, stream_id: StreamId, error_code: u32) {
    Head::new(Kind::Reset, 0, stream_id).encode(4, out);
    out.extend_from_slice(&error_code.to_be_bytes());
}

pub fn encode_ping(out: &mut Vec<u8>, opaque: [u8; 8], ack: bool) {
    let flags = if ack { FLAG_ACK } else { 0 };
    Head::new(Kind::Ping, flags, StreamId::ZERO).encode(8, out);
    out.extend_from_slice(&opaque);
}

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

/// §6.10 forbids any other frame between a HEADERS and its CONTINUATIONs,
/// so the whole block is written in one call.
///
/// `limit` must not be zero — it came off the wire and `chunks` panics on zero.
pub fn encode_header_block(
    out: &mut Vec<u8>,
    stream_id: StreamId,
    block: &[u8],
    limit: usize,
    end_stream: bool,
) {
    let mut fragments = block.chunks(limit.max(1));
    // An empty block is legal — `chunks` yields nothing for it.
    let first = fragments.next().unwrap_or(&[]);
    let mut rest = fragments.peekable();

    if rest.peek().is_none() {
        encode_headers_header(out, stream_id, first.len(), end_stream);
    } else {
        encode_headers_fragment_header(out, stream_id, first.len(), end_stream);
    }
    out.extend_from_slice(first);

    while let Some(fragment) = rest.next() {
        encode_continuation_header(out, stream_id, fragment.len(), rest.peek().is_none());
        out.extend_from_slice(fragment);
    }
}
