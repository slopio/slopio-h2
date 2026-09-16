use bytes::BytesMut;
use zerocopy::{FromBytes, Immutable, KnownLayout, network_endian::U32};

use crate::shared::{
    codec::{
        frames::{
            head::{Head, Kind},
            headers::Headers,
            stream_id::StreamId,
        },
        types::{
            COMPRESSION_ERROR, DecodeError, ENHANCE_YOUR_CALM, ErrorScope, FRAME_SIZE_ERROR,
            PROTOCOL_ERROR, Setting, StreamViolation,
        },
    },
    hpack,
};

pub mod encode;
mod head;
pub mod headers;
pub mod stream_id;

const FRAME_HEADER_SIZE: usize = 9;
const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;
/// The 24-byte client connection preface (§3.4). The server validates it on
/// the inbound stream; a client writes it as the very first bytes it sends.
pub const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Hard cap on the *compressed* bytes accumulated across a HEADERS frame and
/// its CONTINUATIONs before END_HEADERS arrives. Bounds memory against the
/// CONTINUATION flood (CVE-2024-27316): each frame is individually ≤
/// `max_frame_size`, but nothing else limits how many CONTINUATIONs a peer may
/// send while never setting END_HEADERS. Twice `DECODE_MAX_HEADER_LIST_SIZE`:
/// compressed is never much larger than decoded, so anything beyond would be
/// refused after decoding anyway.
const MAX_HEADER_BLOCK_SIZE: usize = 2 * DECODE_MAX_HEADER_LIST_SIZE;

/// Limit on the *decompressed* header-list size (RFC 7541 §4.1: name + value
/// + 32 octets per field) enforced during HPACK decode, and advertised as
/// `SETTINGS_MAX_HEADER_LIST_SIZE`. The compressed cap above cannot see an
/// HPACK bomb: tiny on the wire, huge decoded. Decoding always runs to the
/// end (HPACK state must stay in sync); fields past the limit are dropped and
/// the block is flagged `is_over_size` for the handler to refuse.
pub const DECODE_MAX_HEADER_LIST_SIZE: usize = 16 * 1024;

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
struct RawFrameHeader {
    length: [u8; 3],
    kind: u8,
    flags: u8,
    stream_id: U32,
}

impl RawFrameHeader {
    fn length(&self) -> u32 {
        (self.length[0] as u32) << 16 | (self.length[1] as u32) << 8 | (self.length[2] as u32)
    }

    fn stream_id(&self) -> u32 {
        self.stream_id.get() & 0x7FFF_FFFF
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
}

impl From<u8> for FrameKind {
    fn from(value: u8) -> Self {
        match value {
            0x0 => FrameKind::Data,
            0x1 => FrameKind::Headers,
            0x2 => FrameKind::Priority,
            0x3 => FrameKind::RstStream,
            0x4 => FrameKind::Settings,
            0x5 => FrameKind::PushPromise,
            0x6 => FrameKind::Ping,
            0x7 => FrameKind::GoAway,
            0x8 => FrameKind::WindowUpdate,
            0x9 => FrameKind::Continuation,
            other => FrameKind::Unknown(other),
        }
    }
}

/// Zero-alloc iterator over a SETTINGS frame payload.
pub struct SettingsIter<'a> {
    buf: &'a [u8],
}

impl<'a> SettingsIter<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

impl<'a> Iterator for SettingsIter<'a> {
    type Item = Setting;

    fn next(&mut self) -> Option<Setting> {
        if self.buf.len() < 6 {
            return None;
        }
        let id = u16::from_be_bytes(self.buf[..2].try_into().unwrap());
        let value = u32::from_be_bytes(self.buf[2..6].try_into().unwrap());
        self.buf = &self.buf[6..];
        Some(match id {
            0x1 => Setting::HeaderTableSize(value),
            0x2 => Setting::EnablePush(value),
            0x3 => Setting::MaxConcurrentStreams(value),
            0x4 => Setting::InitialWindowSize(value),
            0x5 => Setting::MaxFrameSize(value),
            0x6 => Setting::MaxHeaderListSize(value),
            _ => Setting::Unknown { id, value },
        })
    }
}

/// Callback interface invoked by [`FrameDecoder`] during parsing.
///
/// Each method corresponds to one complete H2 frame; the decoder calls them
/// in the order frames appear on the wire. Payload slices borrow from the
/// decoder's input buffer and are only valid for the duration of the call —
/// implementations that need to retain the data must copy.
pub trait FrameHandler {
    /// `payload` is the unpadded body delivered to the application.
    /// `padded_len` is the original DATA frame payload length (pad-length
    /// byte + body + padding) — what flow control accounts against per
    /// §6.9.1.
    fn on_data(
        &mut self,
        stream_id: StreamId,
        payload: &[u8],
        padded_len: usize,
        end_stream: bool,
    );

    /// How far `violation` reaches. The decoder reports it as a connection
    /// error when this says so, and stops; the default keeps it to the stream.
    fn stream_error_scope(&self, _violation: StreamViolation) -> ErrorScope {
        ErrorScope::Stream
    }

    /// Invoked for every complete frame, before it is validated or handled:
    /// where accounting that depends only on the frame's type goes.
    fn on_frame(&mut self, _kind: FrameKind, _stream_id: StreamId, _length: u32, _flags: u8) {}

    /// Invoked once the 24-byte client preface has been validated, before
    /// any frames following it are dispatched. The server preface (a
    /// SETTINGS frame) must be the first thing we write, so handlers use
    /// this hook to enqueue it before the decoder begins processing
    /// subsequent frames (which may queue a SETTINGS ACK).
    fn on_preface(&mut self) {}

    /// Invoked once per complete header block (HEADERS + any CONTINUATIONs).
    /// `headers` is fully HPACK-decoded.
    ///
    /// Boxed on purpose, though the decoder is done with it: passing it by
    /// value saves this allocation but costs more than it saves. The value ends
    /// up in the stream task's future, where rustc keeps three live copies of
    /// it (the argument slot and two `RequestHead`s) — measured at +840 bytes
    /// per task and two 288-byte moves per request. See `notes.md`.
    fn on_headers(&mut self, headers: Box<Headers>);

    fn on_settings(&mut self, ack: bool, settings: SettingsIter<'_>);

    fn on_window_update(&mut self, stream_id: StreamId, increment: u32);

    fn on_rst_stream(&mut self, stream_id: StreamId, error_code: u32);

    fn on_ping(&mut self, ack: bool, opaque: [u8; 8]);

    fn on_goaway(&mut self, last_stream_id: StreamId, error_code: u32, debug_data: &[u8]);

    /// Reports a decoder-detected error. The handler is responsible for
    /// emitting the appropriate response (GOAWAY for `Connection`,
    /// RST_STREAM for `Stream`). After a `Connection` error the decoder
    /// stops producing events.
    fn on_error(&mut self, err: DecodeError);
}

/// State accumulated across HEADERS + CONTINUATION frames before HPACK decoding.
struct HeaderBlockState {
    headers: Headers,
    buf: BytesMut,
}

pub struct FrameDecoder {
    hpack: hpack::Decoder,
    max_frame_size: u32,
    max_header_list_size: usize,
    remaining: Vec<u8>,
    header_block: Option<HeaderBlockState>,
    preface_seen: bool,
    /// Set once a connection-level error has been reported. Further input is
    /// untrusted (frame alignment / HPACK table may be out of sync), so
    /// `decode_with` no-ops.
    poisoned: bool,
}

impl FrameDecoder {
    /// True once the 24-byte client preface has been validated.
    pub fn preface_seen(&self) -> bool {
        self.preface_seen
    }

    /// Whether the peer has started a header block and not finished it: a
    /// HEADERS or CONTINUATION still arriving, or a block waiting for its
    /// CONTINUATION. §6.10 forbids interleaving, so this state blocks every
    /// stream on the connection, not just its own.
    ///
    /// A frame header too short to carry its kind counts: nine bytes that take
    /// seconds to arrive are pathological whatever they turn out to introduce,
    /// and refusing to guess is what keeps a slow *body* from counting here.
    pub fn header_pending(&self) -> bool {
        if self.header_block.is_some() {
            return true;
        }
        if self.remaining.is_empty() {
            return false;
        }
        self.remaining.len() < FRAME_HEADER_SIZE
            || matches!(
                FrameKind::from(self.remaining[3]),
                FrameKind::Headers | FrameKind::Continuation,
            )
    }

    pub fn new() -> Self {
        Self {
            hpack: hpack::Decoder::default(),
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
            max_header_list_size: DECODE_MAX_HEADER_LIST_SIZE,
            remaining: Vec::new(),
            header_block: None,
            preface_seen: false,
            poisoned: false,
        }
    }

    /// Decoder for the **client** side: the inbound stream (server → client)
    /// carries no client preface, so it starts already past preface validation.
    /// `on_preface` is therefore never dispatched; the client emits its own
    /// preface out-of-band.
    pub fn client() -> Self {
        Self {
            preface_seen: true,
            ..Self::new()
        }
    }

    /// Parse frames from `data` and dispatch them inline to `handler`.
    /// Errors are surfaced through `handler.on_error`; after a connection
    /// error subsequent calls are a no-op.
    pub fn decode_with<H: FrameHandler>(&mut self, data: &[u8], handler: &mut H) {
        if self.poisoned {
            return;
        }
        let data = if self.preface_seen {
            data
        } else {
            match self.consume_preface(data, handler) {
                Some(rest) => rest,
                None => return,
            }
        };
        if decode_inner(
            &mut self.hpack,
            self.max_frame_size,
            self.max_header_list_size,
            &mut self.remaining,
            &mut self.header_block,
            data,
            handler,
        )
        .is_err()
        {
            self.poisoned = true;
        }
    }

    /// Accumulate up to 24 bytes of the client connection preface. Returns
    /// `Some(rest)` once matched, `None` while buffering or after reporting
    /// a preface mismatch.
    fn consume_preface<'a, H: FrameHandler>(
        &mut self,
        data: &'a [u8],
        handler: &mut H,
    ) -> Option<&'a [u8]> {
        let need = CLIENT_PREFACE.len() - self.remaining.len();
        let take = data.len().min(need);
        self.remaining.extend_from_slice(&data[..take]);
        if self.remaining.len() < CLIENT_PREFACE.len() {
            return None;
        }
        if self.remaining.as_slice() != CLIENT_PREFACE {
            handler.on_error(DecodeError::Connection {
                code: PROTOCOL_ERROR,
                message: "invalid HTTP/2 client preface",
            });
            self.poisoned = true;
            return None;
        }
        self.remaining.clear();
        self.preface_seen = true;
        handler.on_preface();
        Some(&data[take..])
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Internal control signal for decoder helpers: `Ok(())` = continue, `Err(())`
/// = a connection-level error has already been reported via `handler.on_error`
/// and decoding must stop. Stream-level errors stay inside `dispatch_frame`
/// and return `Ok(())` (skip the frame, keep going).
type Decode<T = ()> = Result<T, ()>;

#[inline]
fn report_connection<H: FrameHandler, T>(
    handler: &mut H,
    code: u32,
    message: &'static str,
) -> Decode<T> {
    handler.on_error(DecodeError::Connection { code, message });
    Err(())
}

/// A stream error, reported at the scope the handler gives it.
fn report_violation<H: FrameHandler>(
    handler: &mut H,
    stream_id: StreamId,
    violation: StreamViolation,
) -> Decode {
    match handler.stream_error_scope(violation) {
        ErrorScope::Connection => report_connection(handler, violation.code(), violation.message()),
        ErrorScope::Stream => report_stream(handler, stream_id, violation.code(), violation.message()),
    }
}

#[inline]
fn report_stream<H: FrameHandler>(
    handler: &mut H,
    stream_id: StreamId,
    code: u32,
    message: &'static str,
) -> Decode {
    handler.on_error(DecodeError::Stream {
        stream_id,
        code,
        message,
    });
    Ok(())
}

fn decode_inner<H: FrameHandler>(
    hpack: &mut hpack::Decoder,
    max_frame_size: u32,
    max_header_list_size: usize,
    remaining: &mut Vec<u8>,
    header_block: &mut Option<HeaderBlockState>,
    data: &[u8],
    handler: &mut H,
) -> Decode {
    let mut pos = 0;
    if !remaining.is_empty() {
        pos = handle_reassembly(
            hpack,
            max_frame_size,
            max_header_list_size,
            remaining,
            header_block,
            data,
            handler,
        )?;
    }
    let consumed = decode_buf(
        hpack,
        max_frame_size,
        max_header_list_size,
        header_block,
        &data[pos..],
        handler,
    )?;
    let leftover = &data[pos + consumed..];
    if !leftover.is_empty() {
        remaining.extend_from_slice(leftover);
    }
    Ok(())
}

/// Complete a partial frame using bytes from `data`.
/// Returns the number of bytes consumed from `data`.
fn handle_reassembly<H: FrameHandler>(
    hpack: &mut hpack::Decoder,
    max_frame_size: u32,
    max_header_list_size: usize,
    remaining: &mut Vec<u8>,
    header_block: &mut Option<HeaderBlockState>,
    data: &[u8],
    handler: &mut H,
) -> Decode<usize> {
    let mut pos = 0;

    // Step 1: ensure we have a full 9-byte header in remaining.
    if remaining.len() < FRAME_HEADER_SIZE {
        let need = FRAME_HEADER_SIZE - remaining.len();
        let copy = data.len().min(need);
        remaining.extend_from_slice(&data[..copy]);
        pos += copy;
        if remaining.len() < FRAME_HEADER_SIZE {
            return Ok(pos);
        }
    }

    // Step 2: parse the header.
    let (raw, _) = RawFrameHeader::ref_from_prefix(remaining.as_slice()).unwrap();
    let length = raw.length();
    let kind = FrameKind::from(raw.kind);
    let flags = raw.flags;
    let stream_id = StreamId::from(raw.stream_id());

    // max_frame_size violation: treated as connection-level here regardless of
    // frame kind. Per RFC §4.2 some cases (e.g. oversized DATA) could be
    // stream-level, but without trusting the declared length to skip we can't
    // resync — so we close the connection.
    if length > max_frame_size {
        return report_connection(handler, FRAME_SIZE_ERROR, "frame exceeds max_frame_size");
    }
    let total = FRAME_HEADER_SIZE + length as usize;

    // Step 3: gather the rest of the frame into `remaining`.
    let payload_in_remaining = remaining.len() - FRAME_HEADER_SIZE;
    let need_from_data = (length as usize).saturating_sub(payload_in_remaining);
    let available = data.len() - pos;
    if available < need_from_data {
        remaining.extend_from_slice(&data[pos..]);
        return Ok(data.len());
    }
    remaining.extend_from_slice(&data[pos..pos + need_from_data]);
    pos += need_from_data;

    let payload = &remaining[FRAME_HEADER_SIZE..total];
    dispatch_frame(
        hpack,
        max_header_list_size,
        header_block,
        kind,
        flags,
        stream_id,
        length,
        payload,
        handler,
    )?;
    remaining.clear();
    Ok(pos)
}

/// Decode as many complete frames as possible from `buf`. Returns bytes consumed.
fn decode_buf<H: FrameHandler>(
    hpack: &mut hpack::Decoder,
    max_frame_size: u32,
    max_header_list_size: usize,
    header_block: &mut Option<HeaderBlockState>,
    buf: &[u8],
    handler: &mut H,
) -> Decode<usize> {
    let mut offset = 0;
    loop {
        let remaining = &buf[offset..];
        if remaining.len() < FRAME_HEADER_SIZE {
            break;
        }
        let (raw, _) = RawFrameHeader::ref_from_prefix(remaining).unwrap();
        let length = raw.length();
        let kind = FrameKind::from(raw.kind);
        let flags = raw.flags;
        let stream_id = StreamId::from(raw.stream_id());

        if length > max_frame_size {
            return report_connection(handler, FRAME_SIZE_ERROR, "frame exceeds max_frame_size");
        }
        let total = FRAME_HEADER_SIZE + length as usize;
        if remaining.len() < total {
            break;
        }

        let payload = &remaining[FRAME_HEADER_SIZE..total];
        dispatch_frame(
            hpack,
            max_header_list_size,
            header_block,
            kind,
            flags,
            stream_id,
            length,
            payload,
            handler,
        )?;
        offset += total;
    }
    Ok(offset)
}

#[allow(clippy::too_many_arguments)]
fn dispatch_frame<H: FrameHandler>(
    hpack: &mut hpack::Decoder,
    max_header_list_size: usize,
    header_block: &mut Option<HeaderBlockState>,
    kind: FrameKind,
    flags: u8,
    stream_id: StreamId,
    length: u32,
    payload: &[u8],
    handler: &mut H,
) -> Decode {
    handler.on_frame(kind, stream_id, length, flags);

    // While accumulating a header block, only CONTINUATION is valid (§6.10).
    if header_block.is_some() && kind != FrameKind::Continuation {
        return report_connection(
            handler,
            PROTOCOL_ERROR,
            "expected CONTINUATION frame while header block is incomplete",
        );
    }

    match kind {
        FrameKind::Data => {
            if stream_id.is_zero() {
                return report_connection(handler, PROTOCOL_ERROR, "DATA frame with stream ID 0");
            }
            let padded_len = payload.len();
            let unpadded = strip_data_padding(payload, flags, handler)?;
            handler.on_data(stream_id, unpadded, padded_len, flags & 0x1 != 0);
        }

        FrameKind::Headers => {
            let head = Head::new(Kind::Headers, flags, stream_id);
            let payload_buf = hpack.stage(payload);
            let (mut headers, mut hpack_buf) = match Headers::load(head, payload_buf) {
                Ok(v) => v,
                Err(e) => return report_headers_load(handler, e),
            };
            if headers.is_end_headers() {
                let hdr_stream = headers.stream_id();
                if let Err(e) = headers.load_hpack(&mut hpack_buf, max_header_list_size, hpack) {
                    return report_hpack(handler, hdr_stream, e);
                }
                handler.on_headers(Box::new(headers));
            } else {
                if hpack_buf.len() > MAX_HEADER_BLOCK_SIZE {
                    return report_connection(
                        handler,
                        ENHANCE_YOUR_CALM,
                        "header block exceeds maximum size",
                    );
                }
                *header_block = Some(HeaderBlockState {
                    headers,
                    buf: hpack_buf,
                });
            }
        }

        FrameKind::Continuation => {
            if stream_id.is_zero() {
                return report_connection(
                    handler,
                    PROTOCOL_ERROR,
                    "CONTINUATION frame with stream ID 0",
                );
            }
            let state = match header_block.as_mut() {
                Some(s) => s,
                None => {
                    return report_connection(
                        handler,
                        PROTOCOL_ERROR,
                        "CONTINUATION without preceding HEADERS",
                    );
                }
            };
            if state.headers.stream_id() != stream_id {
                return report_connection(
                    handler,
                    PROTOCOL_ERROR,
                    "CONTINUATION frame on different stream than HEADERS",
                );
            }
            state.buf.extend_from_slice(payload);
            if state.buf.len() > MAX_HEADER_BLOCK_SIZE {
                return report_connection(
                    handler,
                    ENHANCE_YOUR_CALM,
                    "header block exceeds maximum size",
                );
            }
            let end_headers = flags & 0x4 != 0;
            if end_headers {
                let mut state = header_block.take().unwrap();
                let hdr_stream = state.headers.stream_id();
                if let Err(e) =
                    state
                        .headers
                        .load_hpack(&mut state.buf, max_header_list_size, hpack)
                {
                    return report_hpack(handler, hdr_stream, e);
                }
                handler.on_headers(Box::new(state.headers));
            }
        }

        FrameKind::Settings => {
            if !stream_id.is_zero() {
                return report_connection(
                    handler,
                    PROTOCOL_ERROR,
                    "SETTINGS frame with non-zero stream ID",
                );
            }
            let ack = flags & 0x1 != 0;
            if ack && !payload.is_empty() {
                return report_connection(
                    handler,
                    FRAME_SIZE_ERROR,
                    "SETTINGS ACK with non-empty payload",
                );
            }
            if !payload.len().is_multiple_of(6) {
                return report_connection(
                    handler,
                    FRAME_SIZE_ERROR,
                    "SETTINGS payload not a multiple of 6",
                );
            }
            handler.on_settings(ack, SettingsIter::new(payload));
        }

        FrameKind::WindowUpdate => {
            // §6.9: wrong length is always a connection error.
            if length != 4 {
                return report_connection(
                    handler,
                    FRAME_SIZE_ERROR,
                    "WINDOW_UPDATE frame must be 4 bytes",
                );
            }
            let increment = u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7FFF_FFFF;
            // §6.9.1: connection error on stream 0, a stream error otherwise.
            if increment == 0 {
                return match stream_id.is_zero() {
                    true => report_connection(
                        handler,
                        PROTOCOL_ERROR,
                        "WINDOW_UPDATE with zero increment on connection",
                    ),
                    false => report_violation(handler, stream_id, StreamViolation::ZeroWindowIncrement),
                };
            }
            handler.on_window_update(stream_id, increment);
        }

        FrameKind::RstStream => {
            if stream_id.is_zero() {
                return report_connection(
                    handler,
                    PROTOCOL_ERROR,
                    "RST_STREAM frame with stream ID 0",
                );
            }
            // §6.4: wrong length is always a connection error.
            if length != 4 {
                return report_connection(
                    handler,
                    FRAME_SIZE_ERROR,
                    "RST_STREAM frame must be 4 bytes",
                );
            }
            let error_code = u32::from_be_bytes(payload[..4].try_into().unwrap());
            handler.on_rst_stream(stream_id, error_code);
        }

        FrameKind::Ping => {
            if !stream_id.is_zero() {
                return report_connection(
                    handler,
                    PROTOCOL_ERROR,
                    "PING frame with non-zero stream ID",
                );
            }
            if length != 8 {
                return report_connection(handler, FRAME_SIZE_ERROR, "PING frame must be 8 bytes");
            }
            let opaque: [u8; 8] = payload[..8].try_into().unwrap();
            handler.on_ping(flags & 0x1 != 0, opaque);
        }

        FrameKind::GoAway => {
            if !stream_id.is_zero() {
                return report_connection(
                    handler,
                    PROTOCOL_ERROR,
                    "GOAWAY frame with non-zero stream ID",
                );
            }
            if length < 8 {
                return report_connection(
                    handler,
                    FRAME_SIZE_ERROR,
                    "GOAWAY frame must be at least 8 bytes",
                );
            }
            let last_stream_id =
                StreamId::from(u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7FFF_FFFF);
            let error_code = u32::from_be_bytes(payload[4..8].try_into().unwrap());
            handler.on_goaway(last_stream_id, error_code, &payload[8..]);
        }

        FrameKind::Priority => {
            // §6.3: stream ID 0 is a connection error.
            if stream_id.is_zero() {
                return report_connection(
                    handler,
                    PROTOCOL_ERROR,
                    "PRIORITY frame with stream ID 0",
                );
            }
            if length != 5 {
                return report_violation(handler, stream_id, StreamViolation::PriorityLength);
            }
            let (dep_id, _exclusive) = StreamId::parse(&payload[..4]);
            if dep_id == stream_id {
                return report_violation(handler, stream_id, StreamViolation::PrioritySelfDependency);
            }
            // PRIORITY is validated but not emitted.
        }

        FrameKind::PushPromise => {
            return report_connection(handler, PROTOCOL_ERROR, "PUSH_PROMISE from client");
        }

        FrameKind::Unknown(_) => {
            // Unknown frames are silently ignored per RFC 9113 §4.1.
        }
    }
    Ok(())
}

/// Strip the optional pad-length byte and trailing padding from a DATA
/// payload. Both padding errors are connection-level per §6.1.
fn strip_data_padding<'a, H: FrameHandler>(
    payload: &'a [u8],
    flags: u8,
    handler: &mut H,
) -> Decode<&'a [u8]> {
    if flags & 0x8 == 0 {
        return Ok(payload);
    }
    if payload.is_empty() {
        return report_connection(
            handler,
            PROTOCOL_ERROR,
            "DATA with PADDED flag but no payload",
        );
    }
    let pad_len = payload[0] as usize;
    if pad_len >= payload.len() {
        return report_connection(handler, PROTOCOL_ERROR, "DATA pad length exceeds payload");
    }
    Ok(&payload[1..payload.len() - pad_len])
}

/// Errors from parsing the HEADERS frame envelope (padding byte, priority
/// bits, stream id) — all connection-level.
fn report_headers_load<H: FrameHandler>(handler: &mut H, e: crate::shared::hpack::Error) -> Decode {
    let message = match e {
        crate::shared::hpack::Error::InvalidStreamId => "HEADERS frame with stream ID 0",
        _ => "malformed HEADERS frame",
    };
    report_connection(handler, PROTOCOL_ERROR, message)
}

/// Errors from HPACK-decoding a complete header block. `MalformedMessage`
/// (request semantics, e.g. pseudo-header order) is stream-level per §8.1.1;
/// true decompression failures are connection-level COMPRESSION_ERROR (§4.3).
fn report_hpack<H: FrameHandler>(
    handler: &mut H,
    stream_id: StreamId,
    e: crate::shared::hpack::Error,
) -> Decode {
    match e {
        crate::shared::hpack::Error::MalformedMessage => {
            report_violation(handler, stream_id, StreamViolation::MalformedMessage)
        }
        _ => report_connection(handler, COMPRESSION_ERROR, "HPACK decompression failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::codec::types::ENHANCE_YOUR_CALM;

    /// Records what the decoder dispatches so tests can assert on it.
    #[derive(Default)]
    struct Recorder {
        headers: usize,
        errors: Vec<(u32, &'static str)>,
    }

    impl FrameHandler for Recorder {
        fn on_data(&mut self, _: StreamId, _: &[u8], _: usize, _: bool) {}
        fn on_headers(&mut self, _: Box<Headers>) {
            self.headers += 1;
        }
        fn on_settings(&mut self, _: bool, _: SettingsIter<'_>) {}
        fn on_window_update(&mut self, _: StreamId, _: u32) {}
        fn on_rst_stream(&mut self, _: StreamId, _: u32) {}
        fn on_ping(&mut self, _: bool, _: [u8; 8]) {}
        fn on_goaway(&mut self, _: StreamId, _: u32, _: &[u8]) {}
        fn on_error(&mut self, err: DecodeError) {
            match err {
                DecodeError::Connection { code, message } => self.errors.push((code, message)),
                DecodeError::Stream { code, message, .. } => self.errors.push((code, message)),
            }
        }
    }

    /// Append one HTTP/2 frame (9-byte header + payload) to `out`.
    fn push_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
        let len = payload.len() as u32;
        out.extend_from_slice(&len.to_be_bytes()[1..]); // 24-bit length
        out.push(kind);
        out.push(flags);
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(payload);
    }

    /// CONTINUATION flood (CVE-2024-27316): a HEADERS frame without END_HEADERS
    /// followed by an unbounded stream of CONTINUATION frames that never set
    /// END_HEADERS must be rejected once the accumulated block exceeds the cap,
    /// rather than buffered without limit.
    #[test]
    fn continuation_flood_is_rejected() {
        const HEADERS: u8 = 0x1;
        const CONTINUATION: u8 = 0x9;
        let frame_payload = vec![0u8; DEFAULT_MAX_FRAME_SIZE as usize]; // ≤ max_frame_size

        let mut input = Vec::new();
        input.extend_from_slice(CLIENT_PREFACE);
        // HEADERS on stream 1, no END_HEADERS → opens an incomplete header block.
        push_frame(&mut input, HEADERS, 0x0, 1, &frame_payload);
        // Enough CONTINUATIONs (also no END_HEADERS) to blow past the cap.
        // Cap / frame_size, rounded up, plus slack.
        let n = MAX_HEADER_BLOCK_SIZE / frame_payload.len() + 4;
        for _ in 0..n {
            push_frame(&mut input, CONTINUATION, 0x0, 1, &frame_payload);
        }

        let mut rec = Recorder::default();
        let mut decoder = FrameDecoder::new();
        decoder.decode_with(&input, &mut rec);

        assert_eq!(
            rec.errors,
            vec![(ENHANCE_YOUR_CALM, "header block exceeds maximum size")],
            "flood must raise exactly one ENHANCE_YOUR_CALM connection error",
        );
        assert_eq!(rec.headers, 0, "block never completes, so no headers dispatched");

        // After a connection error the decoder is poisoned: further input — even
        // more flood — is ignored, so memory cannot keep growing.
        let mut more = Vec::new();
        push_frame(&mut more, CONTINUATION, 0x0, 1, &frame_payload);
        decoder.decode_with(&more, &mut rec);
        assert_eq!(rec.errors.len(), 1, "poisoned decoder raises no further errors");
    }

    /// A header block that stays under the cap and ends with END_HEADERS must
    /// still decode normally — the cap must not reject legitimate traffic.
    #[test]
    fn small_header_block_with_continuation_is_accepted() {
        const HEADERS: u8 = 0x1;
        const CONTINUATION: u8 = 0x9;
        const END_HEADERS: u8 = 0x4;

        // A single indexed header field (":method: GET" = static index 2),
        // split HEADERS (empty) + CONTINUATION (the byte) to exercise reassembly.
        let mut input = Vec::new();
        input.extend_from_slice(CLIENT_PREFACE);
        push_frame(&mut input, HEADERS, 0x0, 1, &[]);
        push_frame(&mut input, CONTINUATION, END_HEADERS, 1, &[0x82]); // 0x82 = indexed 2

        let mut rec = Recorder::default();
        let mut decoder = FrameDecoder::new();
        decoder.decode_with(&input, &mut rec);

        assert!(rec.errors.is_empty(), "valid small block must not error: {:?}", rec.errors);
        assert_eq!(rec.headers, 1, "the reassembled block must be dispatched once");
    }
}
