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
/// §6.5.2: SETTINGS_MAX_FRAME_SIZE until a peer says otherwise.
pub const DEFAULT_MAX_FRAME_SIZE: u32 = 16_384;
/// §3.4.
pub const CLIENT_PREFACE: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Limit on the *decompressed* header-list size (RFC 7541 §4.1: name, value
/// and 32 octets per field); the compressed cap cannot see an HPACK bomb.
/// Decoding always runs to the end (HPACK state must stay in sync); fields past
/// the limit are dropped and the block is flagged `is_over_size`.
pub const DECODE_MAX_HEADER_LIST_SIZE: usize = 16 * 1024;

/// Cap on *compressed* bytes accumulated across HEADERS + CONTINUATIONs before
/// END_HEADERS: defends against the CONTINUATION flood (CVE-2024-27316), where
/// nothing else limits how many CONTINUATIONs a peer may send. Compressed is
/// never much larger than decoded, so anything beyond would be refused anyway.
fn max_header_block_size(max_header_list_size: usize) -> usize {
    2 * max_header_list_size
}

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

/// Payload slices borrow from the decoder's input buffer and are only valid
/// for the duration of the call.
pub trait FrameHandler {
    /// `padded_len` (pad-length byte + body + padding) is what flow control
    /// accounts against per §6.9.1.
    ///
    /// Not once per frame: an unpadded DATA frame cut by a read comes one call
    /// per piece, each accounting for its own bytes; only the last carries
    /// `end_stream`. [`on_frame`](Self::on_frame) is still once per frame.
    fn on_data(&mut self, stream_id: StreamId, payload: &[u8], padded_len: usize, end_stream: bool);

    fn stream_error_scope(&self, _violation: StreamViolation) -> ErrorScope {
        ErrorScope::Stream
    }

    /// Invoked for every frame, before it is validated or handled.
    fn on_frame(&mut self, _kind: FrameKind, _stream_id: StreamId, _length: u32, _flags: u8) {}

    /// Runs before any following frame is dispatched: the server preface must
    /// be written before anything they queue (e.g. a SETTINGS ACK).
    fn on_preface(&mut self) {}

    /// Boxed on purpose: by value costs +840 bytes per stream task future
    /// (measured). See `notes.md`.
    fn on_headers(&mut self, headers: Box<Headers>);

    fn on_settings(&mut self, ack: bool, settings: SettingsIter<'_>);

    fn on_window_update(&mut self, stream_id: StreamId, increment: u32);

    fn on_rst_stream(&mut self, stream_id: StreamId, error_code: u32);

    fn on_ping(&mut self, ack: bool, opaque: [u8; 8]);

    fn on_goaway(&mut self, last_stream_id: StreamId, error_code: u32, debug_data: &[u8]);

    /// After a `Connection` error the decoder stops producing events.
    fn on_error(&mut self, err: DecodeError);
}

/// An unpadded DATA frame whose payload is still arriving. Padded frames never
/// come through here: telling body from padding needs the whole frame.
struct PartialData {
    stream_id: StreamId,
    /// Payload bytes still to come. Never zero while this is stored.
    left: u32,
    end_stream: bool,
}

struct HeaderBlockState {
    headers: Headers,
    buf: BytesMut,
}

pub struct FrameDecoder {
    hpack: hpack::Decoder,
    max_frame_size: u32,
    max_header_list_size: usize,
    remaining: Vec<u8>,
    partial_data: Option<PartialData>,
    header_block: Option<HeaderBlockState>,
    preface_seen: bool,
    /// Set once a connection-level error has been reported: further input is
    /// untrusted (framing / HPACK table may be out of sync), so `decode_with` no-ops.
    poisoned: bool,
}

impl FrameDecoder {
    pub fn preface_seen(&self) -> bool {
        self.preface_seen
    }

    /// §6.10 forbids interleaving, so a pending header block blocks every
    /// stream on the connection. An incomplete frame header counts too, so a
    /// slow *body* never does.
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
            partial_data: None,
            header_block: None,
            preface_seen: false,
            poisoned: false,
        }
    }

    /// Decoded size past which a header list is refused, and twice which a
    /// header block is a flood.
    pub fn with_max_header_list_size(mut self, size: usize) -> Self {
        self.max_header_list_size = size;
        self
    }

    /// No client preface inbound, so `on_preface` is never dispatched.
    pub fn client() -> Self {
        Self {
            preface_seen: true,
            ..Self::new()
        }
    }

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
            &mut self.partial_data,
            &mut self.header_block,
            data,
            handler,
        )
        .is_err()
        {
            self.poisoned = true;
        }
    }

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

/// `Err(())` = a connection-level error has already been reported and decoding
/// must stop. Stream-level errors return `Ok(())`.
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

fn report_violation<H: FrameHandler>(
    handler: &mut H,
    stream_id: StreamId,
    violation: StreamViolation,
) -> Decode {
    match handler.stream_error_scope(violation) {
        ErrorScope::Connection => report_connection(handler, violation.code(), violation.message()),
        ErrorScope::Stream => report_stream(handler, stream_id, violation),
    }
}

#[inline]
fn report_stream<H: FrameHandler>(
    handler: &mut H,
    stream_id: StreamId,
    violation: StreamViolation,
) -> Decode {
    handler.on_error(DecodeError::Stream {
        stream_id,
        violation,
        message: violation.message(),
    });
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn decode_inner<H: FrameHandler>(
    hpack: &mut hpack::Decoder,
    max_frame_size: u32,
    max_header_list_size: usize,
    remaining: &mut Vec<u8>,
    partial_data: &mut Option<PartialData>,
    header_block: &mut Option<HeaderBlockState>,
    data: &[u8],
    handler: &mut H,
) -> Decode {
    let mut pos = 0;
    if partial_data.is_some() {
        pos = continue_data(partial_data, data, handler);
    } else if !remaining.is_empty() {
        pos = handle_reassembly(
            hpack,
            max_frame_size,
            max_header_list_size,
            remaining,
            partial_data,
            header_block,
            data,
            handler,
        )?;
    }
    if partial_data.is_some() || !remaining.is_empty() {
        debug_assert_eq!(pos, data.len());
        return Ok(());
    }
    let consumed = decode_buf(
        hpack,
        max_frame_size,
        max_header_list_size,
        partial_data,
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

#[inline]
fn streams_payload(kind: FrameKind, flags: u8) -> bool {
    // §6.1: PADDED is 0x8.
    kind == FrameKind::Data && flags & 0x8 == 0
}

fn continue_data<H: FrameHandler>(
    partial_data: &mut Option<PartialData>,
    data: &[u8],
    handler: &mut H,
) -> usize {
    let Some(partial) = partial_data.as_mut() else {
        return 0;
    };
    let take = (partial.left as usize).min(data.len());
    partial.left -= take as u32;
    let (stream_id, done, end_stream) = (partial.stream_id, partial.left == 0, partial.end_stream);
    if done {
        *partial_data = None;
    }
    // An empty read is not an empty DATA frame, and must not look like one.
    if take > 0 {
        handler.on_data(stream_id, &data[..take], take, done && end_stream);
    }
    take
}

#[allow(clippy::too_many_arguments)]
fn begin_data<H: FrameHandler>(
    hpack: &mut hpack::Decoder,
    max_header_list_size: usize,
    partial_data: &mut Option<PartialData>,
    header_block: &mut Option<HeaderBlockState>,
    flags: u8,
    stream_id: StreamId,
    length: u32,
    available: &[u8],
    handler: &mut H,
) -> Decode<usize> {
    if available.len() >= length as usize {
        dispatch_frame(
            hpack,
            max_header_list_size,
            header_block,
            FrameKind::Data,
            flags,
            stream_id,
            length,
            &available[..length as usize],
            handler,
        )?;
        return Ok(length as usize);
    }

    // Must mirror `dispatch_frame`'s DATA checks, so a frame it would refuse
    // is refused before any of it lands.
    handler.on_frame(FrameKind::Data, stream_id, length, flags);
    if header_block.is_some() {
        return report_connection(
            handler,
            PROTOCOL_ERROR,
            "expected CONTINUATION frame while header block is incomplete",
        );
    }
    if stream_id.is_zero() {
        return report_connection(handler, PROTOCOL_ERROR, "DATA frame with stream ID 0");
    }

    *partial_data = Some(PartialData {
        stream_id,
        left: length,
        end_stream: flags & 0x1 != 0,
    });
    Ok(continue_data(partial_data, available, handler))
}

#[allow(clippy::too_many_arguments)]
fn handle_reassembly<H: FrameHandler>(
    hpack: &mut hpack::Decoder,
    max_frame_size: u32,
    max_header_list_size: usize,
    remaining: &mut Vec<u8>,
    partial_data: &mut Option<PartialData>,
    header_block: &mut Option<HeaderBlockState>,
    data: &[u8],
    handler: &mut H,
) -> Decode<usize> {
    let mut pos = 0;

    if remaining.len() < FRAME_HEADER_SIZE {
        let need = FRAME_HEADER_SIZE - remaining.len();
        let copy = data.len().min(need);
        remaining.extend_from_slice(&data[..copy]);
        pos += copy;
        if remaining.len() < FRAME_HEADER_SIZE {
            return Ok(pos);
        }
    }

    let (raw, _) = RawFrameHeader::ref_from_prefix(remaining.as_slice()).unwrap();
    let length = raw.length();
    let kind = FrameKind::from(raw.kind);
    let flags = raw.flags;
    let stream_id = StreamId::from(raw.stream_id());

    // Always connection-level (§4.2 allows stream-level for some kinds): the
    // declared length can't be trusted to skip and resync.
    if length > max_frame_size {
        return report_connection(handler, FRAME_SIZE_ERROR, "frame exceeds max_frame_size");
    }
    let total = FRAME_HEADER_SIZE + length as usize;

    // Only ever a header here: `decode_buf` starts on such a frame rather than
    // leave its payload behind.
    if streams_payload(kind, flags) {
        debug_assert_eq!(remaining.len(), FRAME_HEADER_SIZE);
        remaining.clear();
        let consumed = begin_data(
            hpack,
            max_header_list_size,
            partial_data,
            header_block,
            flags,
            stream_id,
            length,
            &data[pos..],
            handler,
        )?;
        return Ok(pos + consumed);
    }

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

fn decode_buf<H: FrameHandler>(
    hpack: &mut hpack::Decoder,
    max_frame_size: u32,
    max_header_list_size: usize,
    partial_data: &mut Option<PartialData>,
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
            if streams_payload(kind, flags) {
                offset += FRAME_HEADER_SIZE
                    + begin_data(
                        hpack,
                        max_header_list_size,
                        partial_data,
                        header_block,
                        flags,
                        stream_id,
                        length,
                        &remaining[FRAME_HEADER_SIZE..],
                        handler,
                    )?;
            }
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
                if hpack_buf.len() > max_header_block_size(max_header_list_size) {
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
            if state.buf.len() > max_header_block_size(max_header_list_size) {
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
                    false => {
                        report_violation(handler, stream_id, StreamViolation::ZeroWindowIncrement)
                    }
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
                return report_violation(
                    handler,
                    stream_id,
                    StreamViolation::PrioritySelfDependency,
                );
            }
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

/// Both padding errors are connection-level per §6.1.
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

/// HEADERS envelope errors are all connection-level.
fn report_headers_load<H: FrameHandler>(handler: &mut H, e: crate::shared::hpack::Error) -> Decode {
    let message = match e {
        crate::shared::hpack::Error::InvalidStreamId => "HEADERS frame with stream ID 0",
        _ => "malformed HEADERS frame",
    };
    report_connection(handler, PROTOCOL_ERROR, message)
}

/// `MalformedMessage` is stream-level per §8.1.1; decompression failures are
/// connection-level COMPRESSION_ERROR (§4.3).
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
                DecodeError::Stream {
                    violation, message, ..
                } => self.errors.push((violation.code(), message)),
            }
        }
    }

    fn push_frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream_id: u32, payload: &[u8]) {
        let len = payload.len() as u32;
        out.extend_from_slice(&len.to_be_bytes()[1..]);
        out.push(kind);
        out.push(flags);
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(payload);
    }

    /// CVE-2024-27316.
    #[test]
    fn continuation_flood_is_rejected() {
        const HEADERS: u8 = 0x1;
        const CONTINUATION: u8 = 0x9;
        let frame_payload = vec![0u8; DEFAULT_MAX_FRAME_SIZE as usize];

        let mut input = Vec::new();
        input.extend_from_slice(CLIENT_PREFACE);
        push_frame(&mut input, HEADERS, 0x0, 1, &frame_payload);
        let n = max_header_block_size(DECODE_MAX_HEADER_LIST_SIZE) / frame_payload.len() + 4;
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
        assert_eq!(
            rec.headers, 0,
            "block never completes, so no headers dispatched"
        );

        // Poisoned: further flood is ignored, so memory cannot keep growing.
        let mut more = Vec::new();
        push_frame(&mut more, CONTINUATION, 0x0, 1, &frame_payload);
        decoder.decode_with(&more, &mut rec);
        assert_eq!(
            rec.errors.len(),
            1,
            "poisoned decoder raises no further errors"
        );
    }

    #[test]
    fn small_header_block_with_continuation_is_accepted() {
        const HEADERS: u8 = 0x1;
        const CONTINUATION: u8 = 0x9;
        const END_HEADERS: u8 = 0x4;

        let mut input = Vec::new();
        input.extend_from_slice(CLIENT_PREFACE);
        push_frame(&mut input, HEADERS, 0x0, 1, &[]);
        push_frame(&mut input, CONTINUATION, END_HEADERS, 1, &[0x82]);

        let mut rec = Recorder::default();
        let mut decoder = FrameDecoder::new();
        decoder.decode_with(&input, &mut rec);

        assert!(
            rec.errors.is_empty(),
            "valid small block must not error: {:?}",
            rec.errors
        );
        assert_eq!(
            rec.headers, 1,
            "the reassembled block must be dispatched once"
        );
    }
    #[derive(Default)]
    struct DataRecorder {
        calls: Vec<(u32, Vec<u8>, usize, bool)>,
        data_frames: usize,
        pings: usize,
        errors: Vec<(u32, &'static str)>,
    }

    impl DataRecorder {
        fn body(&self) -> Vec<u8> {
            self.calls.iter().flat_map(|call| call.1.clone()).collect()
        }
    }

    impl FrameHandler for DataRecorder {
        fn on_data(&mut self, id: StreamId, payload: &[u8], padded_len: usize, end: bool) {
            self.calls
                .push((id.into(), payload.to_vec(), padded_len, end));
        }
        fn on_frame(&mut self, kind: FrameKind, _: StreamId, _: u32, _: u8) {
            if kind == FrameKind::Data {
                self.data_frames += 1;
            }
        }
        fn on_headers(&mut self, _: Box<Headers>) {}
        fn on_settings(&mut self, _: bool, _: SettingsIter<'_>) {}
        fn on_window_update(&mut self, _: StreamId, _: u32) {}
        fn on_rst_stream(&mut self, _: StreamId, _: u32) {}
        fn on_ping(&mut self, _: bool, _: [u8; 8]) {
            self.pings += 1;
        }
        fn on_goaway(&mut self, _: StreamId, _: u32, _: &[u8]) {}
        fn on_error(&mut self, err: DecodeError) {
            match err {
                DecodeError::Connection { code, message } => self.errors.push((code, message)),
                DecodeError::Stream {
                    violation, message, ..
                } => self.errors.push((violation.code(), message)),
            }
        }
    }

    const DATA: u8 = 0x0;
    const PING: u8 = 0x6;
    const END_STREAM: u8 = 0x1;
    const PADDED: u8 = 0x8;

    fn body(len: usize) -> Vec<u8> {
        (0..len).map(|i| i as u8).collect()
    }

    /// Reaches the stream whole, in order and once, and none of the payload is
    /// parked in `remaining` on the way.
    #[test]
    fn a_data_frame_cut_anywhere_is_delivered_in_pieces() {
        let payload = body(300);
        let mut input = Vec::new();
        push_frame(&mut input, DATA, 0, 1, &payload);
        push_frame(&mut input, DATA, END_STREAM, 1, &payload);
        push_frame(&mut input, PING, 0, 0, &[7; 8]);

        for cut in 1..input.len() {
            let mut rec = DataRecorder::default();
            let mut decoder = FrameDecoder::client();
            for piece in [&input[..cut], &input[cut..]] {
                decoder.decode_with(piece, &mut rec);
                assert!(
                    decoder.remaining.len() < FRAME_HEADER_SIZE + 8,
                    "cut {cut}: {} bytes gathered",
                    decoder.remaining.len()
                );
            }

            assert_eq!(rec.errors, [], "cut {cut}");
            assert_eq!(
                rec.body(),
                [payload.clone(), payload.clone()].concat(),
                "cut {cut}"
            );
            assert_eq!(rec.data_frames, 2, "cut {cut}: `on_frame` is per frame");
            assert_eq!(rec.pings, 1, "cut {cut}: what follows is still framed");
            assert!(rec.calls.len() <= 3, "cut {cut}: one cut, one extra call");
            for call in &rec.calls {
                assert!(!call.1.is_empty(), "cut {cut}: a piece is never empty");
                assert_eq!(call.2, call.1.len(), "cut {cut}: each accounts for itself");
            }
            let ends: Vec<bool> = rec.calls.iter().map(|call| call.3).collect();
            assert_eq!(
                ends.iter().filter(|end| **end).count(),
                1,
                "cut {cut}: END_STREAM once"
            );
            assert_eq!(ends.last(), Some(&true), "cut {cut}: and on the last piece");
        }
    }

    #[test]
    fn a_data_frame_fed_a_byte_at_a_time_adds_up() {
        let payload = body(64);
        let mut input = Vec::new();
        push_frame(&mut input, DATA, END_STREAM, 3, &payload);
        push_frame(&mut input, PING, 0, 0, &[7; 8]);

        let mut rec = DataRecorder::default();
        let mut decoder = FrameDecoder::client();
        for byte in &input {
            decoder.decode_with(std::slice::from_ref(byte), &mut rec);
        }

        assert_eq!(rec.errors, []);
        assert_eq!(rec.body(), payload);
        assert_eq!(rec.calls.iter().map(|call| call.2).sum::<usize>(), 64);
        assert_eq!(rec.calls.iter().filter(|call| call.3).count(), 1);
        assert_eq!((rec.data_frames, rec.pings), (1, 1));
    }

    /// One call, the body alone, flow control for all of it.
    #[test]
    fn a_padded_data_frame_is_still_delivered_whole() {
        let mut framed = vec![4u8];
        framed.extend_from_slice(&body(20));
        framed.extend_from_slice(&[0; 4]);
        let mut input = Vec::new();
        push_frame(&mut input, DATA, PADDED | END_STREAM, 1, &framed);

        for cut in 1..input.len() {
            let mut rec = DataRecorder::default();
            let mut decoder = FrameDecoder::client();
            decoder.decode_with(&input[..cut], &mut rec);
            decoder.decode_with(&input[cut..], &mut rec);

            assert_eq!(rec.errors, [], "cut {cut}");
            assert_eq!(rec.calls, [(1, body(20), 25, true)], "cut {cut}");
        }
    }

    #[test]
    fn a_partial_data_frame_on_stream_zero_delivers_nothing() {
        let mut input = Vec::new();
        push_frame(&mut input, DATA, 0, 0, &body(100));

        let mut rec = DataRecorder::default();
        let mut decoder = FrameDecoder::client();
        decoder.decode_with(&input[..50], &mut rec);
        decoder.decode_with(&input[50..], &mut rec);

        assert_eq!(
            rec.errors,
            [(PROTOCOL_ERROR, "DATA frame with stream ID 0")]
        );
        assert_eq!(rec.calls, []);
    }
}
