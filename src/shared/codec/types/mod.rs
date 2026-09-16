use crate::shared::codec::frames::stream_id::StreamId;

/// An error detected by the frame decoder. The decoder reports these via
/// `FrameHandler::on_error`; the handler decides the response (typically
/// GOAWAY for `Connection`, RST_STREAM for `Stream`).
#[derive(Debug, Clone, Copy)]
pub enum DecodeError {
    /// Connection-level error (RFC 9113 §5.4.1). Once reported, the decoder
    /// no-ops on subsequent `decode_with` calls.
    Connection {
        code: u32,
        message: &'static str,
    },
    /// Stream-level error (RFC 9113 §5.4.2). Decoding continues with the
    /// next frame; the in-progress frame is discarded.
    Stream {
        stream_id: StreamId,
        code: u32,
        message: &'static str,
    },
}

/// A stream error the RFC names (§5.4.2), identified so a connection can
/// decide per violation whether resetting the stream is enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamViolation {
    /// §6.9: a WINDOW_UPDATE of 0 on a stream.
    ZeroWindowIncrement,
    /// §6.9.1: a WINDOW_UPDATE taking a stream's send window past 2^31-1.
    StreamWindowOverflow,
    /// §6.3: a PRIORITY frame not 5 bytes long.
    PriorityLength,
    /// §5.3.1: a PRIORITY frame making a stream depend on itself.
    PrioritySelfDependency,
    /// §5.3.1: a HEADERS frame making a stream depend on itself.
    HeadersSelfDependency,
    /// §8.1.1: a header block HPACK decoded but HTTP rejects.
    MalformedMessage,
    /// §8.3.1: a request missing or misusing its pseudo-headers.
    MalformedRequest,
    /// §8.1: trailers without END_STREAM, or with pseudo-headers.
    MalformedTrailers,
    /// §8.1.1: DATA payloads not adding up to `content-length`.
    ContentLengthMismatch,
}

impl StreamViolation {
    pub fn code(self) -> u32 {
        match self {
            Self::StreamWindowOverflow => FLOW_CONTROL_ERROR,
            Self::PriorityLength => FRAME_SIZE_ERROR,
            _ => PROTOCOL_ERROR,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::ZeroWindowIncrement => "WINDOW_UPDATE with zero increment",
            Self::StreamWindowOverflow => "stream send window exceeds 2^31-1",
            Self::PriorityLength => "PRIORITY frame must be 5 bytes",
            Self::PrioritySelfDependency | Self::HeadersSelfDependency => "stream depends on itself",
            Self::MalformedMessage => "malformed message",
            Self::MalformedRequest => "malformed request",
            Self::MalformedTrailers => "malformed trailers",
            Self::ContentLengthMismatch => "body does not match content-length",
        }
    }
}

/// How far a violation reaches: a reset of its stream, or the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorScope {
    Stream,
    Connection,
}

impl DecodeError {
    pub fn code(&self) -> u32 {
        match self {
            DecodeError::Connection { code, .. } | DecodeError::Stream { code, .. } => *code,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            DecodeError::Connection { message, .. } | DecodeError::Stream { message, .. } => {
                *message
            }
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Connection { message, .. } => write!(f, "connection error: {message}"),
            DecodeError::Stream {
                stream_id, message, ..
            } => write!(f, "stream {stream_id} error: {message}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Setting {
    HeaderTableSize(u32),
    EnablePush(u32),
    MaxConcurrentStreams(u32),
    InitialWindowSize(u32),
    MaxFrameSize(u32),
    MaxHeaderListSize(u32),
    Unknown { id: u16, value: u32 },
}

pub const HEADER_LEN: usize = 9;

// HTTP/2 error codes (RFC 9113 §7)
pub const NO_ERROR: u32 = 0x0;
pub const PROTOCOL_ERROR: u32 = 0x1;
pub const FLOW_CONTROL_ERROR: u32 = 0x3;
pub const STREAM_CLOSED: u32 = 0x5;
pub const FRAME_SIZE_ERROR: u32 = 0x6;
pub const REFUSED_STREAM: u32 = 0x7;
pub const CANCEL: u32 = 0x8;
pub const COMPRESSION_ERROR: u32 = 0x9;
pub const INTERNAL_ERROR: u32 = 0x2;
pub const ENHANCE_YOUR_CALM: u32 = 0xb;
