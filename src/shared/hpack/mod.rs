//! HPACK header compression (RFC 7541).
//!
//! Adapted from hyperium/h2 (MIT), see LICENSE-THIRD-PARTY. `Bytes` is gone
//! from the paths that read out of runtime-owned buffers; upstream's fixtures
//! and fuzz targets are removed.

mod decoder;
mod encoder;
pub(crate) mod header;
pub(crate) mod huffman;
mod table;

use crate::shared::hpack;

pub use self::decoder::{Decoder, DecoderError, NeedMore};
pub use self::encoder::Encoder;
pub use self::header::{BytesStr, Header};

/// Errors that can occur during parsing an HTTP/2 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The padding length was larger than the frame-header-specified
    /// length of the payload.
    TooMuchPadding,

    /// A HEADERS frame arrived on stream 0.
    InvalidStreamId,

    /// A request or response is malformed.
    MalformedMessage,

    /// Failed to perform HPACK decoding
    Hpack(hpack::DecoderError),
}
