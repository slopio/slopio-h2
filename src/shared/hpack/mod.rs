//! Adapted from hyperium/h2 (MIT), see LICENSE-THIRD-PARTY.

mod decoder;
mod encoder;
pub(crate) mod header;
pub(crate) mod huffman;
mod table;

use crate::shared::hpack;

pub use self::decoder::{Decoder, DecoderError};
pub use self::encoder::Encoder;
pub use self::header::{BytesStr, Header};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    TooMuchPadding,

    InvalidStreamId,

    MalformedMessage,

    Hpack(hpack::DecoderError),
}
