//! Everything that is gRPC rather than HTTP/2, in one place — so that it can
//! become a feature, and so that nothing of HTTP/2 has to know what a message
//! is.

mod encode;
mod frame;
mod input;
mod prefix;
mod request;

pub use frame::{
    Accumulating, CompressedGrpcFrame, DecompressError, FrameOverflow, GrpcEncoding, GrpcFrame,
    MessageError, UncompressedGrpcFrame,
};
pub use encode::frame_message;
pub use input::GrpcError;
pub(crate) use input::GrpcInput;
pub use request::GrpcFormat;
