//! Everything that is gRPC rather than HTTP/2, in one place — so that it can
//! become a feature, and so that nothing of HTTP/2 has to know what a message
//! is.

mod call;
pub mod client;
mod encode;
mod frame;
mod input;
mod prefix;
mod request;
mod status;
mod timeout;

pub use frame::{
    Accumulating, CompressedGrpcFrame, DecompressError, FrameOverflow, GrpcEncoding, GrpcFrame,
    MessageError, UncompressedGrpcFrame,
};
pub use encode::frame_message;
pub use input::{GrpcError, GrpcInput};
pub use request::GrpcFormat;
pub use call::{GrpcCall, service};
// The caller's side, named for what it wraps. `client::Call` is the handle
// itself, and is reached through here rather than named.
pub use client::Client as GrpcClient;
pub use status::{Code, Status};
