//! Connection machinery that does not know which end of the connection it is.
//!
//! A send chain, a map of live streams, the two flow-control windows and the
//! peer's settings are the same whichever side holds them: a client and a
//! server both queue frames, both track streams by id, both credit and debit
//! windows in the same direction relative to themselves. What differs is what
//! the frames *mean*, and that stays in `server` and `client`.
//!
//! These lived under `server` until a client needed them, which is the usual
//! way to find out that something was never server-specific.

pub mod output;
pub mod settings;
mod shared_connection;
pub mod stream_map;
pub mod stream_window;

pub use shared_connection::{CONNECTION_INITIAL_WINDOW_SIZE, SendSide, SharedConnection};

/// A stream identifier with its reserved bit already masked off.
///
/// The wire type is [`StreamId`](crate::shared::codec::frames::stream_id::StreamId);
/// this is what the maps and the counters use, where the 31-bit value is all
/// that matters.
#[allow(non_camel_case_types)]
pub type STREAM_ID = u32;
