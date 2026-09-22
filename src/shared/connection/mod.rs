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

use std::time::Duration;

pub mod output;
pub mod settings;
mod shared_connection;
pub mod stream_map;
pub mod stream_window;

pub use shared_connection::{CONNECTION_INITIAL_WINDOW_SIZE, SendSide, SharedConnection};

/// The one duration either loop ever arms a read deadline for.
///
/// Every wait built on it is a count of these rather than a timer of its own
/// length, and that is a performance decision, not a stylistic one. The runtime
/// keeps a store for exactly this duration, separate from its timewheel, and it
/// is the only one a read can afford: a timer is armed and cancelled on *every*
/// chunk, some 300k times a second per core, and a wheel entry is reclaimed
/// when the wheel ticks past it rather than when it is cancelled. Arming 30s on
/// the wheel at that rate measured 178 MB of RSS at 100 connections against
/// 10 MB here — half a minute of dead slots, all live at once.
///
/// Shared by both ends because the store is: a client that picked its own
/// round number would be on the wheel, paying that, for a tick it arms just as
/// often. It also caps the precision of anything counted in ticks — every
/// deadline either loop keeps is a multiple of this, and late by up to one.
pub const DEADLINE_TICK: Duration = Duration::from_secs(5);

/// A stream identifier with its reserved bit already masked off.
///
/// The wire type is [`StreamId`](crate::shared::codec::frames::stream_id::StreamId);
/// this is what the maps and the counters use, where the 31-bit value is all
/// that matters.
#[allow(non_camel_case_types)]
pub type STREAM_ID = u32;
