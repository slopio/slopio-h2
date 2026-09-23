use std::time::Duration;

pub mod output;
pub mod settings;
mod shared_connection;
pub mod stream_map;
pub mod stream_window;

pub use shared_connection::{CONNECTION_INITIAL_WINDOW_SIZE, SendSide, SharedConnection};

/// Must stay the runtime's dedicated read-deadline duration: any other length
/// goes on the timewheel, where the per-chunk arm/cancel churn leaves dead
/// entries until the wheel ticks past them (178 MB vs 10 MB RSS at 100
/// connections). Every deadline counted in ticks is late by up to one.
pub const DEADLINE_TICK: Duration = Duration::from_secs(5);

/// Reserved bit already masked off.
#[allow(non_camel_case_types)]
pub type STREAM_ID = u32;
