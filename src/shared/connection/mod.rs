use std::time::Duration;

pub mod body_length;
pub mod input_data;
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

/// The longest one `Sleep` will take: the runtime's timewheel holds an hour
/// and panics past it. Anything longer is waited in slices.
pub const MAX_SLEEP: Duration = Duration::from_secs(3600);

/// Yields an empty buffer ring gets before the loop sleeps instead. A yield
/// lets the other connections on the worker decode what they hold and recycle
/// it. Once that has not refilled the ring, what holds the buffers is waiting
/// on I/O, and re-arming the recv at once only spins: the kernel answers it
/// with ENOBUFS straight away, so the worker never blocks.
const DRY_YIELDS: u32 = 4;

/// How long a loop sleeps on a ring still empty after [`DRY_YIELDS`]. A sleep
/// ends on the timewheel's next 10 ms tick, so this is up to 10 ms rather than
/// a precise wait.
const DRY_BACKOFF: Duration = Duration::from_millis(10);

/// How a connection's loop waits out an empty buffer ring: a few yields, then
/// sleeps, until a chunk arrives again.
#[derive(Default)]
pub struct DryRing {
    retries: u32,
}

impl DryRing {
    pub async fn wait(&mut self) {
        self.retries += 1;
        match self.retries <= DRY_YIELDS {
            true => slopio::yield_now().await,
            false => slopio::runtime::time::Sleep::during(DRY_BACKOFF).await,
        }
    }

    /// A chunk arrived, so the ring had a buffer again.
    pub fn refilled(&mut self) {
        self.retries = 0;
    }
}

/// Reserved bit already masked off.
#[allow(non_camel_case_types)]
pub type STREAM_ID = u32;
