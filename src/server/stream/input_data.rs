use crate::server::connection::{CONNECTION_RECV_WINDOW, MAX_CONCURRENT_STREAMS};

/// Largest body handed to the task in one piece. Two bounds constrain it, and
/// this value is the smaller:
///
/// - a body held whole must fit in its stream's receive window, since nothing
///   is consumed until it is complete and accumulation can therefore issue no
///   mid-body WINDOW_UPDATE;
/// - `limit * MAX_CONCURRENT_STREAMS` must fit in the connection window, or
///   streams accumulating at once drain it between them and all deadlock,
///   each holding an incomplete body no handler will ever be woken for.
pub const BUFFER_ONESHOT_LIMIT: usize = 16384;

const _: () = assert!(
    BUFFER_ONESHOT_LIMIT * MAX_CONCURRENT_STREAMS as usize <= CONNECTION_RECV_WINDOW as usize,
    "streams accumulating at once must fit in the connection receive window"
);

/// Where a request body's bytes land. What separates the variants is the
/// contract with the stream task, not the storage: `Capped` is delivered
/// whole and once, the other two are drained as they fill.
pub enum InputData {
    /// Length known and small enough to hold: allocated once, exactly, and
    /// written at an offset since nothing consumes it before the end.
    Capped { data: Box<[u8]> },
    /// Length known but too large to hold. `len` is what was declared — kept
    /// for the §8.1.1 check, never allocated.
    BufferedCapped { len: usize, data: Vec<u8> },
    /// No declared length. Bounded by the receive window, since none of it is
    /// credited back before the task drains it.
    Uncapped { data: Vec<u8> },
}

impl InputData {
    /// `content_length` is the declared body length, `None` when the request
    /// declared none.
    pub fn new(content_length: Option<u64>) -> Self {
        match content_length {
            Some(len) if len <= BUFFER_ONESHOT_LIMIT as u64 => Self::capped(len as usize),
            Some(len) => Self::buffered_capped(len as usize),
            None => Self::uncapped(),
        }
    }

    fn capped(len: usize) -> Self {
        Self::Capped {
            data: vec![0u8; len].into_boxed_slice(),
        }
    }

    fn uncapped() -> Self {
        Self::Uncapped { data: Vec::new() }
    }

    fn buffered_capped(len: usize) -> Self {
        Self::BufferedCapped {
            len,
            data: Vec::with_capacity(BUFFER_ONESHOT_LIMIT),
        }
    }

    /// The declared body length, which only the growable forms have to carry
    /// explicitly — for `Capped` it is the buffer itself.
    pub fn expected(&self) -> Option<u64> {
        match self {
            Self::Capped { data } => Some(data.len() as u64),
            Self::BufferedCapped { len, .. } => Some(*len as u64),
            Self::Uncapped { .. } => None,
        }
    }

    /// `at` is how many body bytes already landed. `Capped` needs it as a
    /// write cursor, having been allocated to its full size up front; the
    /// growable forms track their own end.
    ///
    /// The caller must have checked `at + payload.len()` against `expected`,
    /// which is what keeps the `Capped` slicing in bounds.
    pub fn push(&mut self, at: u64, payload: &[u8]) {
        match self {
            Self::Capped { data } => {
                let at = at as usize;
                data[at..at + payload.len()].copy_from_slice(payload);
            }
            Self::BufferedCapped { data, .. } | Self::Uncapped { data } => {
                data.extend_from_slice(payload);
            }
        }
    }

    /// A body held whole is only useful complete, so its task is woken once.
    /// The others have something to drain as soon as a frame lands.
    pub fn wakes_per_frame(&self) -> bool {
        !matches!(self, Self::Capped { .. })
    }
}
