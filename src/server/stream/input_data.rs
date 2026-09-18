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

    /// The capacity here is `BUFFER_ONESHOT_LIMIT`'s second and unrelated
    /// job, and it is not the body's size — a drained buffer holds what one
    /// turn of the connection loop delivered to *this* stream, which the
    /// handler then takes in full. The declared length would be the obvious
    /// thing to reserve instead, and it is the wrong thing: measured on 64
    /// KiB bodies it changed nothing (5.32-5.38 GB/s against 5.41-5.49), and
    /// it would hold `MAX_CONCURRENT_STREAMS` × the stream window — 4 MiB a
    /// connection where this is 1 MiB.
    ///
    /// It changes nothing because a chunk is shared: concurrent streams take
    /// a frame or two each from it, so a buffer is drained long before it
    /// grows. Only one stream receiving a whole 64 KiB chunk alone would
    /// reallocate, and that case is latency-bound anyway — the server sits
    /// at 45% of a core there.
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

    /// What the handler may take right now.
    ///
    /// Always empty for `Capped`: that form is delivered whole or not at
    /// all, which is exactly what lets it issue no WINDOW_UPDATE while it
    /// fills — it never hands back credit mid-body because it never hands
    /// back bytes mid-body. Its receive window is meant to be spent down to
    /// the end of the body and no further.
    pub fn available(&self) -> &[u8] {
        match self {
            Self::Capped { .. } => &[],
            Self::BufferedCapped { data, .. } | Self::Uncapped { data } => data,
        }
    }

    /// Drops the `n` leading bytes the handler has taken.
    ///
    /// A no-op on `Capped`, whose `push` writes at an absolute offset that
    /// removing the front would shift out from under it — and which has
    /// nothing to consume before the end anyway.
    pub fn consume(&mut self, n: usize) {
        match self {
            Self::Capped { .. } => {}
            Self::BufferedCapped { data, .. } | Self::Uncapped { data } => {
                data.drain(..n);
            }
        }
    }

    /// The whole body, for the form that is delivered in one piece.
    pub fn into_oneshot(self) -> Option<Box<[u8]>> {
        match self {
            Self::Capped { data } => Some(data),
            _ => None,
        }
    }
}
