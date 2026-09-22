/// Where a request body's bytes land. What separates the variants is the
/// contract with the stream task, not the storage: `Capped` is delivered
/// whole and once, the other two are drained as they fill.
pub enum InputData {
    /// Length known and small enough to hold: allocated once, exactly, and
    /// appended to since nothing consumes it before the end. `len` is what
    /// was declared, which is also the capacity.
    ///
    /// Reserved, not zeroed. `vec![0u8; len]` writes every byte of a buffer
    /// whose every byte is about to be written again by the body — and
    /// writes it *now*, at HEADERS, so a peer that declares 16 KiB on each of
    /// its streams and sends none of it had us commit and touch all of that
    /// memory for nothing. Capacity that is never filled is never resident.
    Capped { len: usize, data: Vec<u8> },
    /// Length known but too large to hold. `len` is what was declared — kept
    /// for the §8.1.1 check, never allocated.
    BufferedCapped { len: usize, data: Vec<u8> },
    /// No declared length. Bounded by the receive window, since none of it is
    /// credited back before the task drains it.
    Uncapped { data: Vec<u8> },
}

/// A payload that would take the body past the length it declared (§8.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyOverflow {
    pub declared: u64,
    pub at: u64,
    pub pushed: usize,
}

impl InputData {
    /// Largest body handed to the task in one piece.
    ///
    /// A bound on memory and nothing else: this much is buffered per stream
    /// before the handler sees any of it, and `MAX_CONCURRENT_STREAMS` times
    /// it per connection. It has nothing to say to flow control — the bytes
    /// are credited back as they land, being in the buffer already — so a
    /// body cut short holds no window, and no window has to be sized for
    /// this. It used to: when a held body kept its credit until the stream
    /// retired, this had to fit in the stream window and, times the streams,
    /// in the connection window, or bodies arriving together deadlocked
    /// each other. Neither is true any more.
    pub const ONESHOT_LIMIT: usize = 16384;

    /// What a drained buffer starts with. The same number as
    /// [`ONESHOT_LIMIT`](Self::ONESHOT_LIMIT) and unrelated to it — see
    /// [`buffered_capped`](Self::buffered_capped).
    const DRAINED_CAPACITY: usize = 16384;

    /// `content_length` is the declared body length, `None` when the request
    /// declared none.
    pub fn new(content_length: Option<u64>) -> Self {
        match content_length {
            Some(len) if len <= Self::ONESHOT_LIMIT as u64 => Self::capped(len as usize),
            Some(len) => Self::buffered_capped(len as usize),
            None => Self::uncapped(),
        }
    }

    fn capped(len: usize) -> Self {
        Self::Capped {
            len,
            data: Vec::with_capacity(len),
        }
    }

    fn uncapped() -> Self {
        Self::Uncapped { data: Vec::new() }
    }

    /// The capacity here is not the body's size — a drained buffer holds what one
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
            data: Vec::with_capacity(Self::DRAINED_CAPACITY),
        }
    }

    /// The declared body length.
    pub fn expected(&self) -> Option<u64> {
        match self {
            Self::Capped { len, .. } | Self::BufferedCapped { len, .. } => Some(*len as u64),
            Self::Uncapped { .. } => None,
        }
    }

    /// Appends `payload`, all of it or none of it.
    ///
    /// `at` is how many body bytes already landed. For `Capped` that is where
    /// its buffer ends, nothing being consumed from it before the end; the
    /// drained forms have given some of theirs away, so it is the only record
    /// of how much of the declared length is spent.
    ///
    /// This is what decides whether it fits, and not the caller: a payload
    /// that takes the body past its declared length is refused whole, which is
    /// also what keeps `Capped` inside the capacity it reserved. `Uncapped`
    /// declared nothing and refuses nothing — the receive window is its bound.
    pub fn push(&mut self, at: u64, payload: &[u8]) -> Result<(), BodyOverflow> {
        if let Some(declared) = self.expected()
            && at + payload.len() as u64 > declared
        {
            return Err(BodyOverflow {
                declared,
                at,
                pushed: payload.len(),
            });
        }
        match self {
            Self::Capped { data, .. } => {
                debug_assert_eq!(at as usize, data.len());
                data.extend_from_slice(payload);
            }
            Self::BufferedCapped { data, .. } | Self::Uncapped { data } => {
                data.extend_from_slice(payload);
            }
        }
        Ok(())
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
            // Full by the time anyone asks — the stream checked the body
            // against `len` at END_STREAM — so length is capacity and this
            // moves the allocation rather than copying it.
            Self::Capped { data, .. } => Some(data.into_boxed_slice()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether a payload fits is `push`'s to say, for the form held whole —
    /// and refused means nothing was written, so the capacity it reserved is
    /// never outgrown.
    #[test]
    fn a_held_body_refuses_what_takes_it_past_its_declared_length() {
        let mut body = InputData::new(Some(4));
        assert_eq!(body.push(0, b"ab"), Ok(()));
        assert_eq!(
            body.push(2, b"cde"),
            Err(BodyOverflow {
                declared: 4,
                at: 2,
                pushed: 3
            })
        );
        assert_eq!(body.push(2, b"cd"), Ok(()));
        assert_eq!(body.into_oneshot().as_deref(), Some(&b"abcd"[..]));
    }

    /// The drained form has given bytes away, so `at` is the only record of
    /// how much of the declared length is spent.
    #[test]
    fn a_drained_body_counts_what_it_has_already_handed_over() {
        let declared = InputData::ONESHOT_LIMIT as u64 + 10;
        let mut body = InputData::new(Some(declared));
        assert_eq!(body.push(0, &[0; 100]), Ok(()));
        body.consume(100);

        assert!(body.push(declared - 5, &[0; 6]).is_err());
        assert_eq!(body.available().len(), 0, "nothing of it was taken");
        assert_eq!(body.push(declared - 5, &[0; 5]), Ok(()));
    }

    #[test]
    fn a_body_that_declared_nothing_refuses_nothing() {
        let mut body = InputData::new(None);
        assert_eq!(body.push(0, &[0; 70_000]), Ok(()));
    }
}
