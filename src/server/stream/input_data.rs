/// `Capped` is delivered whole and once; the other two are drained as they
/// fill.
pub enum InputData {
    /// `len` is what was declared, which is also the capacity. Reserved, not
    /// zeroed: a peer that declares a length on each stream and sends nothing
    /// must not make us commit that memory at HEADERS.
    Capped { len: usize, data: Vec<u8> },
    /// `len` is kept for the §8.1.1 check, never allocated.
    BufferedCapped { len: usize, data: Vec<u8> },
    /// Bounded by the receive window, since none of it is credited back
    /// before the task drains it.
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
    /// A bound on memory: this much is buffered per stream before the handler
    /// sees any of it, and `MAX_CONCURRENT_STREAMS` times it per connection.
    pub const ONESHOT_LIMIT: usize = 16384;

    const DRAINED_CAPACITY: usize = 16384;

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

    /// Not the declared length: reserving that would hold
    /// `MAX_CONCURRENT_STREAMS` × the stream window per connection.
    fn buffered_capped(len: usize) -> Self {
        Self::BufferedCapped {
            len,
            data: Vec::with_capacity(Self::DRAINED_CAPACITY),
        }
    }

    pub fn expected(&self) -> Option<u64> {
        match self {
            Self::Capped { len, .. } | Self::BufferedCapped { len, .. } => Some(*len as u64),
            Self::Uncapped { .. } => None,
        }
    }

    /// Appends `payload`, all of it or none of it. `at` is how many body bytes
    /// already landed: the drained forms have given some away, so it is the
    /// only record of how much of the declared length is spent.
    ///
    /// A payload past the declared length is refused whole, which is also what
    /// keeps `Capped` inside the capacity it reserved.
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

    pub fn wakes_per_frame(&self) -> bool {
        !matches!(self, Self::Capped { .. })
    }

    /// Always empty for `Capped`: it is delivered whole, which is what lets it
    /// issue no WINDOW_UPDATE while it fills.
    pub fn available(&self) -> &[u8] {
        match self {
            Self::Capped { .. } => &[],
            Self::BufferedCapped { data, .. } | Self::Uncapped { data } => data,
        }
    }

    /// A no-op on `Capped`, whose `push` relies on `at` being where its buffer
    /// ends; removing the front would break that.
    pub fn consume(&mut self, n: usize) {
        match self {
            Self::Capped { .. } => {}
            Self::BufferedCapped { data, .. } | Self::Uncapped { data } => {
                data.drain(..n);
            }
        }
    }

    pub fn into_oneshot(self) -> Option<Box<[u8]>> {
        match self {
            // Full by now (checked against `len` at END_STREAM), so length
            // is capacity and this moves the allocation rather than copying.
            Self::Capped { data, .. } => Some(data.into_boxed_slice()),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Refused means nothing was written, so the reserved capacity is never
    /// outgrown.
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
