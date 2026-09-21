/// Length of gRPC's Length-Prefixed-Message header: one byte of
/// Compressed-Flag, then the message length, big-endian.
pub const PREFIX_LEN: usize = 5;

/// A message prefix whose five bytes are arriving — across DATA frames if that
/// is how they were cut.
///
/// The same three steps as [`Accumulating`](super::Accumulating), which is
/// what it turns into: `missing`, `push`, `finish`.
pub struct Prefix {
    bytes: [u8; PREFIX_LEN],
    filled: usize,
}

/// What a whole prefix says, as the wire said it: neither field is judged
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixRead {
    pub compressed_flag: u8,
    pub length: u32,
}

/// More bytes than a prefix has left to take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixOverflow {
    pub missing: usize,
    pub pushed: usize,
}

impl Prefix {
    pub const fn new() -> Self {
        Self {
            bytes: [0; PREFIX_LEN],
            filled: 0,
        }
    }

    pub fn missing(&self) -> usize {
        PREFIX_LEN - self.filled
    }

    /// Nothing of it has arrived: the body is between two messages, which is
    /// the only place it may end.
    pub fn is_untouched(&self) -> bool {
        self.filled == 0
    }

    /// Appends `payload`, all of it or none of it. Cutting it at
    /// [`missing`](Self::missing) is the caller's: what is past the cut is the
    /// message's.
    pub fn push(&mut self, payload: &[u8]) -> Result<(), PrefixOverflow> {
        if payload.len() > self.missing() {
            return Err(PrefixOverflow {
                missing: self.missing(),
                pushed: payload.len(),
            });
        }
        self.bytes[self.filled..self.filled + payload.len()].copy_from_slice(payload);
        self.filled += payload.len();
        Ok(())
    }

    /// `Err(self)` while bytes are missing: nothing is lost.
    pub fn finish(self) -> Result<PrefixRead, Self> {
        if self.missing() > 0 {
            return Err(self);
        }
        let [flag, length @ ..] = self.bytes;
        Ok(PrefixRead {
            compressed_flag: flag,
            length: u32::from_be_bytes(length),
        })
    }
}

impl Default for Prefix {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn five_bytes_in_pieces_read_as_a_flag_and_a_length() {
        let mut prefix = Prefix::new();
        assert!(prefix.is_untouched());
        assert_eq!(prefix.push(&[1, 0]), Ok(()));
        assert!(!prefix.is_untouched());
        assert_eq!(prefix.missing(), 3);
        assert_eq!(prefix.push(&[0, 1, 2]), Ok(()));

        assert_eq!(
            prefix.finish().ok(),
            Some(PrefixRead {
                compressed_flag: 1,
                length: 258
            })
        );
    }

    #[test]
    fn a_push_past_five_bytes_is_refused_and_writes_nothing() {
        let mut prefix = Prefix::new();
        prefix.push(&[0, 0, 0]).unwrap();
        assert_eq!(
            prefix.push(&[0, 9, 9]),
            Err(PrefixOverflow {
                missing: 2,
                pushed: 3
            })
        );
        assert_eq!(prefix.missing(), 2);
    }

    #[test]
    fn a_prefix_missing_bytes_does_not_finish() {
        let mut prefix = Prefix::new();
        prefix.push(&[0, 0, 0, 0]).unwrap();
        let Err(mut prefix) = prefix.finish() else {
            panic!("one byte short");
        };
        prefix.push(&[7]).unwrap();
        assert_eq!(prefix.finish().ok().map(|read| read.length), Some(7));
    }
}
