//! §8.1.1, for either side's inbound message body.

use crate::shared::codec::types::StreamViolation;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BodyLength {
    /// Padding excluded: flow control counts it, `content-length` does not.
    received: u64,
    declared: Option<u64>,
}

impl BodyLength {
    pub const fn new(declared: Option<u64>) -> Self {
        Self {
            received: 0,
            declared,
        }
    }

    pub fn received(self) -> u64 {
        self.received
    }

    /// Past the declared length is an error at once, short of it only once
    /// the body ends.
    pub fn add(self, len: u64, end_stream: bool) -> Result<Self, StreamViolation> {
        let received = self.received + len;
        if self
            .declared
            .is_some_and(|declared| received > declared || (end_stream && received != declared))
        {
            return Err(StreamViolation::ContentLengthMismatch);
        }
        Ok(Self { received, ..self })
    }

    /// For trailers, which end the body without a DATA frame.
    pub fn finish(self) -> Result<(), StreamViolation> {
        match self.declared {
            Some(declared) if declared != self.received => {
                Err(StreamViolation::ContentLengthMismatch)
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_past_its_declared_length_is_refused_at_once() {
        let body = BodyLength::new(Some(4)).add(3, false).unwrap();
        assert_eq!(
            body.add(2, false),
            Err(StreamViolation::ContentLengthMismatch)
        );
        assert!(body.add(1, true).is_ok());
    }

    #[test]
    fn a_body_short_of_its_declared_length_is_refused_when_it_ends() {
        let body = BodyLength::new(Some(4)).add(3, false).unwrap();
        assert_eq!(
            body.add(0, true),
            Err(StreamViolation::ContentLengthMismatch)
        );
        assert_eq!(body.finish(), Err(StreamViolation::ContentLengthMismatch));
        assert_eq!(body.add(1, false).unwrap().finish(), Ok(()));
    }

    #[test]
    fn a_declared_length_of_zero_takes_no_byte() {
        let body = BodyLength::new(Some(0));
        assert_eq!(
            body.add(1, false),
            Err(StreamViolation::ContentLengthMismatch)
        );
        assert!(body.add(0, true).is_ok());
    }

    #[test]
    fn an_undeclared_body_takes_anything() {
        let body = BodyLength::new(None).add(70_000, false).unwrap();
        assert_eq!(body.received(), 70_000);
        assert_eq!(body.finish(), Ok(()));
    }
}
