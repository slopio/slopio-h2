//! §5.1, one half per direction. Pure transitions: `StreamState` holds the
//! current value in a `Cell` and the mailboxes (body, trailers, waker) beside
//! it.

use crate::shared::codec::types::{INTERNAL_ERROR, NO_ERROR, StreamViolation};
use crate::shared::connection::body_length::BodyLength;

/// The peer's half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    Open(BodyLength),
    /// The peer's END_STREAM.
    Ended,
    /// Cut by our RST_STREAM; what is still in flight is ignored (§5.1).
    Abandoned,
}

impl Inbound {
    pub fn is_open(self) -> bool {
        matches!(self, Self::Open(_))
    }

    /// §5.1, then §8.1.1.
    pub fn on_data(self, len: u64, end_stream: bool) -> Result<Self, StreamViolation> {
        let Self::Open(body) = self else {
            return Err(StreamViolation::DataAfterEndStream);
        };
        let body = body.add(len, end_stream)?;
        Ok(match end_stream {
            true => Self::Ended,
            false => Self::Open(body),
        })
    }

    /// §8.1: trailers end the body, which must then add up (§8.1.1).
    pub fn on_trailers(self) -> Result<Self, StreamViolation> {
        let Self::Open(body) = self else {
            return Err(StreamViolation::DataAfterEndStream);
        };
        body.finish()?;
        Ok(Self::Ended)
    }

    fn abandon(self) -> Self {
        match self {
            Self::Open { .. } => Self::Abandoned,
            done => done,
        }
    }
}

/// Ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outbound {
    /// Nothing said yet.
    Idle,
    /// A head went out without END_STREAM.
    Streaming,
    Ended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Live {
        inbound: Inbound,
        outbound: Outbound,
    },
    /// Out of the connection's live table: nothing its task writes from here
    /// reaches anyone.
    Retired,
}

/// What a stream whose task stopped still owes the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Farewell {
    /// A `500`: nothing else will ever speak for the stream.
    pub answer: bool,
    pub reset: Option<u32>,
    /// The peer's half was still open: its frames in flight are to be
    /// ignored, not answered.
    pub abandoned_input: bool,
}

impl Lifecycle {
    /// §8.1.1: with END_STREAM on the HEADERS no DATA can follow, so a
    /// declared length that is not zero already fails to add up.
    pub fn open(declared: Option<u64>, end_stream: bool) -> Result<Self, StreamViolation> {
        let inbound = match end_stream {
            true if declared.is_some_and(|len| len != 0) => {
                return Err(StreamViolation::ContentLengthMismatch);
            }
            true => Inbound::Ended,
            false => Inbound::Open(BodyLength::new(declared)),
        };
        Ok(Self::Live {
            inbound,
            outbound: Outbound::Idle,
        })
    }

    pub fn inbound(self) -> Option<Inbound> {
        match self {
            Self::Live { inbound, .. } => Some(inbound),
            Self::Retired => None,
        }
    }

    pub fn input_ended(self) -> bool {
        !self.inbound().is_some_and(Inbound::is_open)
    }

    /// Both halves done, which is what lets the connection remove the stream.
    pub fn is_closed(self) -> bool {
        match self {
            Self::Live { inbound, outbound } => !inbound.is_open() && outbound == Outbound::Ended,
            Self::Retired => true,
        }
    }

    pub fn with_inbound(self, inbound: Inbound) -> Self {
        match self {
            Self::Live { outbound, .. } => Self::Live { inbound, outbound },
            Self::Retired => Self::Retired,
        }
    }

    pub fn with_outbound(self, outbound: Outbound) -> Self {
        match self {
            Self::Live { inbound, .. } => Self::Live { inbound, outbound },
            Self::Retired => Self::Retired,
        }
    }

    /// A response started but not ended is reset, not finished: an empty
    /// DATA with END_STREAM would pass a truncated body off as a whole one.
    /// §8.1: a complete response to a request still arriving is followed by
    /// RST_STREAM(NO_ERROR) rather than taking a body nobody will read.
    pub fn on_task_end(self) -> (Self, Farewell) {
        let Self::Live { inbound, outbound } = self else {
            return (
                self,
                Farewell {
                    answer: false,
                    reset: None,
                    abandoned_input: false,
                },
            );
        };
        let open = inbound.is_open();
        let reset = match outbound {
            Outbound::Streaming => Some(INTERNAL_ERROR),
            _ if open => Some(NO_ERROR),
            _ => None,
        };
        let next = Self::Live {
            inbound: inbound.abandon(),
            outbound: Outbound::Ended,
        };
        let farewell = Farewell {
            answer: outbound == Outbound::Idle,
            reset,
            abandoned_input: open,
        };
        (next, farewell)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OPEN: Inbound = Inbound::Open(BodyLength::new(None));

    #[test]
    fn data_after_the_end_is_refused_whichever_way_it_ended() {
        for done in [Inbound::Ended, Inbound::Abandoned] {
            assert_eq!(
                done.on_data(0, false),
                Err(StreamViolation::DataAfterEndStream)
            );
            assert_eq!(done.on_trailers(), Err(StreamViolation::DataAfterEndStream));
        }
    }

    #[test]
    fn the_body_is_held_to_its_declared_length() {
        let open = Inbound::Open(BodyLength::new(Some(4)));
        assert_eq!(
            open.on_data(5, false),
            Err(StreamViolation::ContentLengthMismatch)
        );
        assert_eq!(
            open.on_trailers(),
            Err(StreamViolation::ContentLengthMismatch)
        );
        assert_eq!(open.on_data(4, true), Ok(Inbound::Ended));
    }

    #[test]
    fn headers_that_end_the_stream_cannot_declare_a_body() {
        assert_eq!(
            Lifecycle::open(Some(1), true),
            Err(StreamViolation::ContentLengthMismatch)
        );
        assert!(Lifecycle::open(Some(0), true).unwrap().input_ended());
        assert!(!Lifecycle::open(Some(1), false).unwrap().input_ended());
    }
    #[test]
    fn a_stream_is_closed_when_both_halves_are() {
        let live = |inbound, outbound| Lifecycle::Live { inbound, outbound };
        assert!(!live(OPEN, Outbound::Ended).is_closed());
        assert!(!live(Inbound::Ended, Outbound::Streaming).is_closed());
        assert!(live(Inbound::Ended, Outbound::Ended).is_closed());
        assert!(live(Inbound::Abandoned, Outbound::Ended).is_closed());
    }

    #[test]
    fn a_retired_stream_takes_no_transition() {
        assert_eq!(
            Lifecycle::Retired.with_inbound(Inbound::Ended),
            Lifecycle::Retired
        );
        assert_eq!(
            Lifecycle::Retired.with_outbound(Outbound::Ended),
            Lifecycle::Retired
        );
    }

    #[test]
    fn what_a_stopped_task_owes_the_peer() {
        let cases = [
            // (inbound, outbound, answer, reset, abandoned_input)
            (OPEN, Outbound::Idle, true, Some(NO_ERROR), true),
            (Inbound::Ended, Outbound::Idle, true, None, false),
            (OPEN, Outbound::Streaming, false, Some(INTERNAL_ERROR), true),
            (
                Inbound::Ended,
                Outbound::Streaming,
                false,
                Some(INTERNAL_ERROR),
                false,
            ),
            (OPEN, Outbound::Ended, false, Some(NO_ERROR), true),
            (Inbound::Ended, Outbound::Ended, false, None, false),
        ];
        for (inbound, outbound, answer, reset, abandoned_input) in cases {
            let (next, farewell) = Lifecycle::Live { inbound, outbound }.on_task_end();
            assert_eq!(
                farewell,
                Farewell {
                    answer,
                    reset,
                    abandoned_input
                },
                "{inbound:?} / {outbound:?}"
            );
            assert!(next.is_closed(), "{inbound:?} / {outbound:?}");
        }

        let (next, farewell) = Lifecycle::Retired.on_task_end();
        assert_eq!(next, Lifecycle::Retired);
        assert_eq!(farewell.reset, None);
        assert!(!farewell.answer);
    }
}
