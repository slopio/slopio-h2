//! §5.1 for a request, one half per direction. Pure transitions:
//! `StreamState` holds the current value in a `Cell` and the mailboxes
//! (response head, chunks, trailers, wakers) beside it.

use crate::client::stream::Failure;
use crate::shared::codec::types::StreamViolation;
use crate::shared::connection::body_length::BodyLength;

/// The server's half.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Inbound {
    AwaitingHead,
    Body(BodyLength),
    Ended,
    /// Never from `Ended`: §8.1 has a server stop an upload with
    /// RST_STREAM(NO_ERROR) after a complete response, and clients MUST NOT
    /// discard the response for it.
    Failed(Failure),
}

impl Inbound {
    pub(crate) fn has_response(self) -> bool {
        matches!(self, Self::Body(_) | Self::Ended)
    }

    pub(crate) fn is_ended(self) -> bool {
        matches!(self, Self::Ended | Self::Failed(_))
    }

    /// §8.1.2.4, for a final head. `declared` is already `None` for a
    /// response that carries no body whatever its `content-length` says.
    pub(crate) fn on_head(
        self,
        declared: Option<u64>,
        end_stream: bool,
    ) -> Result<Self, StreamViolation> {
        let Self::AwaitingHead = self else {
            return Err(StreamViolation::MalformedResponse);
        };
        let body = BodyLength::new(declared).add(0, end_stream)?;
        Ok(match end_stream {
            true => Self::Ended,
            false => Self::Body(body),
        })
    }

    /// §8.1: DATA before a final head is malformed; §5.1, then §8.1.1.
    pub(crate) fn on_data(self, len: u64, end_stream: bool) -> Result<Self, StreamViolation> {
        match self {
            Self::AwaitingHead => Err(StreamViolation::MalformedResponse),
            Self::Body(body) => {
                let body = body.add(len, end_stream)?;
                Ok(match end_stream {
                    true => Self::Ended,
                    false => Self::Body(body),
                })
            }
            Self::Ended | Self::Failed(_) => Err(StreamViolation::DataAfterEndStream),
        }
    }

    /// §8.1: trailers end the body, which must then add up (§8.1.1).
    pub(crate) fn on_trailers(self) -> Result<Self, StreamViolation> {
        match self {
            Self::AwaitingHead => Err(StreamViolation::MalformedResponse),
            Self::Body(body) => body.finish().map(|()| Self::Ended),
            Self::Ended | Self::Failed(_) => Err(StreamViolation::DataAfterEndStream),
        }
    }

    fn fail(self, failure: Failure) -> Self {
        match self {
            Self::AwaitingHead | Self::Body(_) => Self::Failed(failure),
            done => done,
        }
    }
}

/// Ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outbound {
    Open,
    Ended,
    Failed(Failure),
}

impl Outbound {
    fn is_ended(self) -> bool {
        !matches!(self, Self::Open)
    }

    pub(crate) fn end(self) -> Self {
        match self {
            Self::Open => Self::Ended,
            done => done,
        }
    }

    fn fail(self, failure: Failure) -> Self {
        match self {
            Self::Open => Self::Failed(failure),
            done => done,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Lifecycle {
    pub(crate) inbound: Inbound,
    pub(crate) outbound: Outbound,
}

impl Lifecycle {
    pub(crate) fn new(end_stream: bool) -> Self {
        Self {
            inbound: Inbound::AwaitingHead,
            outbound: match end_stream {
                true => Outbound::Ended,
                false => Outbound::Open,
            },
        }
    }

    pub(crate) fn is_closed(self) -> bool {
        self.inbound.is_ended() && self.outbound.is_ended()
    }

    /// Fails only the halves still open: a response the peer finished is
    /// still read to its end.
    pub(crate) fn fail(self, failure: Failure) -> Self {
        Self {
            inbound: self.inbound.fail(failure),
            outbound: self.outbound.fail(failure),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RESET: Failure = Failure::Reset(0x8);

    fn body(declared: Option<u64>) -> Inbound {
        Inbound::AwaitingHead.on_head(declared, false).unwrap()
    }

    #[test]
    fn nothing_but_a_head_comes_first() {
        assert_eq!(
            Inbound::AwaitingHead.on_data(0, false),
            Err(StreamViolation::MalformedResponse)
        );
        assert_eq!(
            Inbound::AwaitingHead.on_trailers(),
            Err(StreamViolation::MalformedResponse)
        );
        assert_eq!(
            body(None).on_head(None, false),
            Err(StreamViolation::MalformedResponse)
        );
    }

    #[test]
    fn a_head_that_ends_the_stream_cannot_declare_a_body() {
        assert_eq!(
            Inbound::AwaitingHead.on_head(Some(1), true),
            Err(StreamViolation::ContentLengthMismatch)
        );
        assert_eq!(
            Inbound::AwaitingHead.on_head(Some(0), true),
            Ok(Inbound::Ended)
        );
    }

    #[test]
    fn the_body_is_held_to_its_declared_length() {
        assert_eq!(
            body(Some(4)).on_data(5, false),
            Err(StreamViolation::ContentLengthMismatch)
        );
        assert_eq!(
            body(Some(4)).on_trailers(),
            Err(StreamViolation::ContentLengthMismatch)
        );
        assert_eq!(body(Some(4)).on_data(4, true), Ok(Inbound::Ended));
    }

    #[test]
    fn nothing_comes_after_the_end() {
        for done in [Inbound::Ended, Inbound::Failed(RESET)] {
            assert_eq!(
                done.on_data(0, false),
                Err(StreamViolation::DataAfterEndStream)
            );
            assert_eq!(done.on_trailers(), Err(StreamViolation::DataAfterEndStream));
        }
    }

    #[test]
    fn a_failure_reaches_only_the_halves_still_open() {
        let finished = Lifecycle {
            inbound: Inbound::Ended,
            outbound: Outbound::Open,
        }
        .fail(RESET);
        assert_eq!(finished.inbound, Inbound::Ended);
        assert_eq!(finished.outbound, Outbound::Failed(RESET));

        let sent = Lifecycle {
            inbound: body(None),
            outbound: Outbound::Ended,
        }
        .fail(RESET);
        assert_eq!(sent.inbound, Inbound::Failed(RESET));
        assert_eq!(sent.outbound, Outbound::Ended);
        assert!(sent.is_closed());
    }

    #[test]
    fn the_first_failure_is_the_one_kept() {
        let failed = Lifecycle::new(false).fail(Failure::Expired).fail(RESET);
        assert_eq!(failed.inbound, Inbound::Failed(Failure::Expired));
        assert_eq!(failed.outbound, Outbound::Failed(Failure::Expired));
    }

    #[test]
    fn a_stream_is_closed_when_both_halves_are() {
        let open = Lifecycle::new(false);
        assert!(!open.is_closed());
        let sent = Lifecycle::new(true);
        assert!(!sent.is_closed());
        let done = Lifecycle {
            inbound: Inbound::Ended,
            ..sent
        };
        assert!(done.is_closed());
        assert_eq!(Outbound::Failed(RESET).end(), Outbound::Failed(RESET));
    }
}
