use std::collections::VecDeque;

use http::HeaderMap;

use super::frame::{Accumulating, GrpcFrame};
use super::prefix::{Prefix, PrefixRead};
use super::request::{AnnouncedEncoding, GrpcFormat};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcError {
    MessageTooLarge { declared: u32 },
    InvalidCompressedFlag(u8),
    CompressedWithoutEncoding,
    UnsupportedEncoding,
    TooManyMessages,
    Truncated,
}

enum Reading {
    Prefix(Prefix),
    Frame(Accumulating),
}

/// Message boundaries owe nothing to DATA frames: a prefix may straddle two,
/// and one frame may hold several messages.
pub struct GrpcInput {
    reading: Reading,
    ready: VecDeque<GrpcFrame>,
    /// Set once, by the first thing wrong with the body. Nothing after it is
    /// read: the framing is lost.
    failed: Option<GrpcError>,
    failure_taken: bool,
    announced: AnnouncedEncoding,
    format: GrpcFormat,
    /// §8.1.1 holds whatever the content type.
    declared: Option<u64>,
}

impl GrpcInput {
    /// Largest message held, and gRPC's own default.
    ///
    /// Not tied to any window: DATA bytes are consumed and credited back the
    /// moment they land, so a message may be far larger than a stream's
    /// window. What bounds memory is this limit, checked at the prefix, times
    /// the streams open at once.
    pub const MESSAGE_LIMIT: usize = 4 * 1024 * 1024;

    /// Most messages waiting to be taken. The window bounds them in bytes and
    /// not in entries: a peer sending the smallest messages it can into a
    /// stream nobody is draining spends 64 KiB of window on some thirteen
    /// thousand of them.
    pub const QUEUE_LIMIT: usize = 256;

    pub fn new(format: GrpcFormat, fields: &HeaderMap, declared: Option<u64>) -> Self {
        Self {
            reading: Reading::Prefix(Prefix::new()),
            ready: VecDeque::new(),
            failed: None,
            failure_taken: false,
            announced: AnnouncedEncoding::of(fields),
            format,
            declared,
        }
    }

    pub fn declared(&self) -> Option<u64> {
        self.declared
    }

    /// While a whole message is waiting, the bytes that arrive hold their
    /// credit: the window is what tells the peer the handler is behind.
    pub fn has_ready(&self) -> bool {
        !self.ready.is_empty()
    }

    /// Nothing here knows about flow control: whether the bytes keep their
    /// credit is decided by the caller, from [`has_ready`] after it.
    ///
    /// [`has_ready`]: Self::has_ready
    pub fn push(&mut self, mut payload: &[u8]) -> bool {
        let mut wake = false;
        while !payload.is_empty() && self.failed.is_none() {
            // Cut at what the current piece is missing: it refuses more.
            let missing = match &self.reading {
                Reading::Prefix(prefix) => prefix.missing(),
                Reading::Frame(frame) => frame.missing(),
            };
            let (mine, rest) = payload.split_at(missing.min(payload.len()));
            payload = rest;
            match &mut self.reading {
                Reading::Prefix(prefix) => prefix.push(mine).expect("cut at `missing`"),
                Reading::Frame(frame) => frame.push(mine).expect("cut at `missing`"),
            }
            wake |= self.advance();
        }
        wake || self.failed.is_some()
    }

    /// A loop because a prefix announcing zero bytes is a frame that is whole
    /// the moment it begins.
    fn advance(&mut self) -> bool {
        let mut became_ready = false;
        loop {
            match std::mem::replace(&mut self.reading, Reading::Prefix(Prefix::new())) {
                Reading::Prefix(prefix) => match prefix.finish() {
                    Ok(read) => match self.begin(read) {
                        Ok(frame) => self.reading = Reading::Frame(frame),
                        Err(error) => {
                            self.failed = Some(error);
                            return became_ready;
                        }
                    },
                    Err(prefix) => {
                        self.reading = Reading::Prefix(prefix);
                        return became_ready;
                    }
                },
                Reading::Frame(frame) => match frame.finish() {
                    Ok(frame) => {
                        if self.ready.len() == Self::QUEUE_LIMIT {
                            self.failed = Some(GrpcError::TooManyMessages);
                            return became_ready;
                        }
                        self.ready.push_back(frame);
                        became_ready = true;
                    }
                    Err(frame) => {
                        self.reading = Reading::Frame(frame);
                        return became_ready;
                    }
                },
            }
        }
    }

    /// Refuses a message at its prefix, before anything is reserved for a
    /// length the peer has only claimed.
    fn begin(&self, read: PrefixRead) -> Result<Accumulating, GrpcError> {
        let encoding = match (read.compressed_flag, self.announced) {
            (0, _) => None,
            (1, AnnouncedEncoding::Known(encoding)) => Some(encoding),
            (1, AnnouncedEncoding::None) => return Err(GrpcError::CompressedWithoutEncoding),
            (1, AnnouncedEncoding::Unknown) => return Err(GrpcError::UnsupportedEncoding),
            (flag, _) => return Err(GrpcError::InvalidCompressedFlag(flag)),
        };
        if read.length as usize > Self::MESSAGE_LIMIT {
            return Err(GrpcError::MessageTooLarge {
                declared: read.length,
            });
        }
        Ok(Accumulating::new(
            read.length as usize,
            encoding,
            self.format,
        ))
    }

    pub fn end(&mut self) {
        let between = matches!(&self.reading, Reading::Prefix(prefix) if prefix.is_untouched());
        if !between && self.failed.is_none() {
            self.failed = Some(GrpcError::Truncated);
        }
    }

    pub fn take(&mut self) -> Option<Result<GrpcFrame, GrpcError>> {
        if let Some(frame) = self.ready.pop_front() {
            return Some(Ok(frame));
        }
        if self.failure_taken {
            return None;
        }
        let failure = self.failed?;
        self.failure_taken = true;
        Some(Err(failure))
    }
}

#[cfg(test)]
mod tests {
    use super::super::GrpcEncoding;
    use super::*;

    fn input(encoding: Option<&'static str>) -> GrpcInput {
        let mut fields = HeaderMap::new();
        if let Some(encoding) = encoding {
            fields.insert("grpc-encoding", http::HeaderValue::from_static(encoding));
        }
        GrpcInput::new(GrpcFormat::Proto, &fields, None)
    }

    fn framed(flag: u8, data: &[u8]) -> Vec<u8> {
        let mut out = vec![flag];
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(data);
        out
    }

    fn data(taken: Option<Result<GrpcFrame, GrpcError>>) -> Vec<u8> {
        match taken {
            Some(Ok(GrpcFrame::Uncompressed(frame))) => frame.into_data().into_vec(),
            other => panic!("not an uncompressed frame: {other:?}"),
        }
    }

    #[test]
    fn frames_come_out_whole_wherever_the_bytes_are_cut() {
        let bytes = [framed(0, b"first"), framed(0, b""), framed(0, b"third one")].concat();

        for cut in 0..=bytes.len() {
            let mut input = input(None);
            let wakes = [&bytes[..cut], &bytes[cut..]]
                .into_iter()
                .filter(|piece| input.push(piece))
                .count();
            input.end();

            assert!(wakes >= 1, "cut {cut}");
            assert_eq!(data(input.take()), b"first", "cut {cut}");
            assert_eq!(data(input.take()), b"", "cut {cut}: empty is a message");
            assert_eq!(data(input.take()), b"third one", "cut {cut}");
            assert_eq!(input.take(), None, "cut {cut}");
        }
    }

    #[test]
    fn an_end_inside_a_message_is_a_truncated_body() {
        for cut in 1..framed(0, b"whole").len() {
            let mut input = input(None);
            input.push(&framed(0, b"whole")[..cut]);
            input.end();
            assert_eq!(input.take(), Some(Err(GrpcError::Truncated)), "cut {cut}");
            assert_eq!(input.take(), None, "cut {cut}: told once");
        }
    }

    #[test]
    fn what_was_whole_before_a_failure_is_still_delivered() {
        let mut input = input(None);
        let bytes = [framed(0, b"fine"), framed(2, b"not")].concat();
        assert!(input.push(&bytes));

        assert_eq!(data(input.take()), b"fine");
        assert_eq!(input.take(), Some(Err(GrpcError::InvalidCompressedFlag(2))));
        assert_eq!(input.take(), None);
    }

    #[test]
    fn a_compressed_message_needs_an_encoding_with_a_name() {
        for (announced, expected) in [
            (None, GrpcError::CompressedWithoutEncoding),
            (Some("identity"), GrpcError::CompressedWithoutEncoding),
            (Some("snappy"), GrpcError::UnsupportedEncoding),
        ] {
            let mut input = input(announced);
            input.push(&framed(1, b"zz"));
            assert_eq!(input.take(), Some(Err(expected)), "{announced:?}");
        }

        let mut gzip = input(Some("gzip"));
        gzip.push(&framed(1, b"zz"));
        match gzip.take() {
            Some(Ok(GrpcFrame::Compressed(frame))) => {
                assert_eq!(frame.encoding(), GrpcEncoding::Gzip);
                assert_eq!(frame.compressed_bytes(), b"zz");
            }
            other => panic!("not a compressed frame: {other:?}"),
        }
    }

    #[test]
    fn a_peer_that_queues_past_the_limit_fails_the_body() {
        let mut input = input(None);
        let smallest = framed(0, b"");
        let flood = smallest.repeat(GrpcInput::QUEUE_LIMIT + 1);
        // Well inside the window it would take: the entries are what run out.
        assert!(flood.len() < GrpcInput::MESSAGE_LIMIT);
        assert!(input.push(&flood));

        for _ in 0..GrpcInput::QUEUE_LIMIT {
            assert_eq!(data(input.take()), b"", "everything whole before the cap");
        }
        assert_eq!(input.take(), Some(Err(GrpcError::TooManyMessages)));
        assert_eq!(input.take(), None);
    }

    #[test]
    fn a_drained_queue_takes_more_than_the_limit_in_all() {
        let mut input = input(None);
        for round in 0..4 {
            let batch = framed(0, b"x").repeat(GrpcInput::QUEUE_LIMIT);
            assert!(input.push(&batch), "round {round}");
            for _ in 0..GrpcInput::QUEUE_LIMIT {
                assert_eq!(data(input.take()), b"x", "round {round}");
            }
        }
        input.end();
        assert_eq!(input.take(), None, "nothing went wrong");
    }

    #[test]
    fn a_message_past_the_limit_is_refused_at_its_prefix() {
        let prefix = |declared: u32| [&[0][..], &declared.to_be_bytes()].concat();

        let mut over = input(None);
        let declared = GrpcInput::MESSAGE_LIMIT as u32 + 1;
        assert!(over.push(&prefix(declared)));
        assert_eq!(
            over.take(),
            Some(Err(GrpcError::MessageTooLarge { declared }))
        );

        let mut at_the_limit = input(None);
        at_the_limit.push(&prefix(GrpcInput::MESSAGE_LIMIT as u32));
        assert!(at_the_limit.failed.is_none());
    }
}
