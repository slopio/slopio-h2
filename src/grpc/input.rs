use std::collections::VecDeque;

use http::HeaderMap;

use super::frame::{Accumulating, GrpcFrame};
use super::prefix::{PREFIX_LEN, Prefix, PrefixRead};
use super::request::{AnnouncedEncoding, GrpcFormat};
use crate::shared::connection::stream_window::LOCAL_INITIAL_WINDOW_SIZE;

/// Why a gRPC request body stopped being one. Handed to the handler rather
/// than turned into a RST_STREAM, because the answer to each of these is a
/// `grpc-status`, and the handler is who speaks gRPC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcError {
    /// A message longer than [`GrpcInput::MESSAGE_LIMIT`]. RESOURCE_EXHAUSTED.
    MessageTooLarge { declared: u32 },
    /// A Compressed-Flag that is neither 0 nor 1. INTERNAL.
    InvalidCompressedFlag(u8),
    /// A compressed message on a request that announced no `grpc-encoding`,
    /// or `identity`. INTERNAL.
    CompressedWithoutEncoding,
    /// A compressed message, in an encoding there is no name for here.
    /// UNIMPLEMENTED.
    UnsupportedEncoding,
    /// More whole messages waiting than [`GrpcInput::QUEUE_LIMIT`].
    /// RESOURCE_EXHAUSTED.
    TooManyMessages,
    /// END_STREAM inside a prefix or a message. INTERNAL.
    Truncated,
}

/// What is being read: every message is a prefix, then as many bytes as the
/// prefix said.
enum Reading {
    Prefix(Prefix),
    Frame(Accumulating),
}

/// Where a gRPC request body lands: a sequence of length-prefixed messages,
/// delivered one whole frame at a time.
///
/// Message boundaries owe nothing to DATA frames: a prefix may straddle two,
/// and one frame may hold several messages.
pub struct GrpcInput {
    reading: Reading,
    /// Whole, and not taken yet.
    ready: VecDeque<GrpcFrame>,
    /// Set once, by the first thing wrong with the body. Nothing after it is
    /// read: the framing is lost, and the handler is about to say so.
    failed: Option<GrpcError>,
    /// Told to the handler already, which is when `take` starts answering
    /// `None`.
    failure_taken: bool,
    announced: AnnouncedEncoding,
    format: GrpcFormat,
    /// `content-length`, on the rare gRPC request that declares one. §8.1.1
    /// holds whatever the content type.
    declared: Option<u64>,
}

impl GrpcInput {
    /// Largest message held. A message is held whole and hands back no stream
    /// credit while it fills, so it and its prefix have to fit in the stream's
    /// receive window.
    pub const MESSAGE_LIMIT: usize = LOCAL_INITIAL_WINDOW_SIZE as usize - PREFIX_LEN;

    /// Most messages waiting to be taken.
    ///
    /// The window bounds them in bytes and not in entries, and the two come
    /// apart: a message costs five bytes of window and rather more than five
    /// bytes to hold — an entry, and an allocation that a short one barely
    /// fills. A peer sending the smallest messages it can into a stream
    /// nobody is draining spends 64 KiB of window on some thirteen thousand
    /// of them.
    ///
    /// Well above any honest burst: this is what piles up between two polls
    /// of a handler that is keeping up, and a client-streaming peer that gets
    /// this far ahead is not one.
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

    /// Takes the next of the body. `true` when the task has something new to
    /// be woken for: a frame became whole, or the body went wrong.
    ///
    /// Nothing here knows about flow control. A frame holds its credit, the
    /// stream's and the connection's, from the moment its bytes land until the
    /// handler takes it — the contract `InputData::Capped` has, once per
    /// message instead of once per body.
    pub fn push(&mut self, mut payload: &[u8]) -> bool {
        let mut wake = false;
        while !payload.is_empty() && self.failed.is_none() {
            // Cut at what the current piece is missing: it refuses more, and
            // what is past the cut belongs to the piece after it.
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

    /// Moves on from whatever has all its bytes: a prefix becomes the frame it
    /// announced, a frame becomes ready and leaves a fresh prefix behind.
    /// `true` when a frame became ready.
    ///
    /// A loop because a prefix announcing zero bytes is a frame that is whole
    /// the moment it begins — a message like any other, what a protobuf with
    /// every field at its default serialises to.
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

    /// Judges a prefix, which is where a message is refused: before anything
    /// is reserved for a length the peer has only claimed.
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

    /// The peer's END_STREAM. It has to fall between two messages: there is
    /// no end marker in the body, so anything else is a body cut short.
    pub fn end(&mut self) {
        let between = matches!(&self.reading, Reading::Prefix(prefix) if prefix.is_untouched());
        if !between && self.failed.is_none() {
            self.failed = Some(GrpcError::Truncated);
        }
    }

    /// The next whole frame, then the failure if there was one — once.
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

    /// What `take` gave, as the bytes of an uncompressed frame.
    fn data(taken: Option<Result<GrpcFrame, GrpcError>>) -> Vec<u8> {
        match taken {
            Some(Ok(GrpcFrame::Uncompressed(frame))) => frame.into_data().into_vec(),
            other => panic!("not an uncompressed frame: {other:?}"),
        }
    }

    /// Frames are the transport's, messages are gRPC's: wherever the bytes are
    /// cut, the same messages come out.
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

    /// The flag and the announced encoding only mean something together.
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

    /// The window bounds the queue in bytes, this bounds it in entries: the
    /// two come apart when the messages are small enough.
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

    /// Taking them keeps the room: a handler that drains is never refused,
    /// however many messages the call has.
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

    /// Refused at the prefix: nothing is reserved for a length the peer only
    /// claimed.
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
