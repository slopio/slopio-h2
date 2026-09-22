use super::prefix::PREFIX_LEN;
use super::request::GrpcFormat;

/// A gRPC message whose prefix has been read and whose bytes are arriving.
pub struct Accumulating {
    /// What has arrived. Its capacity is not the announced length: see
    /// [`FIRST_RESERVE`](Self::FIRST_RESERVE).
    bytes: Vec<u8>,
    /// The length the prefix announced.
    expected: usize,
    /// What the message is compressed with, `None` when it is not: the
    /// prefix's Compressed-Flag and the request's `grpc-encoding`, which only
    /// mean something together.
    encoding: Option<GrpcEncoding>,
    /// What the message is serialised as, once it is not compressed: the
    /// request's, the same for every message of it.
    format: GrpcFormat,
}

impl Accumulating {
    /// What is reserved on the prefix alone, when the announced length is
    /// more than this: one stream window, which is what the peer can send
    /// before it needs anything of us.
    ///
    /// The announced length is a claim, and reserving it would let five
    /// bytes of prefix cost us 4 MiB — on every stream at once, for nothing
    /// sent. So a large message starts in a window's worth, and is moved once,
    /// into exactly its announced size, the first time it outgrows that. One
    /// copy of at most this much per large message, and nothing at all for a
    /// message that fits, which is nearly every one.
    pub const FIRST_RESERVE: usize = 64 * 1024;

    /// `expected` comes off the wire: bounding it is the caller's to have
    /// done.
    pub fn new(expected: usize, encoding: Option<GrpcEncoding>, format: GrpcFormat) -> Self {
        Self {
            bytes: Vec::with_capacity(expected.min(Self::FIRST_RESERVE)),
            expected,
            encoding,
            format,
        }
    }

    pub fn missing(&self) -> usize {
        self.expected - self.bytes.len()
    }

    /// Appends `payload`, all of it or none of it.
    ///
    /// This is what decides whether it fits, and not the caller: the length
    /// was fixed by the prefix, and a payload longer than what is
    /// [`missing`](Self::missing) is refused whole, with nothing written. One
    /// DATA payload may well hold the end of this message and the start of the
    /// next — cutting it at `missing` is the caller's, and what is past the
    /// cut is the next prefix's.
    pub fn push(&mut self, payload: &[u8]) -> Result<(), FrameOverflow> {
        if payload.len() > self.missing() {
            return Err(FrameOverflow {
                missing: self.missing(),
                pushed: payload.len(),
            });
        }
        // Outgrown the first reservation: the rest of the message is on its
        // way, so take room for all of it, once. Exactly, so that what is
        // handed out at the end is the allocation it was built in.
        if payload.len() > self.bytes.capacity() - self.bytes.len() {
            self.bytes.reserve_exact(self.missing());
        }
        self.bytes.extend_from_slice(payload);
        Ok(())
    }

    /// Finishes the frame. `Err(self)` while bytes are missing: nothing is
    /// lost.
    pub fn finish(self) -> Result<GrpcFrame, Self> {
        if self.missing() > 0 {
            return Err(self);
        }
        // Capacity is the announced length by now, so this does not move.
        let bytes = self.bytes.into_boxed_slice();
        let format = self.format;
        Ok(match self.encoding {
            Some(encoding) => GrpcFrame::Compressed(CompressedGrpcFrame {
                encoding,
                format,
                bytes,
            }),
            None => GrpcFrame::Uncompressed(UncompressedGrpcFrame { format, bytes }),
        })
    }
}

/// A message compression a request's `grpc-encoding` can name. `identity` is
/// not one: it is the absence of any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcEncoding {
    Gzip,
    Deflate,
}

/// More bytes than the prefix announced were left to come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameOverflow {
    pub missing: usize,
    pub pushed: usize,
}

/// What [`Accumulating::finish`] gives: the prefix's Compressed-Flag, turned
/// into a type.
#[derive(Debug, PartialEq, Eq)]
pub enum GrpcFrame {
    Compressed(CompressedGrpcFrame),
    Uncompressed(UncompressedGrpcFrame),
}

impl GrpcFrame {
    /// What it took on the wire, prefix included — which is what it held of
    /// its stream's receive window.
    pub fn wire_len(&self) -> usize {
        PREFIX_LEN
            + match self {
                Self::Compressed(frame) => frame.bytes.len(),
                Self::Uncompressed(frame) => frame.bytes.len(),
            }
    }

    /// The message, decoded as protobuf — for the handler that takes every
    /// message the same way and would rather not match.
    ///
    /// The two things matching would have told it are the two errors it can
    /// answer instead: a frame still compressed, and a request whose
    /// `content-type` named something other than protobuf.
    pub fn decode<M: prost::Message + Default>(&self) -> Result<M, MessageError> {
        match self {
            Self::Uncompressed(frame) => frame.decode(),
            Self::Compressed(frame) => Err(MessageError::Compressed(frame.encoding)),
        }
    }
}

/// Why a whole message is not the message the handler asked for.
#[derive(Debug, Clone, PartialEq)]
pub enum MessageError {
    /// Still in the encoding `grpc-encoding` named: decompress it first.
    /// INTERNAL, or UNIMPLEMENTED if this end cannot.
    Compressed(GrpcEncoding),
    /// The request's `content-type` named a format that is not protobuf, so
    /// its bytes are not protobuf either. INTERNAL.
    NotProto(GrpcFormat),
    /// Protobuf, and not the message that was asked for. INVALID_ARGUMENT.
    Decode(prost::DecodeError),
}

/// A whole message, still in the encoding the request's `grpc-encoding` named.
/// Its bytes are not a message yet, which is why this is not the type that
/// hands out `data`: the way to one that does is `try_into`.
#[derive(Debug, PartialEq, Eq)]
pub struct CompressedGrpcFrame {
    encoding: GrpcEncoding,
    /// Of the message inside, which decompressing carries over.
    format: GrpcFormat,
    bytes: Box<[u8]>,
}

/// A whole message, as it was serialised — in the [`GrpcFormat`] its request
/// named.
#[derive(Debug, PartialEq, Eq)]
pub struct UncompressedGrpcFrame {
    format: GrpcFormat,
    bytes: Box<[u8]>,
}

impl CompressedGrpcFrame {
    pub fn encoding(&self) -> GrpcEncoding {
        self.encoding
    }

    pub fn format(&self) -> GrpcFormat {
        self.format
    }

    pub fn compressed_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A compressed frame whose bytes were not what its encoding says they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecompressError;

/// The frame knows what it was compressed with, so decompressing it takes
/// nothing else — which is what lets it be a conversion.
impl TryFrom<CompressedGrpcFrame> for UncompressedGrpcFrame {
    type Error = DecompressError;

    fn try_from(_frame: CompressedGrpcFrame) -> Result<Self, Self::Error> {
        unimplemented!("gRPC message decompression")
    }
}

impl UncompressedGrpcFrame {
    pub fn format(&self) -> GrpcFormat {
        self.format
    }

    /// The message, decoded as protobuf into whatever the caller derived
    /// `Message` on.
    ///
    /// Zero bytes is not an absence: proto3 writes nothing for a field at its
    /// default, so a value whose fields are all default encodes to nothing and
    /// decodes back from nothing. `HealthCheckRequest { service: "" }` — the
    /// whole-server health probe — is that message and five bytes on the wire.
    ///
    /// Refused unless the request's `content-type` said protobuf: `+json` is
    /// someone else's bytes, and `prost` would read them as a malformed
    /// message rather than as JSON.
    pub fn decode<M: prost::Message + Default>(&self) -> Result<M, MessageError> {
        if self.format != GrpcFormat::Proto {
            return Err(MessageError::NotProto(self.format));
        }
        M::decode(&*self.bytes).map_err(MessageError::Decode)
    }

    pub fn data(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_data(self) -> Box<[u8]> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data_of(frame: GrpcFrame) -> Box<[u8]> {
        match frame {
            GrpcFrame::Uncompressed(frame) => frame.into_data(),
            GrpcFrame::Compressed(_) => panic!("not compressed"),
        }
    }

    #[test]
    fn bytes_arriving_in_pieces_finish_as_one_frame() {
        let mut frame = Accumulating::new(10, None, GrpcFormat::Proto);
        assert_eq!(frame.push(b"0123"), Ok(()));
        assert_eq!(frame.missing(), 6);
        assert_eq!(frame.push(b"456789"), Ok(()));

        let Ok(frame) = frame.finish() else {
            panic!("every byte arrived");
        };
        assert_eq!(&*data_of(frame), b"0123456789");
    }

    /// Refused whole: a frame that took the part that fits would have eaten
    /// the start of the next prefix without saying so.
    #[test]
    fn a_push_past_the_announced_length_is_refused_and_writes_nothing() {
        let mut frame = Accumulating::new(3, None, GrpcFormat::Proto);
        assert_eq!(frame.push(b"a"), Ok(()));
        assert_eq!(
            frame.push(b"bcdef"),
            Err(FrameOverflow {
                missing: 2,
                pushed: 5
            })
        );
        assert_eq!(frame.missing(), 2, "nothing of it was taken");

        assert_eq!(frame.push(b"bc"), Ok(()));
        assert_eq!(frame.push(b"d"), Err(FrameOverflow { missing: 0, pushed: 1 }));
        assert_eq!(&*data_of(frame.finish().ok().unwrap()), b"abc");
    }

    #[test]
    fn a_frame_missing_bytes_does_not_finish() {
        let mut frame = Accumulating::new(4, None, GrpcFormat::Proto);
        frame.push(b"ab").unwrap();

        let Err(mut frame) = frame.finish() else {
            panic!("two bytes short");
        };
        frame.push(b"cd").unwrap();
        assert_eq!(&*data_of(frame.finish().ok().unwrap()), b"abcd");
    }

    /// A prefix announcing zero bytes is a message like any other.
    #[test]
    fn an_empty_frame_finishes_at_once() {
        let frame = Accumulating::new(0, None, GrpcFormat::Proto).finish().ok().unwrap();
        assert!(data_of(frame).is_empty());
    }

    /// The announced length is a claim: what is reserved on it is one
    /// window, and the rest only once the peer has actually sent that much.
    #[test]
    fn a_large_message_reserves_a_window_first_and_its_whole_size_once() {
        const FIRST: usize = Accumulating::FIRST_RESERVE;
        let expected = 3 * FIRST + 1;
        let mut frame = Accumulating::new(expected, None, GrpcFormat::Proto);
        assert_eq!(frame.bytes.capacity(), FIRST, "announced, not reserved");

        frame.push(&[1; FIRST]).unwrap();
        assert_eq!(frame.bytes.capacity(), FIRST, "fits: nothing moves");

        frame.push(&[2]).unwrap();
        assert_eq!(frame.bytes.capacity(), expected, "once, to exactly the announced length");

        frame.push(&vec![3; expected - FIRST - 1]).unwrap();
        assert_eq!(frame.bytes.capacity(), expected, "and never again");
        assert_eq!(data_of(frame.finish().ok().unwrap()).len(), expected);
    }

    /// A message that fits in the first reservation is reserved exactly, as
    /// it always was: nearly every message is one of these.
    #[test]
    fn a_small_message_is_reserved_exactly() {
        let frame = Accumulating::new(100, None, GrpcFormat::Proto);
        assert_eq!(frame.bytes.capacity(), 100);
        let frame = Accumulating::new(Accumulating::FIRST_RESERVE, None, GrpcFormat::Proto);
        assert_eq!(frame.bytes.capacity(), Accumulating::FIRST_RESERVE);
    }

    /// `grpc.health.v1.HealthCheckRequest`, the one every probe sends.
    #[derive(Clone, PartialEq, prost::Message)]
    struct HealthCheckRequest {
        #[prost(string, tag = "1")]
        service: String,
    }

    fn uncompressed(format: GrpcFormat, bytes: &[u8]) -> UncompressedGrpcFrame {
        let mut frame = Accumulating::new(bytes.len(), None, format);
        frame.push(bytes).unwrap();
        match frame.finish().ok().unwrap() {
            GrpcFrame::Uncompressed(frame) => frame,
            GrpcFrame::Compressed(_) => unreachable!("no encoding"),
        }
    }

    #[test]
    fn a_message_decodes_into_what_the_caller_derived() {
        // Field 1, length-delimited, two bytes: `service = "db"`.
        let frame = uncompressed(GrpcFormat::Proto, &[0x0A, 0x02, b'd', b'b']);
        assert_eq!(
            frame.decode::<HealthCheckRequest>(),
            Ok(HealthCheckRequest {
                service: "db".into()
            })
        );
    }

    /// The whole-server health probe: proto3 writes nothing for a field at its
    /// default, so the request is five bytes of prefix and no content — and it
    /// decodes back into the value that produced it.
    #[test]
    fn a_message_of_no_bytes_decodes_into_one_of_all_defaults() {
        let frame = uncompressed(GrpcFormat::Proto, b"");
        assert_eq!(
            frame.decode::<HealthCheckRequest>(),
            Ok(HealthCheckRequest {
                service: String::new()
            })
        );
    }

    #[test]
    fn json_bytes_are_not_offered_to_protobuf() {
        let frame = uncompressed(GrpcFormat::Json, br#"{"service":"db"}"#);
        assert_eq!(
            frame.decode::<HealthCheckRequest>(),
            Err(MessageError::NotProto(GrpcFormat::Json))
        );
    }

    #[test]
    fn bytes_that_are_not_the_message_asked_for_are_an_error() {
        // Field 1 as a varint, where the message declares a string.
        let frame = uncompressed(GrpcFormat::Proto, &[0x08, 0x2A]);
        assert!(matches!(
            frame.decode::<HealthCheckRequest>(),
            Err(MessageError::Decode(_))
        ));
    }

    /// The handler that does not match takes the same two facts as errors.
    #[test]
    fn decoding_through_the_enum_answers_for_a_compressed_frame() {
        let mut frame = Accumulating::new(2, Some(GrpcEncoding::Gzip), GrpcFormat::Proto);
        frame.push(b"zz").unwrap();
        assert_eq!(
            frame.finish().ok().unwrap().decode::<HealthCheckRequest>(),
            Err(MessageError::Compressed(GrpcEncoding::Gzip))
        );

        let whole = GrpcFrame::Uncompressed(uncompressed(GrpcFormat::Proto, b""));
        assert!(whole.decode::<HealthCheckRequest>().is_ok());
    }

    #[test]
    fn an_encoding_picks_the_type_and_stays_with_the_frame() {
        let mut frame = Accumulating::new(2, Some(GrpcEncoding::Gzip), GrpcFormat::Json);
        frame.push(b"zz").unwrap();
        match frame.finish().ok().unwrap() {
            GrpcFrame::Compressed(frame) => {
                assert_eq!(frame.encoding(), GrpcEncoding::Gzip);
                assert_eq!(frame.format(), GrpcFormat::Json);
                assert_eq!(frame.compressed_bytes(), b"zz");
            }
            GrpcFrame::Uncompressed(_) => panic!("the prefix said compressed"),
        }
    }
}
