use std::mem::MaybeUninit;

use super::prefix::PREFIX_LEN;
use super::request::GrpcFormat;

/// A gRPC message whose prefix has been read and whose bytes are arriving.
pub struct Accumulating {
    /// Allocated once, at the length the prefix announced: `bytes.len()` is
    /// the expected length. Uninitialised, so nothing is written here before
    /// the peer's own bytes.
    bytes: Box<[MaybeUninit<u8>]>,
    /// How many are written. Invariant: `bytes[..filled]` is initialised.
    filled: usize,
    /// What the message is compressed with, `None` when it is not: the
    /// prefix's Compressed-Flag and the request's `grpc-encoding`, which only
    /// mean something together.
    encoding: Option<GrpcEncoding>,
    /// What the message is serialised as, once it is not compressed: the
    /// request's, the same for every message of it.
    format: GrpcFormat,
}

impl Accumulating {
    /// `expected` comes off the wire: bounding it is the caller's to have
    /// done.
    pub fn new(expected: usize, encoding: Option<GrpcEncoding>, format: GrpcFormat) -> Self {
        Self {
            bytes: Box::new_uninit_slice(expected),
            filled: 0,
            encoding,
            format,
        }
    }

    pub fn missing(&self) -> usize {
        self.bytes.len() - self.filled
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
        let dst = self.bytes[self.filled..self.filled + payload.len()].as_mut_ptr();
        // SAFETY: checked above to fit in what is left of our own allocation,
        // which `payload` cannot overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(payload.as_ptr(), dst.cast::<u8>(), payload.len());
        }
        self.filled += payload.len();
        Ok(())
    }

    /// Finishes the frame. `Err(self)` while bytes are missing: nothing is
    /// lost.
    pub fn finish(self) -> Result<GrpcFrame, Self> {
        if self.missing() > 0 {
            return Err(self);
        }
        // SAFETY: `filled == bytes.len()`, so every byte has been written.
        let bytes = unsafe { self.bytes.assume_init() };
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
