use runtime::bytes::{Bytes, BytesMut};

use super::prefix::PREFIX_LEN;
use crate::shared::codec::frames::stream_id::StreamId;
use crate::shared::connection::{SendSide, SharedConnection};

/// The flag is always 0. Compressing a response would mean agreeing an
/// encoding with the peer first, through `grpc-accept-encoding`, and this end
/// announces none.
pub fn frame_message<M: prost::Message>(message: &M) -> Bytes {
    let len = message.encoded_len();
    let mut out = BytesMut::with_capacity(PREFIX_LEN + len);
    out.put_u8(0);
    out.put_u32(len as u32);
    let mut spare = &mut out.spare_capacity_mut()[..len];
    message.encode(&mut spare).expect("room for `encoded_len`");
    assert!(
        spare.is_empty(),
        "a message wrote less than its `encoded_len`"
    );
    // SAFETY: the message wrote all `len` bytes after the prefix.
    unsafe { out.set_len(PREFIX_LEN + len) };
    out.freeze()
}

/// A message on its way, client's or server's: encoded straight into the
/// connection's output when it can all go at once; framed apart otherwise,
/// and sent from its own buffer rather than copied in, if large enough.
pub(crate) async fn write_message<S: SendSide, M: prost::Message>(
    connection: &SharedConnection,
    stream_id: StreamId,
    stream: &S,
    message: &M,
    end_stream: bool,
) {
    let len = message.encoded_len();
    let in_place = connection.try_write_data_in_place(
        stream_id,
        stream,
        PREFIX_LEN + len,
        end_stream,
        |out| put_message(out, message, len),
    );
    if !in_place {
        connection
            .write_data_owned(stream_id, stream, frame_message(message), end_stream)
            .await;
    }
}

/// The prefix and the message after it, appended to `out`. `len` is its
/// `encoded_len`, asked once by the caller, which needed it to know whether
/// it fits.
fn put_message<M: prost::Message>(out: &mut Vec<u8>, message: &M, len: usize) {
    out.push(0);
    out.extend_from_slice(&(len as u32).to_be_bytes());
    message.encode(out).expect("a `Vec` grows");
}

#[cfg(test)]
mod tests {
    use super::super::{Accumulating, GrpcFormat, GrpcFrame};
    use super::*;

    #[derive(Clone, PartialEq, prost::Message)]
    struct HealthCheckResponse {
        #[prost(int32, tag = "1")]
        status: i32,
    }

    #[test]
    fn a_framed_message_is_its_prefix_and_its_bytes() {
        let framed = frame_message(&HealthCheckResponse { status: 1 });

        // Field 1, varint, 1.
        assert_eq!(framed, [0, 0, 0, 0, 2, 0x08, 0x01]);
    }

    #[test]
    fn a_message_of_all_defaults_frames_to_its_prefix_alone() {
        let framed = frame_message(&HealthCheckResponse { status: 0 });
        assert_eq!(framed, [0, 0, 0, 0, 0]);
    }

    #[test]
    fn what_is_framed_here_reads_back_through_the_frame_reader() {
        let response = HealthCheckResponse { status: 7 };
        let framed = frame_message(&response);

        let (prefix, bytes) = framed.split_at(PREFIX_LEN);
        assert_eq!(prefix[0], 0, "not compressed");
        assert_eq!(
            u32::from_be_bytes(prefix[1..].try_into().unwrap()) as usize,
            bytes.len()
        );

        let mut frame = Accumulating::new(bytes.len(), None, GrpcFormat::Proto);
        frame.push(bytes).unwrap();
        let GrpcFrame::Uncompressed(frame) = frame.finish().ok().unwrap() else {
            unreachable!("no encoding")
        };
        assert_eq!(frame.decode(), Ok(response));
    }
}
