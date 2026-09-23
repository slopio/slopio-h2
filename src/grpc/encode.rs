use super::prefix::PREFIX_LEN;

/// The flag is always 0. Compressing a response would mean agreeing an
/// encoding with the peer first, through `grpc-accept-encoding`, and this end
/// announces none.
pub fn frame_message<M: prost::Message>(message: &M) -> Vec<u8> {
    let len = message.encoded_len();
    let mut out = Vec::with_capacity(PREFIX_LEN + len);
    out.push(0);
    out.extend_from_slice(&(len as u32).to_be_bytes());
    message.encode(&mut out).expect("a `Vec` grows");
    out
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
        assert_eq!(framed.capacity(), framed.len(), "reserved exactly");
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
