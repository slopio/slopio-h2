use crate::shared::codec::{frames::stream_id::StreamId, types::HEADER_LEN};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Head {
    kind: Kind,
    flag: u8,
    stream_id: StreamId,
}

/// The frames this end writes: never PRIORITY (RFC 9113 deprecates it), never
/// PUSH_PROMISE (the client refuses push, the server never offers it).
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Kind {
    Data = 0,
    Headers = 1,
    Reset = 3,
    Settings = 4,
    Ping = 6,
    GoAway = 7,
    WindowUpdate = 8,
    Continuation = 9,
}

impl Head {
    pub fn new(kind: Kind, flag: u8, stream_id: StreamId) -> Head {
        Head {
            kind,
            flag,
            stream_id,
        }
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub fn flag(&self) -> u8 {
        self.flag
    }

    pub fn encode(&self, payload_len: usize, dst: &mut Vec<u8>) {
        dst.extend_from_slice(&self.to_bytes(payload_len));
    }

    /// For a header written after its payload, once the length is known.
    pub fn to_bytes(self, payload_len: usize) -> [u8; HEADER_LEN] {
        let [_, l0, l1, l2] = (payload_len as u32).to_be_bytes();
        let [s0, s1, s2, s3] = u32::from(self.stream_id).to_be_bytes();
        [l0, l1, l2, self.kind as u8, self.flag, s0, s1, s2, s3]
    }
}
