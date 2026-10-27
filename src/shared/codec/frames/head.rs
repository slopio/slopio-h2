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
        let start = dst.len();
        let [_, len @ ..] = (payload_len as u32).to_be_bytes();
        dst.extend_from_slice(&len);
        dst.push(self.kind as u8);
        dst.push(self.flag);
        dst.extend_from_slice(&u32::from(self.stream_id).to_be_bytes());
        debug_assert_eq!(dst.len() - start, HEADER_LEN);
    }
}
