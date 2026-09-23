#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StreamId(u32);

const STREAM_ID_MASK: u32 = 1 << 31;

impl StreamId {
    pub const ZERO: StreamId = StreamId(0);

    pub const MAX: StreamId = StreamId(u32::MAX >> 1);

    #[inline]
    pub fn parse(buf: &[u8]) -> (StreamId, bool) {
        let mut ubuf = [0; 4];
        ubuf.copy_from_slice(&buf[0..4]);
        let unpacked = u32::from_be_bytes(ubuf);
        let flag = unpacked & STREAM_ID_MASK == STREAM_ID_MASK;

        // The MSB is reserved and MUST be ignored when received.
        (StreamId(unpacked & !STREAM_ID_MASK), flag)
    }

    pub fn is_client_initiated(&self) -> bool {
        let id = self.0;
        id != 0 && id % 2 == 1
    }

    #[inline]
    pub fn zero() -> StreamId {
        StreamId::ZERO
    }

    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }
}

impl From<u32> for StreamId {
    fn from(src: u32) -> Self {
        assert_eq!(src & STREAM_ID_MASK, 0, "invalid stream ID -- MSB is set");
        StreamId(src)
    }
}

impl From<StreamId> for u32 {
    fn from(src: StreamId) -> Self {
        src.0
    }
}

impl PartialEq<u32> for StreamId {
    fn eq(&self, other: &u32) -> bool {
        self.0 == *other
    }
}

impl std::fmt::Display for StreamId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
