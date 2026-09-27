//! Fixed-size segments put a ceiling on what a connection holds: the peer's
//! flow-control credit says how much it will receive, nothing about our memory.

use std::task::Waker;

use bytes::Bytes;
use runtime::net::IoBuf;

use crate::shared::codec::types::HEADER_LEN;

/// Equal to `DEFAULT_MAX_FRAME_SIZE`, so a DATA frame cut to
/// `OUTPUT_SEGMENT - HEADER_LEN` fills a segment exactly, header included.
pub const OUTPUT_SEGMENT: usize = 16 * 1024;

/// Queued and in-flight bytes both count, so this is the whole output
/// footprint of a connection, not a soft target.
pub const OUTPUT_HIGH_WATER: usize = 16 * OUTPUT_SEGMENT;

const SEGMENT_MIN_ROOM: usize = 64;

/// Segments kept for reuse, at most: a high-water mark's worth. An attached
/// slice closes the segment before it, so a chain can hold more segments
/// than its bytes would fill; those are let go once sent rather than kept.
const POOL_MAX: usize = OUTPUT_HIGH_WATER / OUTPUT_SEGMENT;

/// Below this, a buffer handed over whole is copied into the segments anyway:
/// one more `writev` entry, and a reference to count and drop, costs more
/// than copying it. Provisional, to be measured.
pub const ATTACH_MIN: usize = 4 * 1024;

/// What the chain holds, in wire order.
pub enum Chunk {
    /// Pooled, and written into: frames, and bodies copied in.
    Segment(Vec<u8>),
    /// A slice of a buffer the application handed over, sent as it is: no
    /// copy, and dropped rather than pooled once sent.
    Attached(Bytes),
}

impl Chunk {
    fn len(&self) -> usize {
        match self {
            Self::Segment(segment) => segment.len(),
            Self::Attached(bytes) => bytes.len(),
        }
    }
}

// SAFETY: both hold their bytes on the heap, or in `.rodata` for a static
// `Bytes`, at an address moving the value does not change; neither is ever
// written through while it is being sent.
unsafe impl IoBuf for Chunk {
    fn stable_ptr(&self) -> *const u8 {
        match self {
            Self::Segment(segment) => segment.as_ptr(),
            Self::Attached(bytes) => bytes.as_ptr(),
        }
    }

    fn bytes_init(&self) -> usize {
        self.len()
    }
}

const _: () = assert!(
    OUTPUT_HIGH_WATER > OUTPUT_SEGMENT,
    "one segment must not reach the high-water mark on its own, or every send carries one segment"
);

const _: () = assert!(
    SEGMENT_MIN_ROOM > HEADER_LEN,
    "usable room must hold a frame header, or `data_room` underflows"
);

pub struct Output {
    /// The last is open for writing, if it is a segment. Never holds an empty
    /// chunk.
    chain: Vec<Chunk>,
    queued: usize,
    /// Counted against the high-water mark like queued bytes.
    in_flight: usize,
    /// At most [`POOL_MAX`]: a segment is in the chain, in flight, here, or
    /// freed.
    pool: Vec<Vec<u8>>,
    spare: Vec<Chunk>,
    /// Woken when a send completes, the only thing that makes room.
    waiters: Vec<Waker>,
}

impl Output {
    pub fn new() -> Self {
        Self {
            chain: Vec::new(),
            queued: 0,
            in_flight: 0,
            pool: Vec::new(),
            spare: Vec::new(),
            waiters: Vec::new(),
        }
    }

    /// A frame is never split across segments, so a header block with its
    /// CONTINUATIONs stays contiguous (§6.10).
    ///
    /// Ignores the high-water mark: control frames and heads are bounded
    /// elsewhere (inbound frame rate, `MAX_CONCURRENT_STREAMS`). Bodies are
    /// held back by [`Output::data_room`].
    pub fn write(&mut self, encode: impl FnOnce(&mut Vec<u8>)) {
        let written = {
            let open = self.open();
            let before = open.len();
            encode(open);
            open.len() - before
        };
        self.queued += written;
    }

    /// Zero means the high-water mark is reached. A body is cut on segment
    /// boundaries and never grows one past its size.
    pub fn data_room(&self) -> usize {
        if self.queued + self.in_flight >= OUTPUT_HIGH_WATER {
            return 0;
        }
        match self.room() {
            0 => OUTPUT_SEGMENT - HEADER_LEN,
            room => room - HEADER_LEN,
        }
    }

    /// How much of a handed-over buffer may be attached now: attached bytes
    /// count against the high-water mark as segments do, so a buffer larger
    /// than it goes in slices, each waiting for the last to be sent.
    pub fn attach_room(&self) -> usize {
        OUTPUT_HIGH_WATER.saturating_sub(self.queued + self.in_flight)
    }

    /// Appended after whatever was written last, a frame header for it
    /// included. What is written next goes into a fresh segment.
    pub fn attach(&mut self, bytes: Bytes) {
        if bytes.is_empty() {
            return;
        }
        self.queued += bytes.len();
        self.chain.push(Chunk::Attached(bytes));
    }

    pub fn wait_room(&mut self, waker: &Waker) {
        if !self.waiters.iter().any(|w| w.will_wake(waker)) {
            self.waiters.push(waker.clone());
        }
    }

    pub fn is_empty(&self) -> bool {
        self.queued == 0
    }

    /// The segments stay accounted for as `in_flight` until
    /// [`Output::restore`], so a writer cannot fill a second chain's worth
    /// while the first is in the kernel.
    pub fn take(&mut self) -> Vec<Chunk> {
        self.in_flight += self.queued;
        self.queued = 0;
        std::mem::replace(&mut self.chain, std::mem::take(&mut self.spare))
    }

    /// Segments go back to the pool; attached slices are dropped, and with
    /// the last of them the application's buffer.
    pub fn restore(&mut self, mut sent: Vec<Chunk>) {
        for chunk in sent.drain(..) {
            self.in_flight -= chunk.len();
            let Chunk::Segment(mut segment) = chunk else {
                continue;
            };
            if self.pool.len() >= POOL_MAX {
                continue;
            }
            segment.clear();
            // Keeps one outsized header block from being pooled at that size
            // forever.
            segment.shrink_to(OUTPUT_SEGMENT);
            self.pool.push(segment);
        }
        self.spare = sent;

        for waker in self.waiters.drain(..) {
            waker.wake();
        }
    }

    fn open(&mut self) -> &mut Vec<u8> {
        if self.room() == 0 {
            let segment = self
                .pool
                .pop()
                .unwrap_or_else(|| Vec::with_capacity(OUTPUT_SEGMENT));
            self.chain.push(Chunk::Segment(segment));
        }
        match self.chain.last_mut() {
            Some(Chunk::Segment(open)) => open,
            _ => unreachable!("a segment was just opened"),
        }
    }

    /// Zero whenever the next write must take a fresh segment, which is
    /// always after an attached slice: what follows it on the wire must
    /// follow it in the chain.
    fn room(&self) -> usize {
        match self.chain.last() {
            Some(Chunk::Segment(open)) => match OUTPUT_SEGMENT.saturating_sub(open.len()) {
                room if room >= SEGMENT_MIN_ROOM => room,
                _ => 0,
            },
            Some(Chunk::Attached(_)) | None => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(chain: &[Chunk]) -> Vec<&'static str> {
        chain
            .iter()
            .map(|chunk| match chunk {
                Chunk::Segment(_) => "segment",
                Chunk::Attached(_) => "attached",
            })
            .collect()
    }

    /// What is written after a slice must follow it on the wire.
    #[test]
    fn a_write_after_an_attached_slice_opens_a_segment_after_it() {
        let mut output = Output::new();
        output.write(|out| out.extend_from_slice(b"header"));
        output.attach(Bytes::from_static(&[7; 100]));
        output.write(|out| out.extend_from_slice(b"next"));

        let chain = output.take();
        assert_eq!(kinds(&chain), ["segment", "attached", "segment"]);
        assert_eq!(chain.iter().map(Chunk::len).sum::<usize>(), 6 + 100 + 4);
    }

    #[test]
    fn attached_bytes_count_against_the_high_water_mark_until_sent() {
        let mut output = Output::new();
        output.attach(Bytes::from(vec![0; 1000]));
        assert_eq!(output.attach_room(), OUTPUT_HIGH_WATER - 1000);

        let chain = output.take();
        assert_eq!(output.attach_room(), OUTPUT_HIGH_WATER - 1000, "in flight");
        output.restore(chain);
        assert_eq!(output.attach_room(), OUTPUT_HIGH_WATER);
    }

    /// Only segments are the pool's to reuse; a slice is let go.
    #[test]
    fn a_sent_chain_pools_its_segments_and_drops_its_slices() {
        let mut output = Output::new();
        output.write(|out| out.extend_from_slice(b"header"));
        output.attach(Bytes::from(vec![0; 1000]));
        output.write(|out| out.extend_from_slice(b"next"));

        let chain = output.take();
        output.restore(chain);
        assert_eq!(output.pool.len(), 2);
        assert!(output.pool.iter().all(Vec::is_empty));
    }

    /// A chain of slices leaves many segments behind it; the pool keeps a
    /// high-water mark's worth and lets the rest go.
    #[test]
    fn the_pool_keeps_no_more_than_a_high_water_marks_worth() {
        let mut output = Output::new();
        for _ in 0..POOL_MAX * 3 {
            output.write(|out| out.extend_from_slice(b"header"));
            output.attach(Bytes::from_static(&[7; ATTACH_MIN]));
        }
        let chain = output.take();
        assert_eq!(chain.len(), POOL_MAX * 6);

        output.restore(chain);
        assert_eq!(output.pool.len(), POOL_MAX);
    }
}
