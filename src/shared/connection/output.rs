//! Fixed-size segments put a ceiling on what a connection holds: the peer's
//! flow-control credit says how much it will receive, nothing about our memory.

use std::task::Waker;

use crate::shared::codec::types::HEADER_LEN;

/// Equal to `DEFAULT_MAX_FRAME_SIZE`, so a DATA frame cut to
/// `OUTPUT_SEGMENT - HEADER_LEN` fills a segment exactly, header included.
pub const OUTPUT_SEGMENT: usize = 16 * 1024;

/// Queued and in-flight bytes both count, so this is the whole output
/// footprint of a connection, not a soft target.
pub const OUTPUT_HIGH_WATER: usize = 16 * OUTPUT_SEGMENT;

const SEGMENT_MIN_ROOM: usize = 64;

const _: () = assert!(
    OUTPUT_HIGH_WATER > OUTPUT_SEGMENT,
    "one segment must not reach the high-water mark on its own, or every send carries one segment"
);

const _: () = assert!(
    SEGMENT_MIN_ROOM > HEADER_LEN,
    "usable room must hold a frame header, or `data_room` underflows"
);

pub struct Output {
    /// The last is open for writing. Never holds an empty segment.
    chain: Vec<Vec<u8>>,
    queued: usize,
    /// Counted against the high-water mark like queued bytes.
    in_flight: usize,
    /// Bounded by the high-water mark: a segment is in the chain, in flight,
    /// or here.
    pool: Vec<Vec<u8>>,
    spare: Vec<Vec<u8>>,
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
    pub fn take(&mut self) -> Vec<Vec<u8>> {
        self.in_flight += self.queued;
        self.queued = 0;
        std::mem::replace(&mut self.chain, std::mem::take(&mut self.spare))
    }

    pub fn restore(&mut self, mut sent: Vec<Vec<u8>>) {
        for mut segment in sent.drain(..) {
            self.in_flight -= segment.len();
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
            self.chain.push(segment);
        }
        self.chain.last_mut().expect("a segment was just opened")
    }

    /// Zero whenever the next write must take a fresh segment.
    fn room(&self) -> usize {
        match self.chain.last() {
            Some(open) => match OUTPUT_SEGMENT.saturating_sub(open.len()) {
                room if room >= SEGMENT_MIN_ROOM => room,
                _ => 0,
            },
            None => 0,
        }
    }
}
