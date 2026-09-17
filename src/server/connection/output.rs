//! What a connection has written and not yet sent.
//!
//! A chain of fixed-size segments rather than one growable buffer, for two
//! reasons.
//!
//! It puts a ceiling on what a connection holds. The peer's flow-control
//! credit is not that ceiling: credit says how much the peer is willing to
//! receive, which is no statement at all about our memory. A peer crediting
//! 2^31-1 would have a handler write a whole response into the buffer before
//! the first byte left.
//!
//! And a flush *takes the chain away* instead of draining a buffer, so
//! whatever a task writes while the send is in flight lands in a fresh
//! segment and is simply the next link — where a single buffer had to have
//! those bytes copied back to its front on every flush.

use std::task::Waker;

use crate::shared::codec::types::HEADER_LEN;

/// One segment, and the granularity every output allocation happens at.
///
/// 16 KiB is `DEFAULT_MAX_FRAME_SIZE`, so a DATA frame cut to
/// `OUTPUT_SEGMENT - HEADER_LEN` fills a segment exactly, header included:
/// the common frame and the allocation it travels in are the same size.
pub const OUTPUT_SEGMENT: usize = 16 * 1024;

/// Unsent bytes a connection may hold before a body writer has to wait.
/// Queued and in-flight bytes both count, so this is the whole output
/// footprint of a connection and not a soft target.
///
/// The send-side counterpart of `CONNECTION_RECV_WINDOW`, and ours to choose
/// where the receive window is the peer's. 16 segments: past the 64 KiB a
/// zero-copy send wants to be worth its page pinning, and enough that all
/// `MAX_CONCURRENT_STREAMS` can hold a frame at once.
pub const OUTPUT_HIGH_WATER: usize = 16 * OUTPUT_SEGMENT;

/// Room below which the open segment is closed rather than squeezed: a
/// 9-byte frame header and a handful of payload bytes cost an iovec and a
/// reallocation for nothing.
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
    /// Segments in wire order. The last is open for writing, the ones before
    /// it are full. Never holds an empty segment: a segment is only pushed
    /// for a frame that is about to be written into it.
    chain: Vec<Vec<u8>>,
    /// Bytes across `chain`.
    queued: usize,
    /// Bytes handed to a send that has not completed. Counted against the
    /// high-water mark like queued ones — unsent is unsent, and the kernel
    /// holding them is not us having room.
    in_flight: usize,
    /// Segments a completed send handed back, at nominal capacity. Bounded
    /// by the high-water mark like everything else: a segment is in the
    /// chain, in flight, or here.
    pool: Vec<Vec<u8>>,
    /// The chain vector itself, kept across a flush so that taking the chain
    /// costs no allocation.
    spare: Vec<Vec<u8>>,
    /// Body writers that found no room. Woken when a send completes, which
    /// is the only thing that makes room.
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

    /// Appends one frame. `encode` writes the whole of it — header and
    /// payload — into a single segment, so a frame is never split and a
    /// header block, CONTINUATIONs included, stays contiguous (§6.10).
    ///
    /// Control frames and response heads are written whatever the high-water
    /// mark says: the handlers that produce them are called from the decoder
    /// and cannot wait, and their volume is bounded elsewhere — by the
    /// inbound frame rate for ACKs and resets, by `MAX_CONCURRENT_STREAMS`
    /// for heads. A body is the one producer that can run away, and
    /// [`Output::data_room`] is where it is held back.
    pub fn write(&mut self, encode: impl FnOnce(&mut Vec<u8>)) {
        let written = {
            let open = self.open();
            let before = open.len();
            encode(open);
            open.len() - before
        };
        self.queued += written;
    }

    /// Payload room for one DATA frame, its 9-byte header aside: the fourth
    /// term of the quota in `write_data`, beside the two flow-control
    /// windows and the peer's max frame size.
    ///
    /// Zero is the high-water mark reached, and the writer's cue to park on
    /// [`Output::wait_room`]. Otherwise it is what the open segment has
    /// left, or a whole fresh segment when the open one has nothing usable —
    /// which is what the write will take, so a body is cut on segment
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

    /// Parks a body writer until a send completes.
    pub fn wait_room(&mut self, waker: &Waker) {
        if !self.waiters.iter().any(|w| w.will_wake(waker)) {
            self.waiters.push(waker.clone());
        }
    }

    /// Nothing queued — the connection loop's cue that the tasks have
    /// stopped writing.
    pub fn is_empty(&self) -> bool {
        self.queued == 0
    }

    /// The whole chain, for one gather write. The segments stay accounted
    /// for as `in_flight` until [`Output::restore`] takes them back, so a
    /// writer cannot fill a second chain's worth while the first is in the
    /// kernel.
    pub fn take(&mut self) -> Vec<Vec<u8>> {
        self.in_flight += self.queued;
        self.queued = 0;
        std::mem::replace(&mut self.chain, std::mem::take(&mut self.spare))
    }

    /// Takes the sent segments back into the pool, and wakes whoever was
    /// waiting for the room they just freed.
    pub fn restore(&mut self, mut sent: Vec<Vec<u8>>) {
        for mut segment in sent.drain(..) {
            self.in_flight -= segment.len();
            segment.clear();
            // A frame too large for a segment grew it; shrinking on the way
            // back keeps one outsized header block from being pooled at that
            // size forever. A no-op for a segment that never grew.
            segment.shrink_to(OUTPUT_SEGMENT);
            self.pool.push(segment);
        }
        self.spare = sent;

        for waker in self.waiters.drain(..) {
            waker.wake();
        }
    }

    /// The segment the next frame goes into: the open one while it has room
    /// worth using, a pooled or fresh one otherwise.
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

    /// What the open segment has left. Zero when there is no segment, or too
    /// little of one to bother with, or when the frame that filled it grew it
    /// past its size — all cases where the next write takes a fresh segment.
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
