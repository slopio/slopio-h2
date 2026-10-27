use std::cell::{Cell, RefCell, UnsafeCell};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::task::{Poll, Waker};

use http::{HeaderMap, HeaderName};
use runtime::bytes::Bytes;

use crate::shared::codec::frames::{
    encode::{encode_data_header, encode_header_block, encode_window_update},
    stream_id::StreamId,
};
use crate::shared::connection::STREAM_ID;
use crate::shared::connection::output::{ATTACH_MIN, Chunk, Output};
#[cfg(feature = "grpc")]
use crate::shared::connection::stream_window::StreamWindow;
use crate::shared::hpack::{Encoder, Header};

/// §6.9.2: SETTINGS never moves the connection window — only a WINDOW_UPDATE
/// on stream 0 does.
pub const CONNECTION_INITIAL_WINDOW_SIZE: u32 = 65_535;

/// As many as a connection has streams: more cannot have been reset within
/// one round trip.
const RESETS_REMEMBERED: usize = 64;

pub trait SendSide {
    /// §6.9.1.
    fn available_send(&self) -> u32;

    /// On `Err`, nothing is debited.
    fn debit_send(&self, len: u32) -> Result<(), ()>;

    /// The one place a writer out of credit waits, whichever window ran out:
    /// the stream's own WINDOW_UPDATE wakes it, and so does connection credit
    /// arriving on a spent connection window, the connection walking its
    /// streams for that. Nothing on the connection holds the waker, so
    /// nothing outlives the stream.
    fn register_send_waker(&self, waker: &Waker);

    fn note_sent(&self, n: usize);
}

pub struct ConnectionWindow {
    /// §6.9.1: a DATA frame debits this window *and* its stream's.
    to_send: Cell<i32>,
    /// Debited by `padded_len`, padding included (§6.9.1).
    to_recv: Cell<i32>,
    pending_release: Cell<u32>,
    /// Half the receive window: the peer keeps the other half to spend while
    /// our WINDOW_UPDATE is in flight, so it never stalls.
    release_threshold: u32,
}

impl ConnectionWindow {
    /// Never below zero: only our own sends debit it, and never past it.
    pub fn available_send(&self) -> u32 {
        self.to_send.get().max(0) as u32
    }

    /// §6.9.1: going past 2^31-1 (`i32::MAX`) is a connection error.
    ///
    /// `Ok(true)` when the window was spent: writers may be parked on it, each
    /// in its own stream's slot, and the caller must walk its streams to wake
    /// them. Otherwise nobody waits on it, since a writer takes what is left
    /// before it parks, and a client crediting every few KiB costs nothing.
    pub fn credit_send(&self, increment: u32) -> Result<bool, ()> {
        let before = self.to_send.get();
        let credited = before.checked_add_unsigned(increment).ok_or(())?;
        self.to_send.set(credited);
        Ok(before <= 0)
    }

    /// §6.9.1: debits this window as well as the stream's. On `Err`, nothing
    /// is debited.
    pub fn debit_send(&self, len: u32) -> Result<(), ()> {
        let debited = self
            .to_send
            .get()
            .checked_sub_unsigned(len)
            .filter(|remaining| *remaining >= 0)
            .ok_or(())?;
        self.to_send.set(debited);
        Ok(())
    }

    /// Called beside the WINDOW_UPDATE that carries it, so the ledger never
    /// says more than the wire. The value is our own, hence no overflow check.
    pub fn announce_recv(&self, increment: u32) {
        self.to_recv.set(self.to_recv.get() + increment as i32);
    }

    /// §6.9.1: every DATA frame debits its padded length, whatever becomes of
    /// the frame afterwards.
    pub fn recv(&self, padded_len: u32) -> Result<(), ()> {
        let debited = self
            .to_recv
            .get()
            .checked_sub_unsigned(padded_len)
            .filter(|remaining| *remaining >= 0)
            .ok_or(())?;
        self.to_recv.set(debited);
        Ok(())
    }

    /// `Some` is already credited here, so the caller must write the
    /// WINDOW_UPDATE it is handed — the ledger must never say more than the wire.
    #[must_use]
    pub fn release(&self, len: u32) -> Option<u32> {
        let pending = self.pending_release.get() + len;
        if pending < self.release_threshold {
            self.pending_release.set(pending);
            return None;
        }
        self.pending_release.set(0);
        self.to_recv.set(self.to_recv.get() + pending as i32);
        Some(pending)
    }
}

pub struct SharedConnection {
    /// Header blocks must be encoded in the order they go on the wire, or the
    /// peer's decoder drifts.
    ///
    /// # Safety
    ///
    /// Same two rules as [`Self::output`]: no reference escapes the call,
    /// nothing re-enters under it. [`Self::write_headers`] is a plain `fn` with
    /// no suspension point; making it async would put a reference into a
    /// future, and nothing would say so.
    encoder: UnsafeCell<Encoder>,
    max_frame_size: Cell<u32>,
    /// §5.1: the sender of RST_STREAM must tolerate what the peer had in
    /// flight, where the same frames on any *other* closed stream are the
    /// peer's fault. Bounded to a round trip's worth.
    reset_by_us: RefCell<VecDeque<STREAM_ID>>,
    /// For the Rapid Reset defence; see [`Self::note_completed`].
    completed: Cell<u32>,
    pub window: ConnectionWindow,
    /// # Safety
    ///
    /// Single-threaded and `!Send`, so what must hold is only that no two
    /// references overlap in time:
    ///
    /// **No reference escapes the call that made it.** Every accessor does its
    /// `unsafe` inside one expression and returns an owned value or a copy;
    /// none hands out a `&Output`.
    ///
    /// **Nothing re-enters under the borrow.** Only `Output`'s own code runs,
    /// plus the `encode` closure in [`Self::write_frame`], which is handed the
    /// segment's `Vec<u8>`, not the connection.
    ///
    /// This is a convention, no longer a `RefCell` panic. Turning a `poll_fn`
    /// that writes here into an `async fn` is what would break it: a reference
    /// held across an `.await` outlives the poll.
    output: UnsafeCell<Output>,
    /// Must be woken on every write from another task, or the frame sits in
    /// the chain until the peer happens to send something.
    flusher: RefCell<Option<Waker>>,
    /// No WINDOW_UPDATE will ever come: a writer out of credit is out of it
    /// for good.
    credit_closed: Cell<bool>,
    /// `None` when `getpeername` failed: the peer can be gone by then.
    peer: Option<SocketAddr>,
}

impl SharedConnection {
    pub fn new(
        header_table_size: u32,
        max_frame_size: u32,
        recv_window: u32,
        peer: Option<SocketAddr>,
    ) -> Self {
        Self {
            // `max_size` is bytes, `capacity` is entries: passing the byte
            // size as capacity made 192 KiB resident per idle connection.
            encoder: UnsafeCell::new(Encoder::new(header_table_size as usize, 0)),
            max_frame_size: Cell::new(max_frame_size),
            completed: Cell::new(0),
            reset_by_us: RefCell::new(VecDeque::new()),
            // §6.9.2: SETTINGS never moves these; the gap up to `recv_window`
            // is announced by a WINDOW_UPDATE on stream 0.
            window: ConnectionWindow {
                to_send: Cell::new(CONNECTION_INITIAL_WINDOW_SIZE as i32),
                to_recv: Cell::new(CONNECTION_INITIAL_WINDOW_SIZE as i32),
                pending_release: Cell::new(0),
                release_threshold: recv_window / 2,
            },
            output: UnsafeCell::new(Output::new()),
            flusher: RefCell::new(None),
            credit_closed: Cell::new(false),
            peer,
        }
    }

    pub fn peer(&self) -> Option<SocketAddr> {
        self.peer
    }

    /// The borrow is held for the whole call, so a header block with its
    /// CONTINUATIONs goes out whole, as §6.10 requires.
    pub fn write_frame(&self, encode: impl FnOnce(&mut Vec<u8>)) {
        // SAFETY: the reference dies with the expression, and `encode` is
        // handed a segment rather than the connection, so it cannot re-enter.
        unsafe { (*self.output.get()).write(encode) }
        self.wake_flusher();
    }

    /// `headers` must be in wire order: §8.3 puts every pseudo-header before
    /// every ordinary field.
    pub fn write_headers(
        &self,
        stream_id: StreamId,
        headers: impl Iterator<Item = Header<Option<HeaderName>>>,
        end_stream: bool,
    ) {
        let mut block = Vec::new();
        // SAFETY: the reference dies with the expression. `encode` runs the
        // caller's header iterator, which clones out of a map it owns, and
        // writes into a local that aliases nothing — neither can re-enter.
        unsafe { (*self.encoder.get()).encode(headers, &mut block) };

        // Never zero: `chunks` panics on zero and the value came off the wire.
        let limit = (self.max_frame_size.get() as usize).max(1);

        self.write_frame(|out| encode_header_block(out, stream_id, &block, limit, end_stream));
    }

    /// §8.1: no pseudo-header. The caller must have checked the stream can
    /// take one.
    pub fn write_trailers(&self, stream_id: StreamId, fields: &HeaderMap) {
        let headers = fields.iter().map(|(name, value)| Header::Field {
            name: Some(name.clone()),
            value: value.clone(),
        });
        self.write_headers(stream_id, headers, true);
    }

    /// One DATA frame whose payload `encode` writes straight into the output:
    /// no buffer of its own, no copy. Exactly `len` bytes, which is what is
    /// debited and announced. Only when all of it can go now, in one frame
    /// the stream and the connection have credit for and the open segment has
    /// room for; `false` and nothing written otherwise, for the caller to go
    /// through [`write_data`](Self::write_data).
    #[cfg(feature = "grpc")]
    pub fn try_write_data_in_place<S: SendSide>(
        &self,
        stream_id: StreamId,
        stream: &S,
        len: usize,
        end_stream: bool,
        encode: impl FnOnce(&mut Vec<u8>),
    ) -> bool {
        let credit = stream.available_send().min(self.window.available_send()) as usize;
        // SAFETY: the reference dies with the expression, and `data_room`
        // cannot re-enter.
        let room = unsafe { (*self.output.get()).data_room() };
        if len > credit.min(room).min(self.max_frame_size.get() as usize) {
            return false;
        }

        stream
            .debit_send(len as u32)
            .expect("len is within the stream window");
        self.window
            .debit_send(len as u32)
            .expect("len is within the connection window");
        self.write_frame(|out| {
            encode_data_header(out, stream_id, len, end_stream);
            let before = out.len();
            encode(out);
            debug_assert_eq!(
                out.len() - before,
                len,
                "the payload is the length announced"
            );
        });
        stream.note_sent(len);
        true
    }

    /// As [`write_data`](Self::write_data), for a buffer handed over whole:
    /// each frame's header is written into the output and its payload is a
    /// slice of `payload`, sent as it is, with no copy. Held to the same
    /// credit, frame size and high-water mark, so a buffer past any of them
    /// goes in slices, each waiting its turn.
    ///
    /// Judged frame by frame: one that could only carry less than
    /// [`ATTACH_MIN`] is copied in, as the whole buffer is when it is that
    /// small. A slice forces the next write into a fresh segment, so a peer
    /// crediting a byte at a time must not get one per byte.
    pub async fn write_data_owned<S: SendSide>(
        &self,
        stream_id: StreamId,
        stream: &S,
        payload: Bytes,
        end_stream: bool,
    ) {
        if payload.len() < ATTACH_MIN {
            return self
                .write_data(stream_id, stream, &payload, end_stream)
                .await;
        }

        let mut sent = 0usize;
        std::future::poll_fn(move |cx| {
            loop {
                let remaining = payload.len() - sent;
                let credit = stream.available_send().min(self.window.available_send()) as usize;
                let frame = remaining
                    .min(self.max_frame_size.get() as usize)
                    .min(credit);
                // SAFETY: the references die with their expressions, and
                // neither method can re-enter.
                let (attach_room, data_room) = unsafe {
                    let output = &*self.output.get();
                    (output.attach_room(), output.data_room())
                };
                let attached = frame.min(attach_room);
                let quota = match attached >= ATTACH_MIN {
                    true => attached,
                    false => frame.min(data_room),
                };

                if quota == 0 {
                    // As `write_data`: park on whichever of credit and room
                    // is the empty one.
                    if credit == 0 {
                        stream.register_send_waker(cx.waker());
                        if self.credit_closed.get() {
                            self.wake_flusher();
                        }
                    }
                    if frame > 0 {
                        // SAFETY: the reference dies with the expression;
                        // cloning a waker cannot re-enter.
                        unsafe { (*self.output.get()).wait_room(cx.waker()) }
                    }
                    return Poll::Pending;
                }

                let last = quota == remaining;
                stream
                    .debit_send(quota as u32)
                    .expect("quota is within the stream window");
                self.window
                    .debit_send(quota as u32)
                    .expect("quota is within the connection window");
                let piece = &payload[sent..sent + quota];
                if attached >= ATTACH_MIN {
                    // The header first: `attach` puts the slice after
                    // whatever was written last.
                    self.write_frame(|out| {
                        encode_data_header(out, stream_id, quota, end_stream && last);
                    });
                    let slice = payload.slice(sent..sent + quota);
                    // SAFETY: the reference dies with the expression, and
                    // `attach` cannot re-enter.
                    unsafe { (*self.output.get()).attach(slice) }
                } else {
                    self.write_frame(|out| {
                        encode_data_header(out, stream_id, quota, end_stream && last);
                        out.extend_from_slice(piece);
                    });
                }
                sent += quota;
                stream.note_sent(quota);

                if last {
                    return Poll::Ready(());
                }
            }
        })
        .await
    }

    /// Credit a stream held back while its reader was behind, returned at
    /// once rather than accumulated: the peer was made to wait on exactly
    /// this. Stream and connection both. When to call it is each side's own
    /// to judge; this is only how.
    #[cfg(feature = "grpc")]
    pub fn release_held_credit(&self, stream_id: StreamId, window: &StreamWindow, held: u32) {
        if let Some(increment) = window.release_recv_now(held) {
            self.write_frame(|out| encode_window_update(out, stream_id, increment));
        }
        if held > 0 {
            self.release_stream_credit(held);
        }
    }

    /// §6.9.1: every frame is debited from both the stream's and the
    /// connection's send window.
    ///
    /// Cancel-safe only in that the future is dropped when the stream is
    /// reset, and a half-written body on a reset stream is what §5.1 expects.
    pub fn write_data<S: SendSide>(
        &self,
        stream_id: StreamId,
        stream: &S,
        payload: &[u8],
        end_stream: bool,
    ) -> impl Future<Output = ()> {
        let mut sent = 0usize;

        std::future::poll_fn(move |cx| {
            loop {
                let remaining = &payload[sent..];

                // END_STREAM still has to travel on something, and an empty
                // frame needs no credit.
                if remaining.is_empty() {
                    if end_stream {
                        self.write_frame(|out| encode_data_header(out, stream_id, 0, true));
                    }
                    return Poll::Ready(());
                }

                let credit = stream.available_send().min(self.window.available_send()) as usize;
                // SAFETY: the reference dies with the expression, and
                // `data_room` cannot re-enter.
                let room = unsafe { (*self.output.get()).data_room() };
                let quota = remaining
                    .len()
                    .min(self.max_frame_size.get() as usize)
                    .min(credit)
                    .min(room);

                if quota == 0 {
                    // Credit and room open on different events, so park on
                    // both when both are wanting. Credit is the stream's slot
                    // whichever window is the empty one: see `SendSide`.
                    if credit == 0 {
                        stream.register_send_waker(cx.waker());
                        // Nothing will ever wake this one; tell the loop,
                        // which can end the stream.
                        if self.credit_closed.get() {
                            self.wake_flusher();
                        }
                    }
                    if room == 0 {
                        // SAFETY: the reference dies with the expression;
                        // cloning a waker cannot re-enter.
                        unsafe { (*self.output.get()).wait_room(cx.waker()) }
                    }
                    return Poll::Pending;
                }

                let frame = &remaining[..quota];
                let last = quota == remaining.len();
                stream
                    .debit_send(quota as u32)
                    .expect("quota is within the stream window");
                self.window
                    .debit_send(quota as u32)
                    .expect("quota is within the connection window");
                self.write_frame(|out| {
                    encode_data_header(out, stream_id, frame.len(), end_stream && last);
                    out.extend_from_slice(frame);
                });
                sent += quota;
                stream.note_sent(quota);

                if last {
                    return Poll::Ready(());
                }
            }
        })
    }

    /// The Rapid Reset defence (CVE-2023-44487) tells a client that cancels
    /// *instead of* working from one that cancels *while* working by how much
    /// finished.
    pub fn note_completed(&self) {
        self.completed.set(self.completed.get().saturating_add(1));
    }

    pub fn completed_streams(&self) -> u32 {
        self.completed.get()
    }

    pub fn note_reset(&self, id: STREAM_ID) {
        let mut resets = self.reset_by_us.borrow_mut();
        if resets.len() == RESETS_REMEMBERED {
            resets.pop_front();
        }
        resets.push_back(id);
    }

    /// DATA may keep coming, so the id stays remembered.
    pub fn was_reset(&self, id: STREAM_ID) -> bool {
        self.reset_by_us.borrow().contains(&id)
    }

    /// Forgets `id`: asked for HEADERS, the last thing the peer sends on it.
    pub fn take_reset(&self, id: STREAM_ID) -> bool {
        let mut resets = self.reset_by_us.borrow_mut();
        match resets.iter().position(|reset| *reset == id) {
            Some(at) => {
                resets.remove(at);
                true
            }
            None => false,
        }
    }

    /// The frame goes out beside the ledger entry, never after it.
    pub fn release_stream_credit(&self, len: u32) {
        if let Some(increment) = self.window.release(len) {
            self.write_frame(|out| encode_window_update(out, StreamId::ZERO, increment));
        }
    }

    /// The segments are owed back to `restore_output` once sent; they stay
    /// counted against the high-water mark until then.
    pub(crate) fn take_output(&self) -> Vec<Chunk> {
        // SAFETY: the reference dies with the expression, and the chain is
        // handed back owned.
        unsafe { (*self.output.get()).take() }
    }

    pub(crate) fn restore_output(&self, sent: Vec<Chunk>) {
        // SAFETY: the reference dies with the expression. `restore` wakes the
        // writers waiting for room, and a wake queues a task rather than
        // running one, so nothing re-enters here.
        unsafe { (*self.output.get()).restore(sent) }
    }

    /// The connection loop must drain until this holds: a writer may be
    /// parked waiting for room, and only a flush gives it any.
    pub(crate) fn output_is_empty(&self) -> bool {
        // SAFETY: the reference dies with the expression.
        unsafe { (*self.output.get()).is_empty() }
    }

    /// The peer half-closed: no credit will come back.
    pub(crate) fn close_credit(&self) {
        self.credit_closed.set(true);
    }

    pub(crate) fn park_flusher(&self, waker: &Waker) {
        let mut slot = self.flusher.borrow_mut();
        if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }

    pub(crate) fn wake_flusher(&self) {
        if let Some(waker) = self.flusher.borrow_mut().take() {
            waker.wake();
        }
    }

    /// Must already be clamped to `MAX_ENCODER_TABLE_SIZE`. RFC 7541 §4.2.
    pub fn set_header_table_size(&self, header_table_size: u32) {
        // SAFETY: the reference dies with the expression, and queuing a size
        // update cannot re-enter.
        unsafe { (*self.encoder.get()).update_max_size(header_table_size as usize) };
    }

    pub fn set_max_frame_size(&self, max_frame_size: u32) {
        self.max_frame_size.set(max_frame_size);
    }

    /// See [`Encoder::index_paths`].
    pub fn index_request_paths(&self, on: bool) {
        // SAFETY: the reference dies with the expression, and setting a flag
        // cannot re-enter.
        unsafe { (*self.encoder.get()).index_paths(on) };
    }
}

#[cfg(test)]
mod tests {
    use std::pin::pin;
    use std::task::Context;

    use runtime::net::IoBuf;

    use super::*;
    use crate::shared::codec::types::HEADER_LEN;
    use crate::shared::connection::output::OUTPUT_HIGH_WATER;

    /// A stream with all the credit asked of it.
    struct Unmetered;

    impl SendSide for Unmetered {
        fn available_send(&self) -> u32 {
            u32::MAX >> 1
        }

        fn debit_send(&self, _: u32) -> Result<(), ()> {
            Ok(())
        }

        fn register_send_waker(&self, _: &Waker) {}

        fn note_sent(&self, _: usize) {}
    }

    /// A stream whose credit the test hands out.
    struct Metered(Cell<u32>);

    impl SendSide for Metered {
        fn available_send(&self) -> u32 {
            self.0.get()
        }

        fn debit_send(&self, len: u32) -> Result<(), ()> {
            self.0.set(self.0.get() - len);
            Ok(())
        }

        fn register_send_waker(&self, _: &Waker) {}

        fn note_sent(&self, _: usize) {}
    }

    fn connection(credit: u32) -> SharedConnection {
        let connection = SharedConnection::new(4096, 16_384, 65_535, None);
        connection
            .window
            .credit_send(credit)
            .expect("within 2^31-1");
        connection
    }

    fn poll(connection: &SharedConnection, payload: &Bytes) -> Poll<()> {
        let mut writing =
            pin!(connection.write_data_owned(StreamId::from(1), &Unmetered, payload.clone(), true));
        writing
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
    }

    /// The point of it: what goes to the kernel is the application's own
    /// memory, cut into frames around it.
    #[test]
    fn an_owned_buffer_is_sent_from_its_own_memory() {
        let connection = connection(1 << 20);
        let payload = Bytes::copy_from_slice(&vec![7; 40_000]);
        assert!(poll(&connection, &payload).is_ready());

        let chain = connection.take_output();
        let slices: Vec<&Bytes> = chain
            .iter()
            .filter_map(|chunk| match chunk {
                Chunk::Attached(bytes) => Some(bytes),
                Chunk::Segment(_) => None,
            })
            .collect();
        assert_eq!(
            slices.iter().map(|s| s.len()).collect::<Vec<_>>(),
            [16_384, 16_384, 7_232],
            "cut at max_frame_size"
        );
        let mut at = payload.as_ptr();
        for slice in slices {
            assert_eq!(slice.as_ptr(), at, "not a copy: the payload itself");
            at = at.wrapping_add(slice.len());
        }
        let headers = chain.len() - 3;
        assert_eq!(headers, 3, "a header before each slice");
    }

    #[test]
    fn a_small_owned_buffer_is_copied_in() {
        let connection = connection(1 << 20);
        let payload = Bytes::copy_from_slice(&vec![7; ATTACH_MIN - 1]);
        assert!(poll(&connection, &payload).is_ready());

        let chain = connection.take_output();
        assert!(chain.iter().all(|chunk| matches!(chunk, Chunk::Segment(_))));
        let total: usize = chain
            .iter()
            .map(|chunk| match chunk {
                Chunk::Segment(segment) => segment.len(),
                Chunk::Attached(_) => 0,
            })
            .sum();
        assert_eq!(total, HEADER_LEN + ATTACH_MIN - 1);
    }

    /// Past the high-water mark it waits for a send, as a copied body does.
    #[test]
    fn a_large_owned_buffer_goes_no_further_than_the_high_water_mark() {
        let connection = connection(1 << 24);
        let payload = Bytes::copy_from_slice(&vec![7; OUTPUT_HIGH_WATER * 2]);
        let mut writing =
            pin!(connection.write_data_owned(StreamId::from(1), &Unmetered, payload, true));
        let mut cx = Context::from_waker(Waker::noop());

        assert!(writing.as_mut().poll(&mut cx).is_pending());
        let first = connection.take_output();
        let queued: usize = first.iter().map(IoBuf::bytes_init).sum();
        assert!(
            queued <= OUTPUT_HIGH_WATER + 16 * HEADER_LEN + 16_384,
            "bounded: {queued}"
        );

        // A send completing is what makes room.
        connection.restore_output(first);
        let mut rounds = 1;
        while writing.as_mut().poll(&mut cx).is_pending() {
            let sent = connection.take_output();
            connection.restore_output(sent);
            rounds += 1;
            assert!(rounds < 10, "it moves on as sends complete");
        }
        assert!(rounds >= 2, "it could not all go at once");
    }

    /// A peer crediting a byte at a time gets bytes copied into one segment,
    /// not a slice each with a fresh 16 KiB segment for its header.
    #[test]
    fn a_trickle_of_credit_is_copied_not_attached() {
        let connection = connection(1 << 20);
        let stream = Metered(Cell::new(0));
        let mut writing = pin!(connection.write_data_owned(
            StreamId::from(1),
            &stream,
            Bytes::copy_from_slice(&vec![7; 40_000]),
            true
        ));
        let mut cx = Context::from_waker(Waker::noop());

        for _ in 0..100 {
            stream.0.set(1);
            assert!(writing.as_mut().poll(&mut cx).is_pending());
        }

        let chain = connection.take_output();
        assert!(
            chain.iter().all(|chunk| matches!(chunk, Chunk::Segment(_))),
            "nothing attached"
        );
        assert_eq!(chain.len(), 1, "a hundred one-byte frames, one segment");
        assert_eq!(chain[0].bytes_init(), 100 * (HEADER_LEN + 1));
    }

    /// A waker the connection kept would outlive its stream and pin its task
    /// until the peer next credited stream 0, which it need never do. The
    /// stream's own slot is the only place a writer out of credit waits.
    #[test]
    fn a_writer_out_of_credit_leaves_nothing_on_the_connection() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// Its references counted by the `Arc`, its wakes by itself.
        struct Counted(AtomicUsize);
        impl std::task::Wake for Counted {
            fn wake(self: Arc<Self>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }
        let counted = Arc::new(Counted(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&counted));

        // Out of stream credit, with connection credit to spare.
        let connection = connection(1 << 20);
        let stream = Metered(Cell::new(0));
        {
            let mut writing =
                pin!(connection.write_data(StreamId::from(1), &stream, b"blocked", false));
            let parked = writing.as_mut().poll(&mut Context::from_waker(&waker));
            assert!(parked.is_pending());
        }
        drop(waker);
        assert_eq!(Arc::strong_count(&counted), 1, "no copy of the waker held");

        // Nor woken by credit: the writer is gone.
        let _ = connection.window.credit_send(1);
        assert_eq!(counted.0.load(Ordering::Relaxed), 0);
    }

    /// Only credit to a spent window can find a writer waiting on it.
    #[test]
    fn crediting_a_spent_window_says_so() {
        let connection = connection(0);
        assert_eq!(connection.window.credit_send(1), Ok(false));

        connection
            .window
            .debit_send(connection.window.available_send())
            .expect("all of it");
        assert_eq!(connection.window.credit_send(1), Ok(true));
        assert_eq!(connection.window.credit_send(1), Ok(false));
    }
}
