use std::cell::{Cell, RefCell, UnsafeCell};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::task::{Poll, Waker};

use http::{HeaderMap, HeaderName};

use crate::shared::codec::frames::{
    encode::{encode_data_header, encode_header_block, encode_window_update},
    stream_id::StreamId,
};
use crate::shared::connection::STREAM_ID;
use crate::shared::connection::output::Output;
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
    send_waiters: RefCell<Vec<Waker>>,
}

impl ConnectionWindow {
    /// Never below zero: only our own sends debit it, and never past it.
    pub fn available_send(&self) -> u32 {
        self.to_send.get().max(0) as u32
    }

    /// §6.9.1: going past 2^31-1 (`i32::MAX`) is a connection error.
    pub fn credit_send(&self, increment: u32) -> Result<(), ()> {
        let credited = self
            .to_send
            .get()
            .checked_add_unsigned(increment)
            .ok_or(())?;
        self.to_send.set(credited);
        for waker in self.send_waiters.borrow_mut().drain(..) {
            waker.wake();
        }
        Ok(())
    }

    fn wait_send(&self, waker: &Waker) {
        let mut waiters = self.send_waiters.borrow_mut();
        if !waiters.iter().any(|w| w.will_wake(waker)) {
            waiters.push(waker.clone());
        }
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
                send_waiters: RefCell::new(Vec::new()),
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
                    // Credit and room open on different events, and either
                    // window may be the empty one, so park on all that apply.
                    if credit == 0 {
                        stream.register_send_waker(cx.waker());
                        self.window.wait_send(cx.waker());
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
    pub(crate) fn take_output(&self) -> Vec<Vec<u8>> {
        // SAFETY: the reference dies with the expression, and the chain is
        // handed back owned.
        unsafe { (*self.output.get()).take() }
    }

    pub(crate) fn restore_output(&self, sent: Vec<Vec<u8>>) {
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
