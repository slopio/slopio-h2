//! The half of a connection that its streams reach into: the send chain, the
//! HPACK encoder, the connection window, and the frame writers that use them.
//!
//! This lived under `server` until a client needed it, which is the usual way
//! to find out that something was never server-specific. Nothing here knows
//! which end it is on: a header block is cut the same way whether its first
//! field is `:method` or `:status`, a DATA frame is debited against the same
//! two windows in the same direction, and the credit owed back for bytes an
//! application never reads is owed by both ends alike. What differs is what
//! the *caller* puts in front of the block, and that stays in `server` and
//! `client`.

use std::cell::{Cell, RefCell, UnsafeCell};
use std::collections::VecDeque;
use std::task::{Poll, Waker};

use http::{HeaderMap, HeaderName};

use crate::shared::codec::frames::{
    encode::{encode_data_header, encode_header_block, encode_window_update},
    stream_id::StreamId,
};
use crate::shared::connection::STREAM_ID;
use crate::shared::connection::output::Output;
use crate::shared::hpack::{Encoder, Header};

/// §6.9.2: both halves of the connection window start here, and SETTINGS never
/// moves them — only a WINDOW_UPDATE on stream 0 does. An end that wants more
/// announces the gap itself.
pub const CONNECTION_INITIAL_WINDOW_SIZE: u32 = 65_535;

/// How many of its own resets a connection remembers. As many as it has
/// streams: more than that cannot have been reset within one round trip.
const RESETS_REMEMBERED: usize = 64;

/// What writing a body needs of a stream, whichever end of the connection the
/// stream belongs to.
///
/// A trait rather than one concrete type because the two ends keep different
/// things beside their send window — a server stream carries a request body
/// and the rates it is judged on, a client stream carries a response it is
/// waiting for — while the loop that cuts a payload into DATA frames is the
/// same for both, down to which window it parks on. Monomorphized per end, so
/// there is no `dyn` and no vtable.
pub trait SendSide {
    /// §6.9.1: what a DATA frame may still spend on this stream.
    fn available_send(&self) -> u32;

    /// Debits the stream's send window. `Err` is the peer's credit running
    /// short, with nothing debited.
    fn debit_send(&self, len: u32) -> Result<(), ()>;

    /// Parks the writer until this stream is credited.
    fn register_send_waker(&self, waker: &Waker);

    /// Records `n` body bytes as having gone to the peer. Counted where the
    /// frame is written, which is the point the peer controls: the loop only
    /// advances by what the two windows credited.
    fn note_sent(&self, n: usize);
}

/// Reached through the `Rc` every stream holds, so its counters live behind
/// `Cell`.
pub struct ConnectionWindow {
    /// §6.9.1: a DATA frame debits this window *and* its stream's.
    to_send: Cell<i32>,
    /// Debited by `padded_len`, padding included (§6.9.1).
    to_recv: Cell<i32>,
    pending_release: Cell<u32>,
    /// Credit owed back before a WINDOW_UPDATE on stream 0 goes out. Half the
    /// receive window, as at stream level: the peer keeps the other half to
    /// spend while our frame is in flight, so it never stalls on our silence.
    release_threshold: u32,
    /// Writers out of connection credit. All woken by the next WINDOW_UPDATE
    /// on stream 0: whoever polls first takes what it can, the rest park
    /// again. Fair enough for now.
    send_waiters: RefCell<Vec<Waker>>,
}

impl ConnectionWindow {
    /// What a DATA frame may still spend on the connection. Never below
    /// zero: only our own sends debit it, and they never go past it.
    pub fn available_send(&self) -> u32 {
        self.to_send.get().max(0) as u32
    }

    /// §6.9.1: going past 2^31-1 is a connection error, and `i32::MAX` is
    /// exactly that bound. Credit wakes everyone waiting on it.
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

    /// Parks a writer until the next credit.
    fn wait_send(&self, waker: &Waker) {
        let mut waiters = self.send_waiters.borrow_mut();
        if !waiters.iter().any(|w| w.will_wake(waker)) {
            waiters.push(waker.clone());
        }
    }

    /// §6.9.1: a DATA frame we send debits this window as well as its
    /// stream's. `Err` is the credit running short: nothing is debited.
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

    /// Credit announced to the peer by a WINDOW_UPDATE on stream 0. Called
    /// beside the frame that carries it, so the ledger never says more than
    /// the wire. The value is our own, hence no overflow check.
    pub fn announce_recv(&self, increment: u32) {
        self.to_recv.set(self.to_recv.get() + increment as i32);
    }

    /// §6.9.1: every DATA frame debits this window by its padded length,
    /// whatever becomes of the frame afterwards.
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

    /// Credit owed back to the peer: for bytes no application will ever read
    /// — padding, or what a departing stream still held — and for body bytes
    /// an application has consumed.
    ///
    /// Accumulated rather than sent, so that a WINDOW_UPDATE goes out once a
    /// worthwhile amount has piled up instead of once per DATA frame. `Some`
    /// is that amount, credited here in the same breath, so the caller must
    /// write the frame it is handed — the ledger must never say more than
    /// the wire.
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
    /// Connection-level by definition: every header block on the connection
    /// feeds the same dynamic table, so they have to be encoded in the order
    /// they go on the wire or the peer's decoder drifts.
    ///
    /// # Safety
    ///
    /// Behind the same `Rc` as [`Self::output`] and shared with the same
    /// writers, so it needs the same interior mutability and holds to the same
    /// two rules — no reference escapes the call, nothing re-enters under it.
    ///
    /// It is the easier of the two. There is one access, it is a temporary in
    /// a single statement, and [`Self::write_headers`] is a plain `fn`: there
    /// is no suspension point in the function at all, so no reference can
    /// survive one. What `encode` runs under the reference is the header
    /// iterator, which clones names and values out of the caller's map and
    /// cannot reach back here, and a local `Vec<u8>` that aliases nothing.
    ///
    /// The caveat is [`Self::output`]'s: making `write_headers` async would
    /// put a reference into a future, and nothing would say so.
    encoder: UnsafeCell<Encoder>,
    /// The peer's SETTINGS_MAX_FRAME_SIZE: the largest payload we may emit.
    max_frame_size: Cell<u32>,
    /// Streams we reset while the peer's half was still open, most recent
    /// last. §5.1: whoever sends RST_STREAM has to tolerate what the peer had
    /// in flight — its trailers, and the DATA of a body — where the same
    /// frames on any *other* closed stream are the peer's fault. This is the
    /// record that tells the two apart.
    ///
    /// Here rather than with the streams because one of the resets is a
    /// stream task's own, on its way out, and this is what it can reach.
    /// Bounded: what is in flight is a round trip's worth, and an id that
    /// falls off the front is one the peer has long since heard about.
    reset_by_us: RefCell<VecDeque<STREAM_ID>>,
    /// Streams that finished the way they were meant to. Only the server
    /// reads it, for the defence that has to tell an impatient peer from
    /// Rapid Reset; see [`Self::note_completed`].
    completed: Cell<u32>,
    /// Shared because a stream has to read it before writing: §6.9.1 debits a
    /// DATA frame against this window as well as its stream's, so neither side
    /// alone says whether a write can go out.
    pub window: ConnectionWindow,
    /// Every frame — the connection's and every stream's — in the order it was
    /// written, in segments of a fixed size. Sent as one gather write by
    /// whoever drives the connection, and bounded: past `OUTPUT_HIGH_WATER` a
    /// body writer waits for a flush.
    ///
    /// # Safety
    ///
    /// Reached through an `Rc` by the connection and by every stream, so it
    /// cannot be `&mut` and needs interior mutability. An `UnsafeCell` rather
    /// than a `RefCell` for the same reason as `StreamMap`: the runtime is
    /// single-threaded and this is `!Send`, so what has to hold is only that
    /// no two references overlap in time.
    ///
    /// Two rules make that so, and the methods below are written to enforce
    /// them rather than ask:
    ///
    /// **No reference escapes the call that made it.** Every accessor below
    /// does its `unsafe` inside one expression and returns an owned value or a
    /// copy — `usize`, `bool`, `Vec<Vec<u8>>`. None hands out a `&Output`, so
    /// none can be live at the next suspension.
    ///
    /// **Nothing re-enters under the borrow.** The only code that runs while a
    /// reference exists is `Output`'s own, plus the `encode` closure in
    /// [`Self::write_frame`] — which is handed the segment's `Vec<u8>` and not
    /// the connection, so it has nothing to re-enter through.
    ///
    /// The rule this replaces was enforced by `RefCell` panicking. It is now a
    /// convention, and the change most likely to break it is turning one of
    /// the `poll_fn`s that write here into an `async fn`: a guard held across
    /// an `.await` becomes part of the future and outlives the poll. There is
    /// no such guard today because a `poll_fn` closure must return `Poll`
    /// before it suspends.
    output: UnsafeCell<Output>,
    /// Whoever flushes this output, parked because there was nothing to send.
    ///
    /// The connection loop is a task of its own, and most of what it sends is
    /// written from another: a client's application writes a request from
    /// *its* task, a server's handler a response from its stream's. Either way
    /// the loop has to be told, or the frame sits in the chain until the peer
    /// happens to send something — which, having nothing more to say, it may
    /// never do.
    flusher: RefCell<Option<Waker>>,
    /// The peer can send nothing more, so no WINDOW_UPDATE will ever come:
    /// a writer out of credit is out of it for good. Set by a server whose
    /// peer half-closed; see [`Self::close_credit`].
    credit_closed: Cell<bool>,
}

impl SharedConnection {
    /// `recv_window` is the connection receive window this end will announce,
    /// and sets the threshold at which credit owed back is worth a frame.
    pub fn new(header_table_size: u32, max_frame_size: u32, recv_window: u32) -> Self {
        Self {
            // The two arguments are not the same quantity. `max_size` is the
            // dynamic table's size in *bytes* (§4.1, where every entry costs
            // its name, its value and 32 bytes of overhead); `capacity` is a
            // number of *entries* to index up front. Passing the byte size as
            // the entry count asked for an index of 4096 entries where 4096
            // bytes can hold at most 128 — and `Table::new` rounds that to a
            // raw capacity of 8192 and `vec![None; 8192]` memsets it, so every
            // one of those 192 KiB was resident, per connection, before the
            // connection had served anything.
            //
            // Zero is what `Encoder::default()` passes: the table allocates on
            // its first insert and grows from 8, which is what `reserve_one`
            // is there for.
            encoder: UnsafeCell::new(Encoder::new(header_table_size as usize, 0)),
            max_frame_size: Cell::new(max_frame_size),
            completed: Cell::new(0),
            reset_by_us: RefCell::new(VecDeque::new()),
            // §6.9.2: both halves start at 65535 and SETTINGS never moves
            // them. The gap up to `recv_window` is announced by a
            // WINDOW_UPDATE on stream 0, by whoever opens the connection.
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
        }
    }

    /// Encodes one frame into the output.
    ///
    /// The borrow is held for the whole call, so nothing can land between a
    /// frame's header and its payload — and a header block, CONTINUATIONs
    /// included, goes out whole, as §6.10 requires. The frame lands in one
    /// output segment for the same reason. Callers pass the matching
    /// `encode_*` from the codec:
    ///
    /// ```ignore
    /// shared.write_frame(|out| encode_rst_stream(out, stream_id, CANCEL));
    /// ```
    pub fn write_frame(&self, encode: impl FnOnce(&mut Vec<u8>)) {
        // SAFETY: the reference dies with the expression, and `encode` is
        // handed a segment rather than the connection, so it cannot re-enter.
        unsafe { (*self.output.get()).write(encode) }
        // Told here rather than at every call site, because a frame nobody
        // flushes is a frame nobody sent, and the one place that cannot be
        // forgotten is the one every frame goes through.
        self.wake_flusher();
    }

    /// Writes a header block as a HEADERS frame and however many CONTINUATIONs
    /// the peer's `max_frame_size` makes necessary.
    ///
    /// `headers` is the whole field section in wire order — §8.3 puts every
    /// pseudo-header before every ordinary field, and which pseudo-headers
    /// those are is the caller's business: `:status` for a response, `:method`
    /// and friends for a request.
    ///
    /// The block is HPACK-encoded into a scratch first: its length has to be
    /// known before the 9-byte frame header that carries it. Every frame of
    /// the block then goes out under one `write_frame` — §6.10 forbids
    /// anything between a HEADERS and its CONTINUATIONs, on the whole
    /// connection, and a single borrow is what guarantees it.
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

        // Never zero: §6.5.2 floors max_frame_size at 2^14, but `chunks`
        // panics on zero and the value came off the wire.
        let limit = (self.max_frame_size.get() as usize).max(1);

        self.write_frame(|out| encode_header_block(out, stream_id, &block, limit, end_stream));
    }

    /// Writes a trailer section: the fields and END_STREAM, no pseudo-header
    /// (§8.1). Whether the stream is in a state to take one is the caller's to
    /// have checked.
    ///
    /// Neither end's, which is why it is here: §8.1 lets a request carry
    /// trailers exactly as a response does, and the frame is the same one.
    pub fn write_trailers(&self, stream_id: StreamId, fields: &HeaderMap) {
        let headers = fields.iter().map(|(name, value)| Header::Field {
            name: Some(name.clone()),
            value: value.clone(),
        });
        self.write_headers(stream_id, headers, true);
    }

    /// Writes a body as DATA frames, END_STREAM on the last one. Resolves once
    /// the whole payload is written to the output buffer — not sent.
    ///
    /// §6.9.1: every frame is debited from the stream's send window and the
    /// connection's, and is cut to what both allow, bounded by the peer's
    /// `max_frame_size` — and by the room left in the output, which is the
    /// one of the four bounds that is ours rather than the peer's. With no
    /// credit at all the writer parks on both windows and resumes on the next
    /// WINDOW_UPDATE, or a SETTINGS that widens the initial window (§6.9.2);
    /// with no room it parks on the output and resumes once a flush has sent
    /// what was queued. Whatever is written before a park stays written: a
    /// body goes out in as many frames as the credit and the room came in.
    ///
    /// Cancel-safe in the only way that matters: the future is dropped when
    /// the stream is reset, and a half-written body on a reset stream is
    /// exactly what §5.1 expects.
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

                // An empty body, or the tail of one that fell exactly on a
                // frame boundary: END_STREAM still has to travel on
                // something, and an empty frame needs no credit.
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
                    // Credit and room open on different events — a
                    // WINDOW_UPDATE and a flush — so a writer out of both
                    // waits for both. Within the credit, either window may
                    // be the empty one and either may fill first, so that
                    // park is on both as well. A wake from something that
                    // was not the blocker is one wasted poll, nothing more.
                    if credit == 0 {
                        stream.register_send_waker(cx.waker());
                        self.window.wait_send(cx.waker());
                        // Nothing will ever wake this one. The loop is told,
                        // since it is the one that can end the stream — the
                        // writer parking says nothing to it otherwise.
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
                // On the stream too: `sent` here is this call's cursor, and
                // the check needs the stream's whole body.
                stream.note_sent(quota);

                if last {
                    return Poll::Ready(());
                }
            }
        })
    }

    /// Records a stream that finished the way it was meant to: both halves
    /// closed, nobody having reset anything.
    ///
    /// Counted because the defence against Rapid Reset (CVE-2023-44487) has
    /// to tell a client that cancels *instead of* working from one that
    /// cancels *while* working, and the only difference between them is how
    /// much finished. Reported from here rather than from the connection
    /// loop because the last half to close is usually the stream's own task,
    /// which has this and not the loop.
    pub fn note_completed(&self) {
        self.completed.set(self.completed.get().saturating_add(1));
    }

    /// How many streams have finished normally on this connection.
    pub fn completed_streams(&self) -> u32 {
        self.completed.get()
    }

    /// Records a stream as reset by this end with the peer's half still open.
    pub fn note_reset(&self, id: STREAM_ID) {
        let mut resets = self.reset_by_us.borrow_mut();
        if resets.len() == RESETS_REMEMBERED {
            resets.pop_front();
        }
        resets.push_back(id);
    }

    /// Whether `id` is a stream this end reset. Asked for DATA, which may
    /// keep coming, so the id stays remembered.
    pub fn was_reset(&self, id: STREAM_ID) -> bool {
        self.reset_by_us.borrow().contains(&id)
    }

    /// Whether `id` is a stream this end reset, forgetting it if so: asked
    /// for a HEADERS frame, which is the last thing the peer sends on it.
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

    /// Hands the peer back connection-level credit, writing the
    /// WINDOW_UPDATE on stream 0 when enough has piled up. The frame goes
    /// out beside the ledger entry, never after it.
    pub fn release_stream_credit(&self, len: u32) {
        if let Some(increment) = self.window.release(len) {
            self.write_frame(|out| encode_window_update(out, StreamId::ZERO, increment));
        }
    }

    /// Everything written since the last flush, as one gather write. The
    /// segments are owed back to `restore_output` once sent: they stay
    /// counted against the high-water mark until they are, and the writers
    /// waiting on that room are woken there.
    pub(crate) fn take_output(&self) -> Vec<Vec<u8>> {
        // SAFETY: the reference dies with the expression, and the chain is
        // handed back owned.
        unsafe { (*self.output.get()).take() }
    }

    /// Takes the sent segments back. Whatever a writer produced while they
    /// were in flight is already the next link of the chain — there is
    /// nothing to move.
    pub(crate) fn restore_output(&self, sent: Vec<Vec<u8>>) {
        // SAFETY: the reference dies with the expression. `restore` wakes the
        // writers waiting for room, and a wake queues a task rather than
        // running one, so nothing re-enters here.
        unsafe { (*self.output.get()).restore(sent) }
    }

    /// Nothing queued to send. The connection loop drains until this holds:
    /// with a bounded output, a writer may be parked waiting for room, and
    /// only a flush gives it any.
    pub(crate) fn output_is_empty(&self) -> bool {
        // SAFETY: the reference dies with the expression.
        unsafe { (*self.output.get()).is_empty() }
    }

    /// Parks the loop that flushes this output until there is something to
    /// send. Only one such loop exists per connection, hence one slot.
    /// The peer half-closed: no credit will come back. From here a writer
    /// that runs out of it wakes the flusher on its way to parking, rather
    /// than wait for a WINDOW_UPDATE that cannot arrive.
    pub(crate) fn close_credit(&self) {
        self.credit_closed.set(true);
    }

    pub(crate) fn park_flusher(&self, waker: &Waker) {
        let mut slot = self.flusher.borrow_mut();
        if !slot.as_ref().is_some_and(|w| w.will_wake(waker)) {
            *slot = Some(waker.clone());
        }
    }

    /// Wakes it. Taken rather than cloned: a woken task re-parks on its next
    /// poll if it still has nothing to do, so keeping the waker would only
    /// mean waking something already awake.
    pub(crate) fn wake_flusher(&self) {
        if let Some(waker) = self.flusher.borrow_mut().take() {
            waker.wake();
        }
    }

    /// Takes the peer's new `SETTINGS_HEADER_TABLE_SIZE`, already clamped to
    /// what we are willing to keep. RFC 7541 §4.2: the encoder shrinks its
    /// table and says so at the head of the next block, which `encode` does
    /// on its own once told — a value that changes nothing queues nothing.
    pub fn set_header_table_size(&self, header_table_size: u32) {
        // SAFETY: the reference dies with the expression, and queuing a size
        // update cannot re-enter.
        unsafe { (*self.encoder.get()).update_max_size(header_table_size as usize) };
    }

    /// Takes the peer's new `SETTINGS_MAX_FRAME_SIZE`.
    pub fn set_max_frame_size(&self, max_frame_size: u32) {
        self.max_frame_size.set(max_frame_size);
    }

    /// Lets `:path` values into the HPACK dynamic table, for a connection
    /// whose paths repeat. See [`Encoder::index_paths`].
    ///
    /// Nothing about the wire changes for the peer: a value entering the
    /// table is an ordinary literal-with-incremental-indexing, which every
    /// decoder must already handle. What changes is that the second request
    /// to the same path costs an index byte instead of the whole string.
    pub fn index_request_paths(&self, on: bool) {
        // SAFETY: the reference dies with the expression, and setting a flag
        // cannot re-enter.
        unsafe { (*self.encoder.get()).index_paths(on) };
    }
}
