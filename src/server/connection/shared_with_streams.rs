use std::cell::{Cell, RefCell, UnsafeCell};
use std::rc::Rc;
use std::task::{Poll, Waker};

use http::{HeaderMap, StatusCode};

use crate::shared::connection::STREAM_ID;
use crate::shared::connection::output::Output;
use crate::shared::connection::stream_map::StreamMap;
use crate::server::connection::{CONNECTION_INITIAL_WINDOW_SIZE, CONNECTION_RECV_WINDOW};
use crate::server::stream::Stream;
use crate::shared::{
    codec::frames::{
        encode::{
            encode_continuation_header, encode_data_header, encode_headers_fragment_header,
            encode_headers_header, encode_window_update,
        },
        stream_id::StreamId,
    },
    hpack::{Encoder, Header},
};
use runtime::Handle;
use std::rc::Weak;

/// Credit owed back to the peer before a WINDOW_UPDATE on stream 0 goes out.
/// Half the window, as at stream level: the peer keeps the other half to
/// spend while our frame is in flight, so it never stalls on our silence.
const CONNECTION_RELEASE_THRESHOLD: u32 = CONNECTION_RECV_WINDOW / 2;

pub struct SharedConnection {
    /// Connection-level by definition: every header block on the connection
    /// feeds the same dynamic table, so they have to be encoded in the order
    /// they go on the wire or the peer's decoder drifts.
    encoder: RefCell<Encoder>,
    /// The peer's SETTINGS_MAX_FRAME_SIZE: the largest payload we may emit.
    max_frame_size: Cell<u32>,
    /// Shared because a stream task has to read it before writing: §6.9.1
    /// debits a DATA frame against this window as well as its stream's, so
    /// neither side alone says whether a write can go out.
    pub window: ConnectionWindow,
    /// Every frame — the connection's and every stream task's — in the order
    /// it was written, in segments of a fixed size. Sent as one gather write
    /// once per turn of the connection loop, and bounded: past
    /// `OUTPUT_HIGH_WATER` a body writer waits for a flush.
    ///
    /// # Safety
    ///
    /// Reached through an `Rc` by the connection and by every stream task, so
    /// it cannot be `&mut` and needs interior mutability. An `UnsafeCell`
    /// rather than a `RefCell` for the same reason as [`StreamMap`]: the
    /// runtime is single-threaded and this is `!Send`, so what has to hold is
    /// only that no two references overlap in time.
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
}

/// The connection's live streams. Each entry owns its stream and the handle
/// of the task running it.
pub type LiveStreams = StreamMap<Stream, Handle<()>>;

/// Takes a stream out once both its halves are done (§5.1), handing back
/// whatever connection credit it still held.
///
/// Called by whichever half closes last, which is why it checks rather than
/// assumes: the task reports through its [`StreamToken`], the peer's
/// END_STREAM reports through the connection, and either may be second.
pub fn retire_if_closed(map: &LiveStreams, shared: &SharedConnection, id: STREAM_ID) {
    if !map.get(id).is_some_and(|stream| stream.is_closed()) {
        return;
    }
    let Some((stream, _handle)) = map.remove(id) else {
        return;
    };
    // Body bytes no handler consumed still hold credit. `_handle` drops
    // here, outside the map, which for a task retiring itself is that task
    // detaching its own handle — sound because the scheduler holds a
    // reference to the task for the whole poll its destructor runs in.
    shared.release_stream_credit(stream.take_unreleased());
}

/// What a stream task holds for as long as it runs, and what cleans up when
/// it stops — however it stops. Returning normally, being reset by the peer,
/// going down with its connection: all of them drop this.
///
/// The connection used to ask instead, walking every live stream once per
/// turn of its loop to see which had finished. A task knows when it is done
/// and nothing else does, so it is the task that says so.
pub struct StreamToken {
    id: StreamId,
    stream: Rc<Stream>,
    shared: Rc<SharedConnection>,
    /// `Weak` because the map owns this token, by way of the handle of the
    /// task that holds it: an `Rc` back would be a cycle neither ever leaves.
    map: Weak<LiveStreams>,
}

impl StreamToken {
    pub fn new(
        id: StreamId,
        stream: Rc<Stream>,
        shared: Rc<SharedConnection>,
        map: Weak<LiveStreams>,
    ) -> Self {
        Self {
            id,
            stream,
            shared,
            map,
        }
    }

    pub fn id(&self) -> StreamId {
        self.id
    }

    pub fn stream(&self) -> &Rc<Stream> {
        &self.stream
    }

    pub fn shared(&self) -> &Rc<SharedConnection> {
        &self.shared
    }
}

impl Drop for StreamToken {
    /// Our half of the stream is over (§5.1): the task wrote whatever it was
    /// going to. Whatever body bytes it never consumed still hold connection
    /// credit, and they go back here — `take_unreleased` zeroes as it reads,
    /// so the removal that follows can safely ask again for whatever arrived
    /// in between.
    ///
    /// Then it takes itself out of the map, if the peer is done too. Safe to
    /// do from here because a task only ever runs — and so only ever drops —
    /// while the connection is suspended at an `await`, holding no reference
    /// into the map; `StreamMap` is where that argument lives in full.
    fn drop(&mut self) {
        self.stream.end_output();
        if let Some(map) = self.map.upgrade() {
            retire_if_closed(&map, &self.shared, self.id.into());
        }
    }
}

/// Reached through the `Rc` every stream task holds, so its counters live
/// behind `Cell`.
pub struct ConnectionWindow {
    /// §6.9.1: a DATA frame debits this window *and* its stream's.
    to_send: Cell<i32>,
    /// Debited by `padded_len`, padding included (§6.9.1).
    to_recv: Cell<i32>,
    pending_release: Cell<u32>,
    /// Tasks out of connection credit. All woken by the next WINDOW_UPDATE
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

    /// Parks a task until the next credit.
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
    /// a handler has consumed.
    ///
    /// Accumulated rather than sent, so that a WINDOW_UPDATE goes out once a
    /// worthwhile amount has piled up instead of once per DATA frame. `Some`
    /// is that amount, credited here in the same breath, so the caller must
    /// write the frame it is handed — the ledger must never say more than
    /// the wire.
    #[must_use]
    pub fn release(&self, len: u32) -> Option<u32> {
        let pending = self.pending_release.get() + len;
        if pending < CONNECTION_RELEASE_THRESHOLD {
            self.pending_release.set(pending);
            return None;
        }
        self.pending_release.set(0);
        self.to_recv.set(self.to_recv.get() + pending as i32);
        Some(pending)
    }
}

impl SharedConnection {
    pub fn new(header_table_size: u32, max_frame_size: u32) -> Self {
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
            encoder: RefCell::new(Encoder::new(header_table_size as usize, 0)),
            max_frame_size: Cell::new(max_frame_size),
            // §6.9.2: both halves start at 65535 and SETTINGS never moves
            // them. The gap up to `CONNECTION_RECV_WINDOW` is announced by a
            // WINDOW_UPDATE on stream 0 from `on_preface`.
            window: ConnectionWindow {
                to_send: Cell::new(CONNECTION_INITIAL_WINDOW_SIZE as i32),
                to_recv: Cell::new(CONNECTION_INITIAL_WINDOW_SIZE as i32),
                pending_release: Cell::new(0),
                send_waiters: RefCell::new(Vec::new()),
            },
            output: UnsafeCell::new(Output::new()),
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
    }

    /// Writes a response head, split over CONTINUATION frames when the
    /// encoded block outgrows the peer's `max_frame_size`.
    ///
    /// The block is HPACK-encoded into a scratch first: its length has to be
    /// known before the 9-byte frame header that carries it. Every frame of
    /// the block then goes out under one `write_frame` — §6.10 forbids
    /// anything between a HEADERS and its CONTINUATIONs, on the whole
    /// connection, and a single borrow is what guarantees it.
    pub fn write_headers(
        &self,
        stream_id: StreamId,
        status: StatusCode,
        fields: &HeaderMap,
        end_stream: bool,
    ) {
        // §8.3: the response pseudo-header comes before every ordinary field.
        //
        // Nothing is added here. RFC 9110 §6.6.1 does want a `Date` on every
        // 2xx, 3xx and 4xx from an origin server with a clock, and
        // `shared::date::now` is the cheap way to produce one — but it costs
        // about a tenth of the request rate, and whether to pay that is the
        // handler's call, not the frame writer's. A gateway would relay the
        // origin's `Date` rather than stamp its own anyway.
        let headers =
            std::iter::once(Header::Status(status)).chain(fields.iter().map(|(name, value)| {
                Header::Field {
                    name: Some(name.clone()),
                    value: value.clone(),
                }
            }));
        let mut block = Vec::new();
        self.encoder.borrow_mut().encode(headers, &mut block);

        // Never zero: §6.5.2 floors max_frame_size at 2^14, but `chunks`
        // panics on zero and the value came off the wire.
        let limit = (self.max_frame_size.get() as usize).max(1);

        self.write_frame(|out| {
            let mut fragments = block.chunks(limit);
            // An empty block is legal — `chunks` yields nothing for it.
            let first = fragments.next().unwrap_or(&[]);
            let mut rest = fragments.peekable();

            // END_HEADERS belongs on the last frame of the block, so a block
            // that continues gets the fragment header instead.
            if rest.peek().is_none() {
                encode_headers_header(out, stream_id, first.len(), end_stream);
            } else {
                encode_headers_fragment_header(out, stream_id, first.len(), end_stream);
            }
            out.extend_from_slice(first);

            while let Some(fragment) = rest.next() {
                encode_continuation_header(out, stream_id, fragment.len(), rest.peek().is_none());
                out.extend_from_slice(fragment);
            }
        });
    }

    /// Writes a response body as DATA frames, END_STREAM on the last one.
    /// Resolves once the whole payload is written to the output buffer —
    /// not sent.
    ///
    /// §6.9.1: every frame is debited from the stream's send window and the
    /// connection's, and is cut to what both allow, bounded by the peer's
    /// `max_frame_size` — and by the room left in the output, which is the
    /// one of the four bounds that is ours rather than the peer's. With no
    /// credit at all the task parks on both windows and resumes on the next
    /// WINDOW_UPDATE, or a SETTINGS that widens the initial window (§6.9.2);
    /// with no room it parks on the output and resumes once a flush has sent
    /// what was queued. Whatever is written before a park stays written: a
    /// body goes out in as many frames as the credit and the room came in.
    ///
    /// Cancel-safe in the only way that matters: the future is dropped when
    /// the stream is reset, and a half-written body on a reset stream is
    /// exactly what §5.1 expects.
    pub fn write_data(
        &self,
        stream_id: StreamId,
        stream: &Stream,
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
                        stream.register_waker(cx.waker());
                        self.window.wait_send(cx.waker());
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
                // the check needs the stream's whole response.
                stream.note_sent(quota);

                if last {
                    return Poll::Ready(());
                }
            }
        })
    }

    /// Takes `n` body bytes off the stream on the handler's behalf and gives
    /// the peer back the credit they were holding — on the stream and on the
    /// connection both, §6.9.1 having debited both when they arrived.
    ///
    /// Here rather than on `Stream` for the same reason `write_data` is: it
    /// has to write frames, and the stream half cannot. Nothing goes out
    /// until a worthwhile amount has piled up at either level, so a handler
    /// taking a few bytes at a time does not answer every DATA frame with a
    /// WINDOW_UPDATE of its own.
    pub fn consume(&self, stream_id: StreamId, stream: &Stream, n: usize) {
        let taken = stream.consume(n);
        if taken == 0 {
            return;
        }
        if let Some(increment) = stream.release_recv(taken) {
            self.write_frame(|out| encode_window_update(out, stream_id, increment));
        }
        if let Some(increment) = self.window.release(taken) {
            self.write_frame(|out| encode_window_update(out, StreamId::ZERO, increment));
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

    /// Takes the sent segments back. Whatever a task wrote while they were
    /// in flight is already the next link of the chain — there is nothing
    /// to move.
    pub(crate) fn restore_output(&self, sent: Vec<Vec<u8>>) {
        // SAFETY: the reference dies with the expression. `restore` wakes the
        // writers waiting for room, and a wake queues a task rather than
        // running one, so nothing re-enters here.
        unsafe { (*self.output.get()).restore(sent) }
    }

    /// Nothing queued to send. The connection loop drains until this holds:
    /// with a bounded output, a task may be parked waiting for room, and
    /// only a flush gives it any.
    pub(crate) fn output_is_empty(&self) -> bool {
        // SAFETY: the reference dies with the expression.
        unsafe { (*self.output.get()).is_empty() }
    }

    /// Takes the peer's new `SETTINGS_MAX_FRAME_SIZE`.
    pub fn set_max_frame_size(&self, max_frame_size: u32) {
        self.max_frame_size.set(max_frame_size);
    }
}
