use std::cell::{Cell, RefCell};
use std::task::{Poll, Waker};

use http::{HeaderMap, StatusCode};

use crate::server::connection::CONNECTION_INITIAL_WINDOW_SIZE;
use crate::server::connection::output::Output;
use crate::server::stream::Stream;
use crate::shared::{
    codec::frames::{
        encode::{
            encode_continuation_header, encode_data_header, encode_headers_fragment_header,
            encode_headers_header,
        },
        stream_id::StreamId,
    },
    hpack::{Encoder, Header},
};

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
    output: RefCell<Output>,
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

    /// Credit owed back to the peer for bytes no application will ever read.
    /// Accumulated rather than sent, so that a WINDOW_UPDATE goes out once a
    /// worthwhile amount has piled up instead of once per DATA frame.
    pub fn release(&self, len: u32) {
        self.pending_release.set(self.pending_release.get() + len);
    }
}

impl SharedConnection {
    pub fn new(header_table_size: u32, max_frame_size: u32) -> Self {
        Self {
            encoder: RefCell::new(Encoder::new(
                header_table_size as usize,
                header_table_size as usize,
            )),
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
            output: RefCell::new(Output::new()),
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
        self.output.borrow_mut().write(encode);
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
                let room = self.output.borrow().data_room();
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
                        self.output.borrow_mut().wait_room(cx.waker());
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

                if last {
                    return Poll::Ready(());
                }
            }
        })
    }

    /// Everything written since the last flush, as one gather write. The
    /// segments are owed back to `restore_output` once sent: they stay
    /// counted against the high-water mark until they are, and the writers
    /// waiting on that room are woken there.
    pub(crate) fn take_output(&self) -> Vec<Vec<u8>> {
        self.output.borrow_mut().take()
    }

    /// Takes the sent segments back. Whatever a task wrote while they were
    /// in flight is already the next link of the chain — there is nothing
    /// to move.
    pub(crate) fn restore_output(&self, sent: Vec<Vec<u8>>) {
        self.output.borrow_mut().restore(sent);
    }

    /// Nothing queued to send. The connection loop drains until this holds:
    /// with a bounded output, a task may be parked waiting for room, and
    /// only a flush gives it any.
    pub(crate) fn output_is_empty(&self) -> bool {
        self.output.borrow().is_empty()
    }

    /// Takes the peer's new `SETTINGS_MAX_FRAME_SIZE`.
    pub fn set_max_frame_size(&self, max_frame_size: u32) {
        self.max_frame_size.set(max_frame_size);
    }
}
