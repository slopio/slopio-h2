use std::io;
use std::time::Duration;

use crate::server::Handler;
use crate::server::connection::protocol::Protocol;
use crate::shared::{
    codec::frames::FrameDecoder,
    transport::{RecvError, Transport},
};
use runtime::runtime::time::timeout;
use runtime_streams::StreamExt;

mod protocol;
pub(crate) mod shared_with_streams;
#[cfg(test)]
mod tests;

pub const MAX_CONCURRENT_STREAMS: u32 = 64;

/// §6.9.2's starting point for both halves of the connection window, which a
/// WINDOW_UPDATE on stream 0 is the only thing that moves. Shared with the
/// client, which starts from the same place.
pub use crate::shared::connection::CONNECTION_INITIAL_WINDOW_SIZE;

/// The receive window every stream of ours starts with: what this server
/// announces as `SETTINGS_INITIAL_WINDOW_SIZE`, and so what a peer may send
/// on a stream before it needs credit back.
///
/// This is the one knob of inbound flow control. It sets how much a peer
/// sends per round trip — a message below it arrives in one — and, since
/// credit goes back only for bytes a handler has taken, how much one stream
/// can hold against a handler that stalls: this much, at most, and
/// `MAX_CONCURRENT_STREAMS` times it for a connection. A megabyte is where
/// hyper, Netty and grpc-go's tuning land too.
pub const STREAM_RECV_WINDOW: u32 = 1024 * 1024;

/// The connection receive window this server announces, once the handshake is
/// done. Ours to choose, where the send side is the peer's to credit.
///
/// As large as §6.9.1 allows, so that it never binds: backpressure is the
/// stream windows' job, and the connection window is only ever the thing a
/// stream waits on by mistake. It costs nothing to be this large — what a
/// peer can have in flight unconsumed is bounded by the stream windows, not
/// by this — and the refill is one WINDOW_UPDATE per half of it consumed.
pub const CONNECTION_RECV_WINDOW: u32 = i32::MAX as u32;

/// The peer's spendable connection credit is this window less what we have
/// consumed and not yet announced, which sits below half the window. For the
/// connection never to be what a stream waits on, every stream's full window
/// has to fit in the other half.
const _: () = assert!(
    MAX_CONCURRENT_STREAMS as u64 * STREAM_RECV_WINDOW as u64
        <= (CONNECTION_RECV_WINDOW - CONNECTION_RECV_WINDOW / 2) as u64,
    "every stream holding a full window at once must fit in the announced half of the connection window"
);

/// How long one gather-write may stall before the connection is closed.
///
/// This bounds the whole write, not one submission: `send_vectored_all` loops
/// over short sends itself, so a peer that accepts a byte at a time does not
/// get a fresh deadline per byte — the queued output has to be gone within
/// this, or the peer is not a receiver we keep.
///
/// It is a stall bound rather than a budget for the connection's life. Each
/// flush that completes moved every queued byte, which is progress, so a fast
/// peer never approaches this however long it stays connected.
///
/// The defence it is here for is not the memory of one connection — the
/// high-water mark already bounds that. It is the buffer ring, which is shared
/// by every connection on the worker: a loop parked in `send` stops popping
/// its inbound completions, and each unpopped completion pins one ring buffer
/// until the driver pauses the recv at 32 of them. A handful of peers that
/// stop reading can therefore empty a 512-slot ring, and a recv that finds it
/// empty fails ENOBUFS, which this runtime does not resubmit — so the
/// connection that dies is whichever one drew the empty ring, not the one that
/// caused it. What protects the ring is that the stall *ends*; how soon
/// matters much less than that there is a bound at all.
///
/// What this is not is a judgement about the peer, and it is worth being exact
/// about why, because the obvious reading of it is wrong. Flow control is a
/// promise about buffer space: a peer advertising a window asserts it has
/// somewhere to put those bytes, and one that advertises what it will not
/// drain has broken that promise. A blocked `send` is not evidence of it.
/// `send` completes when the *local* socket buffer accepts the bytes, and that
/// buffer drains at the speed of the network — so a peer that stopped reading
/// and a peer on a slow link stall us identically, and nothing at this level
/// can tell them apart. `tcpi_snd_wnd == 0` from `TCP_INFO` is what actually
/// distinguishes them: a receiver that has closed its window is not draining,
/// and that is provable rather than inferred.
///
/// So what this constant really sets is a minimum bandwidth. A flush carries
/// at most `OUTPUT_HIGH_WATER`, since body writers park at that mark, which
/// makes the floor `OUTPUT_HIGH_WATER / FLUSH_TIMEOUT` in the worst case:
///
/// | flush | implied floor |
/// |-------|---------------|
/// | ~50 B, today's placeholder response | ~10 B/s |
/// | 16 KiB, one segment | ~3.2 KB/s |
/// | 256 KiB, a full high-water flush | ~52 KB/s (~420 kbit/s) |
///
/// The floor rises with the size of the flush, so this is strictest on the
/// largest transfers — which are the ones most likely to be slow for honest
/// reasons. That is backwards, and it is tolerable only because responses are
/// currently tiny: at 50 bytes a flush this fires on nothing but a peer that
/// has genuinely stopped reading. A handler that streams a real body turns the
/// same constant into a 420 kbit/s service requirement that no caller agreed
/// to. `max(FLUSH_TIMEOUT, bytes / MIN_SEND_RATE)` is the honest shape of it
/// once that day comes, since the rate is the thing actually meant.
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// The one duration any read deadline is ever armed for, and the unit every
/// wait below is counted in. Shared with the client, which arms it just as
/// often and for the same reason.
///
/// It caps how long anything below can hold a connection: a deadline is only as
/// precise as this, and all of them are multiples of it.
pub use crate::shared::connection::DEADLINE_TICK;

/// How long a peer with nothing outstanding may send nothing at all.
///
/// This is the keepalive policy, and it is ours to choose: HTTP/2 has no
/// `Keep-Alive` header — §8.2.2 forbids it along with `Connection` — and the
/// RFC sets no idle timeout anywhere. A connection is meant to be long-lived
/// and §6.7 gives the peer PING to say so, so this only has to outlast a
/// reasonable keepalive interval. Two minutes sits above the usual ones and
/// below the NAT rebind windows that would strand a connection anyway.
///
/// 24 ticks of 5s: two minutes.
pub const IDLE_TICKS: u32 = 24;

/// How long a peer that has a stream open may send nothing.
///
/// Stricter than idle because the connection is holding state on its behalf: a
/// live stream owns one of `MAX_CONCURRENT_STREAMS`, a receive window, and
/// whatever its body has buffered. A peer that opens 64 streams and goes quiet
/// is not idle, it is parked on everything the connection has.
///
/// 6 ticks of 5s: thirty seconds.
pub const ACTIVE_TICKS: u32 = 6;

/// How long a peer may leave something half-sent.
///
/// The slowloris deadline, and the strict one, because a half-sent thing is
/// pathological rather than merely slow. Two states qualify: a preface that has
/// not finished arriving, and a header block between its HEADERS and its
/// CONTINUATION — which §6.10 makes worse than it looks, since no frame for any
/// *other* stream may be interleaved, so one peer's unfinished block stops the
/// whole connection. `FrameDecoder::header_pending` folds in a frame header too
/// short to carry its kind, on the grounds that nine bytes taking seconds is
/// pathological whatever it turns out to introduce.
///
/// Wall clock from when the half-sent state began, and not a count of silent
/// ticks like the other two, because sending more of the same frame must not
/// refill it — a peer dribbling a byte every four seconds resets a silence
/// count for ever and is exactly the attack. Measuring the budget instead
/// covers the silent peer too, so this is the only bound the partial case
/// needs.
///
/// Ten seconds. Nothing legitimate starts a frame and then waits: the bytes
/// were already written by a peer that had them.
pub const PARTIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How often live streams are swept for one that is starving.
///
/// The per-stream rates are checked where the evidence arrives — a body on its
/// DATA, a response where it is written — and neither fires for the peer that
/// sends nothing at all, which is the one worth catching. This is what runs
/// without the peer's help.
///
/// Driven off inbound chunks rather than a timer, deliberately: a connection
/// with no traffic at all is the read deadline's business, and arming a second
/// timer per connection is the cost that made the read deadline expensive
/// before it was counted in ticks. The sweep is at most
/// `MAX_CONCURRENT_STREAMS` comparisons against an already-sampled clock, so a
/// few seconds apart it does not register.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Empty-ring reads in a row before a connection gives up.
///
/// The buffer ring is shared by every connection on the worker, and a poll
/// that finds it empty is told to come back rather than that the peer is gone.
/// Coming back means yielding: buffers return when the other connections are
/// polled and drop theirs, which is the next pass. So a handful of passes is
/// all a transient shortage needs, and a count rather than a deadline is the
/// right shape — the question is whether progress is being made elsewhere, not
/// how much time has gone by.
///
/// Bounded because the retry is not free: each one re-arms the multishot and
/// costs an SQE, so a ring that never refills would spin. Sixteen passes of
/// every other connection on the worker making no progress at all is a worker
/// in trouble, and dropping one connection is the lesser harm.
pub const MAX_DRY_READS: u32 = 16;

/// One HTTP/2 connection: bytes come in through `transport`, `decoder` cuts
/// them into frames, and each frame is dispatched into `protocol`.
///
/// `protocol` is a struct of its own rather than its fields flattened in
/// here, because the decoder borrows it as its `FrameHandler` while being
/// borrowed itself — two `&mut` at once, which is only sound across disjoint
/// fields.
pub struct Connection<T: Transport, H: Handler> {
    transport: T,
    decoder: FrameDecoder,
    protocol: Protocol<H>,
    /// When the peer last entered a half-sent state, cleared when it leaves
    /// one. `None` is a connection that owes us nothing in particular.
    ///
    /// The whole reason [`PARTIAL_TIMEOUT`] is measured from here and not from
    /// the last byte: an inactivity deadline resets on every byte, so a peer
    /// that dribbles just faster than it holds the connection for ever, which
    /// is precisely what slowloris does. A budget for *finishing* what it
    /// started cannot be reset by sending more of it.
    partial_since: Option<std::time::SystemTime>,
    /// When the streams were last swept for a starving one.
    last_swept: std::time::SystemTime,
}

impl<T: Transport, H: Handler> Connection<T, H> {
    pub fn new(transport: T, handler: H) -> Self {
        Self {
            transport,
            decoder: FrameDecoder::new(),
            protocol: Protocol::new(handler),
            partial_since: None,
            last_swept: runtime::runtime::now(),
        }
    }

    /// Drives the connection to completion: one chunk in, everything it
    /// produced out, until the peer closes or a connection error is answered.
    ///
    /// Sequential on purpose — the simple version. Output written by a
    /// stream task while we wait on `recv` only leaves with the next inbound
    /// chunk; a select on "output ready" is what fixes that, later.
    pub async fn run(mut self) {
        // Ticks in a row with nothing from the peer. Any byte resets it, so
        // this counts silence and not time.
        let mut silent_ticks = 0;
        // Dry reads in a row. Reset by anything that arrives, so this counts a
        // ring that will not refill, not one that was briefly empty.
        let mut dry_reads = 0;
        loop {
            if self.wait_expired(silent_ticks) {
                // §6.8: say so rather than vanishing. The GOAWAY is queued, so
                // it needs the drain to carry it.
                self.protocol.time_out();
                let _ = self.drain().await;
                let _ = self.transport.shutdown().await;
                return;
            }
            match timeout(DEADLINE_TICK, self.recv()).await {
                // Nothing arrived. Nothing is drained either: the loop's rule
                // that output leaves with the next inbound chunk is not changed
                // by a tick passing.
                Err(()) => {
                    silent_ticks += 1;
                    continue;
                }
                // Half-close: the peer sends no more, but is still owed
                // whatever is queued.
                Ok(None) => break,
                // The ring was empty, not the connection. Yielding is the
                // whole remedy: a buffer comes back when another connection on
                // this worker recycles one, which happens when it is polled,
                // which is what yielding lets happen. Bounded, because a ring
                // that stays dry would otherwise spin — every retry re-arms the
                // op and costs an SQE.
                Ok(Some(Err(RecvError::Later))) => {
                    if dry_reads == MAX_DRY_READS {
                        return;
                    }
                    dry_reads += 1;
                    runtime::yield_now().await;
                    continue;
                }
                // Transport failure: nowhere left to send a GOAWAY, so drop it
                // as silently as the clean EOF above.
                Ok(Some(Err(RecvError::Fatal(_)))) => return,
                Ok(Some(Ok(()))) => {}
            }
            silent_ticks = 0;
            dry_reads = 0;
            self.sweep_if_due();
            // The drain carries the GOAWAY, if there was one. An invalid
            // preface queued nothing, so it closes in silence (§3.4).
            if self.drain().await.is_err() || self.is_closing() {
                return;
            }
        }
        // The peer half-closed and whatever was owed has gone out. On a
        // transport with a goodbye of its own, this is where it goes.
        let _ = self.drain().await;
        let _ = self.transport.shutdown().await;
    }

    /// Sends what this turn produced, and keeps sending while the tasks it
    /// woke keep writing. Returns once they have nothing more: done, or
    /// parked on flow control.
    ///
    /// One flush is not enough now that the output is bounded — a task may
    /// have parked on a full buffer, and a flush is the only thing that
    /// gives it room again, so the loop has to come back for what it wrote
    /// next. A response larger than `OUTPUT_HIGH_WATER` therefore leaves in
    /// several sends before we read again, where it used to be buffered
    /// whole and sent in one: the same starvation of `recv` as before, for
    /// bounded memory. A select on "output ready" is what unties the two,
    /// later.
    async fn drain(&mut self) -> io::Result<()> {
        loop {
            self.flush().await?;
            // The tasks this turn spawned or woke — and the ones the flush
            // just gave room to — have not run yet; they only do once we
            // yield. Let them. A task that ends takes itself out of the
            // stream map as it goes, so there is nothing to collect after.
            runtime::yield_now().await;
            if self.protocol.shared().output_is_empty() {
                return Ok(());
            }
        }
    }

    /// How long the peer may say nothing, given what it has left half-said.
    ///
    /// Three states rather than one deadline, because the honest reasons for
    /// silence differ by an order of magnitude between them. A peer with
    /// nothing outstanding is entitled to sit there; a peer that stopped in the
    /// middle of a frame is not.
    ///
    /// Dropping the read future is safe where dropping a send is not:
    /// `MultiRecv` queues its completions in a buffer it owns and `poll_next`
    /// drains that queue, so the multishot stays armed and nothing is lost
    /// between one poll and the next.
    /// Whether the peer has run out of time to say something.
    ///
    /// Two clocks, because two different things are bounded. A half-sent frame
    /// gets a wall-clock budget from when it started, which more of the same
    /// frame does not refill. Everything else gets a count of silent ticks,
    /// which any byte resets — and that is right there, because a peer sending
    /// real frames is a peer making progress.
    #[inline]
    fn wait_expired(&mut self, silent_ticks: u32) -> bool {
        if !self.decoder.preface_seen() || self.decoder.header_pending() {
            let now = runtime::runtime::now();
            let since = *self.partial_since.get_or_insert(now);
            // Floors at zero on a clock that stepped backwards, as
            // `Stream::age` does, so an adjustment cannot close a connection.
            return now.duration_since(since).unwrap_or_default() >= PARTIAL_TIMEOUT;
        }
        self.partial_since = None;
        let allowed = match self.protocol.has_live_streams() {
            true => ACTIVE_TICKS,
            false => IDLE_TICKS,
        };
        silent_ticks >= allowed
    }

    /// Sweeps for starving streams, a few seconds apart at most.
    ///
    /// After the dispatch rather than before: the chunk just decoded may have
    /// been the DATA that a starving stream needed, and judging it on evidence
    /// one turn stale would reset a stream that had just made progress.
    fn sweep_if_due(&mut self) {
        let now = runtime::runtime::now();
        let due = now
            .duration_since(self.last_swept)
            .is_ok_and(|since| since >= SWEEP_INTERVAL);
        if due {
            self.last_swept = now;
            self.protocol.sweep_starving_streams();
        }
    }

    /// Once true, nothing more should be read: a connection error has been
    /// answered — or, for an invalid preface, deliberately not — and what
    /// remains is to flush and close.
    pub fn is_closing(&self) -> bool {
        self.protocol.is_closing()
    }

    /// Sends everything written since the last flush, as one gather write.
    /// The segments come back with their capacity intact, for the writers
    /// waiting on the room they free.
    ///
    /// `may_hold` is `false`: a send that frees its buffers only at the
    /// kernel's notification holds them against the high-water mark for a
    /// round trip, which is throughput this connection has no way of
    /// knowing it can spare.
    pub async fn flush(&mut self) -> io::Result<()> {
        if self.protocol.shared().output_is_empty() {
            return Ok(());
        }
        let bufs = self.protocol.shared().take_output();
        // Bound before the match rather than inside it: the send borrows
        // `self.transport`, and a match scrutinee's temporaries live to the end
        // of the match, where the arms want `self.protocol` back.
        let sent = timeout(FLUSH_TIMEOUT, self.transport.send(bufs, false)).await;
        match sent {
            Ok((result, bufs)) => {
                self.protocol.shared().restore_output(bufs);
                result
            }
            // The segments do not come back, and must not: `timeout` drops the
            // send, and a dropped send moves its chunks and the kernel-visible
            // `msghdr` into the driver's keepalive slot so the kernel can
            // finish reading them after the cancel CQE. Freeing them here is
            // what would be unsound. `Output` goes on counting them against
            // `in_flight`, which costs nothing, because this error is what ends
            // the connection.
            Err(()) => Err(io::ErrorKind::TimedOut.into()),
        }
    }

    /// Takes one chunk off the transport and dispatches every frame in it.
    ///
    /// `None` is the peer closing its side — it may still be owed responses.
    /// Chunk boundaries mean nothing: a frame split across two chunks is
    /// reassembled by the decoder, which also keeps the header block a
    /// CONTINUATION is still completing.
    ///
    /// The dispatch is not interrupted, and that is a decision rather than
    /// an oversight. Every frame in the chunk is handled before anything
    /// else runs, so a stream task cannot consume — and so cannot hand the
    /// peer its credit back — until the whole chunk is through. Feeding the
    /// decoder in slices with a `yield_now` between them is the obvious fix,
    /// costs nothing to write since the decoder already reassembles across
    /// calls, and loses: on 1 MiB uploads, one core, ingest by slice size —
    /// 5.42-5.48 GB/s for the whole chunk at once, 5.27-5.45 at 32 KiB,
    /// 4.83-5.12 at 16 KiB, 4.69-5.04 at 8 KiB. Monotonic, and the same
    /// shape as shrinking the ring buffer, which loses for the same reason:
    /// what a dispatch costs to enter is larger than what earlier credit
    /// buys.
    ///
    /// Earlier credit buys little because the loop is CPU-bound at these
    /// rates, not waiting on the peer. It would be worth something on a
    /// connection that is actually stalling for credit, which is not the
    /// shape a benchmark produces.
    pub async fn recv(&mut self) -> Option<Result<(), RecvError>> {
        let chunk = match self.transport.next().await? {
            Ok(chunk) => chunk,
            Err(e) => return Some(Err(e)),
        };
        self.decoder.decode_with(chunk.as_ref(), &mut self.protocol);
        Some(Ok(()))
    }
}
