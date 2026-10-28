use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::Poll;
use std::time::{Duration, SystemTime};

use crate::server::connection::protocol::{Phase, Protocol};
use crate::server::shutdown::Registration;
use crate::server::{Handler, Limits};
use crate::shared::{
    codec::frames::FrameDecoder,
    connection::DryRing,
    transport::{RecvError, Transport},
};
use runtime::runtime::time::timeout;

mod protocol;
pub(crate) mod shared_with_streams;
#[cfg(test)]
mod tests;

pub const MAX_CONCURRENT_STREAMS: u32 = 64;

/// §6.9.2's starting point for both halves of the connection window.
pub use crate::shared::connection::CONNECTION_INITIAL_WINDOW_SIZE;

/// Since credit goes back only for bytes a handler has taken, this bounds
/// what one stream can hold against a stalled handler, and
/// `MAX_CONCURRENT_STREAMS` times it for a connection.
pub const STREAM_RECV_WINDOW: u32 = 1024 * 1024;

/// As large as §6.9.1 allows, so that it never binds: what a peer can have in
/// flight unconsumed is bounded by the stream windows, not by this.
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

/// How long one gather-write may stall before the connection is closed. It
/// bounds the whole write, so a peer that accepts a byte at a time gets no
/// fresh deadline per byte.
///
/// It protects the buffer ring shared by every connection on the worker: a
/// loop parked in `send` pins ring buffers, so a handful of peers that stop
/// reading could otherwise empty the ring and fail other connections' recvs
/// with ENOBUFS.
///
/// It effectively sets a minimum bandwidth of `OUTPUT_HIGH_WATER /
/// FLUSH_TIMEOUT` (~52 KB/s for a full flush), which is strictest on the
/// largest transfers.
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a connection that ends first reads out what its peer still sends,
/// after its FIN. Closed with input unread, a Linux socket resets the
/// connection instead of ending it, and the peer may meet the reset before
/// our last frames. A peer that has read our FIN ends within a round trip;
/// one that keeps sending this long gets the reset.
pub const LINGER: Duration = Duration::from_secs(1);

/// Every deadline below is a multiple of this, and only as precise as it.
pub use crate::shared::connection::DEADLINE_TICK;

/// How long a peer with nothing outstanding may send nothing at all.
pub const IDLE_TICKS: u32 = 24;

/// How long a peer that has a stream open may send nothing before we ask,
/// with a PING (§6.7), whether it is still there.
///
/// A peer that holds streams open without sending their bodies is not this
/// deadline's to catch: the sweep's `body_is_starving` resets those.
pub const ACTIVE_TICKS: u32 = 6;

/// How long our PING may go unanswered before the peer is taken to be gone.
pub const PING_TIMEOUT_TICKS: u32 = 4;

/// How long a peer that closed its half of the transport waits for the
/// answers it is still owed. Final, since a PING could not be answered.
///
/// Only handlers still working are waited on. A stream waiting on the peer
/// is waiting on nothing, and is reset the moment it is found.
pub const HALF_CLOSED_TICKS: u32 = 6;

/// The slowloris deadline: how long a peer may leave a preface or a header
/// block (HEADERS awaiting CONTINUATION) half-sent. §6.10 forbids
/// interleaving other frames during a header block, so one unfinished block
/// stops the whole connection.
///
/// Wall clock from when the half-sent state began, not a silence count:
/// sending more of the same frame must not refill it, or a peer dribbling a
/// byte at a time holds the connection for ever.
pub const PARTIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// How often live streams are swept for one that is starving. The per-stream
/// rate checks run only when the peer sends on that stream, so this catches
/// the stream whose peer sends nothing at all.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// Flushes a turn may take before handing back to the loop. Two carry a
/// request's whole answer: the first sends what the decode queued and lets
/// the handlers it woke run, the second sends what they wrote.
///
/// Not until the output is empty: a writer with credit refills it every
/// round, and that kept the loop from reading — the peer's RST_STREAM, its
/// WINDOW_UPDATEs, its next requests — and from checking its deadlines for
/// as long as the peer kept crediting.
const DRAIN_ROUNDS: usize = 2;

enum Event<B> {
    Inbound(B),
    Flush,
    Retry,
    Closed,
    Failed,
    /// The server stopped accepting, and the streams in flight have until
    /// then to finish. Once per connection.
    Shutdown(SystemTime),
}

enum Due {
    Nothing,
    Ping,
    Close(&'static str),
}

/// `protocol` must stay a separate field: the decoder borrows it as its
/// `FrameHandler` while being borrowed itself, which is only sound across
/// disjoint fields.
pub struct Connection<T: Transport, H: Handler> {
    transport: T,
    decoder: FrameDecoder,
    protocol: Protocol<H>,
    /// When the peer last entered a half-sent state. [`PARTIAL_TIMEOUT`] is
    /// measured from here, not from the last byte, so that sending more of it
    /// cannot reset the budget (slowloris).
    partial_since: Option<std::time::SystemTime>,
    last_swept: std::time::SystemTime,
    probe_sent: Option<SystemTime>,
    idle_timeout: Duration,
    /// `None` outside a `Server`: nothing can stop the connection but itself.
    shutdown: Option<Registration>,
    shutdown_seen: bool,
    /// The peer's end has been read: closing then leaves nothing unread.
    peer_ended: bool,
}

impl<T: Transport, H: Handler> Connection<T, H> {
    pub fn new(transport: T, peer: Option<SocketAddr>, limits: Limits, handler: H) -> Self {
        Self {
            transport,
            decoder: FrameDecoder::new()
                .with_max_header_list_size(limits.max_header_list_size as usize),
            protocol: Protocol::new(handler, peer, limits),
            partial_since: None,
            last_swept: runtime::runtime::now(),
            probe_sent: None,
            idle_timeout: limits.idle_timeout,
            shutdown: None,
            shutdown_seen: false,
            peer_ended: false,
        }
    }

    /// Counted among the connections its server waits for when it stops, and
    /// told to drain when it does, even if that was before this.
    pub(crate) fn in_shutdown(mut self, registration: Registration) -> Self {
        registration.attach(self.protocol.shared_handle());
        self.shutdown = Some(registration);
        self
    }

    pub async fn run(mut self) {
        // Silence is measured from here, not counted in ticks: the tick
        // restarts whenever handler output wakes the loop, so a dead peer
        // would otherwise be held for as long as a handler kept writing.
        let mut last_heard = runtime::runtime::now();
        let mut dry = DryRing::default();
        loop {
            match self.due(last_heard) {
                Due::Nothing => {}
                Due::Ping => self.protocol.ping(),
                // §6.8: the GOAWAY is queued, and the `Closing` drain carries it.
                Due::Close(reason) => self.protocol.time_out(reason),
            }
            let waited = match self.protocol.phase() {
                Phase::Open => timeout(DEADLINE_TICK, self.next_event()).await,
                // Woken at the drain's deadline rather than up to a tick past it.
                Phase::Draining { until } => {
                    let left = until.map_or(DEADLINE_TICK, |until| {
                        until
                            .duration_since(runtime::runtime::now())
                            .unwrap_or_default()
                    });
                    timeout(left.min(DEADLINE_TICK), self.next_event()).await
                }
                Phase::HalfClosed { .. } => timeout(DEADLINE_TICK, self.next_output()).await,
                Phase::Closing => break,
            };
            let chunk = match waited {
                Err(()) => continue,
                Ok(Event::Inbound(chunk)) => {
                    dry.refilled();
                    chunk
                }
                // Not the peer's doing, so it must not reset the peer's
                // silence or run the sweep.
                Ok(Event::Flush) => {
                    // Before the drain, so the reset goes out with it.
                    self.protocol.reset_stalled();
                    if self.drain().await.is_err() {
                        return;
                    }
                    if self.protocol.is_done() {
                        break;
                    }
                    continue;
                }
                Ok(Event::Closed) => {
                    self.peer_ended = true;
                    self.protocol.peer_closed();
                    if self.protocol.is_done() {
                        break;
                    }
                    continue;
                }
                // An empty ring is other connections holding buffers, not
                // this peer's doing, so it never ends the connection.
                // `last_heard` is untouched, so a ring that never refills
                // still ends in the silence deadline's GOAWAY.
                Ok(Event::Retry) => {
                    dry.wait().await;
                    continue;
                }
                Ok(Event::Failed) => return,
                // Not the peer's doing either.
                Ok(Event::Shutdown(until)) => {
                    self.protocol.shut_down(until);
                    if self.drain().await.is_err() {
                        return;
                    }
                    // A connection with nothing in flight goes now.
                    if self.protocol.is_done() {
                        break;
                    }
                    continue;
                }
            };
            self.decoder.decode_with(chunk.as_ref(), &mut self.protocol);
            last_heard = runtime::runtime::now();
            self.probe_sent = None;
            self.sweep_if_due();
            if self.drain().await.is_err() {
                return;
            }
            if self.protocol.is_done() {
                break;
            }
        }
        // The streams go before the last flush, and with nothing awaited in
        // between: no task gets a turn to write past the GOAWAY, and a writer
        // with credit cannot hold the connection open past its deadline.
        self.protocol.end_streams();
        // An invalid preface queued nothing, so it closes in silence (§3.4).
        let _ = self.flush().await;
        let _ = self.transport.shutdown().await;
        // Ending first, we read out what the peer still sends up to its end,
        // so that the socket closes with nothing unread and is not reset.
        if !self.peer_ended {
            let _ = timeout(LINGER, self.read_to_end()).await;
        }
    }

    /// Drops what arrives, until the peer's end or a dead socket.
    async fn read_to_end(&mut self) {
        let mut dry = DryRing::default();
        loop {
            let next = std::future::poll_fn(|cx| Pin::new(&mut self.transport).poll_next(cx));
            match next.await {
                Some(Ok(_)) => {}
                // An empty ring is other connections holding buffers.
                Some(Err(RecvError::Later)) => dry.wait().await,
                Some(Err(RecvError::Fatal(_))) | None => return,
            }
        }
    }

    /// One flush is not enough: a task may have parked on a full buffer, and
    /// only a flush gives it room again. What is left after
    /// [`DRAIN_ROUNDS`] goes out on later turns, between reads.
    ///
    /// Nothing once the connection is closing: the loop ends it before any
    /// task writes again.
    async fn drain(&mut self) -> io::Result<()> {
        for _ in 0..DRAIN_ROUNDS {
            if self.protocol.phase() == Phase::Closing {
                return Ok(());
            }
            self.flush().await?;
            runtime::yield_now().await;
            if self.protocol.shared().output_is_empty() {
                return Ok(());
            }
        }
        Ok(())
    }

    /// Clocks that step backwards floor at zero, so an adjustment cannot close
    /// a connection.
    #[inline]
    fn due(&mut self, last_heard: SystemTime) -> Due {
        let now = runtime::runtime::now();
        let since = |then: SystemTime| now.duration_since(then).unwrap_or_default();

        match self.protocol.phase() {
            Phase::Open | Phase::Draining { until: None } => {}
            // What has not finished by then is cut, whatever else is due.
            Phase::Draining { until: Some(until) } => {
                if now >= until {
                    return Due::Close("shutting down");
                }
            }
            Phase::HalfClosed { since: closed } => {
                return match since(closed) >= DEADLINE_TICK * HALF_CLOSED_TICKS {
                    true => Due::Close("peer half-closed, answers not finished"),
                    false => Due::Nothing,
                };
            }
            Phase::Closing => return Due::Nothing,
        }

        if !self.decoder.preface_seen() || self.decoder.header_pending() {
            let started = *self.partial_since.get_or_insert(now);
            return match since(started) >= PARTIAL_TIMEOUT {
                true => Due::Close("idle too long"),
                false => Due::Nothing,
            };
        }
        self.partial_since = None;

        if let Some(sent) = self.probe_sent {
            return match since(sent) >= DEADLINE_TICK * PING_TIMEOUT_TICKS {
                true => Due::Close("keepalive PING unanswered"),
                false => Due::Nothing,
            };
        }

        let silent = since(last_heard);
        if !self.protocol.has_live_streams() {
            return match silent >= self.idle_timeout {
                true => Due::Close("idle too long"),
                false => Due::Nothing,
            };
        }
        if silent < DEADLINE_TICK * ACTIVE_TICKS {
            return Due::Nothing;
        }
        self.probe_sent = Some(now);
        Due::Ping
    }

    /// Must run after the dispatch: judging on evidence one turn stale would
    /// reset a stream whose DATA just arrived.
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

    pub async fn flush(&mut self) -> io::Result<()> {
        if self.protocol.shared().output_is_empty() {
            return Ok(());
        }
        let bufs = self.protocol.shared().take_output();
        // Bound before the match: a scrutinee's temporaries would hold the
        // borrow of `self.transport` into the arms.
        let sent = timeout(FLUSH_TIMEOUT, self.transport.send(bufs, false)).await;
        match sent {
            Ok((result, bufs)) => {
                self.protocol.shared().restore_output(bufs);
                result
            }
            // The segments must not come back: a dropped send moves its
            // chunks and `msghdr` into the driver's keepalive slot so the
            // kernel can finish reading them after the cancel CQE. Freeing
            // them here would be unsound.
            Err(()) => Err(io::ErrorKind::TimedOut.into()),
        }
    }

    /// A handler writing between polls is caught by `write_frame` waking the
    /// waker parked below.
    ///
    /// Reads before it flushes: output a writer keeps refilling must not keep
    /// the peer's frames waiting. Every inbound turn flushes on its way out.
    fn next_event(&mut self) -> impl Future<Output = Event<T::Buf>> + '_ {
        let Self {
            transport,
            protocol,
            shutdown,
            shutdown_seen,
            ..
        } = self;
        let shared = protocol.shared();

        std::future::poll_fn(move |cx| {
            // `Shutdown::begin` wakes the flusher parked below.
            if !*shutdown_seen && let Some(until) = shutdown.as_ref().and_then(|s| s.until()) {
                *shutdown_seen = true;
                return Poll::Ready(Event::Shutdown(until));
            }
            match Pin::new(&mut *transport).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Event::Inbound(chunk)),
                // An empty ring holds up reading, not writing; the next poll
                // retries the read.
                Poll::Ready(Some(Err(RecvError::Later))) if !shared.output_is_empty() => {
                    Poll::Ready(Event::Flush)
                }
                Poll::Ready(Some(Err(RecvError::Later))) => Poll::Ready(Event::Retry),
                Poll::Ready(Some(Err(RecvError::Fatal(_)))) => Poll::Ready(Event::Failed),
                Poll::Ready(None) => Poll::Ready(Event::Closed),
                Poll::Pending => {
                    shared.park_flusher(cx.waker());
                    match shared.output_is_empty() {
                        true => Poll::Pending,
                        false => Poll::Ready(Event::Flush),
                    }
                }
            }
        })
    }

    /// Any wake is a turn, not only one that brought output: a writer out of
    /// credit wakes the flusher with nothing written, and the turn is what
    /// resets its stream.
    ///
    /// The transport must not be polled: it has returned `None`.
    fn next_output(&self) -> impl Future<Output = Event<T::Buf>> + '_ {
        let shared = self.protocol.shared();
        let mut parked = false;
        std::future::poll_fn(move |cx| {
            if parked || !shared.output_is_empty() {
                return Poll::Ready(Event::Flush);
            }
            parked = true;
            shared.park_flusher(cx.waker());
            match shared.output_is_empty() {
                true => Poll::Pending,
                false => Poll::Ready(Event::Flush),
            }
        })
    }
}
