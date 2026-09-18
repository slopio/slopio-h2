use std::io;
use std::time::Duration;

use crate::server::connection::protocol::Protocol;
use crate::shared::{codec::frames::FrameDecoder, transport::Transport};
use runtime::runtime::time::timeout;
use runtime_streams::StreamExt;

mod output;
mod protocol;
pub(crate) mod settings;
mod shared_with_streams;
mod stream_map;
#[cfg(test)]
mod tests;

pub const MAX_CONCURRENT_STREAMS: u32 = 64;

pub const CONNECTION_INITIAL_WINDOW_SIZE: u32 = 65_535;
pub const CONNECTION_RECV_WINDOW: u32 = 1024 * 1024;

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
/// caused it. Five seconds is far longer than any receiver that is actually
/// reading needs, and short enough that the ring is not held hostage.
pub const FLUSH_TIMEOUT: Duration = Duration::from_secs(5);

/// One HTTP/2 connection: bytes come in through `transport`, `decoder` cuts
/// them into frames, and each frame is dispatched into `protocol`.
///
/// `protocol` is a struct of its own rather than its fields flattened in
/// here, because the decoder borrows it as its `FrameHandler` while being
/// borrowed itself — two `&mut` at once, which is only sound across disjoint
/// fields.
pub struct Connection<T: Transport> {
    transport: T,
    decoder: FrameDecoder,
    protocol: Protocol,
}

impl<T: Transport> Connection<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            decoder: FrameDecoder::new(),
            protocol: Protocol::new(),
        }
    }

    /// Drives the connection to completion: one chunk in, everything it
    /// produced out, until the peer closes or a connection error is answered.
    ///
    /// Sequential on purpose — the simple version. Output written by a
    /// stream task while we wait on `recv` only leaves with the next inbound
    /// chunk; a select on "output ready" is what fixes that, later.
    pub async fn run(mut self) {
        loop {
            match self.recv().await {
                // Half-close: the peer sends no more, but is still owed
                // whatever is queued.
                None => break,
                Some(Err(e)) => {
                    eprintln!("transport error: {e}");
                    return;
                }
                Some(Ok(())) => {}
            }
            if self.drain().await.is_err() {
                return;
            }
            // The drain carried the GOAWAY, if there was one. An invalid
            // preface queued nothing, so it closed in silence (§3.4).
            if self.is_closing() {
                return;
            }
        }
        let _ = self.drain().await;
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
    pub async fn recv(&mut self) -> Option<io::Result<()>> {
        let chunk = match self.transport.next().await? {
            Ok(chunk) => chunk,
            Err(e) => return Some(Err(e)),
        };
        self.decoder.decode_with(chunk.as_ref(), &mut self.protocol);
        Some(Ok(()))
    }
}
