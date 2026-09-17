use std::io;

use crate::server::connection::protocol::Protocol;
use crate::shared::{codec::frames::FrameDecoder, transport::Transport};
use runtime_streams::StreamExt;

mod output;
mod protocol;
pub(crate) mod settings;
mod shared_with_streams;

pub const MAX_CONCURRENT_STREAMS: u32 = 64;

pub const CONNECTION_INITIAL_WINDOW_SIZE: u32 = 65_535;
pub const CONNECTION_RECV_WINDOW: u32 = 1024 * 1024;

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
            // yield. Let them, then retire the ones that finished.
            runtime::yield_now().await;
            self.protocol.sweep();
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
        let (result, bufs) = self.transport.send(bufs, false).await;
        self.protocol.shared().restore_output(bufs);
        result
    }

    /// Takes one chunk off the transport and dispatches every frame in it.
    ///
    /// `None` is the peer closing its side — it may still be owed responses.
    /// Chunk boundaries mean nothing: a frame split across two chunks is
    /// reassembled by the decoder, which also keeps the header block a
    /// CONTINUATION is still completing.
    pub async fn recv(&mut self) -> Option<io::Result<()>> {
        let chunk = match self.transport.next().await? {
            Ok(chunk) => chunk,
            Err(e) => return Some(Err(e)),
        };
        self.decoder.decode_with(chunk.as_ref(), &mut self.protocol);
        Some(Ok(()))
    }
}
