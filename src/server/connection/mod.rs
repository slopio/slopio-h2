use std::io;

use crate::server::connection::protocol::Protocol;
use crate::shared::{codec::frames::FrameDecoder, transport::Transport};
use runtime_streams::StreamExt;

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
            if self.flush().await.is_err() {
                return;
            }
            // The tasks this turn spawned or woke have not run yet — they
            // only do once we yield. Let them, retire the ones that finished,
            // and send what they wrote. A select on "output ready" is what
            // replaces this, later.
            runtime::yield_now().await;
            self.protocol.sweep();
            if self.flush().await.is_err() {
                return;
            }
            // The flushes above carried the GOAWAY, if there was one. An
            // invalid preface queued nothing, so it closed in silence (§3.4).
            if self.is_closing() {
                return;
            }
        }
        let _ = self.flush().await;
    }

    /// Once true, nothing more should be read: a connection error has been
    /// answered — or, for an invalid preface, deliberately not — and what
    /// remains is to flush and close.
    pub fn is_closing(&self) -> bool {
        self.protocol.is_closing()
    }

    /// Sends everything written since the last turn, as one write. The
    /// buffer comes back with its capacity intact.
    pub async fn flush(&mut self) -> io::Result<()> {
        let buf = self.protocol.shared().take_output();
        if buf.is_empty() {
            self.protocol.shared().restore_output(buf);
            return Ok(());
        }
        let (result, mut bufs) = self.transport.send(vec![buf], false).await;
        let buf = bufs.pop().expect("send hands back the buffer it was given");
        self.protocol.shared().restore_output(buf);
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
