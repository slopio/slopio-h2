//! One client connection: the handshake, and the loop that carries requests
//! over it.

use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;

use runtime_streams::StreamExt;

use crate::client::shared::ClientShared;
use crate::client::{CONNECTION_RECV_WINDOW, Client};
use crate::shared::codec::frames::{
    CLIENT_PREFACE, DECODE_MAX_HEADER_LIST_SIZE, FrameDecoder,
    encode::{encode_settings, encode_window_update},
    stream_id::StreamId,
};
use crate::shared::codec::types::{NO_ERROR, Setting};
use crate::shared::connection::CONNECTION_INITIAL_WINDOW_SIZE;
use crate::shared::transport::{RecvError, Transport};

mod protocol;
#[cfg(test)]
mod tests;

use protocol::Protocol;

/// What one turn of the connection loop found to do.
enum Event<B> {
    /// A chunk off the transport, to be cut into frames.
    Inbound(B),
    /// Frames are queued: somebody wrote a request, or a frame we produced
    /// ourselves is waiting.
    Flush,
    /// The buffer ring was empty. Nothing to do but come back.
    Retry,
    /// The peer is gone, cleanly or otherwise.
    Closed,
}

pub struct Connection<T: Transport> {
    transport: T,
    decoder: FrameDecoder,
    protocol: Protocol,
}

impl<T: Transport> Connection<T> {
    /// Opens the connection: preface out, the peer's SETTINGS in, both
    /// acknowledged.
    ///
    /// §3.4 makes the preface a magic string immediately followed by a
    /// SETTINGS frame, and both go out together — a server that has read the
    /// string and is waiting for the frame is a server holding a connection
    /// open for a round trip that need not happen.
    pub async fn handshake(transport: T) -> io::Result<Self> {
        let mut conn = Self {
            transport,
            // The inbound stream carries no preface — a server sends frames
            // from its first byte — so the decoder starts past that check.
            decoder: FrameDecoder::client(),
            protocol: Protocol::new(Rc::new(ClientShared::new(CONNECTION_RECV_WINDOW))),
        };

        conn.protocol.write_frame(|out| {
            out.extend_from_slice(CLIENT_PREFACE);
            encode_settings(
                out,
                &[
                    // We accept no pushed streams (§8.2), so say so before the
                    // peer can promise one.
                    Setting::EnablePush(0),
                    // The decoder drops fields past this; telling the peer
                    // lets it stay under rather than find out by refusal.
                    Setting::MaxHeaderListSize(DECODE_MAX_HEADER_LIST_SIZE as u32),
                ],
            );
        });

        // §6.9.2: the connection window starts at 65535 and SETTINGS never
        // touches it — only a WINDOW_UPDATE on stream 0 does. A client is the
        // end that downloads, so the gap is worth announcing before the first
        // response rather than after it stalls. Frame and credit go together,
        // so the ledger never says more than the wire.
        let gap = CONNECTION_RECV_WINDOW - CONNECTION_INITIAL_WINDOW_SIZE;
        conn.protocol
            .write_frame(|out| encode_window_update(out, StreamId::ZERO, gap));
        conn.protocol.shared.core.window.announce_recv(gap);

        conn.flush().await?;

        while !conn.protocol.handshake.is_complete() {
            match conn.recv().await {
                // The peer closed without finishing the handshake.
                None => return Err(handshake_failed(&conn, "peer closed during the handshake")),
                Some(Err(RecvError::Fatal(e))) => return Err(e),
                // The ring was empty, not the connection: come back for it.
                Some(Err(RecvError::Later)) => {
                    runtime::yield_now().await;
                    continue;
                }
                Some(Ok(())) => {}
            }
            // Whatever the frames produced — a SETTINGS ack, a PING answer, a
            // GOAWAY — leaves now.
            conn.flush().await?;
            if conn.protocol.is_closing() || conn.protocol.shared.is_closing() {
                return Err(handshake_failed(&conn, "peer refused the connection"));
            }
        }

        Ok(conn)
    }

    /// A handle on this connection, for the task that will make requests on
    /// it. Nothing happens on it until [`Connection::run`] is driving.
    pub fn client(&self) -> Client {
        Client::new(Rc::clone(&self.protocol.shared))
    }

    /// Drives the connection until there is nothing left to drive: the peer
    /// closes, the protocol fails, or every handle has been dropped.
    ///
    /// Unlike the server's loop, this one does not take its turns from
    /// inbound chunks alone. A client's frames are written by the
    /// application's task, at a moment the peer knows nothing about, so a
    /// loop that only flushed after a read would hold a request until the
    /// server happened to say something — which, having not been asked
    /// anything, it will not. [`Connection::next_event`] is what waits on
    /// both.
    ///
    /// What is deliberately missing is a deadline. The server bounds how long
    /// a peer may say nothing, because its connections are a resource
    /// strangers can hold; a client's connection is held by its own
    /// application, and how long a request may take is that application's
    /// business, not this loop's. A request that must not hang forever wraps
    /// its own `timeout` around `response()` today.
    pub async fn run(mut self) {
        let reason = loop {
            // Nobody holds a handle any more, so no request can ever be made
            // on this connection again — and anything still in the map has no
            // one left to read it. §6.8: say goodbye rather than vanishing.
            if self.is_abandoned() {
                self.protocol
                    .fail(NO_ERROR, "the client is done with this connection");
                let _ = self.flush().await;
                break "the client closed the connection";
            }

            let event = self.next_event().await;
            match event {
                Event::Inbound(chunk) => {
                    self.decoder.decode_with(chunk.as_ref(), &mut self.protocol);
                }
                Event::Flush => {
                    if self.flush().await.is_err() {
                        break "the connection failed while sending";
                    }
                    continue;
                }
                // The ring was empty, not the connection. Yielding is the
                // whole remedy: a buffer comes back when another connection on
                // this worker recycles one, which happens when it is polled,
                // which is what yielding lets happen.
                Event::Retry => {
                    runtime::yield_now().await;
                    continue;
                }
                Event::Closed => break "the peer closed the connection",
            }

            // A connection error was answered with a GOAWAY, which still has
            // to leave before the socket does.
            if self.protocol.is_closing() {
                let _ = self.flush().await;
                break self.protocol.failure.unwrap_or("the connection failed");
            }
            // A GOAWAY from the peer with nothing left to finish: the streams
            // it would not process are already failed, and no new one can be
            // opened, so there is nothing to stay for.
            if self.protocol.shared.is_closing() && self.protocol.shared.streams.len() == 0 {
                let _ = self.flush().await;
                break "the peer went away";
            }
        };

        // Whatever was still in flight ends here, with a reason, rather than
        // waiting on frames that will never come.
        self.protocol.shared.shut_down(reason);
    }

    /// Whether anything outside this loop still holds the connection. The
    /// loop's own `Rc` is the one that is always there, so being alone with
    /// it means every [`Client`] and [`Stream`] has been dropped.
    ///
    /// [`Stream`]: crate::client::Stream
    fn is_abandoned(&self) -> bool {
        Rc::strong_count(&self.protocol.shared) == 1
    }

    /// Waits for whichever comes first: a chunk from the peer, or a frame to
    /// send.
    ///
    /// The output is checked before the transport is polled and again before
    /// parking, which is belt and braces on a single-threaded runtime: no
    /// task can write between those two points, because no task runs while
    /// this one is being polled. What does happen between polls is a write
    /// from the application's task, and `write_frame` wakes the waker parked
    /// below for exactly that.
    fn next_event(&mut self) -> impl Future<Output = Event<T::Buf>> + '_ {
        let Self {
            transport,
            protocol,
            ..
        } = self;
        let shared = &protocol.shared;

        std::future::poll_fn(move |cx| {
            if !shared.core.output_is_empty() {
                return Poll::Ready(Event::Flush);
            }
            match Pin::new(&mut *transport).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Event::Inbound(chunk)),
                Poll::Ready(Some(Err(RecvError::Later))) => Poll::Ready(Event::Retry),
                // A transport failure and a clean close are the same thing to
                // a loop that has nowhere left to send a GOAWAY.
                Poll::Ready(Some(Err(RecvError::Fatal(_))) | None) => Poll::Ready(Event::Closed),
                Poll::Pending => {
                    shared.core.park_flusher(cx.waker());
                    match shared.core.output_is_empty() {
                        true => Poll::Pending,
                        false => Poll::Ready(Event::Flush),
                    }
                }
            }
        })
    }

    /// Takes one chunk off the transport and dispatches every frame in it.
    async fn recv(&mut self) -> Option<Result<(), RecvError>> {
        let chunk = match self.transport.next().await? {
            Ok(chunk) => chunk,
            Err(e) => return Some(Err(e)),
        };
        self.decoder.decode_with(chunk.as_ref(), &mut self.protocol);
        Some(Ok(()))
    }

    /// Sends everything written since the last flush, as one gather write.
    async fn flush(&mut self) -> io::Result<()> {
        if self.protocol.shared.core.output_is_empty() {
            return Ok(());
        }
        let bufs = self.protocol.shared.core.take_output();
        let (result, bufs) = self.transport.send(bufs, false).await;
        self.protocol.shared.core.restore_output(bufs);
        result
    }
}

/// The peer's own reason where there is one, so a failed handshake says what
/// the server objected to rather than only that it objected.
fn handshake_failed<T: Transport>(conn: &Connection<T>, fallback: &'static str) -> io::Error {
    io::Error::other(conn.protocol.failure.unwrap_or(fallback))
}
