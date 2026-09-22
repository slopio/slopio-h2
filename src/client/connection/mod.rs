//! One client connection: the handshake, and the loop that carries requests
//! over it.

use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;

use runtime::runtime::time::timeout;
use runtime_streams::StreamExt;

use crate::client::shared::ClientShared;
use crate::client::{CONNECTION_RECV_WINDOW, Client, STREAM_RECV_WINDOW};
use crate::shared::codec::frames::{
    CLIENT_PREFACE, DECODE_MAX_HEADER_LIST_SIZE, FrameDecoder,
    encode::{encode_ping, encode_settings, encode_window_update},
    stream_id::StreamId,
};
use crate::shared::codec::types::{NO_ERROR, Setting};
use crate::shared::connection::{CONNECTION_INITIAL_WINDOW_SIZE, DEADLINE_TICK};
use crate::shared::transport::{RecvError, Transport};

mod keepalive;
mod protocol;
#[cfg(test)]
mod tests;

use keepalive::Due;
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
    /// The peer closed its side.
    Closed,
    /// The transport failed, which is a close with nobody to tell.
    Failed,
    /// Nothing will be asked of this connection again, and nothing is left on
    /// it to finish.
    Finished,
}

/// Why the loop stopped: what the streams in flight are told, and what the
/// caller hears.
///
/// The two are the same sentence deliberately. A stream failing with "the
/// peer closed the connection" and a `run` that answered something else about
/// the same moment would be two accounts of one event.
enum Ended {
    /// The connection was finished with: by this client, or by a peer that
    /// closed or said goodbye.
    Done(&'static str),
    /// It stopped for a reason — a transport failure, or a protocol error we
    /// answered with a GOAWAY.
    Failed(&'static str),
}

impl Ended {
    fn reason(&self) -> &'static str {
        match self {
            Self::Done(reason) | Self::Failed(reason) => reason,
        }
    }

    fn into_result(self) -> io::Result<()> {
        match self {
            Self::Done(_) => Ok(()),
            Self::Failed(reason) => Err(io::Error::other(reason)),
        }
    }
}

/// Whether the connection has nothing left to do, ever.
///
/// Two ways to get there, and they are the same answer. Nobody holds a handle
/// — the loop's own `Rc` is the one always there, so being alone with it means
/// no request can be made again — or no further request will be taken, because
/// a GOAWAY arrived or [`Client::close`] was called, and what was in flight
/// has finished.
///
/// A free function on the shared state rather than a method on the connection,
/// because the one place it has to be asked is inside a poll that has the
/// transport borrowed. That is not a detail: neither of these is an *event*.
/// Nothing arrives to announce them, and the wake that follows a dropped
/// handle or a `close` carries no frame — so a loop that only asked between
/// events would sleep through both, which is precisely what it did.
fn finished(shared: &Rc<ClientShared>) -> bool {
    Rc::strong_count(shared) == 1 || (shared.is_closing() && shared.streams.len() == 0)
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
                    // §6.9.2: what every stream of ours starts with. Unlike
                    // the connection window below, this one SETTINGS carries,
                    // and a client that left it at the default would take
                    // every response 64 KiB at a time.
                    Setting::InitialWindowSize(STREAM_RECV_WINDOW),
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

    /// Puts the loop in a task of its own and answers the handle requests are
    /// made on.
    ///
    /// The [`Client`] owns that task rather than the task being detached, and
    /// that is the whole difference: a detached task cannot be waited on, cannot
    /// be stopped, and reports nothing when it ends — so a connection that died
    /// with no stream open died in silence. Owned, its end is
    /// [`Client::closed`], and dropping the handle still detaches, which is
    /// what keeps a client that simply walks away from having to say so.
    pub fn spawn(self) -> Client
    where
        T: 'static,
    {
        let shared = Rc::clone(&self.protocol.shared);
        Client::new(shared, Some(runtime::spawn(self.run())))
    }

    /// A handle on a connection somebody else is driving — the tests, which
    /// run the loop themselves or not at all. A `Client` made this way has no
    /// task to wait on, which is why it is not the way out of this module.
    pub(crate) fn client(&self) -> Client {
        Client::new(Rc::clone(&self.protocol.shared), None)
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
    /// What this loop does not do is put a deadline on the peer for its own
    /// sake. The server bounds how long a peer may say nothing, because its
    /// connections are a resource strangers can hold; a client's connection is
    /// held by its own application, and how long a request may take is that
    /// application's business — [`Stream::with_deadline`] is where it says so.
    /// The tick below is not that bound: it is the clock the keepalive counts
    /// silence in, and a peer that answers its probes may take all day.
    ///
    /// [`Stream::with_deadline`]: crate::client::Stream::with_deadline
    ///
    /// `Ok` is a connection that ended because it was finished with — by this
    /// client, or by a peer that closed or said goodbye. `Err` is one that
    /// stopped for a reason: a transport failure, or a protocol error we
    /// answered with a GOAWAY. Either way the streams still in flight are
    /// told the same thing, which is what they report to whoever was waiting.
    pub async fn run(mut self) -> io::Result<()> {
        let ended = loop {
            if finished(&self.protocol.shared) {
                break self.farewell().await;
            }

            // The tick is the keepalive's clock and nothing else's: it fires
            // only when neither the peer nor the application has given this
            // loop anything to do, and `DEADLINE_TICK` is the one duration the
            // runtime serves outside its timewheel, so arming and cancelling
            // it on every turn is what it is for. Dropping the wait is safe:
            // `MultiRecv` queues its completions in a buffer it owns, so the
            // read stays armed and nothing is lost between one poll and the
            // next.
            let event = match timeout(DEADLINE_TICK, self.next_event()).await {
                Ok(event) => event,
                Err(()) => match self.probe() {
                    Ok(()) => continue,
                    Err(reason) => {
                        // §6.8: say so rather than vanishing. The peer is very
                        // likely not listening, which is why the flush is
                        // allowed to fail.
                        self.protocol.fail(NO_ERROR, reason);
                        let _ = self.flush().await;
                        break Ended::Failed(reason);
                    }
                },
            };
            match event {
                Event::Inbound(chunk) => {
                    // Whatever it says, it came from a peer that is alive.
                    self.protocol.keepalive.heard();
                    self.decoder.decode_with(chunk.as_ref(), &mut self.protocol);
                }
                Event::Flush => {
                    if self.flush().await.is_err() {
                        break Ended::Failed("the connection failed while sending");
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
                Event::Closed => break Ended::Done("the peer closed the connection"),
                Event::Failed => break Ended::Failed("the connection failed while reading"),
                Event::Finished => break self.farewell().await,
            }

            // A connection error was answered with a GOAWAY, which still has
            // to leave before the socket does.
            if self.protocol.is_closing() {
                let _ = self.flush().await;
                break Ended::Failed(self.protocol.failure.unwrap_or("the connection failed"));
            }
        };

        // Whatever was still in flight ends here, with a reason, rather than
        // waiting on frames that will never come.
        self.protocol.shared.shut_down(ended.reason());
        ended.into_result()
    }

    /// One tick with nothing from the peer, and what the keepalive makes of
    /// it: a PING queued, nothing, or `Err` with the reason this connection is
    /// over.
    ///
    /// Nothing is flushed here. `write_frame` wakes the flusher, so the next
    /// turn of the loop finds the output non-empty and sends it — the same
    /// path every other frame this end produces takes, and one fewer place
    /// that has to remember to send.
    fn probe(&mut self) -> Result<(), &'static str> {
        let in_flight = self.protocol.shared.streams.len() > 0;
        match self.protocol.keepalive.tick(in_flight) {
            Due::Nothing => Ok(()),
            Due::Ping(opaque) => {
                self.protocol
                    .write_frame(|out| encode_ping(out, opaque, false));
                Ok(())
            }
            Due::Unanswered => Err("the peer did not answer a keepalive PING"),
        }
    }

    /// §6.8: a connection that is done is said to be done. The GOAWAY is
    /// written only if none has gone out — `fail` is idempotent — and then
    /// what is queued leaves, since a goodbye nobody sends is a socket that
    /// simply vanished.
    ///
    /// The reason the peer already gave, where there is one, so a connection
    /// that ends because the peer said goodbye does not report itself as
    /// having ended because we did.
    async fn farewell(&mut self) -> Ended {
        let reason = self
            .protocol
            .failure
            .unwrap_or("the client closed the connection");
        self.protocol.fail(NO_ERROR, reason);
        match self.flush().await {
            Ok(()) => Ended::Done(reason),
            Err(_) => Ended::Failed("the connection failed while sending"),
        }
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
            // Asked on every poll, because this is the one thing that becomes
            // true without an event: a handle dropped or a `close` wakes this
            // task and brings no frame with it, so the answer has to be looked
            // for rather than waited for.
            if finished(shared) {
                return Poll::Ready(Event::Finished);
            }
            if !shared.core.output_is_empty() {
                return Poll::Ready(Event::Flush);
            }
            match Pin::new(&mut *transport).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => Poll::Ready(Event::Inbound(chunk)),
                Poll::Ready(Some(Err(RecvError::Later))) => Poll::Ready(Event::Retry),
                Poll::Ready(None) => Poll::Ready(Event::Closed),
                // Nowhere left to send a GOAWAY, so this ends the loop as a
                // close does — but it is not one, and whoever waits on the
                // connection is owed the difference.
                Poll::Ready(Some(Err(RecvError::Fatal(_)))) => Poll::Ready(Event::Failed),
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
