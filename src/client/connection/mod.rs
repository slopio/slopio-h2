use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;
use std::time::SystemTime;

use runtime::runtime::time::timeout;
use runtime_streams::StreamExt;

use crate::client::shared::ClientShared;
use crate::client::{
    CONNECTION_RECV_WINDOW, Connection, FLUSH_TIMEOUT, IDLE_CLOSE_TICKS, STREAM_RECV_WINDOW,
};
use crate::shared::codec::frames::{
    CLIENT_PREFACE, DECODE_MAX_HEADER_LIST_SIZE, FrameDecoder,
    encode::{encode_ping, encode_settings, encode_window_update},
    stream_id::StreamId,
};
use crate::shared::codec::types::{NO_ERROR, Setting};
use crate::shared::connection::{CONNECTION_INITIAL_WINDOW_SIZE, DEADLINE_TICK};
use crate::shared::transport::{RecvError, Security, Transport};

mod keepalive;
mod protocol;
#[cfg(test)]
mod tests;

use keepalive::Due;
use protocol::{Handshake, Protocol};

enum Event<B> {
    Inbound(B),
    Flush,
    /// The buffer ring was empty, not the connection.
    Retry,
    Closed,
    Failed,
    Finished,
}

/// The reason is both what the streams in flight are told and what `run`
/// returns, so the two always agree.
enum Ended {
    Done(&'static str),
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

/// Strong count 1 means only the loop's own `Rc` remains, so no request can be
/// made again.
///
/// Neither condition arrives as an event, so this must be asked on every poll,
/// inside a poll that has the transport borrowed (hence a free function).
fn finished(shared: &Rc<ClientShared>) -> bool {
    Rc::strong_count(shared) == 1 || (shared.is_closing() && shared.streams.len() == 0)
}

/// A connection from its handshake until [`Driver::spawn`] hands its loop to
/// a task and its handle to the caller.
pub(crate) struct Driver<T: Transport> {
    transport: T,
    decoder: FrameDecoder,
    protocol: Protocol,
    /// Since when no stream has been open, as the loop last saw it.
    idle_since: Option<SystemTime>,
}

impl<T: Transport> Driver<T> {
    /// §3.4: the preface is immediately followed by a SETTINGS frame.
    pub(crate) async fn handshake(transport: T) -> io::Result<Self> {
        let shared = ClientShared::new(CONNECTION_RECV_WINDOW, T::Security::scheme());
        let mut conn = Self {
            transport,
            // A server sends no preface, so the decoder starts past that check.
            decoder: FrameDecoder::client(),
            protocol: Protocol::new(Rc::new(shared)),
            idle_since: None,
        };

        conn.protocol.write_frame(|out| {
            out.extend_from_slice(CLIENT_PREFACE);
            encode_settings(
                out,
                &[
                    // §8.2: we accept no pushed streams.
                    Setting::EnablePush(0),
                    Setting::InitialWindowSize(STREAM_RECV_WINDOW),
                    // The decoder drops fields past this.
                    Setting::MaxHeaderListSize(DECODE_MAX_HEADER_LIST_SIZE as u32),
                ],
            );
        });

        // §6.9.2: only a WINDOW_UPDATE on stream 0 moves the connection
        // window. Frame and credit go together, so the ledger never says more
        // than the wire.
        let gap = CONNECTION_RECV_WINDOW - CONNECTION_INITIAL_WINDOW_SIZE;
        conn.protocol
            .write_frame(|out| encode_window_update(out, StreamId::ZERO, gap));
        conn.protocol.shared.core.window.announce_recv(gap);

        conn.flush().await?;

        while conn.protocol.handshake != Handshake::Complete {
            match conn.recv().await {
                None => return Err(handshake_failed(&conn, "peer closed during the handshake")),
                Some(Err(RecvError::Fatal(e))) => return Err(e),
                Some(Err(RecvError::Later)) => {
                    runtime::yield_now().await;
                    continue;
                }
                Some(Ok(())) => {}
            }
            conn.flush().await?;
            if conn.protocol.is_closing() || conn.protocol.shared.is_closing() {
                return Err(handshake_failed(&conn, "peer refused the connection"));
            }
        }

        Ok(conn)
    }

    pub(crate) fn spawn(self) -> Connection<T::Security>
    where
        T: 'static,
    {
        let shared = Rc::clone(&self.protocol.shared);
        Connection::new(shared, Some(runtime::spawn(self.run())))
    }

    /// Test-only: a handle with no task to wait on.
    #[cfg(test)]
    pub(crate) fn connection(&self) -> Connection<T::Security> {
        Connection::new(Rc::clone(&self.protocol.shared), None)
    }

    /// Must wake on application writes as well as inbound chunks: a loop that
    /// only flushed after a read would hold a request until the server spoke,
    /// which it never will.
    async fn run(mut self) -> io::Result<()> {
        // Silence starts after the handshake, which was the peer talking.
        self.protocol.keepalive.heard(runtime::runtime::now());
        let ended = loop {
            if finished(&self.protocol.shared) {
                break self.farewell().await;
            }

            // Must be asked on every turn, whatever woke it: asking only after
            // an idle tick let our own writes hide a dead peer.
            if let Err(reason) = self.probe() {
                // §6.8. The peer is likely gone, so the flush may fail.
                self.protocol.fail(NO_ERROR, reason);
                let _ = self.flush().await;
                break Ended::Failed(reason);
            }

            // Nothing in flight is cut: with no stream open, `finished` says so
            // on the next turn.
            if self.idle_too_long(runtime::runtime::now()) {
                self.protocol.shared.stop_opening();
                continue;
            }

            // Dropping the wait is safe: `MultiRecv` queues its completions in
            // a buffer it owns, so the read stays armed and nothing is lost.
            let Ok(event) = timeout(DEADLINE_TICK, self.next_event()).await else {
                continue;
            };
            match event {
                Event::Inbound(chunk) => {
                    self.protocol.keepalive.heard(runtime::runtime::now());
                    self.decoder.decode_with(chunk.as_ref(), &mut self.protocol);
                }
                Event::Flush => {
                    if self.flush().await.is_err() {
                        break Ended::Failed("the connection failed while sending");
                    }
                    continue;
                }
                // Buffers come back only when other connections on this worker
                // are polled, which yielding lets happen.
                Event::Retry => {
                    runtime::yield_now().await;
                    continue;
                }
                Event::Closed => break Ended::Done("the peer closed the connection"),
                Event::Failed => break Ended::Failed("the connection failed while reading"),
                Event::Finished => break self.farewell().await,
            }

            // The GOAWAY answering a connection error must leave before the
            // socket does.
            if self.protocol.is_closing() {
                let _ = self.flush().await;
                break Ended::Failed(self.protocol.failure.unwrap_or("the connection failed"));
            }
        };

        // Streams still in flight must end here, or they wait for ever.
        self.protocol.shared.shut_down(ended.reason());
        ended.into_result()
    }

    fn probe(&mut self) -> Result<(), &'static str> {
        let in_flight = self.protocol.shared.streams.len() > 0;
        match self
            .protocol
            .keepalive
            .due(runtime::runtime::now(), in_flight)
        {
            Due::Nothing => Ok(()),
            Due::Ping(opaque) => {
                self.protocol
                    .write_frame(|out| encode_ping(out, opaque, false));
                Ok(())
            }
            Due::Unanswered => Err("the peer did not answer a keepalive PING"),
        }
    }

    /// Opening a stream writes its HEADERS, which wakes the loop, so no
    /// request comes and goes between two turns unseen.
    fn idle_too_long(&mut self, now: SystemTime) -> bool {
        if self.protocol.shared.streams.len() > 0 {
            self.idle_since = None;
            return false;
        }
        let since = *self.idle_since.get_or_insert(now);
        now.duration_since(since).unwrap_or_default() >= DEADLINE_TICK * IDLE_CLOSE_TICKS
    }

    /// §6.8. `fail` is idempotent, so the GOAWAY is written only if none has
    /// gone out, and a reason the peer already gave is kept.
    async fn farewell(&mut self) -> Ended {
        let reason = self
            .protocol
            .failure
            .unwrap_or("the client closed the connection");
        self.protocol.fail(NO_ERROR, reason);
        // Bounded by the flush's own deadline.
        match self.flush().await {
            Ok(()) => {
                // Only after the GOAWAY has gone.
                let _ = self.transport.shutdown().await;
                Ended::Done(reason)
            }
            Err(e) if e.kind() == io::ErrorKind::TimedOut => {
                Ended::Failed("the peer did not take the GOAWAY")
            }
            Err(_) => Ended::Failed("the connection failed while sending"),
        }
    }

    /// Application writes between polls are caught by `write_frame` waking the
    /// waker parked below.
    fn next_event(&mut self) -> impl Future<Output = Event<T::Buf>> + '_ {
        let Self {
            transport,
            protocol,
            ..
        } = self;
        let shared = &protocol.shared;

        std::future::poll_fn(move |cx| {
            // A dropped handle or `close` wakes this task with no frame, so it
            // must be checked on every poll.
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

    async fn recv(&mut self) -> Option<Result<(), RecvError>> {
        let chunk = match self.transport.next().await? {
            Ok(chunk) => chunk,
            Err(e) => return Some(Err(e)),
        };
        self.decoder.decode_with(chunk.as_ref(), &mut self.protocol);
        Some(Ok(()))
    }

    async fn flush(&mut self) -> io::Result<()> {
        if self.protocol.shared.core.output_is_empty() {
            return Ok(());
        }
        let bufs = self.protocol.shared.core.take_output();
        // Bound before the match: a scrutinee's temporaries would hold the
        // borrow of `self.transport` into the arms.
        let sent = timeout(FLUSH_TIMEOUT, self.transport.send(bufs, false)).await;
        match sent {
            Ok((result, bufs)) => {
                self.protocol.shared.core.restore_output(bufs);
                result
            }
            // The segments must not come back: a dropped send hands them to
            // the driver, which keeps them until the kernel is done with them.
            Err(()) => Err(io::ErrorKind::TimedOut.into()),
        }
    }
}

fn handshake_failed<T: Transport>(conn: &Driver<T>, fallback: &'static str) -> io::Error {
    io::Error::other(conn.protocol.failure.unwrap_or(fallback))
}
