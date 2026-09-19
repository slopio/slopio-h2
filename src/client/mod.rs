//! The client half: opening a connection to a server and speaking HTTP/2 over
//! it.
//!
//! Cleartext with **prior knowledge** only (§3.4), matching the server — the
//! preface goes out as the first bytes and there is no negotiation to lose.
//!
//! ```ignore
//! let client = client::connect::<Ring>(addr).await?;
//!
//! let request = http::Request::get("http://example.test/").body(())?;
//! let stream = client.send_request(&request, true)?;
//!
//! let response = stream.response().await?;
//! while let Some(chunk) = stream.read().await? {
//!     // ...
//! }
//! ```
//!
//! Three types, and the shape is the protocol's. A [`Client`] is the
//! connection, and it is a handle rather than the connection itself because
//! the connection is a task: something has to be reading frames while the
//! application is between calls, or a response would only arrive while
//! somebody happened to be waiting for it. A [`Stream`] is one request — write
//! its body, read its response, close it. The connection loop and every
//! handle reach the same state through an `Rc`, which is why neither is
//! `Send`: this runtime is a thread per core and a connection belongs to one.
//!
//! Most of what all this needs is shared with the server, because it was never
//! server-specific: the frame decoder has a [`client`] constructor, the HPACK
//! encoder takes request pseudo-headers exactly as it takes `:status`, and the
//! send chain, the stream map and the windows live in
//! [`shared::connection`](crate::shared::connection). What is here is the part
//! that differs — which end sends the preface, who picks stream ids, and what
//! an inbound HEADERS *means*.
//!
//! [`client`]: crate::shared::codec::frames::FrameDecoder::client

use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use runtime::net::{BufRingSpec, connect_tcp};
use runtime::runtime::time::timeout;

use crate::client::shared::ClientShared;
use crate::shared::connection::settings::Settings;
use crate::shared::transport::PlainMessages;

mod connection;
mod shared;
mod stream;

pub use connection::Connection;
pub use shared::Unavailable;
pub use stream::Stream;

/// The connection receive window this client announces, once the handshake is
/// done.
///
/// Ours to choose, where the send side is the peer's to credit, and chosen
/// larger than §6.9.2's 65535 default for the same reason the server's is: a
/// window that small stalls a download every 64 KiB until a WINDOW_UPDATE
/// completes a round trip. A client is the end that mostly downloads, so it
/// is the end where this matters most.
pub const CONNECTION_RECV_WINDOW: u32 = 1024 * 1024;

/// How long [`connect`] has to produce a connection that can carry a request.
///
/// One bound over the whole establishment rather than one per stage, because
/// what a caller wants to limit is how long until it has something usable, and
/// two constants that sum to a third nobody wrote down is worse than one that
/// says what it means.
///
/// Every stage under it is otherwise unbounded, and the middle one is the
/// reason this exists. A TCP connect is at least bounded by the kernel — six
/// SYN retries, about two minutes, which is far too long but is finite. The
/// handshake is not bounded by anything: a peer that accepts the connection
/// and then sends nothing holds us for ever. That is the shape `PARTIAL_TIMEOUT`
/// stops on the server side, pointed the other way, and it is cheaper to cause
/// here than to mount — one `accept` and silence.
///
/// It is also what happens by accident, which matters more than the attack.
/// Point this at a port where something that is not HTTP/2 is listening — an
/// HTTP/1.1 server, sshd, a TLS endpoint — and without a deadline it hangs
/// instead of failing.
///
/// Ten seconds is generous for what it covers: a TCP handshake and one round
/// trip of SETTINGS. A peer that cannot manage both in ten seconds is not one
/// a request was going to go well over.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection to one server: the handle requests are made on.
///
/// Dropping it does not close the connection while streams are still running
/// — the loop stays up until the last of them is done with. What ends the
/// connection is the last handle of any kind going away, and then the loop
/// says goodbye with a GOAWAY (§6.8) rather than vanishing.
pub struct Client {
    shared: Rc<ClientShared>,
}

impl Client {
    pub(crate) fn new(shared: Rc<ClientShared>) -> Self {
        Self { shared }
    }

    /// What the peer said it will accept, as of its last SETTINGS frame.
    pub fn peer_settings(&self) -> Settings {
        self.shared.peer_settings()
    }

    /// Opens a stream and puts `request`'s head on it.
    ///
    /// `end_stream` says the request has no body, which is what a GET is:
    /// §8.1 lets the message end at its head. With `false`, the body is
    /// written through [`Stream::write`].
    ///
    /// Not `async`, and it does not wait for the response: the frame is
    /// written to the connection's output and the loop sends it, so a client
    /// can put a hundred requests in flight from one task without a task per
    /// request. [`Unavailable`] is the two reasons it can decline, each with
    /// a different remedy.
    pub fn send_request(
        &self,
        request: &http::Request<()>,
        end_stream: bool,
    ) -> Result<Stream, Unavailable> {
        self.shared.send_request(request, end_stream)
    }

    /// Whether this connection can still take requests. `true` once a GOAWAY
    /// has arrived, the loop has stopped, or §5.1.1's stream ids are spent.
    pub fn is_closed(&self) -> bool {
        self.shared.is_closing()
    }

    /// How many streams are open on this connection, against the peer's
    /// `max_concurrent_streams` (§5.1.2).
    pub fn live_streams(&self) -> usize {
        self.shared.streams.len()
    }
}

impl Drop for Client {
    /// The loop is parked on the socket with nothing to send, and a handle
    /// going away is not something it can see. Waking it is what lets it
    /// notice that it is the last thing holding the connection.
    fn drop(&mut self) {
        self.shared.core.wake_flusher();
    }
}

/// Connects to `addr`, completes the HTTP/2 handshake, and leaves the
/// connection running in a task of its own.
///
/// Returns once both ends have exchanged SETTINGS and acknowledged each
/// other's — §3.4 lets a client send requests without waiting for the server's
/// SETTINGS, but a connection handed over half-open is one whose first request
/// has to cope with limits it has not been told yet. Waiting costs one round
/// trip and makes `max_concurrent_streams` mean something before it is needed.
///
/// The spawned loop is detached: it ends on its own when the last [`Client`]
/// and [`Stream`] have been dropped, which is the only thing that can tell it
/// no further request is coming.
///
/// `U` is the buffer ring inbound reads land in, as on the server side.
pub async fn connect<U: BufRingSpec + 'static>(addr: SocketAddr) -> io::Result<Client> {
    let connection = match timeout(CONNECT_TIMEOUT, establish::<U>(addr)).await {
        Ok(connection) => connection?,
        // Dropping the attempt is what cancels it, and both halves are built
        // for that: `ConnectTcp::drop` cancels the op and parks the fd and the
        // `sockaddr` the kernel may still be reading, and dropping the
        // handshake drops the `MultiRecv`, which recycles its buffers and
        // cancels in that order.
        Err(()) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no usable connection within CONNECT_TIMEOUT",
            ));
        }
    };

    let client = connection.client();
    runtime::spawn(connection.run());
    Ok(client)
}

/// The two stages the deadline covers.
async fn establish<U: BufRingSpec + 'static>(
    addr: SocketAddr,
) -> io::Result<Connection<PlainMessages<U, false>>> {
    let socket = connect_tcp(addr).await?;
    Connection::handshake(PlainMessages::new(socket)).await
}
