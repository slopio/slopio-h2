//! The client half: opening a connection to a server and speaking HTTP/2 over
//! it.
//!
//! Cleartext with **prior knowledge** only (§3.4), matching the server — the
//! preface goes out as the first bytes and there is no negotiation to lose.
//!
//! Most of what a connection needs is already shared, because it was never
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
use std::time::Duration;

use runtime::net::{BufRingSpec, connect_tcp};
use runtime::runtime::time::timeout;

use crate::shared::transport::PlainMessages;

mod connection;

pub use connection::Connection;

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

/// Connects to `addr` and completes the HTTP/2 handshake.
///
/// Returns once both ends have exchanged SETTINGS and acknowledged each
/// other's — §3.4 lets a client send requests without waiting for the server's
/// SETTINGS, but a connection handed over half-open is one whose first request
/// has to cope with limits it has not been told yet. Waiting costs one round
/// trip and makes `max_concurrent_streams` mean something before it is needed.
///
/// `U` is the buffer ring inbound reads land in, as on the server side.
pub async fn connect<U: BufRingSpec + 'static>(
    addr: SocketAddr,
) -> io::Result<Connection<PlainMessages<U, false>>> {
    match timeout(CONNECT_TIMEOUT, establish::<U>(addr)).await {
        Ok(connection) => connection,
        // Dropping the attempt is what cancels it, and both halves are built
        // for that: `ConnectTcp::drop` cancels the op and parks the fd and the
        // `sockaddr` the kernel may still be reading, and dropping the
        // handshake drops the `MultiRecv`, which recycles its buffers and
        // cancels in that order.
        Err(()) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no usable connection within CONNECT_TIMEOUT",
        )),
    }
}

/// The two stages the deadline covers.
async fn establish<U: BufRingSpec + 'static>(
    addr: SocketAddr,
) -> io::Result<Connection<PlainMessages<U, false>>> {
    let socket = connect_tcp(addr).await?;
    Connection::handshake(PlainMessages::new(socket)).await
}
