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

use runtime::net::{BufRingSpec, connect_tcp};

use crate::shared::transport::PlainMessages;

mod connection;

pub use connection::Connection;

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
    let socket = connect_tcp(addr).await?;
    Connection::handshake(PlainMessages::new(socket)).await
}
