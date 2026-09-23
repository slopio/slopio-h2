//! HTTP/2 client. Cleartext with prior knowledge only (§3.4).
//!
//! The connection loop and every handle share state through an `Rc`, so
//! nothing here is `Send`: a connection belongs to one thread.
//!
//! No request deadline is imposed; that is the application's, via
//! [`Stream::with_deadline`].

use std::cell::RefCell;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use runtime::Handle;
use runtime::net::{BufRingSpec, connect_tcp};
use runtime::runtime::time::timeout;

use crate::client::shared::ClientShared;
use crate::shared::connection::settings::Settings;
use crate::shared::transport::PlainMessages;
#[cfg(feature = "tls")]
use crate::shared::transport::{ALPN_H2, KtlsTransport};

mod connection;
mod shared;
mod stream;

pub use connection::Connection;
pub use shared::Unavailable;
pub use stream::Stream;

/// Our `SETTINGS_INITIAL_WINDOW_SIZE`. Credit goes back only for bytes the
/// application has read, so this bounds how much one response can pile up
/// against a caller that stops reading.
pub const STREAM_RECV_WINDOW: u32 = 1024 * 1024;

/// As large as §6.9.1 allows, so it never binds; backpressure is
/// [`STREAM_RECV_WINDOW`]'s job. Safe because what a client has in flight is
/// bounded by the requests the application chose to make.
pub const CONNECTION_RECV_WINDOW: u32 = i32::MAX as u32;

/// One bound over the whole of [`connect`]. Without it the handshake is
/// unbounded: a peer that accepts and then sends nothing, or a non-HTTP/2
/// listener, would hang us for ever.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Ticks of silence with a stream open before a keepalive PING (§6.7) goes
/// out. Must stay below our server's `ACTIVE_TICKS` (thirty seconds) with a
/// tick of slack, since tick deadlines fire up to one late.
pub const ACTIVE_PING_TICKS: u32 = 4;

/// Ticks of silence with nothing in flight before a keepalive PING goes out.
/// Kept long because strict gRPC servers answer frequent idle pings with
/// GOAWAY ENHANCE_YOUR_CALM.
pub const IDLE_PING_TICKS: u32 = 12;

/// Ticks a keepalive PING may go unanswered before the connection is given up
/// on. Only one probe is outstanding at a time, so this is the full budget.
pub const PING_TIMEOUT_TICKS: u32 = 4;

/// Dropping it does not close the connection while streams are still running;
/// the last handle of any kind going away ends it with a GOAWAY (§6.8).
pub struct Client {
    shared: Rc<ClientShared>,
    /// Owned rather than detached so the connection's end is observable.
    /// Dropping the handle detaches the task rather than killing it. `None`
    /// only in tests.
    task: RefCell<Option<Handle<io::Result<()>>>>,
}

impl Client {
    pub(crate) fn new(shared: Rc<ClientShared>, task: Option<Handle<io::Result<()>>>) -> Self {
        Self {
            shared,
            task: RefCell::new(task),
        }
    }

    pub fn peer_settings(&self) -> Settings {
        self.shared.peer_settings()
    }

    pub fn send_request(
        &self,
        request: &http::Request<()>,
        end_stream: bool,
    ) -> Result<Stream, Unavailable> {
        self.shared.send_request(request, end_stream)
    }

    pub fn is_closed(&self) -> bool {
        self.shared.is_closing()
    }

    /// Graceful shutdown (§6.8): nothing in flight is cancelled.
    pub fn close(&self) {
        self.shared.stop_opening();
        // The loop is parked on the socket, which will not tell it this.
        self.shared.core.wake_flusher();
    }

    /// Waits; does not close. Without [`Client::close`] first this waits for
    /// the peer to go. The end is handed over once; a second call errors.
    pub async fn closed(&self) -> io::Result<()> {
        let task = self.task.borrow_mut().take();
        match task {
            Some(task) => task.await,
            None => Err(io::Error::other(
                "this client does not own the connection loop",
            )),
        }
    }

    /// Against the peer's `max_concurrent_streams` (§5.1.2).
    pub fn live_streams(&self) -> usize {
        self.shared.streams.len()
    }

    pub fn index_request_paths(&self, repeated: bool) {
        self.shared.core.index_request_paths(repeated);
    }
}

impl Drop for Client {
    /// The parked loop cannot see a handle go away; waking it lets it notice
    /// it may be the last thing holding the connection.
    fn drop(&mut self) {
        self.shared.core.wake_flusher();
    }
}

/// Returns only once both ends have exchanged and acknowledged SETTINGS, so
/// the peer's limits are known before the first request.
pub async fn connect<U: BufRingSpec + 'static>(addr: SocketAddr) -> io::Result<Client> {
    let connection = match timeout(CONNECT_TIMEOUT, establish::<U>(addr)).await {
        Ok(connection) => connection?,
        // Dropping the attempt cancels it: `ConnectTcp::drop` cancels the op
        // and parks the fd and the `sockaddr` the kernel may still be reading,
        // and the `MultiRecv` recycles its buffers and cancels in that order.
        Err(()) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "no usable connection within CONNECT_TIMEOUT",
            ));
        }
    };

    Ok(connection.spawn())
}

/// `server_name` is what the certificate is checked against, so it must be the
/// host, not the address. §3.3: a server that does not agree to `h2` via ALPN
/// is refused.
#[cfg(feature = "tls")]
pub async fn connect_tls<U: BufRingSpec + 'static>(
    addr: SocketAddr,
    server_name: popple_tls::ServerName<'static>,
    config: popple_tls::ClientConfig,
) -> io::Result<Client> {
    if !popple_tls::ktls_available() {
        return Err(io::Error::other(
            "this kernel has no kTLS: `modprobe tls`, or build without the tls feature",
        ));
    }

    let established = timeout(CONNECT_TIMEOUT, async move {
        let socket = connect_tcp(addr).await?;
        let ktls = popple_tls::handshake_client(socket, server_name, config, CONNECT_TIMEOUT)
            .await
            .map_err(|e| io::Error::other(format!("TLS handshake: {e}")))?;

        let transport = KtlsTransport::<U, _>::new(ktls.into_messages::<U>());
        if transport.alpn() != Some(ALPN_H2) {
            return Err(io::Error::other(
                "the server did not agree to h2 (§3.3: ALPN is not optional over TLS)",
            ));
        }
        Connection::handshake(transport).await
    })
    .await;

    match established {
        Ok(connection) => Ok(connection?.spawn()),
        Err(()) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "no usable connection within CONNECT_TIMEOUT",
        )),
    }
}

async fn establish<U: BufRingSpec + 'static>(
    addr: SocketAddr,
) -> io::Result<Connection<PlainMessages<U, false>>> {
    let socket = connect_tcp(addr).await?;
    Connection::handshake(PlainMessages::new(socket)).await
}
