use std::net::SocketAddr;
use std::time::Duration;

use runtime::io_driver::operations::sockets::multi_accept::AcceptError;
use runtime::io_driver::operations::sockets::multi_recv::Continuation;
use runtime::net::{BufRingSpec, MultiAccept, SocketWrapper};
use runtime::runtime::time::Sleep;
use runtime::spawn;
use runtime_streams::StreamExt;

use crate::server::connection::Connection;
#[cfg(feature = "tls")]
use crate::shared::transport::{ALPN_H2, KtlsTransport};
use crate::shared::transport::{PlainMessages, Transport};

pub(crate) mod connection;
mod limits;
mod stream;

pub use limits::Limits;
pub use stream::Stream;

/// Taken by value because the future it returns is spawned and must not
/// borrow the handler.
///
/// A handler that panics fails its own stream, with a `500` or a reset, and
/// nothing else. Not under `panic = "abort"`, where there is no unwinding to
/// stop.
pub trait Handler: Clone + 'static {
    fn handle(self, stream: Stream) -> impl Future<Output = ()> + 'static;
}

impl<F, Fut> Handler for F
where
    F: FnOnce(Stream) -> Fut + Clone + 'static,
    Fut: Future<Output = ()> + 'static,
{
    fn handle(self, stream: Stream) -> impl Future<Output = ()> + 'static {
        self(stream)
    }
}

pub struct Header {}

pub struct Server {
    pub settings: ServerSettings,
}

pub struct ServerSettings {
    /// A v6 address serves v6 only.
    pub bind: SocketAddr,
    pub transport: ServerTransport,
    pub limits: Limits,
}

impl ServerSettings {
    /// With the default [`Limits`].
    pub fn new(bind: impl Into<SocketAddr>, transport: ServerTransport) -> Self {
        Self {
            bind: bind.into(),
            transport,
            limits: Limits::default(),
        }
    }
}

/// Cleartext HTTP/2 is prior knowledge only (§3.4); there is no `Upgrade: h2c`.
pub enum ServerTransport {
    Plain,
    PlainZeroCopy,
    #[cfg(feature = "tls")]
    Tls(popple_tls::Config),
}

/// How long the listener waits after running out of descriptors or memory.
/// Only another holder can release them, so re-arming at once would spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(10);

impl Server {
    pub fn new(settings: ServerSettings) -> Self {
        Self { settings }
    }

    pub async fn run<U: BufRingSpec + 'static, H: Handler>(
        self,
        handler: H,
    ) -> std::io::Result<()> {
        let limits = self.settings.limits;
        limits.validate()?;
        let mut acceptor = MultiAccept::bind(self.settings.bind)?;
        match self.settings.transport {
            ServerTransport::Plain => {
                serve_plain::<U, false, H>(&mut acceptor, limits, handler).await
            }
            ServerTransport::PlainZeroCopy => {
                serve_plain::<U, true, H>(&mut acceptor, limits, handler).await
            }
            // A server asked for TLS must not come up at all without kTLS,
            // rather than refuse every connection or serve them in the clear.
            #[cfg(feature = "tls")]
            ServerTransport::Tls(config) => {
                if !popple_tls::ktls_available() {
                    return Err(std::io::Error::other(
                        "this kernel has no kTLS: `modprobe tls`, or build without the tls feature",
                    ));
                }
                serve_tls::<U, H>(&mut acceptor, config, limits, handler).await
            }
        }
    }
}

/// Exhaustion leaves the listener open; any other error ends it, and is
/// what `run` returns.
async fn accept(acceptor: &mut MultiAccept) -> std::io::Result<Option<SocketWrapper>> {
    loop {
        match acceptor.next().await {
            Some(Ok(socket)) => return Ok(Some(socket)),
            Some(Err(e)) if e.continuation() == Continuation::ContinueLater => {
                Sleep::during(ACCEPT_BACKOFF).await
            }
            Some(Err(AcceptError::Other(errno))) => {
                return Err(std::io::Error::from_raw_os_error(errno));
            }
            // Cancelled is the driver's own pause or shutdown, never the peer's.
            Some(Err(AcceptError::Cancelled)) | None => return Ok(None),
        }
    }
}

async fn serve_plain<U: BufRingSpec + 'static, const ZC: bool, H: Handler>(
    acceptor: &mut MultiAccept,
    limits: Limits,
    handler: H,
) -> std::io::Result<()>
where
    PlainMessages<U, ZC>: Transport,
{
    while let Some(socket) = accept(acceptor).await? {
        let peer = socket.peer_addr().ok();
        let transport = PlainMessages::<U, ZC>::new(socket);
        spawn(Connection::new(transport, peer, limits, handler.clone()).run());
    }
    Ok(())
}

/// The handshake runs inside the spawned task, not the accept loop: there,
/// a single slow peer would stall every waiting connection.
#[cfg(feature = "tls")]
async fn serve_tls<U: BufRingSpec + 'static, H: Handler>(
    acceptor: &mut MultiAccept,
    config: popple_tls::Config,
    limits: Limits,
    handler: H,
) -> std::io::Result<()> {
    while let Some(socket) = accept(acceptor).await? {
        // Before the handshake, which takes the socket.
        let peer = socket.peer_addr().ok();
        let config = config.clone();
        let handler = handler.clone();
        spawn(async move {
            let deadline = limits.tls_handshake_timeout;
            let ktls = match popple_tls::handshake(socket, config, deadline).await {
                Ok(ktls) => ktls,
                Err(_) => return,
            };
            let transport = KtlsTransport::<U, _>::new(ktls.into_messages::<U>());
            // §3.3: `h2` or nothing, including a peer that offered no ALPN.
            if transport.alpn() != Some(ALPN_H2) {
                return;
            }
            Connection::new(transport, peer, limits, handler).run().await;
        });
    }
    Ok(())
}
