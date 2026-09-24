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
mod stream;

pub use stream::Stream;

/// Taken by value because the future it returns is spawned and must not
/// borrow the handler.
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
    pub bind_port: u16,
    pub transport: ServerTransport,
}

/// Cleartext HTTP/2 is prior knowledge only (§3.4); there is no `Upgrade: h2c`.
pub enum ServerTransport {
    Plain,
    PlainZeroCopy,
    #[cfg(feature = "tls")]
    Tls(popple_tls::Config),
}

/// How long a peer has to complete the TLS handshake. A peer that connects
/// and sends nothing would otherwise hold a task, a socket and a handshake
/// buffer indefinitely: none of the connection deadlines apply yet.
#[cfg(feature = "tls")]
pub const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
        let mut acceptor = MultiAccept::new(self.settings.bind_port)?;
        match self.settings.transport {
            ServerTransport::Plain => serve_plain::<U, false, H>(&mut acceptor, handler).await,
            ServerTransport::PlainZeroCopy => {
                serve_plain::<U, true, H>(&mut acceptor, handler).await
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
                serve_tls::<U, H>(&mut acceptor, config, handler).await
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
    handler: H,
) -> std::io::Result<()>
where
    PlainMessages<U, ZC>: Transport,
{
    while let Some(socket) = accept(acceptor).await? {
        spawn(Connection::new(PlainMessages::<U, ZC>::new(socket), handler.clone()).run());
    }
    Ok(())
}

/// The handshake runs inside the spawned task, not the accept loop: there,
/// a single slow peer would stall every waiting connection.
#[cfg(feature = "tls")]
async fn serve_tls<U: BufRingSpec + 'static, H: Handler>(
    acceptor: &mut MultiAccept,
    config: popple_tls::Config,
    handler: H,
) -> std::io::Result<()> {
    while let Some(socket) = accept(acceptor).await? {
        let config = config.clone();
        let handler = handler.clone();
        spawn(async move {
            let ktls = match popple_tls::handshake(socket, config, TLS_HANDSHAKE_TIMEOUT).await {
                Ok(ktls) => ktls,
                Err(_) => return,
            };
            let transport = KtlsTransport::<U, _>::new(ktls.into_messages::<U>());
            // §3.3: `h2` or nothing, including a peer that offered no ALPN.
            if transport.alpn() != Some(ALPN_H2) {
                return;
            }
            Connection::new(transport, handler).run().await;
        });
    }
    Ok(())
}
