use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::rc::Rc;
use std::time::Duration;

use runtime::io_driver::operations::sockets::multi_accept::AcceptError;
use runtime::io_driver::operations::sockets::multi_recv::Continuation;
use runtime::net::{BufRingSpec, MultiAccept, SocketWrapper};
use runtime::runtime::select::{SelectResult, select};
use runtime::runtime::time::{Sleep, timeout};
use runtime::spawn;
use runtime_streams::StreamExt;

use crate::server::connection::Connection;
use crate::server::limits::DRAIN_GRACE;
use crate::server::shutdown::Shutdown;
#[cfg(feature = "tls")]
use crate::shared::transport::{ALPN_H2, KtlsTransport};
use crate::shared::transport::{PlainMessages, Transport};

pub(crate) mod connection;
mod handler;
mod limits;
pub mod router;
mod shutdown;
mod stream;

pub use handler::{Handler, Incoming, StreamTask};
pub use limits::Limits;
pub use router::{Params, Router};
pub use stream::{BodyTooLarge, Stream};

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
    Tls(slopio_tls::Config),
}

/// How long the listener waits after running out of descriptors or memory.
/// Only another holder can release them, so re-arming at once would spin.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(10);

impl Server {
    pub fn new(settings: ServerSettings) -> Self {
        Self { settings }
    }

    /// Until the runtime is asked to stop — under `thread_per_core`, SIGTERM
    /// or SIGINT — and then as [`run_until`](Self::run_until) does.
    pub async fn run<U: BufRingSpec + 'static, H: Handler>(
        self,
        handler: H,
    ) -> std::io::Result<()> {
        self.run_until::<U, H, _>(handler, std::future::pending())
            .await
    }

    /// Until `stop` completes or the runtime is asked to stop, whichever is
    /// first. Then the listener closes, every connection is sent a
    /// GOAWAY(NO_ERROR) naming the last stream it took (§6.8), and the
    /// streams in flight get [`Limits::drain_timeout`] to finish. Returns once
    /// the last connection has closed, or when that has run out; an accept
    /// error is returned after the drain, not instead of it.
    ///
    /// The drain is this worker's: under `thread_per_core` each worker runs
    /// its own server, and stops it on the same signal.
    pub async fn run_until<U: BufRingSpec + 'static, H: Handler, S: Future<Output = ()>>(
        self,
        handler: H,
        stop: S,
    ) -> std::io::Result<()> {
        let limits = self.settings.limits;
        limits.validate()?;
        let acceptor = MultiAccept::bind(self.settings.bind)?;
        let shutdown = Rc::new(Shutdown::default());
        let stop = pin!(stop);
        let served = match self.settings.transport {
            ServerTransport::Plain => {
                serve_plain::<U, false, H, S>(acceptor, limits, handler, &shutdown, stop).await
            }
            ServerTransport::PlainZeroCopy => {
                serve_plain::<U, true, H, S>(acceptor, limits, handler, &shutdown, stop).await
            }
            // A server asked for TLS must not come up at all without kTLS,
            // rather than refuse every connection or serve them in the clear.
            #[cfg(feature = "tls")]
            ServerTransport::Tls(config) => {
                if !slopio_tls::ktls_available() {
                    return Err(std::io::Error::other(
                        "this kernel has no kTLS: `modprobe tls`, or build without the tls feature",
                    ));
                }
                serve_tls::<U, H, S>(acceptor, config, limits, handler, &shutdown, stop).await
            }
        };
        // The listener is gone by now, so nothing new can join.
        shutdown.begin(limits.drain_timeout);
        // Each connection holds its own deadline; this only stops a server
        // being held past it by one that never turns its loop.
        let _ = timeout(limits.drain_timeout + DRAIN_GRACE, shutdown.emptied()).await;
        served
    }
}

/// `None` once `stop` has completed or the runtime is stopping.
async fn next_socket<S: Future<Output = ()>>(
    acceptor: &mut MultiAccept,
    stop: Pin<&mut S>,
) -> std::io::Result<Option<SocketWrapper>> {
    match select(accept(acceptor), stop).await {
        SelectResult::First(accepted) => accepted,
        SelectResult::Second(()) => Ok(None),
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

/// Takes the listener, so that it closes on the way out.
async fn serve_plain<U: BufRingSpec + 'static, const ZC: bool, H: Handler, S: Future<Output = ()>>(
    mut acceptor: MultiAccept,
    limits: Limits,
    handler: H,
    shutdown: &Rc<Shutdown>,
    mut stop: Pin<&mut S>,
) -> std::io::Result<()>
where
    PlainMessages<U, ZC>: Transport,
{
    while let Some(socket) = next_socket(&mut acceptor, stop.as_mut()).await? {
        let peer = socket.peer_addr().ok();
        let transport = PlainMessages::<U, ZC>::new(socket);
        let connection = Connection::new(transport, peer, limits, handler.clone());
        spawn(connection.in_shutdown(shutdown.join()).run());
    }
    Ok(())
}

/// The handshake runs inside the spawned task, not the accept loop: there,
/// a single slow peer would stall every waiting connection.
///
/// A handshake joins the shutdown from its accept, so a stopping server
/// waits for it too; its connection learns of the drain on its first turn.
#[cfg(feature = "tls")]
async fn serve_tls<U: BufRingSpec + 'static, H: Handler, S: Future<Output = ()>>(
    mut acceptor: MultiAccept,
    config: slopio_tls::Config,
    limits: Limits,
    handler: H,
    shutdown: &Rc<Shutdown>,
    mut stop: Pin<&mut S>,
) -> std::io::Result<()> {
    while let Some(socket) = next_socket(&mut acceptor, stop.as_mut()).await? {
        // Before the handshake, which takes the socket.
        let peer = socket.peer_addr().ok();
        let config = config.clone();
        let handler = handler.clone();
        let registration = shutdown.join();
        spawn(async move {
            let deadline = limits.tls_handshake_timeout;
            let ktls = match slopio_tls::handshake(socket, config, deadline).await {
                Ok(ktls) => ktls,
                Err(_) => return,
            };
            let transport = KtlsTransport::<U, _>::new(ktls.into_messages::<U>());
            // §3.3: `h2` or nothing, including a peer that offered no ALPN.
            if transport.alpn() != Some(ALPN_H2) {
                return;
            }
            Connection::new(transport, peer, limits, handler)
                .in_shutdown(registration)
                .run()
                .await;
        });
    }
    Ok(())
}
