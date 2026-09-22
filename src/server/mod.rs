use runtime::net::{BufRingSpec, MultiAccept};
use runtime::spawn;
use runtime_streams::StreamExt;

use crate::server::connection::Connection;
#[cfg(feature = "tls")]
use crate::shared::transport::{ALPN_H2, KtlsTransport};
use crate::shared::transport::{PlainMessages, Transport};

pub(crate) mod connection;
mod stream;

pub use stream::Stream;

/// What answers a request.
///
/// One handler serves the whole server, cloned per connection and again per
/// stream, which is why `Clone` is in the bound: a handler is a *factory* for
/// the work of one exchange, not the work itself. For most of them the clone
/// is a no-op — a function pointer, or a closure over an `Rc`.
///
/// Taken by value rather than by reference because the future it returns is
/// spawned, and a future borrowing the handler could not outlive the call that
/// made it. The blanket impl below means a closure is a handler, so this trait
/// is rarely named:
///
/// ```ignore
/// Server::new(settings).run::<Ring, _>(|stream: Stream| async move {
///     stream.write_headers(StatusCode::OK, &HeaderMap::new());
///     stream.write_data_final(b"hello\n").await;
/// }).await
/// ```
///
/// Returning without answering is not a protocol error the peer can see
/// coming, so the stream writes a `500` on the way out rather than leaving it
/// waiting.
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

/// The transport every accepted connection runs over.
///
/// Cleartext HTTP/2 with **prior knowledge** only (§3.4): the client sends
/// the connection preface as its first bytes. There is no HTTP/1.1
/// `Upgrade: h2c` and there will not be one — RFC 9113 dropped it, and the
/// clients that matter (curl `--http2-prior-knowledge`, h2load, tonic,
/// grpc-go insecure) never used it.
///
/// `PlainZeroCopy` transmits straight from the send buffers instead of
/// copying them into socket memory. A build-time choice: the two spawn
/// distinct monomorphized connection loops.
///
/// `Tls` is the same connection loop over a socket the kernel encrypts, and
/// carries the configuration rather than sitting beside it: the transport and
/// the certificates it needs are one decision, and a `Plain` server holding a
/// `Config` nothing reads is a state worth not being able to spell.
pub enum ServerTransport {
    Plain,
    PlainZeroCopy,
    #[cfg(feature = "tls")]
    Tls(popple_tls::Config),
}

/// How long a peer has to complete the TLS handshake.
///
/// [`PARTIAL_TIMEOUT`]'s shape one layer down, and the same hazard: a peer
/// that connects and then sends nothing costs itself one `accept` and holds a
/// task, a socket and a handshake buffer here until something says otherwise.
/// Nothing above has started yet, so none of the connection deadlines apply.
///
/// Ten seconds is generous for what it covers — two round trips and a
/// signature — and it is the same number [`PARTIAL_TIMEOUT`] uses for the
/// same reason: nothing legitimate starts a handshake and then waits.
///
/// [`PARTIAL_TIMEOUT`]: crate::server::connection::PARTIAL_TIMEOUT
#[cfg(feature = "tls")]
pub const TLS_HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

impl Server {
    pub fn new(settings: ServerSettings) -> Self {
        Self { settings }
    }

    /// `U` is the buffer ring accepted sockets receive into: one per worker
    /// thread, shared by every connection on it.
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
            // Asked once, here, rather than per connection: a kernel without
            // the `tls` ULP will not grow one while we are running, and a
            // server that was asked for TLS must not come up at all rather
            // than come up refusing every connection — or, worse, serving
            // them in the clear.
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
        Ok(())
    }
}

/// Accept loop. `ZC` picks the send op and is baked into the spawned
/// connection's type, so the two variants share this source and nothing
/// else.
async fn serve_plain<U: BufRingSpec + 'static, const ZC: bool, H: Handler>(
    acceptor: &mut MultiAccept,
    handler: H,
) where
    PlainMessages<U, ZC>: Transport,
{
    while let Some(socket) = acceptor.next().await {
        // One clone per connection, and the connection clones again per
        // stream: the handler is shared by every exchange the server ever
        // serves.
        spawn(Connection::new(PlainMessages::<U, ZC>::new(socket), handler.clone()).run());
    }
}

/// Accept loop for TLS. The same connection loop underneath — only what the
/// bytes travel through differs.
///
/// The handshake runs inside the spawned task, not here. It is two round
/// trips and a signature, and doing it in the accept loop would put every
/// waiting connection behind the slowest one — which is a denial of service
/// a single slow peer could mount by hand.
///
/// Both refusals are silent, and deliberately so. A handshake that failed has
/// nothing to say it in: there is no session to carry an alert rustls did not
/// already send. A peer that completed one without agreeing on `h2` gets its
/// connection closed rather than an HTTP/2 GOAWAY it would have no way to
/// read as one.
#[cfg(feature = "tls")]
async fn serve_tls<U: BufRingSpec + 'static, H: Handler>(
    acceptor: &mut MultiAccept,
    config: popple_tls::Config,
    handler: H,
) {
    while let Some(socket) = acceptor.next().await {
        let config = config.clone();
        let handler = handler.clone();
        spawn(async move {
            let ktls = match popple_tls::handshake(socket, config, TLS_HANDSHAKE_TIMEOUT).await {
                Ok(ktls) => ktls,
                Err(_) => return,
            };
            let transport = KtlsTransport::<U, _>::new(ktls.into_messages::<U>());
            // §3.3: `h2` or nothing. rustls has already refused a peer that
            // offered protocols we share none of; this catches the one that
            // offered no ALPN at all, which cannot have meant HTTP/2.
            if transport.alpn() != Some(ALPN_H2) {
                return;
            }
            Connection::new(transport, handler).run().await;
        });
    }
}
