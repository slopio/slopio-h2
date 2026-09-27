//! The client: connections by origin, a new one opened only when every
//! connection held for that origin is at the peer's `max_concurrent_streams`
//! (§5.1.2).
//!
//! One transport per client, in its type: a [`PlainTextClient`] serves `http`
//! origins only, a [`TlsClient`] `https` only.
//!
//! Nothing is queued: past its connections for an origin a request is refused
//! with [`Unavailable::AtLimit`].

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Poll, Waker};

use http::uri::{Scheme, Uri};
use popple_dns::protocol::Name;
use popple_dns::{DnsClient, IpVersion, ResolveError};
use runtime::net::BufRingSpec;

use crate::client::{Connection, PlainText, Security, Stream, Tls, Unavailable, connect};

/// How many connections a client opens to one origin unless told otherwise.
pub const MAX_CONNECTIONS_PER_ORIGIN: usize = 4;

/// Over TCP in cleartext: serves `http` origins.
pub type PlainTextClient = Client<PlainText>;

/// Over TLS: serves `https` origins.
pub type TlsClient = Client<Tls>;

#[derive(Debug)]
pub enum ClientError {
    /// The URI names no origin a connection could be opened to, or one whose
    /// scheme is not this client's transport.
    InvalidUri(&'static str),
    Unavailable(Unavailable),
    /// No connection could be opened: the name did not resolve, the peer
    /// refused, a handshake failed or timed out.
    Connect(io::Error),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUri(reason) => f.write_str(reason),
            Self::Unavailable(e) => e.fmt(f),
            Self::Connect(e) => write!(f, "no new connection could be opened: {e}"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<Unavailable> for ClientError {
    fn from(e: Unavailable) -> Self {
        Self::Unavailable(e)
    }
}

/// Scheme, host and port: what two requests must share to share a connection.
/// The port is always explicit, so `http://a` is `http://a:80`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Origin {
    scheme: Scheme,
    /// Lowercased: hosts are case-insensitive (RFC 3986 §3.2.2).
    host: String,
    port: u16,
}

impl Origin {
    pub fn of(uri: &Uri) -> Result<Self, &'static str> {
        let scheme = uri.scheme().ok_or("the URI has no scheme")?;
        let authority = uri.authority().ok_or("the URI has no authority")?;
        let default_port = if *scheme == Scheme::HTTP {
            80
        } else if *scheme == Scheme::HTTPS {
            443
        } else {
            return Err("only http and https URIs name an origin");
        };
        Ok(Self {
            scheme: scheme.clone(),
            host: authority.host().to_ascii_lowercase(),
            port: authority.port_u16().unwrap_or(default_port),
        })
    }

    pub fn scheme(&self) -> &Scheme {
        &self.scheme
    }

    /// Brackets kept for IPv6, as in the URI.
    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// The host without an IPv6 literal's brackets: what DNS and a TLS
    /// server name take.
    fn bare_host(&self) -> &str {
        self.host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(&self.host)
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}:{}", self.scheme, self.host, self.port)
    }
}

type Connecting<S> = Pin<Box<dyn Future<Output = io::Result<Connection<S>>>>>;

/// Opens a connection to an origin at an address already resolved. Boxed, so
/// the ring and TLS configuration it was made with stay out of the type.
type Open<S> = Box<dyn Fn(&Origin, SocketAddr) -> Connecting<S>>;

/// Holds connections by origin, and opens them as requests need them.
///
/// ```ignore
/// let dns = DnsClient::<DnsRing>::new("127.0.0.53:53".parse()?)?;
/// let client = PlainTextClient::plaintext::<Ring>().with_dns(dns);
/// let request = http::Request::get("http://api.example.com/users").body(())?;
/// let stream = client.send_request(&request, true).await?;
/// ```
///
/// IP literals need no DNS client; names do. Not `Send`: a client belongs to
/// one thread. Share it between tasks through an `Rc`.
pub struct Client<S: Security> {
    open: Open<S>,
    dns: Option<Rc<dyn Resolve>>,
    /// Per origin.
    max_connections: usize,
    /// Applied to every connection, those opened later included.
    index_request_paths: Cell<Option<bool>>,
    /// Behind an `Rc` so no borrow of the map is held across an `await`.
    origins: RefCell<HashMap<Origin, Rc<Connections<S>>>>,
    closed: Cell<bool>,
}

impl Client<PlainText> {
    /// Over TCP in cleartext, receiving into `U`'s buffers, which must be
    /// installed on the runtime.
    pub fn plaintext<U: BufRingSpec + 'static>() -> Self {
        Self::with_opener(Box::new(|_, addr| Box::pin(connect::<U>(addr))))
    }
}

#[cfg(feature = "tls")]
impl Client<Tls> {
    /// Over TLS, receiving into `U`'s buffers. Each server's certificate is
    /// checked against its origin's host, by `config`'s verifier. §3.3: a
    /// server that does not agree to `h2` via ALPN is refused.
    pub fn tls<U: BufRingSpec + 'static>(config: popple_tls::ClientConfig) -> Self {
        Self::with_opener(Box::new(move |origin, addr| {
            let config = config.clone();
            let host = origin.bare_host().to_owned();
            Box::pin(async move {
                let name = popple_tls::ServerName::try_from(host)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
                crate::client::connect_tls::<U>(addr, name, config).await
            })
        }))
    }
}

impl<S: Security> Client<S> {
    fn with_opener(open: Open<S>) -> Self {
        Self {
            open,
            dns: None,
            max_connections: MAX_CONNECTIONS_PER_ORIGIN,
            index_request_paths: Cell::new(None),
            origins: RefCell::new(HashMap::new()),
            closed: Cell::new(false),
        }
    }

    /// Resolves hosts that are names. Takes an address from its A records,
    /// or from its AAAA records if it has none.
    pub fn with_dns<D: BufRingSpec + 'static>(self, dns: impl Into<Rc<DnsClient<D>>>) -> Self {
        let dns: Rc<DnsClient<D>> = dns.into();
        self.with_resolver(dns)
    }

    fn with_resolver(mut self, resolver: Rc<dyn Resolve>) -> Self {
        self.dns = Some(resolver);
        self
    }

    pub fn with_max_connections(mut self, per_origin: usize) -> Self {
        assert!(per_origin > 0, "a client must be allowed a connection");
        self.max_connections = per_origin;
        self
    }

    /// The URI must be absolute: its scheme and authority choose the
    /// connection. Awaits only when a connection must be opened, or is being
    /// opened.
    pub async fn send_request(
        &self,
        request: &http::Request<()>,
        end_stream: bool,
    ) -> Result<Stream, ClientError> {
        self.send(request, end_stream, false).await
    }

    /// A gRPC call: its response is gathered message by message, straight
    /// from what the connection receives.
    #[cfg(feature = "grpc")]
    pub(crate) async fn send_call(
        &self,
        request: &http::Request<()>,
        end_stream: bool,
    ) -> Result<Stream, ClientError> {
        self.send(request, end_stream, true).await
    }

    async fn send(
        &self,
        request: &http::Request<()>,
        end_stream: bool,
        grpc: bool,
    ) -> Result<Stream, ClientError> {
        let origin = self.origin_of(request.uri())?;
        let connections = self.connections_to(&origin);

        loop {
            if self.closed.get() {
                return Err(Unavailable::Closed.into());
            }
            if let Some(stream) = connections.on_a_held_connection(request, end_stream, grpc) {
                return Ok(stream);
            }
            if let Some(outcome) = connections.opened_elsewhere().await {
                outcome?;
                // What it opened may already be full, or it was dropped.
                continue;
            }

            let connection = self.open(&origin, &connections).await?;
            // Asked before any waiter runs, so the request that paid for the
            // connection is the first on it.
            let stream = connection.open(request, end_stream, grpc);
            connections.keep(connection, self.closed.get());
            return stream.map_err(ClientError::from);
        }
    }

    /// Has a connection to `uri`'s origin open, without sending anything, so
    /// the first request does not pay for the handshakes.
    pub async fn preconnect(&self, uri: &Uri) -> Result<(), ClientError> {
        let origin = self.origin_of(uri)?;
        let connections = self.connections_to(&origin);

        loop {
            if self.closed.get() {
                return Err(Unavailable::Closed.into());
            }
            if connections.live() > 0 {
                return Ok(());
            }
            if let Some(outcome) = connections.opened_elsewhere().await {
                outcome?;
                continue;
            }

            let connection = self.open(&origin, &connections).await?;
            connections.keep(connection, self.closed.get());
            return Ok(());
        }
    }

    /// Connections open to `origin` that still take requests.
    pub fn connections(&self, origin: &Origin) -> usize {
        self.origins
            .borrow()
            .get(origin)
            .map_or(0, |connections| connections.live())
    }

    /// Streams running on `origin`'s connections, closing ones included.
    pub fn live_streams(&self, origin: &Origin) -> usize {
        self.origins.borrow().get(origin).map_or(0, |connections| {
            connections
                .held
                .borrow()
                .iter()
                .map(Connection::live_streams)
                .sum()
        })
    }

    /// Whether HPACK indexes `:path`, on every connection: worth it when the
    /// same paths come back, as a gRPC client's do.
    pub fn index_request_paths(&self, repeated: bool) {
        self.index_request_paths.set(Some(repeated));
        for connections in self.origins.borrow().values() {
            for connection in connections.held.borrow().iter() {
                connection.index_request_paths(repeated);
            }
        }
    }

    /// Graceful (§6.8): nothing in flight is cancelled, and nothing new is
    /// opened.
    pub fn close(&self) {
        self.closed.set(true);
        for connections in self.origins.borrow().values() {
            for connection in connections.held.borrow().iter() {
                connection.close();
            }
        }
    }

    /// Waits for every connection held to end; does not close them. Without
    /// [`Client::close`] first, this waits for the peers to go. The first
    /// connection to end badly says why.
    pub async fn closed(&self) -> io::Result<()> {
        // Taken out first: no borrow of the map may be held across an await.
        let ends: Vec<_> = self
            .origins
            .borrow()
            .values()
            .flat_map(|connections| {
                let held = connections.held.borrow();
                held.iter().map(Connection::closed).collect::<Vec<_>>()
            })
            .collect();

        let mut first_failure = Ok(());
        for end in ends {
            if let Err(e) = end.await
                && first_failure.is_ok()
            {
                first_failure = Err(e);
            }
        }
        first_failure
    }

    fn origin_of(&self, uri: &Uri) -> Result<Origin, ClientError> {
        let origin = Origin::of(uri).map_err(ClientError::InvalidUri)?;
        if *origin.scheme() != S::scheme() {
            return Err(ClientError::InvalidUri(if S::scheme() == Scheme::HTTPS {
                "a TLS client serves only https URIs"
            } else {
                "a cleartext client serves only http URIs"
            }));
        }
        Ok(origin)
    }

    fn connections_to(&self, origin: &Origin) -> Rc<Connections<S>> {
        Rc::clone(self.origins.borrow_mut().entry(origin.clone()).or_default())
    }

    async fn open(
        &self,
        origin: &Origin,
        connections: &Connections<S>,
    ) -> Result<Connection<S>, ClientError> {
        if connections.held.borrow().len() >= self.max_connections {
            return Err(Unavailable::AtLimit.into());
        }
        let connection = connections
            .open(async {
                let addr = self.address(origin).await?;
                (self.open)(origin, addr).await
            })
            .await
            .map_err(ClientError::Connect)?;
        if let Some(repeated) = self.index_request_paths.get() {
            connection.index_request_paths(repeated);
        }
        Ok(connection)
    }

    async fn address(&self, origin: &Origin) -> io::Result<SocketAddr> {
        let host = origin.bare_host();
        let ip = match host.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => match &self.dns {
                Some(dns) => dns.resolve(host).await?,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("{host} is a name, and this client has no DNS client"),
                    ));
                }
            },
        };
        Ok(SocketAddr::new(ip, origin.port()))
    }
}

/// A host name to an address. A trait so that tests can answer without a
/// server.
trait Resolve {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + 'a>>;
}

impl<D: BufRingSpec> Resolve for DnsClient<D> {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
    ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + 'a>> {
        Box::pin(async move {
            let name: Name = host
                .parse()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{host}: {e}")))?;
            let found = match DnsClient::resolve(self, name.clone(), IpVersion::V4).await {
                Err(ResolveError::NoAddress) => DnsClient::resolve(self, name, IpVersion::V6).await,
                found => found,
            };
            found.map_err(|e| {
                let kind = match e {
                    ResolveError::NotFound | ResolveError::NoAddress => io::ErrorKind::NotFound,
                    _ => io::ErrorKind::Other,
                };
                io::Error::new(kind, format!("{host}: {e}"))
            })
        })
    }
}

/// One origin's.
struct Connections<S: Security> {
    /// Oldest first, and filled in that order, so the newer ones are the
    /// ones left idle once a burst has passed.
    held: RefCell<Vec<Connection<S>>>,
    /// At most one connection is opened at a time: a burst that finds every
    /// connection full waits for it rather than opening one each.
    opening: RefCell<Option<Rc<Opening>>>,
}

/// By hand: a derive would ask `S: Default` of a marker that has no value.
impl<S: Security> Default for Connections<S> {
    fn default() -> Self {
        Self {
            held: RefCell::new(Vec::new()),
            opening: RefCell::new(None),
        }
    }
}

impl<S: Security> Connections<S> {
    /// Connections that can take no more are let go here; their streams keep
    /// them running until they end.
    fn on_a_held_connection(
        &self,
        request: &http::Request<()>,
        end_stream: bool,
        grpc: bool,
    ) -> Option<Stream> {
        let mut held = self.held.borrow_mut();
        held.retain(|connection| !connection.is_closed());
        held.iter()
            .find_map(|connection| connection.open(request, end_stream, grpc).ok())
    }

    fn live(&self) -> usize {
        self.held
            .borrow()
            .iter()
            .filter(|connection| !connection.is_closed())
            .count()
    }

    /// `None` if no connection is being opened; else, once it is, whether
    /// it failed.
    async fn opened_elsewhere(&self) -> Option<Result<(), ClientError>> {
        let opening = self.opening.borrow().clone()?;
        Some(match opening.finished().await {
            Outcome::Failed(kind, reason) => {
                Err(ClientError::Connect(io::Error::new(kind, reason)))
            }
            Outcome::Opened | Outcome::Abandoned => Ok(()),
        })
    }

    /// Closed while it was opening: it keeps what it carries and takes
    /// nothing more.
    fn keep(&self, connection: Connection<S>, closed: bool) {
        if closed {
            connection.close();
        }
        self.held.borrow_mut().push(connection);
    }

    async fn open(
        &self,
        connect: impl Future<Output = io::Result<Connection<S>>>,
    ) -> io::Result<Connection<S>> {
        let opening = Rc::new(Opening::default());
        *self.opening.borrow_mut() = Some(Rc::clone(&opening));
        // Also on drop: a caller that gives up must not leave its waiters
        // waiting for ever.
        let mut done = Done {
            slot: &self.opening,
            opening,
            outcome: Some(Outcome::Abandoned),
        };

        let result = connect.await;
        done.outcome = Some(match &result {
            Ok(_) => Outcome::Opened,
            Err(e) => Outcome::Failed(e.kind(), e.to_string()),
        });
        drop(done);
        result
    }
}

#[derive(Clone)]
enum Outcome {
    Opened,
    /// `io::Error` is not `Clone`, so each waiter gets its own.
    Failed(io::ErrorKind, String),
    Abandoned,
}

#[derive(Default)]
struct Opening {
    outcome: RefCell<Option<Outcome>>,
    waiters: RefCell<Vec<Waker>>,
}

impl Opening {
    fn finished(&self) -> impl Future<Output = Outcome> + '_ {
        std::future::poll_fn(|cx| {
            if let Some(outcome) = self.outcome.borrow().clone() {
                return Poll::Ready(outcome);
            }
            let mut waiters = self.waiters.borrow_mut();
            if !waiters.iter().any(|w| w.will_wake(cx.waker())) {
                waiters.push(cx.waker().clone());
            }
            Poll::Pending
        })
    }
}

struct Done<'a> {
    slot: &'a RefCell<Option<Rc<Opening>>>,
    opening: Rc<Opening>,
    outcome: Option<Outcome>,
}

impl Drop for Done<'_> {
    fn drop(&mut self) {
        *self.slot.borrow_mut() = None;
        *self.opening.outcome.borrow_mut() = self.outcome.take();
        for waker in self.opening.waiters.take() {
            waker.wake();
        }
    }
}

/// A client holding `connection` for `uri`'s origin, and opening no other:
/// lets tests put a scripted connection behind the client's API.
#[cfg(test)]
pub(crate) fn holding<S: Security>(connection: Connection<S>, uri: &str) -> Client<S> {
    let client = Client::with_opener(Box::new(|_, _| {
        Box::pin(async { Err(io::Error::other("this client opens no connection")) })
    }));
    let origin = Origin::of(&uri.parse().expect("a URI")).expect("an origin");
    client.connections_to(&origin).keep(connection, false);
    client
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use runtime_core::deterministic_testing::FakeRing;
    use runtime_core::runtime::RuntimeInner;
    use runtime_core::runtime::time::timeout;

    use super::*;
    use crate::client::CONNECTION_RECV_WINDOW;
    use crate::client::shared::ClientShared;
    use crate::shared::connection::settings::Settings;

    runtime_core::define_buf_ring!(PoolRing, bgid = 1, buffer_size = 4096, ring_size = 4);

    /// A connection whose handshake is done and whose loop never runs: its
    /// requests are written to a buffer no one flushes, which is all a client
    /// looks at.
    fn connection<S: Security>(max_concurrent_streams: u32) -> Connection<S> {
        let shared = ClientShared::new(CONNECTION_RECV_WINDOW, S::scheme());
        shared.set_peer_settings(Settings {
            max_concurrent_streams: Some(max_concurrent_streams),
            ..Settings::default()
        });
        Connection::new(Rc::new(shared), None)
    }

    /// Every name is 127.0.0.1, at once.
    struct AnyHost;

    impl Resolve for AnyHost {
        fn resolve<'a>(
            &'a self,
            _: &'a str,
        ) -> Pin<Box<dyn Future<Output = io::Result<IpAddr>> + 'a>> {
            Box::pin(async { Ok(IpAddr::V4(Ipv4Addr::LOCALHOST)) })
        }
    }

    async fn sleep(for_: Duration) {
        let _ = timeout(for_, std::future::pending::<()>()).await;
    }

    fn run<R: 'static>(app: impl Future<Output = R> + 'static) -> R {
        let (fake, _) = FakeRing::builder().virtual_time().build();
        RuntimeInner::simulated(fake).block_on::<PoolRing, _>(
            // Spawned from inside: `spawn` needs the runtime already running.
            async move { runtime_core::runtime::spawn(app).await },
            None,
            |run| run(),
        )
    }

    type Opened = Rc<RefCell<Vec<Origin>>>;

    /// Records the origin of each connection opened; each takes a
    /// millisecond, so requests made meanwhile find it still opening.
    fn counting_as<S: Security>(
        max_connections: usize,
        max_concurrent_streams: u32,
    ) -> (Opened, Client<S>) {
        let opened = Rc::new(RefCell::new(Vec::new()));
        let log = Rc::clone(&opened);
        let client = Client::with_opener(Box::new(move |origin: &Origin, _| {
            log.borrow_mut().push(origin.clone());
            Box::pin(async move {
                sleep(Duration::from_millis(1)).await;
                Ok(connection::<S>(max_concurrent_streams))
            })
        }))
        .with_resolver(Rc::new(AnyHost))
        .with_max_connections(max_connections);
        (opened, client)
    }

    fn counting(max_connections: usize, max_concurrent_streams: u32) -> (Opened, PlainTextClient) {
        counting_as::<PlainText>(max_connections, max_concurrent_streams)
    }

    fn request_to(uri: &str) -> http::Request<()> {
        http::Request::get(uri).body(()).unwrap()
    }

    fn request() -> http::Request<()> {
        request_to("http://example.test/")
    }

    fn origin(uri: &str) -> Origin {
        Origin::of(&uri.parse().unwrap()).unwrap()
    }

    #[test]
    fn an_origin_is_its_scheme_host_and_port() {
        assert_eq!(
            origin("http://Example.TEST/a"),
            origin("http://example.test:80/b")
        );
        assert_eq!(
            origin("https://example.test/"),
            origin("https://example.test:443/")
        );
        assert_ne!(
            origin("http://example.test/"),
            origin("https://example.test/")
        );
        assert_ne!(
            origin("http://example.test/"),
            origin("http://example.test:8080/")
        );
        assert_eq!(origin("https://[::1]/").to_string(), "https://[::1]:443");
        assert_eq!(origin("https://[::1]/").bare_host(), "::1");
    }

    #[test]
    fn a_uri_without_an_origin_is_refused() {
        let (opened, client) = counting(4, 8);
        run(async move {
            for uri in ["/path", "ftp://example.test/"] {
                let refused = client.send_request(&request_to(uri), true).await.err();
                assert!(
                    matches!(refused, Some(ClientError::InvalidUri(_))),
                    "{uri}: {refused:?}"
                );
            }
        });

        assert!(opened.borrow().is_empty(), "nothing opened");
    }

    #[test]
    fn a_client_serves_only_its_transports_scheme() {
        let (plain_opened, plain) = counting(4, 8);
        let (tls_opened, tls) = counting_as::<Tls>(4, 8);
        run(async move {
            let refused = plain
                .send_request(&request_to("https://example.test/"), true)
                .await
                .err();
            assert!(
                matches!(refused, Some(ClientError::InvalidUri(_))),
                "cleartext for https: {refused:?}"
            );
            let refused = tls
                .send_request(&request_to("http://example.test/"), true)
                .await
                .err();
            assert!(
                matches!(refused, Some(ClientError::InvalidUri(_))),
                "TLS for http: {refused:?}"
            );

            let _ = plain
                .send_request(&request_to("http://example.test/"), true)
                .await
                .expect("an http stream");
            let _ = tls
                .send_request(&request_to("https://example.test/"), true)
                .await
                .expect("an https stream");
        });

        assert_eq!(*plain_opened.borrow(), vec![origin("http://example.test/")]);
        assert_eq!(*tls_opened.borrow(), vec![origin("https://example.test/")]);
    }

    #[test]
    fn a_name_needs_a_dns_client_and_an_address_does_not() {
        let addresses = Rc::new(RefCell::new(Vec::new()));
        let log = Rc::clone(&addresses);
        let client = Client::<PlainText>::with_opener(Box::new(move |_, addr| {
            log.borrow_mut().push(addr);
            Box::pin(async { Ok(connection(8)) })
        }));

        let (literal, name) = run(async move {
            let literal = client
                .send_request(&request_to("http://[::1]:8080/"), true)
                .await
                .is_ok();
            let name = match client.send_request(&request(), true).await {
                Err(ClientError::Connect(e)) => Some(e.kind()),
                _ => None,
            };
            (literal, name)
        });

        assert!(literal);
        assert_eq!(*addresses.borrow(), vec!["[::1]:8080".parse().unwrap()]);
        assert_eq!(name, Some(io::ErrorKind::NotFound));
    }

    #[test]
    fn requests_to_one_origin_share_its_connection() {
        let (opened, client) = counting(4, 8);
        run(async move {
            let _first = client
                .send_request(&request_to("http://example.test/a"), true)
                .await
                .expect("a stream");
            let _second = client
                .send_request(&request_to("http://EXAMPLE.test:80/b"), true)
                .await
                .expect("a stream");
        });

        assert_eq!(*opened.borrow(), vec![origin("http://example.test/")]);
    }

    #[test]
    fn each_origin_has_its_own_connections() {
        let (opened, client) = counting(4, 8);
        run(async move {
            let mut streams = Vec::new();
            for uri in ["http://a.test/", "http://a.test:8080/", "http://b.test/"] {
                streams.push(
                    client
                        .send_request(&request_to(uri), true)
                        .await
                        .expect(uri),
                );
            }
            for uri in ["http://a.test/", "http://b.test/"] {
                assert_eq!(client.connections(&origin(uri)), 1, "{uri}");
                assert_eq!(client.live_streams(&origin(uri)), 1, "{uri}");
            }
        });

        assert_eq!(
            *opened.borrow(),
            vec![
                origin("http://a.test/"),
                origin("http://a.test:8080/"),
                origin("http://b.test/"),
            ]
        );
    }

    #[test]
    fn one_origin_at_its_limit_does_not_hold_up_another() {
        let (opened, client) = counting(1, 1);
        let other = run(async move {
            let _first = client
                .send_request(&request_to("http://a.test/"), true)
                .await
                .expect("a stream");
            let full = client
                .send_request(&request_to("http://a.test/"), true)
                .await;
            assert!(matches!(
                full,
                Err(ClientError::Unavailable(Unavailable::AtLimit))
            ));
            client
                .send_request(&request_to("http://b.test/"), true)
                .await
                .is_ok()
        });

        assert!(other);
        assert_eq!(opened.borrow().len(), 2);
    }

    #[test]
    fn a_connection_with_room_is_reused() {
        let (opened, client) = counting(4, 2);
        let connections = run(async move {
            let _first = client
                .send_request(&request(), true)
                .await
                .expect("a stream");
            let _second = client
                .send_request(&request(), true)
                .await
                .expect("a stream");
            client.connections(&origin("http://example.test/"))
        });

        assert_eq!(connections, 1);
        assert_eq!(opened.borrow().len(), 1);
    }

    #[test]
    fn a_full_connection_leads_to_another() {
        let (opened, client) = counting(4, 1);
        let (ids, connections) = run(async move {
            // Held: dropping one would free its slot.
            let first = client
                .send_request(&request(), true)
                .await
                .expect("a stream");
            let second = client
                .send_request(&request(), true)
                .await
                .expect("a stream");
            (
                (u32::from(first.id()), u32::from(second.id())),
                client.connections(&origin("http://example.test/")),
            )
        });

        assert_eq!(connections, 2);
        assert_eq!(opened.borrow().len(), 2);
        assert_eq!(ids, (1, 1), "each the first stream of its own connection");
    }

    #[test]
    fn a_freed_slot_is_taken_before_a_new_connection() {
        let (opened, client) = counting(4, 1);
        run(async move {
            let first = client
                .send_request(&request(), true)
                .await
                .expect("a stream");
            drop(first);
            let _second = client
                .send_request(&request(), true)
                .await
                .expect("a stream");
        });

        assert_eq!(opened.borrow().len(), 1);
    }

    #[test]
    fn past_the_last_connection_a_request_is_refused() {
        let (opened, client) = counting(1, 1);
        let refused = run(async move {
            let _first = client
                .send_request(&request(), true)
                .await
                .expect("a stream");
            client.send_request(&request(), true).await.err()
        });

        assert!(
            matches!(
                refused,
                Some(ClientError::Unavailable(Unavailable::AtLimit))
            ),
            "refused as full: {refused:?}"
        );
        assert_eq!(opened.borrow().len(), 1, "without trying to open another");
    }

    #[test]
    fn a_burst_opens_one_connection_not_one_each() {
        let (opened, client) = counting(4, 8);
        let served = run(async move {
            let client = Rc::new(client);
            let tasks: Vec<_> = (0..5)
                .map(|_| {
                    let client = Rc::clone(&client);
                    runtime_core::runtime::spawn(async move {
                        // Kept alive past the burst, so no slot frees early.
                        let stream = client.send_request(&request(), true).await;
                        sleep(Duration::from_millis(5)).await;
                        stream.is_ok()
                    })
                })
                .collect();
            let mut served = 0;
            for task in tasks {
                served += task.await as usize;
            }
            served
        });

        assert_eq!(served, 5);
        assert_eq!(opened.borrow().len(), 1);
    }

    #[test]
    fn a_failed_opening_fails_those_waiting_on_it() {
        let attempts = Rc::new(Cell::new(0));
        let count = Rc::clone(&attempts);
        let client = Client::<PlainText>::with_opener(Box::new(move |_, _| {
            count.set(count.get() + 1);
            Box::pin(async {
                sleep(Duration::from_millis(1)).await;
                Err(io::Error::new(io::ErrorKind::ConnectionRefused, "refused"))
            })
        }))
        .with_resolver(Rc::new(AnyHost));

        let kinds = run(async move {
            let client = Rc::new(client);
            let tasks: Vec<_> = (0..3)
                .map(|_| {
                    let client = Rc::clone(&client);
                    runtime_core::runtime::spawn(async move {
                        match client.send_request(&request(), true).await {
                            Err(ClientError::Connect(e)) => Some(e.kind()),
                            _ => None,
                        }
                    })
                })
                .collect();
            let mut kinds = Vec::new();
            for task in tasks {
                kinds.push(task.await);
            }
            kinds
        });

        assert_eq!(kinds, vec![Some(io::ErrorKind::ConnectionRefused); 3]);
        assert_eq!(attempts.get(), 1, "one attempt, shared");
    }

    #[test]
    fn a_connection_that_takes_no_more_is_replaced() {
        let (opened, client) = counting(4, 8);
        let connections = run(async move {
            let key = origin("http://example.test/");
            let _first = client
                .send_request(&request(), true)
                .await
                .expect("a stream");
            // As a GOAWAY would leave it.
            client.origins.borrow()[&key].held.borrow()[0]
                .shared
                .stop_opening();
            assert_eq!(client.connections(&key), 0, "it no longer counts");
            let _second = client
                .send_request(&request(), true)
                .await
                .expect("a stream");
            client.connections(&key)
        });

        assert_eq!(opened.borrow().len(), 2);
        assert_eq!(connections, 1);
    }

    #[test]
    fn preconnecting_opens_a_connection_and_sends_nothing() {
        let (opened, client) = counting(4, 8);
        let (live_streams, connections) = run(async move {
            let uri = "http://example.test/".parse().unwrap();
            client.preconnect(&uri).await.expect("a connection");
            client.preconnect(&uri).await.expect("the same one");
            let key = origin("http://example.test/");
            (client.live_streams(&key), client.connections(&key))
        });

        assert_eq!(opened.borrow().len(), 1);
        assert_eq!((live_streams, connections), (0, 1));
    }

    #[test]
    fn a_closed_client_opens_nothing() {
        let (opened, client) = counting(4, 8);
        let refused = run(async move {
            client.close();
            client.send_request(&request(), true).await.err()
        });

        assert!(matches!(
            refused,
            Some(ClientError::Unavailable(Unavailable::Closed))
        ));
        assert!(opened.borrow().is_empty());
    }
}
