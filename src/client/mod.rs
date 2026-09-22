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
//! Two things happen without being asked for, because a connection that is a
//! task is a connection nobody is watching. It keeps itself honest about the
//! peer: §6.7 PINGs go out once the peer has been silent for
//! [`ACTIVE_PING_TICKS`] with a request outstanding, or [`IDLE_PING_TICKS`]
//! without, and a probe that goes unanswered ends the connection and every
//! stream on it — the failure TCP alone takes minutes to report. And it
//! announces windows worth downloading through ([`STREAM_RECV_WINDOW`]), which
//! a client feels more than a server does.
//!
//! What it does not do is bound how long a request may take. That is the
//! application's to say, with [`Stream::with_deadline`].
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

/// The receive window every stream of ours starts with: what this client
/// announces as `SETTINGS_INITIAL_WINDOW_SIZE`, and so what a server may send
/// on one response before it needs credit back.
///
/// The one knob of inbound flow control, as the server's twin of it is. It sets
/// how much of a response arrives per round trip — a body below it arrives in
/// one — and, since credit goes back only for bytes the application has read,
/// how much one response can pile up against a caller that stops reading: this
/// much, at most, and once per stream it has open.
///
/// A client is the end that mostly downloads, so leaving this at §6.9.2's 65535
/// is the one setting a client feels immediately: every 64 KiB of every
/// response stalls until a WINDOW_UPDATE completes a round trip. A megabyte is
/// where hyper, Netty and grpc-go's tuning land too.
pub const STREAM_RECV_WINDOW: u32 = 1024 * 1024;

/// The connection receive window this client announces, once the handshake is
/// done.
///
/// As large as §6.9.1 allows, so that it never binds: backpressure is
/// [`STREAM_RECV_WINDOW`]'s job, and the connection window is only ever the
/// thing a stream waits on by mistake. Sized like the server's and for the same
/// reason, with one difference in what it rests on — a server bounds the
/// streams a stranger may open, where what a client has in flight unconsumed is
/// bounded by the requests the application itself chose to make.
pub const CONNECTION_RECV_WINDOW: u32 = i32::MAX as u32;

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

/// Ticks of silence with a stream open before a keepalive PING goes out.
///
/// HTTP/2 has no `Keep-Alive` header — §8.2.2 forbids it along with
/// `Connection` — and the RFC sets no idle timeout anywhere. §6.7's PING is the
/// whole mechanism: a frame the peer must echo, which proves the connection is
/// alive in both directions and, incidentally, resets whatever idle timer the
/// peer keeps.
///
/// Four ticks is twenty seconds, and the number is chosen against the strictest
/// timeout we know of, which is our own server's: it drops a peer that has a
/// stream open and has said nothing for `ACTIVE_TICKS` — thirty seconds. A
/// client waiting on a response *is* a silent peer, and a slow handler or a
/// server-streaming call is silence it cannot help. Probing at twenty leaves a
/// tick of slack for the granularity, since a deadline counted in ticks fires
/// up to one late.
///
/// The cost of being wrong in the other direction is a peer that thinks it is
/// being flooded: gRPC servers enforce a minimum interval between pings and
/// answer a client that beats it with GOAWAY ENHANCE_YOUR_CALM. That
/// enforcement is aimed at pings on connections with nothing in flight, which
/// is what [`IDLE_PING_TICKS`] is the conservative half of.
pub const ACTIVE_PING_TICKS: u32 = 4;

/// Ticks of silence with nothing in flight before a keepalive PING goes out.
///
/// Twelve ticks is a minute, against the two minutes our server lets an idle
/// peer sit there (`IDLE_TICKS`) — the same halving as
/// [`ACTIVE_PING_TICKS`], applied to the budget that is four times longer.
///
/// What this buys is a connection that survives being held for reuse: the
/// NAT and load-balancer tables that forget an idle flow do so in minutes, and
/// a connection nobody has noticed is dead fails the next request rather than
/// this one. What it costs is a frame a minute per connection the application
/// is not using, and the risk that a strict peer counts it as a flood. A client
/// that holds many idle connections to one gRPC server is the case to raise
/// this for.
pub const IDLE_PING_TICKS: u32 = 12;

/// Ticks a keepalive PING may go unanswered before the connection is given up
/// on.
///
/// Four ticks is twenty seconds, which is generous for a frame the peer's
/// protocol layer echoes without asking anything above it: §6.7 requires the
/// ACK as soon as the frame is read, so this outlasts a handful of
/// retransmissions and not much else. A peer that has not answered by then is
/// one whose socket is open and whose other end is gone — the failure TCP alone
/// takes minutes to report, and the whole reason to probe.
///
/// Only one probe is outstanding at a time, so this is the full budget and not
/// the first of several.
pub const PING_TIMEOUT_TICKS: u32 = 4;

/// A connection to one server: the handle requests are made on.
///
/// Dropping it does not close the connection while streams are still running
/// — the loop stays up until the last of them is done with. What ends the
/// connection is the last handle of any kind going away, and then the loop
/// says goodbye with a GOAWAY (§6.8) rather than vanishing. [`Client::close`]
/// is the same ending asked for out loud, which is what a caller that means to
/// wait for it wants.
pub struct Client {
    shared: Rc<ClientShared>,
    /// The task the loop runs in, owned rather than detached.
    ///
    /// Owning it is what makes the connection's end observable: a detached
    /// task answers nobody, so a connection that failed with no stream open
    /// failed in silence — `is_closed` turned true and the reason went
    /// nowhere. Dropping this handle detaches the task rather than killing it,
    /// which is what lets a client walk away from a connection its streams are
    /// still using.
    ///
    /// `None` for a client on a connection somebody else drives, which only
    /// the tests do.
    task: RefCell<Option<Handle<io::Result<()>>>>,
}

impl Client {
    pub(crate) fn new(shared: Rc<ClientShared>, task: Option<Handle<io::Result<()>>>) -> Self {
        Self {
            shared,
            task: RefCell::new(task),
        }
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
    /// has arrived, the loop has stopped, [`Client::close`] has been called,
    /// or §5.1.1's stream ids are spent.
    pub fn is_closed(&self) -> bool {
        self.shared.is_closing()
    }

    /// Stops this connection taking new requests, and lets the streams already
    /// on it finish.
    ///
    /// The graceful shutdown of §6.8, from this end: nothing in flight is
    /// cancelled, and the loop sends its GOAWAY and stops once the last stream
    /// is done. Returns at once — [`Client::closed`] is how to wait for it.
    ///
    /// Dropping every handle does the same thing. This is for the caller that
    /// wants to keep the handle and still say when it is finished.
    pub fn close(&self) {
        self.shared.stop_opening();
        // The loop is parked on the socket, and what just changed is not
        // something the socket will tell it.
        self.shared.core.wake_flusher();
    }

    /// Waits for the connection to end, and says why it did.
    ///
    /// `Ok` is a connection that was finished with — by this client, or by a
    /// peer that closed or said goodbye. `Err` is one that stopped for a
    /// reason, and it is the same reason the streams in flight were given.
    ///
    /// This waits; it does not close. A caller that holds this handle and
    /// awaits here is waiting for the *peer* to go, which is a thing to want
    /// on purpose and a hang to fall into by accident — [`Client::close`]
    /// first is what makes it the end of one's own connection.
    ///
    /// The end is handed over once, as a response head is. A second call
    /// answers the error that says so rather than waiting for something that
    /// has already happened.
    pub async fn closed(&self) -> io::Result<()> {
        let task = self.task.borrow_mut().take();
        match task {
            Some(task) => task.await,
            None => Err(io::Error::other(
                "this client does not own the connection loop",
            )),
        }
    }

    /// How many streams are open on this connection, against the peer's
    /// `max_concurrent_streams` (§5.1.2).
    pub fn live_streams(&self) -> usize {
        self.shared.streams.len()
    }

    /// Says that this connection will ask for the same handful of paths over
    /// and over, so that HPACK may keep them.
    ///
    /// A fact about the workload, which only the caller has: the encoder
    /// leaves `:path` out of its dynamic table by default because a browser's
    /// paths are nearly all distinct, and indexing those would evict the
    /// entries worth keeping. Where they *do* repeat, the second request to a
    /// path costs one byte instead of the string and its Huffman coding — on
    /// a 28-character gRPC method name, 23 bytes and most of the encode.
    ///
    /// Safe to call at any time and on any connection; it changes nothing the
    /// peer has to understand, only how much of it we send.
    pub fn index_request_paths(&self, repeated: bool) {
        self.shared.core.index_request_paths(repeated);
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
/// The loop runs in a task the returned [`Client`] owns: [`Client::closed`]
/// is its end, and dropping every handle — or [`Client::close`] — is what
/// brings that end about, since nothing else can tell it that no further
/// request is coming.
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

    Ok(connection.spawn())
}

/// Connects to `addr` over TLS, and leaves an HTTP/2 connection running on it.
///
/// [`connect`]'s three stages plus one: TCP, then the TLS handshake, then
/// HTTP/2's own, all inside [`CONNECT_TIMEOUT`] — which is why the deadline
/// is one bound over the whole establishment rather than one per stage. The
/// handshake takes its own deadline because it has to; the outer one is what
/// actually decides.
///
/// `server_name` is what the certificate is checked against, so it is the
/// host, not the address: the two differ whenever the address came from
/// somewhere other than the name.
///
/// §3.3 requires ALPN, and `config` is where `h2` is offered — build it with
/// `alpn_protocols: Some(&[b"h2"])`. A server that agrees to something else,
/// or to nothing, is refused here rather than spoken HTTP/2 at.
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

/// The two stages the deadline covers.
async fn establish<U: BufRingSpec + 'static>(
    addr: SocketAddr,
) -> io::Result<Connection<PlainMessages<U, false>>> {
    let socket = connect_tcp(addr).await?;
    Connection::handshake(PlainMessages::new(socket)).await
}
