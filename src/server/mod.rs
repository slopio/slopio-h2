use runtime::net::{BufRingSpec, MultiAccept};
use runtime::spawn;
use runtime_streams::StreamExt;

use crate::server::connection::Connection;
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
pub enum ServerTransport {
    Plain,
    PlainZeroCopy,
}

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
