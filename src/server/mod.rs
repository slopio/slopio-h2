use runtime::net::{BufRingSpec, MultiAccept};
use runtime::spawn;
use runtime_streams::StreamExt;

use crate::server::connection::Connection;
use crate::shared::transport::{PlainMessages, Transport};

mod connection;
mod stream;

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
    pub async fn run<U: BufRingSpec + 'static>(self) -> std::io::Result<()> {
        let mut acceptor = MultiAccept::new(self.settings.bind_port)?;
        match self.settings.transport {
            ServerTransport::Plain => serve_plain::<U, false>(&mut acceptor).await,
            ServerTransport::PlainZeroCopy => serve_plain::<U, true>(&mut acceptor).await,
        }
        Ok(())
    }
}

/// Accept loop. `ZC` picks the send op and is baked into the spawned
/// connection's type, so the two variants share this source and nothing
/// else.
async fn serve_plain<U: BufRingSpec + 'static, const ZC: bool>(acceptor: &mut MultiAccept)
where
    PlainMessages<U, ZC>: Transport,
{
    while let Some(socket) = acceptor.next().await {
        spawn(Connection::new(PlainMessages::<U, ZC>::new(socket)).run());
    }
}
