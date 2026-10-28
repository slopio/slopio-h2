//! h2c is prior knowledge only (§3.4); there is deliberately no HTTP/1.1
//! `Upgrade: h2c` path.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use http::uri::Scheme;
use runtime::io_driver::operations::sockets::multi_recv::{CompletionError, Continuation};
use runtime::io_driver::operations::sockets::recv::{ClassicRecv, socket_recv};
use runtime::io_driver::operations::sockets::send_vectored::send_vectored_all;
use runtime::io_driver::operations::sockets::send_vectored_zc::send_vectored_all_zc;
use runtime::net::{BorrowedBuffer, BufRingSpec, IoBuf, MultiRecv, SocketWrapper};
use runtime_streams::Stream;

/// What a transport is, as a type: [`PlainText`] or [`Tls`]. Sealed, since the
/// scheme a connection claims must be the one it runs.
pub trait Security: sealed::Sealed + 'static {
    fn scheme() -> Scheme;
}

/// `http`.
pub enum PlainText {}

/// `https`.
pub enum Tls {}

impl Security for PlainText {
    fn scheme() -> Scheme {
        Scheme::HTTP
    }
}

impl Security for Tls {
    fn scheme() -> Scheme {
        Scheme::HTTPS
    }
}

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::PlainText {}
    impl Sealed for super::Tls {}
}

/// Chunk boundaries carry no meaning — the frame decoder reassembles across
/// them.
pub trait Transport: Stream<Item = Result<Self::Buf, RecvError>> + Unpin {
    type Buf: AsRef<[u8]>;
    type Security: Security;

    /// The `Vec` is handed back for io_uring cancel-safety.
    ///
    /// `may_hold`: the caller can afford a send that frees these buffers only
    /// at the kernel's notification rather than at the send completion.
    fn send<B: IoBuf>(
        &mut self,
        bufs: Vec<B>,
        may_hold: bool,
    ) -> impl Future<Output = (io::Result<()>, Vec<B>)>;

    /// Ends our side of the stream: FIN, after close_notify over TLS.
    /// Receiving goes on, for the caller to read out what the peer still
    /// sends before the socket closes. Best-effort: runs when the connection
    /// is already over, so callers ignore failures.
    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>>;
}

/// Provisional — to be calibrated against h2load.
const ZC_MIN_BATCH: usize = 64 * 1024;

fn batch_bytes<B: IoBuf>(batch: &[B]) -> usize {
    batch.iter().map(|b| b.bytes_init()).sum()
}

/// The recv owns the whole socket; sends borrow it through
/// [`MultiRecv::socket`], and the loop never reads and writes at the same
/// instant.
pub struct PlainMessages<R: BufRingSpec, const ZC: bool = false> {
    recv: MultiRecv<R>,
    /// A recv into a buffer of our own, while the ring has none to lend.
    own: Option<ClassicRecv<Vec<u8>>>,
    /// The last one filled its buffer: more is likely waiting in the socket,
    /// to be read the same way rather than through a multishot re-armed into
    /// a ring that may still be empty.
    own_again: bool,
}

/// What a plain connection reads: a buffer of the ring every connection on
/// the worker shares or, while that ring is empty, one of its own.
pub enum Chunk<R: BufRingSpec> {
    Ring(BorrowedBuffer<R>),
    Own(Vec<u8>),
}

impl<R: BufRingSpec> AsRef<[u8]> for Chunk<R> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Chunk::Ring(buf) => buf.as_ref(),
            Chunk::Own(buf) => buf,
        }
    }
}

/// How much a recv of a connection's own takes: a ring buffer's worth, since
/// a connection that keeps them coming back full reads this way for as long
/// as its peer sends. One at a time per connection, freed once decoded, so
/// it adds at most this per connection to what the ring bounds; the
/// allocator hands the same block back, warm, where the ring rotates
/// through cold ones.
const OWN_RECV: usize = 64 * 1024;

/// Chunks a connection may have received and not yet decoded before its recv
/// pauses. Each holds a buffer of the ring every connection on the worker
/// shares, however few bytes it carries, and a loop stalled in a send decodes
/// nothing: at the runtime's default of 32, a few such connections empty the
/// ring for everyone until `FLUSH_TIMEOUT` cuts them. Paused, the peer's
/// bytes wait in the socket, for TCP to push back with.
const RECV_QUEUE_LIMIT: usize = 4;

impl<R: BufRingSpec, const ZC: bool> PlainMessages<R, ZC> {
    pub fn new(socket: SocketWrapper) -> Self {
        Self {
            recv: MultiRecv::with_queue_limit(socket, RECV_QUEUE_LIMIT),
            own: None,
            own_again: false,
        }
    }

    fn read_own(&mut self) {
        let buf = Vec::with_capacity(OWN_RECV);
        self.own = Some(socket_recv(self.recv.socket(), buf));
    }
}

impl<R: BufRingSpec, const ZC: bool> Unpin for PlainMessages<R, ZC> {}

impl<R: BufRingSpec, const ZC: bool> Stream for PlainMessages<R, ZC> {
    type Item = Result<Chunk<R>, RecvError>;

    /// An empty ring does not stop the connection: waiting for a buffer to
    /// come back, it lost each one to the recvs still armed on other
    /// connections, for seconds at a time, until the body sweep reset its
    /// streams. It reads into a buffer of its own instead, and goes on so
    /// while those come back full, which also keeps a peer holding the
    /// ring's buffers from slowing anyone else. One that comes back short
    /// drained the socket: the multishot is re-armed for what comes next.
    /// It is over until then, so nothing else reads the socket meanwhile,
    /// and the bytes keep their order.
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        loop {
            if let Some(recv) = this.own.as_mut() {
                let (result, buf) = ready!(Pin::new(recv).poll(cx));
                this.own = None;
                return Poll::Ready(match result {
                    Ok(0) => None,
                    Ok(n) => {
                        this.own_again = n == OWN_RECV;
                        Some(Ok(Chunk::Own(buf)))
                    }
                    Err(e) => Some(Err(RecvError::Fatal(e))),
                });
            }
            if this.own_again {
                this.read_own();
                continue;
            }
            match Pin::new(&mut this.recv).poll_next(cx) {
                Poll::Ready(Some(Err(e)))
                    if matches!(e.continuation(), Continuation::ContinueLater) =>
                {
                    this.read_own();
                }
                // What `MultiRecv` hands up is not all fatal — hence `RecvError`.
                polled => {
                    return polled
                        .map(|item| item.map(|r| r.map(Chunk::Ring).map_err(RecvError::from)));
                }
            }
        }
    }
}

/// Two impls rather than a branch on `ZC`: a branch would size the copy
/// send's future for the zero-copy one.
impl<R: BufRingSpec> Transport for PlainMessages<R, false> {
    type Buf = Chunk<R>;
    type Security = PlainText;

    fn send<B: IoBuf>(
        &mut self,
        bufs: Vec<B>,
        _may_hold: bool,
    ) -> impl Future<Output = (io::Result<()>, Vec<B>)> {
        send_vectored_all(self.recv.socket(), bufs)
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        std::future::ready(self.recv.socket().shutdown_write())
    }
}

impl<R: BufRingSpec> Transport for PlainMessages<R, true> {
    type Buf = Chunk<R>;
    type Security = PlainText;

    async fn send<B: IoBuf>(&mut self, bufs: Vec<B>, may_hold: bool) -> (io::Result<()>, Vec<B>) {
        match may_hold && batch_bytes(&bufs) >= ZC_MIN_BATCH {
            true => send_vectored_all_zc(self.recv.socket(), bufs).await,
            false => send_vectored_all(self.recv.socket(), bufs).await,
        }
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        std::future::ready(self.recv.socket().shutdown_write())
    }
}

/// §3.3: ALPN is mandatory over TLS. rustls cannot fail a peer that offered
/// no ALPN at all, so both ends must check what was negotiated.
#[cfg(feature = "tls")]
pub const ALPN_H2: &[u8] = b"h2";

#[cfg(feature = "tls")]
pub struct KtlsTransport<R: BufRingSpec, S> {
    stream: slopio_tls::KtlsMessages<R, S>,
}

#[cfg(feature = "tls")]
impl<R: BufRingSpec, S> KtlsTransport<R, S> {
    pub fn new(stream: slopio_tls::KtlsMessages<R, S>) -> Self {
        Self { stream }
    }

    /// §3.3: must be `h2`.
    pub fn alpn(&self) -> Option<&'static [u8]> {
        self.stream.alpn()
    }
}

#[cfg(feature = "tls")]
impl<R: BufRingSpec, S> Unpin for KtlsTransport<R, S> {}

#[cfg(feature = "tls")]
impl<R: BufRingSpec, S> Stream for KtlsTransport<R, S> {
    type Item = Result<slopio_tls::Frame<R>, RecvError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().stream)
            .poll_next(cx)
            .map(|item| item.map(|result| result.map_err(RecvError::from_tls)))
    }
}

#[cfg(feature = "tls")]
impl<R: BufRingSpec, S> Transport for KtlsTransport<R, S> {
    type Buf = slopio_tls::Frame<R>;
    type Security = Tls;

    /// `may_hold` is ignored: kTLS zero-copy only takes the runtime's
    /// registered buffers.
    fn send<B: IoBuf>(
        &mut self,
        bufs: Vec<B>,
        _may_hold: bool,
    ) -> impl Future<Output = (io::Result<()>, Vec<B>)> {
        self.stream.send_vectored(bufs)
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        self.stream.close()
    }
}

/// Must not be flattened into one `io::Error`: that made a dry buffer ring
/// look like a dead socket.
pub enum RecvError {
    Fatal(io::Error),
    /// Armable once a resource someone else holds comes back (the buffer ring
    /// refilling). The caller has to come back rather than spin.
    Later,
}

#[cfg(feature = "tls")]
impl RecvError {
    /// `WouldBlock` is an empty buffer ring: io_uring picks a buffer before it
    /// touches the socket, so the record is still queued. Everything else ends
    /// the connection.
    fn from_tls(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::WouldBlock => Self::Later,
            _ => Self::Fatal(e),
        }
    }
}

impl From<CompletionError> for RecvError {
    fn from(e: CompletionError) -> Self {
        match e.continuation() {
            // `MultiRecv` never hands `Continue` up; if that changes,
            // retryable is still right.
            Continuation::Continue | Continuation::ContinueLater => Self::Later,
            Continuation::NotContinue => Self::Fatal(completion_to_io(e)),
        }
    }
}

fn completion_to_io(e: CompletionError) -> io::Error {
    match e {
        CompletionError::ConnectionReset => io::ErrorKind::ConnectionReset.into(),
        CompletionError::BrokenPipe => io::ErrorKind::BrokenPipe.into(),
        CompletionError::Cancelled => io::ErrorKind::Interrupted.into(),
        CompletionError::Eof { .. } => io::ErrorKind::UnexpectedEof.into(),
        CompletionError::Other(code) => io::Error::from_raw_os_error(-code),
    }
}
