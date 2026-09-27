//! h2c is prior knowledge only (§3.4); there is deliberately no HTTP/1.1
//! `Upgrade: h2c` path.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use http::uri::Scheme;
use runtime::io_driver::operations::sockets::multi_recv::{CompletionError, Continuation};
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

    /// Best-effort: runs when the connection is already over, so callers
    /// ignore failures.
    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        std::future::ready(Ok(()))
    }
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
}

impl<R: BufRingSpec, const ZC: bool> PlainMessages<R, ZC> {
    pub fn new(socket: SocketWrapper) -> Self {
        Self {
            recv: MultiRecv::new(socket),
        }
    }
}

impl<R: BufRingSpec, const ZC: bool> Unpin for PlainMessages<R, ZC> {}

impl<R: BufRingSpec, const ZC: bool> Stream for PlainMessages<R, ZC> {
    type Item = Result<BorrowedBuffer<R>, RecvError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // What `MultiRecv` hands up is not all fatal — hence `RecvError`.
        Pin::new(&mut self.get_mut().recv)
            .poll_next(cx)
            .map(|item| item.map(|r| r.map_err(RecvError::from)))
    }
}

/// Two impls rather than a branch on `ZC`: a branch would size the copy
/// send's future for the zero-copy one.
impl<R: BufRingSpec> Transport for PlainMessages<R, false> {
    type Buf = BorrowedBuffer<R>;
    type Security = PlainText;

    fn send<B: IoBuf>(
        &mut self,
        bufs: Vec<B>,
        _may_hold: bool,
    ) -> impl Future<Output = (io::Result<()>, Vec<B>)> {
        send_vectored_all(self.recv.socket(), bufs)
    }
}

impl<R: BufRingSpec> Transport for PlainMessages<R, true> {
    type Buf = BorrowedBuffer<R>;
    type Security = PlainText;

    fn send<B: IoBuf>(
        &mut self,
        bufs: Vec<B>,
        may_hold: bool,
    ) -> impl Future<Output = (io::Result<()>, Vec<B>)> {
        async move {
            match may_hold && batch_bytes(&bufs) >= ZC_MIN_BATCH {
                true => send_vectored_all_zc(self.recv.socket(), bufs).await,
                false => send_vectored_all(self.recv.socket(), bufs).await,
            }
        }
    }
}

/// §3.3: ALPN is mandatory over TLS. rustls cannot fail a peer that offered
/// no ALPN at all, so both ends must check what was negotiated.
#[cfg(feature = "tls")]
pub const ALPN_H2: &[u8] = b"h2";

#[cfg(feature = "tls")]
pub struct KtlsTransport<R: BufRingSpec, S> {
    stream: popple_tls::KtlsMessages<R, S>,
}

#[cfg(feature = "tls")]
impl<R: BufRingSpec, S> KtlsTransport<R, S> {
    pub fn new(stream: popple_tls::KtlsMessages<R, S>) -> Self {
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
    type Item = Result<popple_tls::Frame<R>, RecvError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.get_mut().stream)
            .poll_next(cx)
            .map(|item| item.map(|result| result.map_err(RecvError::from_tls)))
    }
}

#[cfg(feature = "tls")]
impl<R: BufRingSpec, S> Transport for KtlsTransport<R, S> {
    type Buf = popple_tls::Frame<R>;
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
