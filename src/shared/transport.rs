//! The byte transport under an HTTP/2 connection: plain TCP for now (h2c,
//! prior knowledge only — §3.4; there is deliberately no HTTP/1.1
//! `Upgrade: h2c` path). A kTLS transport slots in as one more impl.
//!
//! The connection loop is generic over [`Transport`], so each transport
//! monomorphizes its own copy of the loop: no `dyn`, no vtable.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use runtime::io_driver::operations::sockets::multi_recv::{CompletionError, Continuation};
use runtime::io_driver::operations::sockets::send_vectored::send_vectored_all;
use runtime::io_driver::operations::sockets::send_vectored_zc::send_vectored_all_zc;
use runtime::net::{BorrowedBuffer, BufRingSpec, IoBuf, MultiRecv, SocketWrapper};
use runtime_streams::Stream;

/// A framed inbound stream plus a gather-write, which is all the connection
/// loop needs from the layer below it.
///
/// Inbound: a [`Stream`] of byte chunks (one multishot-recv buffer, or one
/// kernel-decrypted TLS record). Chunk boundaries carry no meaning — the
/// frame decoder reassembles across them. `None` is a clean peer close; `Err`
/// is a transport failure (RST, AEAD failure, ...).
pub trait Transport: Stream<Item = Result<Self::Buf, RecvError>> + Unpin {
    /// One inbound chunk. `AsRef<[u8]>` is the only thing the decoder needs.
    type Buf: AsRef<[u8]>;

    /// Gather-write every chunk in `bufs`, looping over short writes. The
    /// `Vec` is handed back for io_uring cancel-safety.
    ///
    /// `may_hold` says the caller can afford a send that frees these buffers
    /// only at the kernel's notification — roughly a round trip after the data
    /// left — rather than at the send completion. That is a fact about where
    /// the connection is in its life, which only the caller knows; whether a
    /// send of that kind exists here, and whether this batch is big enough to
    /// be worth one, is the transport's business and stays behind this call.
    fn send<B: IoBuf>(
        &mut self,
        bufs: Vec<B>,
        may_hold: bool,
    ) -> impl Future<Output = (io::Result<()>, Vec<B>)>;

    /// Ends our side of the transport, after the last frame has gone.
    ///
    /// Nothing for plain TCP: §6.8's GOAWAY is the goodbye, and the FIN that
    /// follows the socket being dropped says the rest. TLS has a goodbye of
    /// its own — `close_notify` — and a peer that never gets one cannot tell
    /// a finished stream from a truncated one without trusting the layer
    /// above to have framed it. HTTP/2 does frame it, so this is manners
    /// rather than safety; it is still what a peer's TLS stack is waiting
    /// for.
    ///
    /// Best-effort by construction: it runs when the connection is already
    /// over, so a failure here changes nothing and the callers ignore it.
    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        std::future::ready(Ok(()))
    }
}

/// Batch size at or above which zero-copy pays, on a transport that has it.
/// Provisional — to be calibrated against h2load, not reasoned about: below
/// it the page pinning and the second CQE cost more than the copy they save.
const ZC_MIN_BATCH: usize = 64 * 1024;

fn batch_bytes<B: IoBuf>(batch: &[B]) -> usize {
    batch.iter().map(|b| b.bytes_init()).sum()
}

/// Plain-TCP transport for cleartext HTTP/2 (h2c, prior knowledge).
///
/// A multishot recv armed on the socket for inbound chunks, and vectored
/// sends on the same fd for output. The recv owns the whole socket (no split
/// needed — sends borrow it through [`MultiRecv::socket`] and the loop never
/// reads and writes at the same instant).
///
/// `ZC` selects the send op at compile time: `false` copies into socket
/// memory, `true` transmits from the send buffers and holds them until the
/// kernel's notification. A deployment choice, not a per-connection one —
/// monomorphized, so a build that does not want zero-copy has no trace of it.
pub struct PlainMessages<R: BufRingSpec, const ZC: bool = false> {
    recv: MultiRecv<R>,
}

impl<R: BufRingSpec, const ZC: bool> PlainMessages<R, ZC> {
    /// Arm a multishot recv on an already-connected `socket`.
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
        // `MultiRecv` folds EOF into `None` and retries the failures that a
        // re-arm alone fixes. What reaches us is the rest, and it is not all
        // fatal — hence `RecvError` rather than a bare `io::Error`.
        Pin::new(&mut self.get_mut().recv)
            .poll_next(cx)
            .map(|item| item.map(|r| r.map_err(RecvError::from)))
    }
}

/// Two impls rather than a branch on `ZC`: a future's layout is fixed before
/// `ZC` is known, so a branch would size the copy send for the zero-copy one.
impl<R: BufRingSpec> Transport for PlainMessages<R, false> {
    type Buf = BorrowedBuffer<R>;

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

    /// `may_hold` is the caller's answer to whether a send may keep its
    /// buffers until the kernel's notification.
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

/// §3.3: the protocol identifier HTTP/2 over TLS is negotiated under, and the
/// only one either end here will accept.
///
/// RFC 9113 makes ALPN not optional over TLS: a client "MUST" offer `h2`, and
/// a connection that settled on anything else — or on nothing, because the
/// peer offered no ALPN at all — is not one to speak HTTP/2 on. rustls fails
/// the handshake itself when both sides offered protocols and none matched;
/// what it cannot fail is a peer that never asked, which is why both ends
/// check what was negotiated rather than assuming.
#[cfg(feature = "tls")]
pub const ALPN_H2: &[u8] = b"h2";

/// The kTLS transport: HTTP/2 over a connection the kernel encrypts.
///
/// A newtype over [`KtlsMessages`] rather than an impl on it directly,
/// because [`Transport`] asks for a [`Stream`] of `Result<_, RecvError>` and
/// that stream yields `io::Result` — the mapping between the two error models
/// is the whole of what this adds.
///
/// It is generic over the rustls connection-data type, so one impl serves
/// both ends: the accept side and the dial side differ in what they handed
/// `into_messages`, and in nothing after that. Records arrive decrypted by
/// the kernel through the same buffer ring a plain connection reads into, so
/// the frame decoder above cannot tell the difference and does not have to.
#[cfg(feature = "tls")]
pub struct KtlsTransport<R: BufRingSpec, S> {
    stream: popple_tls::KtlsMessages<R, S>,
}

#[cfg(feature = "tls")]
impl<R: BufRingSpec, S> KtlsTransport<R, S> {
    pub fn new(stream: popple_tls::KtlsMessages<R, S>) -> Self {
        Self { stream }
    }

    /// §3.3: what ALPN settled on, which for us must be `h2`.
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

    /// `may_hold` has nowhere to go here. The zero-copy send this crate can
    /// reach on a plain socket takes any `IoBuf`; kTLS offers one only for
    /// the runtime's registered buffers, which is not what the output chain
    /// hands us. The kernel coalesces the vector into as few records as it
    /// can either way, which is the saving that mattered.
    fn send<B: IoBuf>(
        &mut self,
        bufs: Vec<B>,
        _may_hold: bool,
    ) -> impl Future<Output = (io::Result<()>, Vec<B>)> {
        self.stream.send_vectored(bufs)
    }

    /// §6.8's GOAWAY has gone; this is TLS saying the same thing in its own
    /// words, and then the FIN.
    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        self.stream.close()
    }
}

/// Why a chunk did not arrive, split by whether the connection is over.
///
/// The distinction is the runtime's — it classifies every completion as
/// re-armable now, re-armable later, or finished — and flattening it into one
/// `io::Error` is what used to make a dry buffer ring look like a dead socket.
pub enum RecvError {
    /// Nothing more will come: the peer is gone, or the op cannot be re-armed.
    Fatal(io::Error),
    /// The op is still armable, but only once a resource someone else holds
    /// comes back. In practice: the buffer ring was empty, and it refills when
    /// another connection on this worker recycles. Nothing a poll of *this*
    /// stream does brings that about, so the caller has to come back rather
    /// than spin — and coming back is all it takes.
    Later,
}

#[cfg(feature = "tls")]
impl RecvError {
    /// What a kTLS stream's `io::Error` means to a loop that wants to know
    /// whether to come back.
    ///
    /// One kind is not a failure: `WouldBlock` is the buffer ring having been
    /// empty when a record landed. Nothing was consumed — io_uring picks a
    /// buffer before it goes near the socket — so the record is still queued
    /// and the next poll re-arms the recv. Everything else ends the
    /// connection: a reset, an AEAD failure, a peer that violated the record
    /// protocol.
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
            // `MultiRecv` handles this one itself and never hands it up; if
            // that changes, treating it as retryable is still right.
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
