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
