//! What answers a stream, and the one task it gets.
//!
//! The task is spawned by the handler rather than by the connection, so that
//! whatever routes a request, by protocol or by path, can spawn exactly the
//! function that answers it: a task holds the future it runs, and one spawned
//! around every route at once would be as large as the largest of them, for
//! every request.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::task::{Context, Poll};

use runtime::Handle;
use runtime::spawn;

#[cfg(feature = "grpc")]
use crate::grpc::GrpcFormat;
use crate::server::Stream;

/// Called on the connection's task as each stream opens, to spawn the task
/// that answers it; see [`Incoming`].
///
/// A handler that panics fails its own stream, with a `500` or a reset, and
/// nothing else, whether it panics here or in its task. Not under
/// `panic = "abort"`, where there is no unwinding to stop.
///
/// Any `async fn(Stream)`, or closure returning a future, is one.
pub trait Handler: Clone + 'static {
    fn start(&self, incoming: Incoming) -> StreamTask;
}

impl<F, Fut> Handler for F
where
    F: FnOnce(Stream) -> Fut + Clone + 'static,
    Fut: Future<Output = ()> + 'static,
{
    fn start(&self, incoming: Incoming) -> StreamTask {
        incoming.spawn(self.clone())
    }
}

/// A request whose stream is not yet the connection's: its head can be read,
/// to choose what answers it, and the stream itself goes only to the task
/// [`Incoming::spawn`] starts. Dropped any earlier, it would end the stream
/// before the connection had taken it in.
pub struct Incoming {
    stream: Stream,
}

impl Incoming {
    pub(crate) fn new(stream: Stream) -> Self {
        Self { stream }
    }

    pub fn method(&self) -> Option<&http::Method> {
        self.stream.method()
    }

    /// The query included.
    pub fn path(&self) -> Option<&str> {
        self.stream.path()
    }

    pub fn fields(&self) -> &http::HeaderMap {
        self.stream.fields()
    }

    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.peer_addr()
    }

    #[cfg(feature = "grpc")]
    pub fn grpc_format(&self) -> Option<GrpcFormat> {
        self.stream.grpc_format()
    }

    /// `answer` runs on the task's first poll, so the stream is the
    /// connection's before anything touches it. The task is as large as
    /// `answer`'s future and no larger.
    pub fn spawn<F, Fut>(self, answer: F) -> StreamTask
    where
        F: FnOnce(Stream) -> Fut + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        let stream = self.stream;
        StreamTask(spawn(ContainPanic(async move { answer(stream).await })))
    }
}

/// The task answering a stream. Only [`Incoming::spawn`] makes one, so every
/// stream's task contains its handler's panics.
pub struct StreamTask(Handle<()>);

impl StreamTask {
    pub(crate) fn into_handle(self) -> Handle<()> {
        self.0
    }
}

/// `None` if the handler panicked choosing: the `Incoming` it held was
/// dropped as the panic unwound, which answered the stream.
pub(crate) fn start<H: Handler>(handler: &H, incoming: Incoming) -> Option<StreamTask> {
    catch_unwind(AssertUnwindSafe(|| handler.start(incoming))).ok()
}

/// A panicking handler fails its stream, not the process: unwinding out of a
/// task takes down the worker, and the runtime aborts on that. The handler is
/// then dropped here, and its `StreamToken` answers for the stream as for any
/// handler that returned early: a `500`, or `INTERNAL_ERROR` once the
/// response has started.
///
/// Asserted unwind-safe because the panic is the application's, raised
/// between our calls: nothing on the connection is left half-written, since
/// no frame is encoded across a call into application code.
struct ContainPanic<F>(F);

impl<F: Future<Output = ()>> Future for ContainPanic<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // SAFETY: the field is pinned structurally: never moved out of, and
        // `ContainPanic` has no `Drop` or `Unpin` of its own.
        let handler = unsafe { self.map_unchecked_mut(|this| &mut this.0) };
        catch_unwind(AssertUnwindSafe(|| handler.poll(cx))).unwrap_or(Poll::Ready(()))
    }
}
