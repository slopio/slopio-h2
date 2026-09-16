use http::{HeaderMap, StatusCode};
use runtime::io_driver::operations::{IoBuf, IoBufMut};

use crate::shared::codec::{frames::stream_id::StreamId, types::Setting};

/// Supplies the buffers a body is built in, so that what a handler writes is
/// already what the kernel will read.
///
/// The pool's depth is a source of backpressure that flow control does not
/// provide: a peer that credits generously but reads slowly is caught only
/// here. Buffers return themselves on drop, so there is nothing to release.
pub trait BufferProvider {
    type Buf: IoBuf + IoBufMut;

    /// Waits for a free buffer. With the whole pool in flight, the only sound
    /// answer is to stop producing.
    async fn acquire(&self) -> Self::Buf;

    /// Takes a buffer only if one is free right now, for callers that must
    /// degrade rather than wait — on a pool shared by every connection on the
    /// thread, parking makes one connection's stall everyone's stall.
    fn try_acquire(&self) -> Option<Self::Buf>;

    /// Bytes that can be written without `acquire` waiting: room left in a
    /// buffer already at hand, or in a slot free for the taking.
    ///
    /// Read before committing to a write rather than after — the DATA loop
    /// takes it as one more term of its `min(stream credit, connection
    /// credit, max_frame_size, …)`, and a caller that must not block reads it
    /// to know whether it can proceed at all.
    ///
    /// Must never over-report. Under-reporting costs an `acquire`;
    /// over-reporting stalls a caller that cannot afford to wait. Zero means
    /// there is no room without waiting for one to come back.
    fn writable(&self) -> usize;
}

/// Why a write will never reach the peer. Both resolve a task parked on
/// credit: a future waiting for a window that no one will ever credit again
/// is a leaked task.
pub enum WriteError {
    /// The stream was reset — by the peer, or by us on a violation.
    StreamReset,
    /// The connection is going away; nothing more goes out on it.
    ConnectionGone,
}

/// Frames the connection emits from its decode loop.
///
/// None are flow-controlled and none may wait, which is not a convenience:
/// WINDOW_UPDATE is what unblocks a peer and GOAWAY is what ends a connection,
/// so making them depend on a resource that can run out builds the deadlock
/// they exist to break. They are infallible for the same reason — there is no
/// sensible way to decline to send a GOAWAY.
pub trait ControlSink {
    fn settings(&self, settings: &[Setting]);
    fn settings_ack(&self);
    fn ping_ack(&self, opaque: [u8; 8]);
    fn window_update(&self, stream_id: StreamId, increment: u32);
    fn rst_stream(&self, stream_id: StreamId, error_code: u32);
    fn goaway(&self, last_stream_id: StreamId, error_code: u32, debug: &[u8]);
}

/// Frames a stream task emits.
pub trait StreamSink<P: BufferProvider> {
    /// Writes a whole response head, CONTINUATION frames included.
    ///
    /// Synchronous on purpose: §6.10 forbids interleaving a header block with
    /// anything else, on the whole connection. A call that cannot yield
    /// cannot let another task splice its frames into the middle of ours, so
    /// the atomicity comes for free.
    fn headers(
        &self,
        stream_id: StreamId,
        status: StatusCode,
        fields: &HeaderMap,
        end_stream: bool,
    ) -> Result<(), WriteError>;

    /// Hands out a buffer to build a body in, so that the bytes a handler
    /// writes are already the ones the kernel reads. How much it fills is
    /// read back off the buffer — a body never has to declare its length in
    /// advance, since any split between DATA frames is legal.
    async fn buffer(&self) -> P::Buf;

    /// The only frame that waits: it needs credit on the stream and on the
    /// connection, and splits itself over `max_frame_size`.
    ///
    /// Takes any owned buffer — one from `buffer`, a `Vec`, or a
    /// `&'static [u8]` for a canned body, which the runtime knows it need not
    /// keep alive through a cancellation. Returned either way, including on
    /// error: a pooled buffer that is not given back is one the pool loses.
    async fn data<B: IoBuf>(
        &self,
        stream_id: StreamId,
        payload: B,
        end_stream: bool,
    ) -> (Result<(), WriteError>, B);
}
