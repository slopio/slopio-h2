use std::cell::{Cell, RefCell};
use std::time::Duration;

use http::{HeaderMap, HeaderValue, StatusCode};

use super::frame::{GrpcFrame, MessageError};
use super::input::GrpcError;
use super::request::GrpcFormat;
use super::status::{Code, Status};
use super::timeout::{parse_timeout, sleep};
use crate::server::{Handler, Incoming, Stream, StreamTask};

/// The layer owns the stream and lends this to the handler, so the call can be
/// ended by something other than the handler returning — a deadline. Were the
/// handler to own the stream, its future being dropped would drop the stream
/// with it, and the token's destructor would write a `500` where a
/// `grpc-status` was owed.
pub struct GrpcCall {
    stream: Stream,
    format: GrpcFormat,
    timeout: Option<Duration>,
    /// Until the head has gone out, a failure can still be the whole response.
    headed: Cell<bool>,
    /// Taken as they go out, so neither is written twice.
    headers: RefCell<HeaderMap>,
    trailers: RefCell<HeaderMap>,
}

impl GrpcCall {
    pub fn path(&self) -> Option<&str> {
        self.stream.path()
    }

    pub fn fields(&self) -> &HeaderMap {
        self.stream.fields()
    }

    pub fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.peer_addr()
    }

    pub fn format(&self) -> GrpcFormat {
        self.format
    }

    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    pub async fn message<M: prost::Message + Default>(&self) -> Result<Option<M>, Status> {
        match self.stream.message().await {
            None => Ok(None),
            Some(Ok(frame)) => frame.decode().map(Some).map_err(Status::from),
            Some(Err(e)) => Err(Status::from(e)),
        }
    }

    pub async fn frame(&self) -> Option<Result<GrpcFrame, GrpcError>> {
        self.stream.message().await
    }

    /// Has to be called before the first [`write_message`](Self::write_message),
    /// the head going out with it. Later is a no-op.
    pub fn set_headers(&self, fields: &HeaderMap) {
        let mut headers = self.headers.borrow_mut();
        for (name, value) in fields {
            headers.append(name.clone(), value.clone());
        }
    }

    /// `grpc-status` and `grpc-message` are written from the [`Status`] the
    /// handler returns, after these, so the returned value is what it says it is.
    pub fn set_trailers(&self, fields: &HeaderMap) {
        let mut trailers = self.trailers.borrow_mut();
        for (name, value) in fields {
            trailers.append(name.clone(), value.clone());
        }
    }

    pub async fn write_message<M: prost::Message>(&self, message: &M) {
        self.head();
        self.stream.write_message(message).await;
    }

    /// Deferred to the first write so that a call failing before it produces
    /// anything can still be Trailers-Only.
    fn head(&self) {
        if self.headed.replace(true) {
            return;
        }
        let mut fields = self.headers.take();
        if !fields.contains_key("content-type") {
            fields.insert("content-type", HeaderValue::from_static("application/grpc"));
        }
        self.stream.write_headers(StatusCode::OK, &fields);
    }

    /// §9.1 puts the outcome in the trailers, so `:status` is 200 whatever
    /// happened.
    fn finish(self, status: Status) {
        // The handler's first, then the status: what it returned is what the
        // call ended as.
        let mut fields = self.trailers.take();
        for (name, value) in &status.fields() {
            fields.insert(name.clone(), value.clone());
        }
        if self.headed.get() {
            return self.stream.write_trailers(&fields);
        }
        // Trailers-Only: one frame for the whole response, so the head's
        // fields belong in it too.
        for (name, value) in &self.headers.take() {
            if !fields.contains_key(name) {
                fields.append(name.clone(), value.clone());
            }
        }
        if !fields.contains_key("content-type") {
            fields.insert("content-type", HeaderValue::from_static("application/grpc"));
        }
        self.stream.write_headers_final(StatusCode::OK, &fields);
    }
}

impl From<MessageError> for Status {
    fn from(e: MessageError) -> Self {
        match e {
            MessageError::Compressed(_) => {
                Status::unimplemented("compressed messages are not decompressed by this server")
            }
            MessageError::NotProto(_) => {
                Status::internal("only proto messages are decoded by this server")
            }
            MessageError::Decode(_) => Status::invalid_argument("the message could not be decoded"),
        }
    }
}

impl From<GrpcError> for Status {
    fn from(e: GrpcError) -> Self {
        match e {
            GrpcError::MessageTooLarge { .. } => {
                Status::resource_exhausted("a message past what this server will hold")
            }
            GrpcError::TooManyMessages => {
                Status::resource_exhausted("too many messages waiting to be read")
            }
            GrpcError::UnsupportedEncoding => Status::unimplemented(
                "grpc-encoding names a compression this server has no name for",
            ),
            GrpcError::CompressedWithoutEncoding => Status::internal(
                "a compressed message on a request that announced no grpc-encoding",
            ),
            GrpcError::InvalidCompressedFlag(_) => {
                Status::internal("a Compressed-Flag that is neither 0 nor 1")
            }
            GrpcError::Truncated => Status::internal("the request body ended inside a message"),
        }
    }
}

/// What answers a gRPC call: an `async fn(&GrpcCall) -> Status`, or a
/// [`GrpcRouter`](super::GrpcRouter) choosing one by method.
pub trait GrpcHandler: Clone + 'static {
    fn start(&self, incoming: Incoming, format: GrpcFormat) -> StreamTask;
}

impl<G> GrpcHandler for G
where
    G: AsyncFn(&GrpcCall) -> Status + Clone + 'static,
{
    fn start(&self, incoming: Incoming, format: GrpcFormat) -> StreamTask {
        let grpc = self.clone();
        incoming.spawn(move |stream| answer(grpc, stream, format))
    }
}

/// gRPC to `grpc`, the rest to `http`, chosen as the stream opens: each
/// side's task holds only what its protocol needs.
pub fn service<G: GrpcHandler, H: Handler>(grpc: G, http: H) -> impl Handler {
    Service { grpc, http }
}

#[derive(Clone)]
struct Service<G, H> {
    grpc: G,
    http: H,
}

impl<G: GrpcHandler, H: Handler> Handler for Service<G, H> {
    fn start(&self, incoming: Incoming) -> StreamTask {
        match incoming.grpc_format() {
            Some(format) => self.grpc.start(incoming, format),
            None => self.http.start(incoming),
        }
    }
}

/// One call, from its head to its status: the task a gRPC function runs in.
pub(super) async fn answer<G>(grpc: G, stream: Stream, format: GrpcFormat)
where
    G: AsyncFn(&GrpcCall) -> Status,
{
    let call = GrpcCall {
        timeout: parse_timeout(stream.fields()),
        stream,
        format,
        headed: Cell::new(false),
        headers: RefCell::new(HeaderMap::new()),
        trailers: RefCell::new(HeaderMap::new()),
    };

    // The deadline is the layer's to enforce and not the handler's.
    // Ours starts when the headers landed, so it is always a little
    // later than the client's — by the transit, the safe direction.
    let status = match call.timeout {
        None => grpc(&call).await,
        Some(timeout) => {
            match runtime::runtime::select::select(grpc(&call), sleep(timeout)).await {
                runtime::runtime::select::SelectResult::First(status) => status,
                runtime::runtime::select::SelectResult::Second(()) => {
                    Status::new(Code::DeadlineExceeded, "deadline exceeded")
                }
            }
        }
    };
    call.finish(status);
}
