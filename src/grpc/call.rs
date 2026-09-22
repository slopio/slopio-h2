use std::cell::{Cell, RefCell};
use std::time::Duration;

use http::{HeaderMap, HeaderValue, StatusCode};

use super::frame::{GrpcFrame, MessageError};
use super::input::GrpcError;
use super::request::GrpcFormat;
use super::status::{Code, Status};
use super::timeout::{parse_timeout, sleep};
use crate::server::{Handler, Stream};

/// One gRPC call, and the stream it runs on.
///
/// The layer owns the stream and lends this to the handler, which is what lets
/// the call be *ended* by something other than the handler returning — a
/// deadline, most of all. Were the handler to own the stream, its future being
/// dropped would drop the stream with it, and the token's destructor would
/// write a `500` where a `grpc-status` was owed.
///
/// It also means a handler cannot forget to answer: it returns a [`Status`],
/// and the head, the trailers and the choice between a trailer section and a
/// Trailers-Only response are all made here.
pub struct GrpcCall {
    stream: Stream,
    format: GrpcFormat,
    /// What `grpc-timeout` said, `None` for a call that may run as long as it
    /// likes.
    timeout: Option<Duration>,
    /// The head has gone out, so what is left is a trailer section. Until
    /// then a failure can still be the whole response.
    headed: Cell<bool>,
    /// What the handler wants sent with the head, and with the trailers.
    /// Taken as they go out, so neither is written twice.
    headers: RefCell<HeaderMap>,
    trailers: RefCell<HeaderMap>,
}

impl GrpcCall {
    /// The request's path, `/package.Service/Method`. Routing on it is the
    /// caller's — the shape of that differs by protocol, so this layer stays
    /// out of it.
    pub fn path(&self) -> Option<&str> {
        self.stream.path()
    }

    /// The request's ordinary fields, which is where gRPC's metadata lives:
    /// `authorization`, `user-agent`, anything the client sent. Names ending
    /// `-bin` carry base64 and are not decoded here.
    pub fn fields(&self) -> &HeaderMap {
        self.stream.fields()
    }

    /// What the request's `content-type` said its messages are serialised as.
    pub fn format(&self) -> GrpcFormat {
        self.format
    }

    /// What `grpc-timeout` gave the call, `None` if it sent none. Read by a
    /// handler that would rather give up gracefully than be cut off — and
    /// passed on, decremented, to whatever it calls in turn.
    pub fn timeout(&self) -> Option<Duration> {
        self.timeout
    }

    /// The next message, decoded.
    ///
    /// `Ok(None)` is the peer's half-close with nothing left to take: for a
    /// unary call that is one message short, for a streaming one it is the
    /// end. Every way a body can stop being gRPC comes back as the `Status`
    /// it deserves, so a handler answers them with `?`.
    pub async fn message<M: prost::Message + Default>(&self) -> Result<Option<M>, Status> {
        match self.stream.message().await {
            None => Ok(None),
            Some(Ok(frame)) => frame.decode().map(Some).map_err(Status::from),
            Some(Err(e)) => Err(Status::from(e)),
        }
    }

    /// The next message, as the frame it arrived in — for a handler that
    /// wants the bytes, a format this end does not decode, or the
    /// compressed form.
    pub async fn frame(&self) -> Option<Result<GrpcFrame, GrpcError>> {
        self.stream.message().await
    }

    /// Fields to send with the response head — gRPC's initial metadata.
    ///
    /// Nothing is filtered. `content-type` is this layer's only default and a
    /// handler that sets its own wins, which is what a service answering
    /// `application/grpc+json` needs; the same goes for every other name,
    /// reserved or not. What a response carries is the handler's to decide.
    ///
    /// Has to be called before the first [`write_message`](Self::write_message),
    /// the head going out with it. Later is a no-op.
    ///
    /// One caveat, said rather than enforced: `grpc-status` here, on a
    /// response that then sends a body, puts a status in the head *and* in the
    /// trailers. Clients read the head's when the response is Trailers-Only,
    /// so the two disagree and which one wins is the client's business.
    pub fn set_headers(&self, fields: &HeaderMap) {
        let mut headers = self.headers.borrow_mut();
        for (name, value) in fields {
            headers.append(name.clone(), value.clone());
        }
    }

    /// Fields to send with the trailers — gRPC's trailing metadata, which is
    /// what a handler has to say once it knows how the call went.
    ///
    /// Unfiltered, as [`set_headers`](Self::set_headers) is, with one
    /// exception that is not a filter: `grpc-status` and `grpc-message` are
    /// written from the [`Status`] the handler returns, after these, so that
    /// the returned value is what it says it is.
    pub fn set_trailers(&self, fields: &HeaderMap) {
        let mut trailers = self.trailers.borrow_mut();
        for (name, value) in fields {
            trailers.append(name.clone(), value.clone());
        }
    }

    /// Writes one message, sending the response head first if it has not gone
    /// yet. A streaming response is this, called as often as it likes.
    pub async fn write_message<M: prost::Message>(&self, message: &M) {
        self.head();
        self.stream.write_message(message).await;
    }

    /// The response head, once. Deferred to the first write so that a call
    /// failing before it produces anything can still be Trailers-Only.
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

    /// Ends the call.
    ///
    /// §9.1 puts the outcome in the trailers, so `:status` is 200 whatever
    /// happened: the request was carried, and the call it carried is what
    /// succeeded or failed. A call that wrote nothing gets the whole thing in
    /// one HEADERS frame — Trailers-Only — and one that already has a head
    /// gets a trailer section.
    fn finish(self, status: Status) {
        // The handler's first, then the status: what it returned is what the
        // call ended as, whatever it may also have put in the map.
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
            MessageError::Compressed(encoding) => Status::unimplemented(format!(
                "messages compressed with {encoding:?} are not decompressed by this server"
            )),
            MessageError::NotProto(format) => {
                Status::internal(format!("{format:?} messages are not decoded by this server"))
            }
            MessageError::Decode(e) => Status::invalid_argument(format!("{e}")),
        }
    }
}

impl From<GrpcError> for Status {
    fn from(e: GrpcError) -> Self {
        match e {
            GrpcError::MessageTooLarge { declared } => {
                Status::resource_exhausted(format!("message of {declared} bytes is too large"))
            }
            GrpcError::TooManyMessages => {
                Status::resource_exhausted("too many messages waiting to be read")
            }
            GrpcError::UnsupportedEncoding => {
                Status::unimplemented("grpc-encoding names a compression this server has no name for")
            }
            GrpcError::CompressedWithoutEncoding => {
                Status::internal("a compressed message on a request that announced no grpc-encoding")
            }
            GrpcError::InvalidCompressedFlag(flag) => {
                Status::internal(format!("compressed flag {flag} is neither 0 nor 1"))
            }
            GrpcError::Truncated => Status::internal("the request body ended inside a message"),
        }
    }
}

/// Turns a gRPC handler into one the server can run.
///
/// `grpc` is `async fn(&GrpcCall) -> Status`. It borrows the call rather than
/// owning it — an `AsyncFn` and not the by-value [`Handler`] this wraps —
/// because the layer has to still be holding the stream when the handler is
/// done, or cut short. Returning a [`Status`] is what makes answering
/// something a handler cannot forget.
///
/// Requests that are not gRPC never reach it: `http` answers those, which is
/// what lets one port carry both.
///
/// ```ignore
/// Server::new(settings)
///     .run::<Ring, _>(grpc::service(
///         |call: &GrpcCall| async move { Status::ok() },
///         |stream: Stream| async move { ... },
///     ))
///     .await
/// ```
pub fn service<G, H>(grpc: G, http: H) -> impl Handler
where
    G: AsyncFn(&GrpcCall) -> Status + Clone + 'static,
    H: Handler,
{
    move |stream: Stream| {
        let (grpc, http) = (grpc.clone(), http.clone());
        async move {
            let Some(format) = stream.grpc_format() else {
                return http.handle(stream).await;
            };
            let call = GrpcCall {
                timeout: parse_timeout(stream.fields()),
                stream,
                format,
                headed: Cell::new(false),
                headers: RefCell::new(HeaderMap::new()),
                trailers: RefCell::new(HeaderMap::new()),
            };

            // The deadline is the layer's to enforce and not the handler's:
            // the client is already counting against the same budget, and a
            // server that runs on is working for nobody. Ours starts when the
            // headers landed, so it is always a little later than the
            // client's — by the transit, which is the safe direction.
            let status = match call.timeout {
                None => grpc(&call).await,
                Some(timeout) => {
                    match runtime::runtime::select::select(grpc(&call), sleep(timeout)).await
                    {
                        runtime::runtime::select::SelectResult::First(status) => status,
                        runtime::runtime::select::SelectResult::Second(()) => {
                            Status::new(Code::DeadlineExceeded, "deadline exceeded")
                        }
                    }
                }
            };
            call.finish(status);
        }
    }
}
