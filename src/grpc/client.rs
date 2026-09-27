use std::cell::{Cell, RefCell};

use http::uri::{Authority, Scheme, Uri};
use http::{HeaderMap, HeaderValue, Method, header};

use super::input::GrpcError;
use super::status::{Code, Status};
use crate::client::{self, ClientError, Origin, Security};

const CONTENT_TYPE: HeaderValue = HeaderValue::from_static("application/grpc+proto");

/// §4.1 requires `te: trailers` of a client.
const TE_TRAILERS: HeaderValue = HeaderValue::from_static("trailers");

/// Calls to one origin, over a [`client::Client`] that opens the connections
/// they need. `S` is its transport, as there.
pub struct Client<S: Security> {
    inner: client::Client<S>,
    origin: Origin,
    /// A call names only its method's path (§4.1); these make the rest of its
    /// URI, as given, so `:authority` is what the caller wrote.
    scheme: Scheme,
    authority: Authority,
}

impl<S: Security> Client<S> {
    /// `origin` is where the calls go, as `https://api.example.com` or
    /// `http://10.0.0.1:50051`. Its scheme must be `inner`'s transport.
    pub fn new(inner: client::Client<S>, origin: &str) -> Result<Self, ClientError> {
        let uri: Uri = origin
            .parse()
            .map_err(|_| ClientError::InvalidUri("the origin is not a URI"))?;
        let parsed = Origin::of(&uri).map_err(ClientError::InvalidUri)?;
        if *parsed.scheme() != S::scheme() {
            return Err(ClientError::InvalidUri(
                "the origin's scheme is not the client's transport",
            ));
        }
        let parts = uri.into_parts();
        let (Some(scheme), Some(authority)) = (parts.scheme, parts.authority) else {
            unreachable!("`Origin::of` found both");
        };

        inner.index_request_paths(true);
        Ok(Self {
            inner,
            origin: parsed,
            scheme,
            authority,
        })
    }

    pub fn client(&self) -> &client::Client<S> {
        &self.inner
    }

    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    pub async fn call(&self, path: &str) -> Result<Call, ClientError> {
        self.call_with(path, &HeaderMap::new()).await
    }

    /// The fields the protocol requires win over anything `metadata` carries
    /// by the same name. Awaits only when a connection must be opened.
    pub async fn call_with(&self, path: &str, metadata: &HeaderMap) -> Result<Call, ClientError> {
        let uri = Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(path)
            .build()
            .map_err(|_| ClientError::InvalidUri("the method's path is not a URI path"))?;
        let mut request = http::Request::builder()
            .method(Method::POST)
            .uri(uri)
            .body(())
            .map_err(|_| ClientError::InvalidUri("the method's path is not a URI path"))?;

        let fields = request.headers_mut();
        for (name, value) in metadata {
            fields.append(name, value.clone());
        }
        fields.insert(header::CONTENT_TYPE, CONTENT_TYPE);
        fields.insert(header::TE, TE_TRAILERS);

        // The head alone never ends a gRPC request (§4.1): even a call with no
        // messages ends with an empty DATA frame.
        let stream = self.inner.send_call(&request, false).await?;
        Ok(Call::new(stream))
    }

    /// The status is read *after* the message: [`Call::status`] drops
    /// messages still unread.
    pub async fn unary<Req, Resp>(&self, path: &str, request: &Req) -> Result<Resp, Status>
    where
        Req: prost::Message,
        Resp: prost::Message + Default,
    {
        let call = self.call(path).await.map_err(|e| match e {
            ClientError::InvalidUri(reason) => Status::new(Code::Internal, reason),
            ClientError::Unavailable(unavailable) => {
                Status::new(Code::Unavailable, unavailable.reason())
            }
            ClientError::Connect(_) => {
                Status::new(Code::Unavailable, "no connection could be opened")
            }
        })?;

        call.write_message_final(request).await?;
        let reply = call.message::<Resp>().await?;
        let status = call.status().await;

        match (status.is_ok(), reply) {
            (true, Some(reply)) => Ok(reply),
            // §4.1 gives a unary response exactly one message.
            (true, None) => Err(Status::new(
                Code::Internal,
                "the call ended OK without a response message",
            )),
            (false, _) => Err(status),
        }
    }
}

/// Dropping it cancels the call: the stream is reset with CANCEL (§8.1).
///
/// Its messages are gathered by the stream itself, as they land, and each is
/// decoded from the buffer it was gathered in.
pub struct Call {
    stream: client::Stream,
    /// Taken from the stream exactly once.
    head: RefCell<Option<HeaderMap>>,
    status: RefCell<Option<Status>>,
    ended: Cell<bool>,
}

impl Call {
    fn new(stream: client::Stream) -> Self {
        Self {
            stream,
            head: RefCell::new(None),
            status: RefCell::new(None),
            ended: Cell::new(false),
        }
    }

    pub fn id(&self) -> crate::shared::codec::frames::stream_id::StreamId {
        self.stream.id()
    }

    pub async fn write_message<M: prost::Message>(&self, message: &M) -> Result<(), Status> {
        self.write(message, false).await
    }

    pub async fn write_message_final<M: prost::Message>(&self, message: &M) -> Result<(), Status> {
        self.write(message, true).await
    }

    pub async fn finish(&self) -> Result<(), Status> {
        self.stream
            .write(&[], true)
            .await
            .map_err(|e| sending_failed(&e))
    }

    async fn write<M: prost::Message>(&self, message: &M, last: bool) -> Result<(), Status> {
        self.stream
            .write_message(message, last)
            .await
            .map_err(|e| sending_failed(&e))
    }

    pub async fn message<M: prost::Message + Default>(&self) -> Result<Option<M>, Status> {
        let Some(frame) = self.frame().await? else {
            return Ok(None);
        };
        frame
            .decode::<M>()
            .map(Some)
            .map_err(|_| Status::new(Code::Internal, "undecodable response message"))
    }

    pub async fn frame(&self) -> Result<Option<super::GrpcFrame>, Status> {
        self.receive_head().await?;
        if self.ended.get() {
            return Ok(None);
        }

        // A response that announced no gRPC content-type carries no
        // messages, whatever its body holds: the stream says `None` once it
        // has ended, so the trailers are in.
        match self.stream.message().await {
            Ok(Some(message)) => message.map(Some).map_err(from_input),
            Ok(None) => {
                self.ended.set(true);
                self.take_trailers();
                Ok(None)
            }
            Err(e) => {
                self.ended.set(true);
                let status = receiving_failed(&e);
                self.settle(status.clone());
                Err(status)
            }
        }
    }

    /// Reads the response to its end first, because §4.1 puts the status in
    /// the trailers. Messages still unread are dropped.
    pub async fn status(&self) -> Status {
        while !self.ended.get() {
            match self.frame().await {
                Ok(Some(_)) => continue,
                Ok(None) => break,
                Err(status) => return status,
            }
        }
        self.take_trailers();

        self.status.borrow().clone().unwrap_or_else(|| {
            // §9.1: a response that carried no status at all.
            match self.head.borrow().as_ref() {
                Some(_) => Status::new(
                    Code::Internal,
                    "the response ended without a grpc-status in its trailers",
                ),
                None => Status::new(Code::Internal, "no response"),
            }
        })
    }

    pub fn metadata(&self) -> Option<HeaderMap> {
        self.head.borrow().clone()
    }

    async fn receive_head(&self) -> Result<(), Status> {
        if self.head.borrow().is_some() || self.ended.get() {
            return Ok(());
        }

        let response = match self.stream.response().await {
            Ok(response) => response,
            Err(e) => {
                self.ended.set(true);
                let status = receiving_failed(&e);
                self.settle(status.clone());
                return Err(status);
            }
        };

        let http_status = response.status();
        let fields = response.into_parts().0.headers;

        // By the rule the stream chose by: a head that settles the call has
        // no messages coming.
        if let Some(status) = Status::settled_by_head(http_status, &fields) {
            self.settle(status);
        }

        *self.head.borrow_mut() = Some(fields);
        Ok(())
    }

    fn take_trailers(&self) {
        if self.status.borrow().is_some() {
            return;
        }
        if let Some(trailers) = self.stream.trailers()
            && let Some(status) = Status::of(&trailers)
        {
            self.settle(status);
        }
    }

    /// The first thing to settle the status is the one that explains the
    /// call: a peer's own status beats the guess a later failure would make.
    fn settle(&self, status: Status) {
        let mut slot = self.status.borrow_mut();
        if slot.is_none() {
            *slot = Some(status);
        }
    }
}

/// The deadline's own error says nothing a status would not.
const DEADLINE_PASSED: &str = "the deadline on this call passed";

fn sending_failed(e: &std::io::Error) -> Status {
    match e.kind() {
        std::io::ErrorKind::TimedOut => Status::new(Code::DeadlineExceeded, DEADLINE_PASSED),
        _ => Status::new(Code::Unavailable, "the request could not be sent"),
    }
}

fn receiving_failed(e: &std::io::Error) -> Status {
    match e.kind() {
        std::io::ErrorKind::TimedOut => Status::new(Code::DeadlineExceeded, DEADLINE_PASSED),
        _ => Status::new(Code::Unavailable, "the call ended early"),
    }
}

fn from_input(e: GrpcError) -> Status {
    match e {
        GrpcError::MessageTooLarge { .. } => {
            Status::resource_exhausted("the server sent a message past what this client will hold")
        }
        GrpcError::InvalidCompressedFlag(_) => {
            Status::internal("a Compressed-Flag that is neither 0 nor 1")
        }
        GrpcError::CompressedWithoutEncoding => {
            Status::internal("a compressed message on a response announcing no grpc-encoding")
        }
        GrpcError::UnsupportedEncoding => Status::unimplemented(
            "the response is compressed with an encoding this client has no name for",
        ),
        GrpcError::TooManyMessages => {
            Status::resource_exhausted("too many messages waiting to be read")
        }
        GrpcError::Truncated => Status::internal("the response body ended inside a message"),
    }
}
