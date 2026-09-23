use std::cell::{Cell, RefCell};

use http::{HeaderMap, HeaderValue, Method, header};

use super::encode::frame_message;
use super::input::{GrpcError, GrpcInput};
use super::request::GrpcFormat;
use super::status::{Code, Status};
use crate::client::{self, Unavailable};

const CONTENT_TYPE: HeaderValue = HeaderValue::from_static("application/grpc+proto");

/// §4.1 requires `te: trailers` of a client.
const TE_TRAILERS: HeaderValue = HeaderValue::from_static("trailers");

pub struct Client {
    inner: client::Client,
}

impl Client {
    pub fn new(inner: client::Client) -> Self {
        inner.index_request_paths(true);
        Self { inner }
    }

    pub fn connection(&self) -> &client::Client {
        &self.inner
    }

    pub fn call(&self, path: &str) -> Result<Call, Unavailable> {
        self.call_with(path, &HeaderMap::new())
    }

    /// The fields the protocol requires win over anything `metadata` carries
    /// by the same name.
    pub fn call_with(&self, path: &str, metadata: &HeaderMap) -> Result<Call, Unavailable> {
        let mut request = http::Request::builder()
            .method(Method::POST)
            .uri(path)
            .body(())
            .map_err(|_| Unavailable::Closed)?;

        let fields = request.headers_mut();
        for (name, value) in metadata {
            fields.append(name, value.clone());
        }
        fields.insert(header::CONTENT_TYPE, CONTENT_TYPE);
        fields.insert(header::TE, TE_TRAILERS);

        // The head alone never ends a gRPC request (§4.1): even a call with no
        // messages ends with an empty DATA frame.
        let stream = self.inner.send_request(&request, false)?;
        Ok(Call::new(stream))
    }

    /// The status is read *after* the message: [`Call::status`] drops
    /// messages still unread.
    pub async fn unary<Req, Resp>(&self, path: &str, request: &Req) -> Result<Resp, Status>
    where
        Req: prost::Message,
        Resp: prost::Message + Default,
    {
        let call = self.call(path).map_err(|e| match e {
            Unavailable::AtLimit | Unavailable::Closed => {
                Status::new(Code::Unavailable, e.to_string())
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
pub struct Call {
    stream: client::Stream,
    /// Taken from the stream exactly once.
    head: RefCell<Option<HeaderMap>>,
    input: RefCell<Option<GrpcInput>>,
    status: RefCell<Option<Status>>,
    ended: Cell<bool>,
}

impl Call {
    fn new(stream: client::Stream) -> Self {
        Self {
            stream,
            head: RefCell::new(None),
            input: RefCell::new(None),
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
            .write(&frame_message(message), last)
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
            .map_err(|e| Status::new(Code::Internal, format!("undecodable response: {e:?}")))
    }

    pub async fn frame(&self) -> Result<Option<super::GrpcFrame>, Status> {
        self.receive_head().await?;

        loop {
            if let Some(input) = self.input.borrow_mut().as_mut()
                && let Some(ready) = input.take()
            {
                return ready.map(Some).map_err(from_input);
            }
            if self.ended.get() {
                return Ok(None);
            }

            match self.stream.read().await {
                Ok(Some(chunk)) => {
                    let mut input = self.input.borrow_mut();
                    let Some(input) = input.as_mut() else {
                        // A response that announced no gRPC content-type is
                        // not carrying messages, whatever its body holds.
                        return Ok(None);
                    };
                    input.push(&chunk);
                }
                Ok(None) => {
                    self.ended.set(true);
                    if let Some(input) = self.input.borrow_mut().as_mut() {
                        input.end();
                    }
                    self.take_trailers();
                }
                Err(e) => {
                    self.ended.set(true);
                    let status = receiving_failed(&e);
                    self.settle(status.clone());
                    return Err(status);
                }
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

        // §9.1: a status in the head is a Trailers-Only response, with no
        // messages coming.
        if let Some(status) = Status::of(&fields) {
            self.settle(status);
        } else if !http_status.is_success() {
            self.settle(Status::of_http(http_status));
        } else if let Some(format) = GrpcFormat::of_response(&fields) {
            *self.input.borrow_mut() = Some(GrpcInput::new(format, &fields, None));
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

fn sending_failed(e: &std::io::Error) -> Status {
    match e.kind() {
        std::io::ErrorKind::TimedOut => Status::new(Code::DeadlineExceeded, e.to_string()),
        _ => Status::new(
            Code::Unavailable,
            format!("the request could not be sent: {e}"),
        ),
    }
}

fn receiving_failed(e: &std::io::Error) -> Status {
    match e.kind() {
        std::io::ErrorKind::TimedOut => Status::new(Code::DeadlineExceeded, e.to_string()),
        _ => Status::new(Code::Unavailable, format!("the call ended early: {e}")),
    }
}

fn from_input(e: GrpcError) -> Status {
    match e {
        GrpcError::MessageTooLarge { declared } => Status::resource_exhausted(format!(
            "the server sent a message of {declared} bytes, past what this client will hold"
        )),
        GrpcError::InvalidCompressedFlag(byte) => {
            Status::internal(format!("Compressed-Flag was {byte}, not 0 or 1"))
        }
        GrpcError::CompressedWithoutEncoding => {
            Status::internal("a compressed message on a response announcing no grpc-encoding")
        }
        GrpcError::UnsupportedEncoding => Status::unimplemented(
            "the response is compressed with an encoding this client has no name for",
        ),
        other => Status::internal(format!("malformed response: {other:?}")),
    }
}
