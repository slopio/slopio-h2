//! Making gRPC calls: the handle an application holds for one of them.
//!
//! The mirror of [`GrpcCall`](super::GrpcCall), which is what a *handler*
//! holds, and deliberately the same words: both read with `message`, both
//! write with `write_message`. The asymmetry is in the ending. A handler
//! returns a [`Status`] and the library writes it into the trailers; a caller
//! reads one out of them, which is what [`Call::status`] is for.
//!
//! ```ignore
//! let grpc = GrpcClient::new(client::connect::<Ring>(addr).await?);
//! let reply: HelloReply = grpc.unary("/helloworld.Greeter/SayHello", &request).await?;
//! ```
//!
//! Nothing here knows about HTTP/2 beyond [`client::Stream`]: a call is one
//! stream, its messages are that stream's body, and a status is a field in
//! its trailers. That is also why this wraps [`client::Client`] rather than
//! being a method on it — the whole of `grpc` is arranged so that nothing of
//! HTTP/2 has to know what a message is.

use std::cell::{Cell, RefCell};

use http::{HeaderMap, HeaderValue, Method, header};

use super::encode::frame_message;
use super::input::{GrpcError, GrpcInput};
use super::request::GrpcFormat;
use super::status::{Code, Status};
use crate::client::{self, Unavailable};

/// What this client sends and accepts: `application/grpc+proto`, which §4.1
/// makes the meaning of bare `application/grpc` too.
const CONTENT_TYPE: HeaderValue = HeaderValue::from_static("application/grpc+proto");

/// §4.1 requires `te: trailers` of a client, as the thing that distinguishes
/// a peer that can receive a trailer section from one an intermediary would
/// have to buffer for.
const TE_TRAILERS: HeaderValue = HeaderValue::from_static("trailers");

/// One connection's worth of gRPC.
///
/// A wrapper rather than a pool: it holds one [`client::Client`], and what
/// happens when that connection goes away is the caller's to decide, because
/// only the caller knows whether a call is safe to make again. §6.8's GOAWAY
/// is reported honestly for exactly this reason — a request the peer says it
/// never processed is one that can be made elsewhere.
pub struct Client {
    inner: client::Client,
}

impl Client {
    pub fn new(inner: client::Client) -> Self {
        // A gRPC connection asks for a handful of paths — the methods of one
        // service — for its whole life, which is the case HPACK's dynamic
        // table exists for and the one its default policy assumes away. Set
        // here rather than left to the caller: it is not a preference, it is
        // what gRPC *is*.
        inner.index_request_paths(true);
        Self { inner }
    }

    /// The connection underneath, for the things that are HTTP/2's and not
    /// gRPC's: whether it is still usable, how many calls are open on it, and
    /// waiting for it to end.
    pub fn connection(&self) -> &client::Client {
        &self.inner
    }

    /// Opens a call to `path`, which gRPC spells `/package.Service/Method`.
    ///
    /// The head goes out here and the stream stays open: nothing has been
    /// said about what the call carries, so this is where a client-streaming
    /// call writes its first message and where a unary one writes its only.
    ///
    /// [`Unavailable`] is the connection declining, and it declines for two
    /// different reasons — see its variants. Neither is a call that failed;
    /// no call was made.
    pub fn call(&self, path: &str) -> Result<Call, Unavailable> {
        self.call_with(path, &HeaderMap::new())
    }

    /// [`call`](Self::call) with metadata: gRPC's leading metadata is just
    /// fields on the request head.
    ///
    /// The three fields the protocol requires are set here and win over
    /// anything `metadata` carries by the same name — a caller that overrode
    /// `content-type` would be making a request no server would read as gRPC.
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

        // The head alone never ends a gRPC request: even a call with no
        // messages ends with an empty DATA frame, because the messages are
        // the body and §4.1 puts the status in a trailer section after it.
        let stream = self.inner.send_request(&request, false)?;
        Ok(Call::new(stream))
    }

    /// The shape nearly every call has: one message out, one message back.
    ///
    /// Everything [`Call`] does, in the order it has to be done in — which is
    /// the reason this exists, since the order is where the mistakes are. The
    /// status is read *after* the message, because a call that failed half
    /// way still sent what it sent, and reading the status first would mean
    /// waiting for an end that the message is holding up.
    pub async fn unary<Req, Resp>(&self, path: &str, request: &Req) -> Result<Resp, Status>
    where
        Req: prost::Message,
        Resp: prost::Message + Default,
    {
        let call = self.call(path).map_err(|e| match e {
            // §6.8 and §5.1.2 again: one says come back to this connection,
            // the other says go to another. UNAVAILABLE is what a caller
            // retries, which is right for both.
            Unavailable::AtLimit | Unavailable::Closed => {
                Status::new(Code::Unavailable, e.to_string())
            }
        })?;

        call.write_message_final(request).await?;
        let reply = call.message::<Resp>().await?;
        let status = call.status().await;

        match (status.is_ok(), reply) {
            (true, Some(reply)) => Ok(reply),
            // A call that ended OK and sent nothing is a server that did not
            // answer. §4.1 gives a unary response exactly one message, and a
            // caller cannot invent the missing one.
            (true, None) => Err(Status::new(
                Code::Internal,
                "the call ended OK without a response message",
            )),
            (false, _) => Err(status),
        }
    }
}

/// One call: write its messages, read its replies, read how it ended.
///
/// Dropping it cancels the call — the stream is reset with CANCEL (§8.1), so
/// a server streaming into it stops rather than filling a window nobody will
/// read. That is [`client::Stream`]'s behaviour, inherited rather than
/// arranged.
pub struct Call {
    stream: client::Stream,
    /// The response head, once it has arrived. Taken from the stream exactly
    /// once, because that is how the stream hands it over.
    head: RefCell<Option<HeaderMap>>,
    /// The message reader, built once the head says what format to read in.
    /// `None` before that, and on a response that carries no messages at all.
    input: RefCell<Option<GrpcInput>>,
    /// The status, once something has settled it: the trailers, a
    /// Trailers-Only head, or a failure that ended the call before either.
    status: RefCell<Option<Status>>,
    /// The peer's half is done. Nothing more will arrive, so nothing more is
    /// waited for.
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

    /// §5.1.1: the stream this call is on, which is what a log needs to line
    /// it up against the peer's.
    pub fn id(&self) -> crate::shared::codec::frames::stream_id::StreamId {
        self.stream.id()
    }

    /// Writes one message. More may follow.
    pub async fn write_message<M: prost::Message>(&self, message: &M) -> Result<(), Status> {
        self.write(message, false).await
    }

    /// Writes the last message, ending the request with it.
    ///
    /// The END_STREAM rides on the same DATA frame rather than following in
    /// an empty one, which is a round trip's worth of difference on a unary
    /// call and the only reason this is separate from
    /// [`write_message`](Self::write_message).
    pub async fn write_message_final<M: prost::Message>(&self, message: &M) -> Result<(), Status> {
        self.write(message, true).await
    }

    /// Ends the request without another message — the half-close a
    /// client-streaming call needs when it runs out of things to say.
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

    /// The next message, or `None` at the end of the response.
    ///
    /// `None` is not an error even when the call failed: the status says what
    /// happened, and [`status`](Self::status) is where it is read. A response
    /// that is malformed *as gRPC* — a message longer than the limit, a
    /// compression this end never offered — is an `Err` here, because there
    /// is no message to hand over and the peer is the reason.
    pub async fn message<M: prost::Message + Default>(&self) -> Result<Option<M>, Status> {
        let Some(frame) = self.frame().await? else {
            return Ok(None);
        };
        frame
            .decode::<M>()
            .map(Some)
            .map_err(|e| Status::new(Code::Internal, format!("undecodable response: {e:?}")))
    }

    /// The next message as it arrived, undecoded. What
    /// [`message`](Self::message) is built on, for a caller holding bytes
    /// rather than a `prost` type.
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

    /// How the call ended.
    ///
    /// Reads the response to its end first, because §4.1 puts the status in
    /// the trailers and the trailers come after the body: a status asked for
    /// early is one that has not been sent yet. Messages still unread are
    /// dropped, which is the caller's choice made explicit — ask for the
    /// status and you have said you are done listening.
    ///
    /// Always answers. A call whose connection died has no trailers to read,
    /// and gets the status that failure deserves rather than a wait.
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
            // §9.1: a response that carried no status at all. The HTTP one is
            // all there is to go on, and for some of them it is enough.
            match self.head.borrow().as_ref() {
                Some(_) => Status::new(
                    Code::Internal,
                    "the response ended without a grpc-status in its trailers",
                ),
                None => Status::new(Code::Internal, "no response"),
            }
        })
    }

    /// The response's leading metadata, once the head has arrived. `None`
    /// before the first read, and on a call that never got one.
    pub fn metadata(&self) -> Option<HeaderMap> {
        self.head.borrow().clone()
    }

    /// Takes the response head and makes what it says usable: what the
    /// messages are framed as, and — for a Trailers-Only response — the
    /// status, which arrives in the head itself with no body behind it.
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

        // §9.1: a status in the head is a Trailers-Only response — the whole
        // of the answer, with no messages coming. It is also what a server
        // sends for "no such method", which is the most common failure there
        // is, so it cannot be a special case that is easy to forget.
        if let Some(status) = Status::of(&fields) {
            self.settle(status);
        } else if !http_status.is_success() {
            // A response that is not gRPC and not a success: an intermediary
            // answering instead of the server. §9.1 maps the ones that have
            // an obvious meaning.
            self.settle(Status::of_http(http_status));
        } else if let Some(format) = GrpcFormat::of_response(&fields) {
            *self.input.borrow_mut() = Some(GrpcInput::new(format, &fields, None));
        }

        *self.head.borrow_mut() = Some(fields);
        Ok(())
    }

    /// §4.1: the trailer section, which is where the status is when the
    /// response had a body. Taken once — the stream hands them over — and
    /// only counted if nothing has settled the status already.
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

/// What a failed write means to a call. The stream says why it failed; this
/// says what that is in gRPC's terms.
fn sending_failed(e: &std::io::Error) -> Status {
    match e.kind() {
        std::io::ErrorKind::TimedOut => Status::new(Code::DeadlineExceeded, e.to_string()),
        _ => Status::new(
            Code::Unavailable,
            format!("the request could not be sent: {e}"),
        ),
    }
}

/// The same for a read. UNAVAILABLE rather than UNKNOWN: a connection that
/// went is the case a caller retries, and telling it apart from a call that
/// genuinely failed is the difference between a retry and a bug report.
fn receiving_failed(e: &std::io::Error) -> Status {
    match e.kind() {
        std::io::ErrorKind::TimedOut => Status::new(Code::DeadlineExceeded, e.to_string()),
        _ => Status::new(Code::Unavailable, format!("the call ended early: {e}")),
    }
}

/// Each way a response can be malformed as gRPC, with the code §9.1 gives it.
/// The same table the server answers requests with, pointed the other way.
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
