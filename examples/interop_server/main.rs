//! `grpc.testing.TestService`, which is what the gRPC project's own interop
//! suite calls. Its client is the one every language implementation is
//! validated against, so this is conformance measured by somebody else's
//! judgement rather than by our tests.
//!
//!     cargo run --release --example interop_server
//!
//!     go install google.golang.org/grpc/interop/client@latest
//!     client -server_host localhost -server_port 8080 -test_case empty_unary
//!
//! `bench/interop.sh` runs the whole list.
//!
//! The service is a programmable echo: the request says how large a response
//! to send, how many of them, and what status to end on, and the server obeys.
//! Which is what makes it a conformance test — the client knows exactly what
//! it asked for and checks it got it.
//!
//! Not implemented, and refused rather than faked: compression. A request that
//! asks for a compressed response, or arrives compressed, is answered
//! UNIMPLEMENTED. `TryFrom<CompressedGrpcFrame>` is where that would go.

use http::{HeaderMap, StatusCode};
use popple_h2::grpc::{Code, GrpcCall, Status, service};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::{main_thread_with, thread_per_core_with};

mod testing;
use testing::{
    Empty, Payload, SimpleRequest, SimpleResponse, StreamingInputCallRequest,
    StreamingInputCallResponse, StreamingOutputCallRequest, StreamingOutputCallResponse,
};

runtime::define_buf_ring!(
    MyBufRing,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 128,
    pool_size = 512
);

/// §9.1's `custom_metadata` case: the client sends these two and expects them
/// back, one in the head and one in the trailers.
const ECHO_INITIAL: &str = "x-grpc-test-echo-initial";
const ECHO_TRAILING: &str = "x-grpc-test-echo-trailing-bin";

fn main() {
    let port = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);
    let per_core = std::env::var("PER_CORE").is_ok_and(|v| v != "0");

    println!("grpc.testing.TestService on :{port} (h2c), per_core={per_core}");
    if per_core {
        thread_per_core_with::<MyBufRing, _>(move |_| Box::pin(serve(port)));
    } else {
        main_thread_with::<MyBufRing, _>(serve(port));
    }
}

async fn serve(port: u16) {
    let settings = ServerSettings {
        bind_port: port,
        transport: ServerTransport::Plain,
    };
    if let Err(e) = Server::new(settings).run::<MyBufRing, _>(service(route, plain_http)).await {
        eprintln!("server error: {e}");
    }
}

async fn route(call: &GrpcCall) -> Status {
    // Whatever the method, `custom_metadata` expects these echoed — so it is
    // done once, here, before anything writes.
    echo_metadata(call);

    match call.path() {
        Some("/grpc.testing.TestService/EmptyCall") => empty_call(call).await,
        Some("/grpc.testing.TestService/UnaryCall")
        | Some("/grpc.testing.TestService/CacheableUnaryCall") => unary_call(call).await,
        Some("/grpc.testing.TestService/StreamingInputCall") => streaming_input(call).await,
        Some("/grpc.testing.TestService/StreamingOutputCall") => streaming_output(call).await,
        // Both are a stream in each direction. The difference is only when the
        // client sends, so one handler serves them: read one, answer it, read
        // the next — which is what `ping_pong` does, and `half_duplex` does
        // the same with everything already in flight.
        Some("/grpc.testing.TestService/FullDuplexCall")
        | Some("/grpc.testing.TestService/HalfDuplexCall") => full_duplex(call).await,
        // The case is named for it: a method the service declares and does not
        // have, answered UNIMPLEMENTED rather than 404.
        Some("/grpc.testing.TestService/UnimplementedCall") => {
            Status::unimplemented("UnimplementedCall")
        }
        _ => Status::unimplemented("no such method"),
    }
}

/// `custom_metadata`: the initial one goes in the head, the trailing one in
/// the trailers. Names ending `-bin` carry base64, which is passed through as
/// it came — decoding it would only mean encoding it again.
fn echo_metadata(call: &GrpcCall) {
    if let Some(value) = call.fields().get(ECHO_INITIAL) {
        let mut head = HeaderMap::new();
        head.insert(ECHO_INITIAL, value.clone());
        call.set_headers(&head);
    }
    if let Some(value) = call.fields().get(ECHO_TRAILING) {
        let mut trailers = HeaderMap::new();
        trailers.insert(ECHO_TRAILING, value.clone());
        call.set_trailers(&trailers);
    }
}

async fn empty_call(call: &GrpcCall) -> Status {
    match call.message::<Empty>().await {
        Ok(Some(_)) => {
            call.write_message(&Empty {}).await;
            Status::ok()
        }
        Ok(None) => Status::invalid_argument("no request message"),
        Err(status) => status,
    }
}

/// `large_unary`, `status_code_and_message`, `special_status_message`: a
/// payload of the size asked for, or the status asked for instead.
async fn unary_call(call: &GrpcCall) -> Status {
    let request: SimpleRequest = match call.message().await {
        Ok(Some(request)) => request,
        Ok(None) => return Status::invalid_argument("no request message"),
        Err(status) => return status,
    };

    if let Some(refusal) = refuse_compression(
        request.response_compressed.map(|b| b.value),
        request.expect_compressed.map(|b| b.value),
    ) {
        return refusal;
    }
    if let Some(status) = asked_for(request.response_status) {
        return status;
    }

    call.write_message(&SimpleResponse {
        payload: Some(payload_of(request.response_size)),
        ..Default::default()
    })
    .await;
    Status::ok()
}

/// `client_streaming`: read every message, answer with how much arrived.
async fn streaming_input(call: &GrpcCall) -> Status {
    let mut total = 0i32;
    loop {
        let request: StreamingInputCallRequest = match call.message().await {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(status) => return status,
        };
        if let Some(refusal) = refuse_compression(None, request.expect_compressed.map(|b| b.value))
        {
            return refusal;
        }
        total += request.payload.map_or(0, |payload| payload.body.len() as i32);
    }

    call.write_message(&StreamingInputCallResponse {
        aggregated_payload_size: total,
    })
    .await;
    Status::ok()
}

/// `server_streaming`: one request naming a list of sizes, one response each.
async fn streaming_output(call: &GrpcCall) -> Status {
    let request: StreamingOutputCallRequest = match call.message().await {
        Ok(Some(request)) => request,
        Ok(None) => return Status::invalid_argument("no request message"),
        Err(status) => return status,
    };
    write_responses(call, &request).await
}

/// `ping_pong`, `empty_stream`, `half_duplex`: a stream in both directions,
/// answered one for one as each arrives.
async fn full_duplex(call: &GrpcCall) -> Status {
    loop {
        let request: StreamingOutputCallRequest = match call.message().await {
            Ok(Some(request)) => request,
            // `empty_stream` is exactly this, with nothing before it.
            Ok(None) => return Status::ok(),
            Err(status) => return status,
        };
        let status = write_responses(call, &request).await;
        if !status.is_ok() {
            return status;
        }
    }
}

/// One response per `ResponseParameters`, each of the size it names.
async fn write_responses(call: &GrpcCall, request: &StreamingOutputCallRequest) -> Status {
    for parameters in &request.response_parameters {
        if let Some(refusal) = refuse_compression(parameters.compressed.map(|b| b.value), None) {
            return refusal;
        }
    }
    if let Some(status) = asked_for(request.response_status.clone()) {
        return status;
    }

    for parameters in &request.response_parameters {
        call.write_message(&StreamingOutputCallResponse {
            payload: Some(payload_of(parameters.size)),
        })
        .await;
    }
    Status::ok()
}

/// A payload of `size` bytes, zeroed. The client checks the length and not
/// what is in it.
fn payload_of(size: i32) -> Payload {
    Payload {
        r#type: 0,
        body: vec![0; size.max(0) as usize],
    }
}

/// The status a request asked the server to end on, `None` for a request that
/// asked for none. An `EchoStatus` of code 0 is a request for `OK`, which is
/// not the same as not asking.
fn asked_for(status: Option<testing::EchoStatus>) -> Option<Status> {
    let status = status?;
    let code = match status.code {
        0 => return None,
        1 => Code::Cancelled,
        2 => Code::Unknown,
        3 => Code::InvalidArgument,
        4 => Code::DeadlineExceeded,
        5 => Code::NotFound,
        6 => Code::AlreadyExists,
        7 => Code::PermissionDenied,
        8 => Code::ResourceExhausted,
        9 => Code::FailedPrecondition,
        10 => Code::Aborted,
        11 => Code::OutOfRange,
        12 => Code::Unimplemented,
        13 => Code::Internal,
        14 => Code::Unavailable,
        15 => Code::DataLoss,
        16 => Code::Unauthenticated,
        _ => Code::Unknown,
    };
    Some(Status::new(code, status.message))
}

/// Compression is not implemented, and a request that turns on either side of
/// it is told so rather than served something it did not ask for.
fn refuse_compression(response: Option<bool>, expect: Option<bool>) -> Option<Status> {
    (response == Some(true) || expect == Some(true))
        .then(|| Status::unimplemented("message compression is not implemented"))
}

async fn plain_http(stream: Stream) {
    stream.write_headers_final(StatusCode::NOT_FOUND, &HeaderMap::new());
}
