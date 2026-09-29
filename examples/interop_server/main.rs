//! `grpc.testing.TestService`, which is what the gRPC project's own interop
//! suite calls.
//!
//!     cargo run --release --example interop_server
//!
//!     go install google.golang.org/grpc/interop/client@latest
//!     client -server_host localhost -server_port 8080 -test_case empty_unary

use http::{HeaderMap, StatusCode};
use runtime::{main_thread_with, thread_per_core_with};
use slopio_h2::grpc::{Code, GrpcCall, GrpcRouter, Status, service};
use slopio_h2::server::{Server, ServerSettings, ServerTransport, Stream};

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

/// `UnimplementedCall` is left out on purpose: a method the router does not
/// have is UNIMPLEMENTED, which is what the suite expects of it.
async fn serve(port: u16) {
    let grpc = GrpcRouter::new()
        .route("/grpc.testing.TestService/EmptyCall", empty_call)
        .route("/grpc.testing.TestService/UnaryCall", unary_call)
        .route("/grpc.testing.TestService/CacheableUnaryCall", unary_call)
        .route(
            "/grpc.testing.TestService/StreamingInputCall",
            streaming_input,
        )
        .route(
            "/grpc.testing.TestService/StreamingOutputCall",
            streaming_output,
        )
        .route("/grpc.testing.TestService/FullDuplexCall", full_duplex)
        .route("/grpc.testing.TestService/HalfDuplexCall", full_duplex);

    let settings = ServerSettings::new(([0, 0, 0, 0], port), ServerTransport::Plain);
    if let Err(e) = Server::new(settings)
        .run::<MyBufRing, _>(service(grpc, plain_http))
        .await
    {
        eprintln!("server error: {e}");
    }
}

/// Each method's first act, before anything writes. Names ending `-bin`
/// carry base64, which is passed through as it came.
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
    echo_metadata(call);
    match call.message::<Empty>().await {
        Ok(Some(_)) => {
            call.write_message(&Empty {}).await;
            Status::ok()
        }
        Ok(None) => Status::invalid_argument("no request message"),
        Err(status) => status,
    }
}

async fn unary_call(call: &GrpcCall) -> Status {
    echo_metadata(call);
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

async fn streaming_input(call: &GrpcCall) -> Status {
    echo_metadata(call);
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
        total += request
            .payload
            .map_or(0, |payload| payload.body.len() as i32);
    }

    call.write_message(&StreamingInputCallResponse {
        aggregated_payload_size: total,
    })
    .await;
    Status::ok()
}

async fn streaming_output(call: &GrpcCall) -> Status {
    echo_metadata(call);
    let request: StreamingOutputCallRequest = match call.message().await {
        Ok(Some(request)) => request,
        Ok(None) => return Status::invalid_argument("no request message"),
        Err(status) => return status,
    };
    write_responses(call, &request).await
}

async fn full_duplex(call: &GrpcCall) -> Status {
    echo_metadata(call);
    loop {
        let request: StreamingOutputCallRequest = match call.message().await {
            Ok(Some(request)) => request,
            Ok(None) => return Status::ok(),
            Err(status) => return status,
        };
        let status = write_responses(call, &request).await;
        if !status.is_ok() {
            return status;
        }
    }
}

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

fn payload_of(size: i32) -> Payload {
    Payload {
        r#type: 0,
        body: vec![0; size.max(0) as usize],
    }
}

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

fn refuse_compression(response: Option<bool>, expect: Option<bool>) -> Option<Status> {
    (response == Some(true) || expect == Some(true))
        .then(|| Status::unimplemented("message compression is not implemented"))
}

async fn plain_http(stream: Stream) {
    stream.write_headers_final(StatusCode::NOT_FOUND, &HeaderMap::new());
}
