//! Two gRPC services, answered by hand — no code generation, no stubs.
//!
//!     cargo run --example grpc_server

use http::{HeaderMap, StatusCode};
use popple_h2::grpc::{GrpcCall, Status, service};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::{main_thread_with, thread_per_core_with};

runtime::define_buf_ring!(
    MyBufRing,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 128,
    pool_size = 512
);

#[derive(Clone, PartialEq, prost::Message)]
struct HealthCheckRequest {
    #[prost(string, tag = "1")]
    service: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct HealthCheckResponse {
    #[prost(int32, tag = "1")]
    status: i32,
}

/// `popple.echo.v1`, a stream in both directions at once.
#[derive(Clone, PartialEq, prost::Message)]
struct EchoRequest {
    #[prost(string, tag = "1")]
    text: String,
    #[prost(int32, tag = "2")]
    index: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct EchoResponse {
    #[prost(string, tag = "1")]
    text: String,
    #[prost(int32, tag = "2")]
    index: i32,
}

const SERVING: i32 = 1;
const NOT_SERVING: i32 = 2;

fn status_of(service: &str) -> Option<i32> {
    match service {
        "" => Some(SERVING),
        "down" => Some(NOT_SERVING),
        "ready" | "grpc.health.v1.Health" => Some(SERVING),
        _ => None,
    }
}

fn main() {
    let port = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);

    let per_core = std::env::var("PER_CORE").is_ok_and(|v| v != "0");

    println!("gRPC health and echo services on :{port} (h2c), per_core={per_core}");
    if per_core {
        thread_per_core_with::<MyBufRing, _>(move |_| Box::pin(serve(port)));
    } else {
        main_thread_with::<MyBufRing, _>(serve(port));
    }
}

async fn serve(port: u16) {
    let settings = ServerSettings::new(([0, 0, 0, 0], port), ServerTransport::Plain);
    if let Err(e) = Server::new(settings)
        .run::<MyBufRing, _>(service(route, plain_http))
        .await
    {
        eprintln!("server error: {e}");
    }
}

/// §9.1: a method this server does not have is UNIMPLEMENTED rather than a 404.
async fn route(call: &GrpcCall) -> Status {
    match call.path() {
        Some("/grpc.health.v1.Health/Check") => check(call).await,
        Some("/popple.echo.v1.Echo/Chat") => chat(call).await,
        Some("/grpc.health.v1.Health/Watch") => Status::unimplemented("Watch is not implemented"),
        _ => Status::unimplemented("no such method"),
    }
}

async fn check(call: &GrpcCall) -> Status {
    let Some(request) = (match call.message::<HealthCheckRequest>().await {
        Ok(request) => request,
        Err(status) => return status,
    }) else {
        return Status::invalid_argument("no request message");
    };

    let Some(status) = status_of(&request.service) else {
        return Status::not_found("unknown service");
    };

    call.write_message(&HealthCheckResponse { status }).await;
    Status::ok()
}

async fn chat(call: &GrpcCall) -> Status {
    let started = std::time::Instant::now();
    let mut answered = 0;

    loop {
        let request: EchoRequest = match call.message().await {
            Ok(Some(request)) => request,
            Ok(None) => break,
            Err(status) => return status,
        };
        eprintln!(
            "  [{:>6.0}ms] #{} in: {:?}",
            started.elapsed().as_secs_f64() * 1000.0,
            request.index,
            request.text
        );

        call.write_message(&EchoResponse {
            text: request.text.to_uppercase(),
            index: request.index,
        })
        .await;
        answered += 1;
    }

    eprintln!(
        "  [{:>6.0}ms] {answered} answered, closing",
        started.elapsed().as_secs_f64() * 1000.0
    );
    Status::ok()
}

async fn plain_http(stream: Stream) {
    stream.write_headers_final(StatusCode::NOT_FOUND, &HeaderMap::new());
}
