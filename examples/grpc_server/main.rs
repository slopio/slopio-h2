//! Two gRPC services, answered by hand — no code generation, no stubs.
//!
//! `grpc.health.v1.Health`, which every gRPC deployment already has and
//! Kubernetes probes, and a bidirectional `popple.echo.v1.Echo` to talk both
//! ways at once. Cleartext on 8080, as gRPC over h2c. Their `.proto` files sit
//! beside this one, under `proto/`, and are what a client needs to call them.
//!
//!     cargo run --example grpc_server
//!
//!     grpc-health-probe -addr localhost:8080
//!     grpc-health-probe -addr localhost:8080 -service down
//!
//!     grpcurl -plaintext -proto examples/grpc_server/proto/health.proto \
//!         -d '{}' localhost:8080 grpc.health.v1.Health/Check
//!
//!     printf '{"text":"hi","index":1}' | grpcurl -plaintext \
//!         -proto examples/grpc_server/proto/echo.proto -d @ \
//!         localhost:8080 popple.echo.v1.Echo/Chat
//!
//! [`grpc::service`] is what makes these handlers handlers: it owns the call,
//! reads the request's messages, writes the response's, and turns the [`Status`]
//! each one returns into the trailers — or into a Trailers-Only response, when
//! the call failed before it produced anything. The deadline in `grpc-timeout`
//! is its business too, so a handler is never left running for a client that
//! has given up.
//!
//! What is left here is the service: routing on `:path`, and what to answer.

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

/// `grpc.health.v1.HealthCheckRequest`. An empty `service` asks after the
/// server as a whole — and encodes to nothing at all, proto3 writing no bytes
/// for a field at its default. That request is five bytes on the wire: its
/// prefix, and no content.
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

/// What this server says it is: everything but `down` is up.
fn status_of(service: &str) -> Option<i32> {
    match service {
        // The whole server.
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

    // As the other examples: one worker per core of the affinity mask.
    let per_core = std::env::var("PER_CORE").is_ok_and(|v| v != "0");

    println!("gRPC health and echo services on :{port} (h2c), per_core={per_core}");
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
    if let Err(e) = Server::new(settings)
        .run::<MyBufRing, _>(service(route, plain_http))
        .await
    {
        eprintln!("server error: {e}");
    }
}

/// §9.1: the path is `/package.Service/Method`, and one this server does not
/// have is UNIMPLEMENTED — which a client wants as a `grpc-status` and not as
/// a 404, the HTTP exchange having gone perfectly well.
async fn route(call: &GrpcCall) -> Status {
    match call.path() {
        Some("/grpc.health.v1.Health/Check") => check(call).await,
        Some("/popple.echo.v1.Echo/Chat") => chat(call).await,
        Some("/grpc.health.v1.Health/Watch") => Status::unimplemented("Watch is not implemented"),
        _ => Status::unimplemented("no such method"),
    }
}

/// A unary call: one message in, one out. Every way the request can fail to be
/// one is already a `Status`, so `?` answers them.
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

/// A stream in both directions: one answer per message, as each arrives.
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

/// Everything on this port that is not gRPC. One connection carries both, and
/// the layer tells them apart by the request's `content-type`.
async fn plain_http(stream: Stream) {
    stream.write_headers_final(StatusCode::NOT_FOUND, &HeaderMap::new());
}
