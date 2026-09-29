//! Routing by protocol, then by method and path, to one async function per
//! route: the crate's `Router` for HTTP, `GrpcRouter` for gRPC. Each route's
//! function is spawned as its own task, holding only what that route needs,
//! and each core builds its own tables.
//!
//!     cargo run --example router
//!     curl --http2-prior-knowledge http://localhost:8080/users/42
//!     curl --http2-prior-knowledge http://localhost:8080/files/a/b/c.txt
//!     curl --http2-prior-knowledge http://localhost:8080/echo -d hello
//!     head -c 2000000 /dev/zero | curl --http2-prior-knowledge http://localhost:8080/echo -X POST -T - -v  # 413
//!     curl --http2-prior-knowledge http://localhost:8080/echo -v       # 405
//!     curl --http2-prior-knowledge http://localhost:8080/nowhere -v    # 404
//!
//!     grpcurl -plaintext -import-path examples/grpc_server/proto -proto health.proto \
//!         -d '{"service": ""}' localhost:8080 grpc.health.v1.Health/Check
//!     grpcurl -plaintext -import-path examples/grpc_server/proto -proto echo.proto \
//!         -d '{"text": "a", "index": 1} {"text": "b", "index": 2}' \
//!         localhost:8080 popple.echo.v1.Echo/Chat

use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use popple_h2::grpc::{GrpcCall, GrpcRouter, Status, service};
use popple_h2::server::{Params, Router, Server, ServerSettings, ServerTransport, Stream};
use runtime::main_thread_with;

runtime::define_buf_ring!(
    RouterRing,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 128,
    pool_size = 512
);

fn main() {
    println!("listening on http://localhost:8080 (HTTP/2 cleartext, prior knowledge)");
    if std::env::var_os("PER_CORE").is_some() {
        runtime::thread_per_core_with::<RouterRing, _>(|_| Box::pin(serve()));
    } else {
        main_thread_with::<RouterRing, _>(serve());
    }
}

async fn serve() {
    // Per core, inside the runtime: the tables are `Rc`s, never shared.
    let http = Router::new()
        .route(Method::GET, "/", index)
        .route(Method::GET, "/users/{id}", user)
        .route(Method::DELETE, "/users/{id}", delete_user)
        .route(Method::GET, "/files/{*path}", file)
        .route(Method::POST, "/echo", echo);
    let grpc = GrpcRouter::new()
        .route("/grpc.health.v1.Health/Check", check)
        .route("/popple.echo.v1.Echo/Chat", chat);

    let settings = ServerSettings::new(([0, 0, 0, 0], 8080), ServerTransport::Plain);
    if let Err(e) = Server::new(settings)
        .run::<RouterRing, _>(service(grpc, http))
        .await
    {
        eprintln!("server error: {e}");
    }
}

// ---- HTTP handlers ---------------------------------------------------------

async fn index(stream: Stream, _: Params) {
    text(
        stream,
        StatusCode::OK,
        "try /users/42, /files/a/b.txt, POST /echo\n",
    )
    .await
}

async fn user(stream: Stream, params: Params) {
    let body = format!("user {}\n", params.get(&stream, 0).unwrap_or(""));
    text(stream, StatusCode::OK, &body).await
}

async fn delete_user(stream: Stream, params: Params) {
    let body = format!("deleted user {}\n", params.get(&stream, 0).unwrap_or(""));
    text(stream, StatusCode::OK, &body).await
}

async fn file(stream: Stream, params: Params) {
    let body = format!("file {}\n", params.get(&stream, 0).unwrap_or(""));
    text(stream, StatusCode::OK, &body).await
}

/// What the echo takes back whole; past it, a `413`.
const ECHO_LIMIT: usize = 1 << 20;

/// The body whole, whether the client declared its length or not.
async fn echo(stream: Stream, _: Params) {
    let Ok(body) = stream.body(ECHO_LIMIT).await else {
        return text(stream, StatusCode::PAYLOAD_TOO_LARGE, "too large\n").await;
    };
    stream.write_headers(StatusCode::OK, &HeaderMap::new());
    stream.write_data_final(&body).await;
}

// ---- gRPC handlers ---------------------------------------------------------

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

async fn check(call: &GrpcCall) -> Status {
    let request = match call.message::<HealthCheckRequest>().await {
        Ok(Some(request)) => request,
        Ok(None) => return Status::invalid_argument("no request message"),
        Err(status) => return status,
    };
    if !request.service.is_empty() {
        return Status::not_found("unknown service");
    }
    call.write_message(&HealthCheckResponse { status: SERVING })
        .await;
    Status::ok()
}

/// Both directions at once: each request is answered as it lands.
async fn chat(call: &GrpcCall) -> Status {
    loop {
        let request: EchoRequest = match call.message().await {
            Ok(Some(request)) => request,
            Ok(None) => return Status::ok(),
            Err(status) => return status,
        };
        call.write_message(&EchoResponse {
            text: request.text.to_uppercase(),
            index: request.index,
        })
        .await;
    }
}

async fn text(stream: Stream, status: StatusCode, body: &str) {
    let mut fields = HeaderMap::new();
    fields.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    stream.write_headers(status, &fields);
    stream.write_data_final(body.as_bytes()).await;
}
