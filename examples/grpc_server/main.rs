//! A gRPC service, answered by hand — no code generation, no stubs.
//!
//! Two services on 8080, as gRPC over h2c: `grpc.health.v1.Health`, which
//! every gRPC deployment already has and Kubernetes probes, and a
//! bidirectional `popple.echo.v1.Echo` to talk to both ways at once. Their
//! `.proto` files are beside this one, under `proto/`, and are what a client
//! needs to call them.
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
//! What the library does is read the request as messages and write the
//! response as one: `stream.message()`, `frame.decode()`,
//! `stream.write_message()`. What is left here — the routing on `:path`, the
//! `grpc-status` in the trailers — is what gRPC asks of a service and what
//! generated code would otherwise write for you.

use http::{HeaderMap, HeaderValue, StatusCode};
use popple_h2::grpc::MessageError;
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::main_thread_with;

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

/// §9.1's codes, the few this service can answer with.
const OK: &str = "0";
const INVALID_ARGUMENT: &str = "3";
const NOT_FOUND: &str = "5";
const UNIMPLEMENTED: &str = "12";
const INTERNAL: &str = "13";

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

    println!("gRPC health service on :{port} (h2c)");
    main_thread_with::<MyBufRing, _>(async move {
        let settings = ServerSettings {
            bind_port: port,
            transport: ServerTransport::Plain,
        };
        if let Err(e) = Server::new(settings).run::<MyBufRing, _>(route).await {
            eprintln!("server error: {e}");
        }
    });
}

async fn route(stream: Stream) {
    // Anything that is not gRPC gets an HTTP answer: the two share a port and
    // a connection, and `is_grpc` is read from the request's `content-type`.
    if !stream.is_grpc() {
        return stream.write_headers_final(StatusCode::NOT_FOUND, &HeaderMap::new());
    }

    // §9.1: the path is `/package.Service/Method`, and an unknown one is
    // UNIMPLEMENTED — which a gRPC client wants as a `grpc-status` and not as
    // a 404, the HTTP exchange having gone perfectly well.
    match stream.path() {
        Some("/grpc.health.v1.Health/Check") => check(stream).await,
        Some("/popple.echo.v1.Echo/Chat") => chat(stream).await,
        Some("/grpc.health.v1.Health/Watch") => {
            fail(stream, UNIMPLEMENTED, "Watch is not implemented")
        }
        _ => fail(stream, UNIMPLEMENTED, "no such method"),
    }
}

async fn check(stream: Stream) {
    let request: HealthCheckRequest = match stream.message().await {
        Some(Ok(frame)) => match frame.decode() {
            Ok(request) => request,
            // Each of these is a `grpc-status` the handler is the one to know.
            Err(MessageError::Decode(e)) => {
                return fail(stream, INVALID_ARGUMENT, &format!("{e}"));
            }
            Err(e) => return fail(stream, INTERNAL, &format!("{e:?}")),
        },
        // The peer half-closed without a request: for a unary call that is
        // one message short, however well-formed the stream was.
        None => return fail(stream, INVALID_ARGUMENT, "no request message"),
        Some(Err(e)) => return fail(stream, INTERNAL, &format!("{e:?}")),
    };

    let Some(status) = status_of(&request.service) else {
        return fail(stream, NOT_FOUND, "unknown service");
    };

    stream.write_headers(StatusCode::OK, &grpc_headers());
    stream.write_message(&HealthCheckResponse { status }).await;
    stream.write_trailers(&trailers(OK, None));
}

/// A stream in both directions: one answer per message, as each arrives.
///
/// The head goes out before the first message, which is what a streaming
/// response does — from here on an error is a `grpc-status` in the trailers,
/// Trailers-Only being no longer available.
async fn chat(stream: Stream) {
    stream.write_headers(StatusCode::OK, &grpc_headers());

    let started = std::time::Instant::now();
    let mut answered = 0;
    while let Some(message) = stream.message().await {
        let request: EchoRequest = match message.map(|frame| frame.decode()) {
            Ok(Ok(request)) => request,
            _ => return stream.write_trailers(&trailers(INVALID_ARGUMENT, Some("bad message"))),
        };
        eprintln!(
            "  [{:>6.0}ms] #{} in: {:?}",
            started.elapsed().as_secs_f64() * 1000.0,
            request.index,
            request.text
        );

        stream
            .write_message(&EchoResponse {
                text: request.text.to_uppercase(),
                index: request.index,
            })
            .await;
        answered += 1;
    }

    eprintln!("  [{:>6.0}ms] {answered} answered, closing", started.elapsed().as_secs_f64() * 1000.0);
    stream.write_trailers(&trailers(OK, None));
}

/// A call that fails before it produces anything: §9.1's Trailers-Only, one
/// HEADERS frame carrying the status and ending the stream.
fn fail(stream: Stream, code: &str, message: &str) {
    let mut fields = grpc_headers();
    for (name, value) in trailers(code, Some(message)).drain() {
        fields.insert(name.expect("a name per value"), value);
    }
    stream.write_headers_final(StatusCode::OK, &fields);
}

fn grpc_headers() -> HeaderMap {
    let mut fields = HeaderMap::new();
    fields.insert("content-type", HeaderValue::from_static("application/grpc"));
    fields
}

fn trailers(code: &str, message: Option<&str>) -> HeaderMap {
    let mut fields = HeaderMap::new();
    fields.insert("grpc-status", HeaderValue::from_str(code).expect("ASCII"));
    if let Some(message) = message {
        // §9.1: percent-encoded, which for the ASCII this service produces is
        // the string itself.
        if let Ok(value) = HeaderValue::from_str(message) {
            fields.insert("grpc-message", value);
        }
    }
    fields
}
