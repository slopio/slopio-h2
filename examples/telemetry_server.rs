//! A server with telemetry on: a span for each request, exported over
//! OTLP/gRPC to Jaeger, Tempo or an OpenTelemetry collector.
//!
//!     podman run --rm -p 16686:16686 -p 4317:4317 docker.io/jaegertracing/jaeger
//!     cargo run --example telemetry_server --features otlp
//!     curl --http2-prior-knowledge http://localhost:8080/hello
//!     curl --http2-prior-knowledge http://localhost:8080/hello -d 'a body'
//!     curl --http2-prior-knowledge http://localhost:8080/slow        # 100 ms
//!     curl --http2-prior-knowledge http://localhost:8080/fail -v     # 500
//!     curl --http2-prior-knowledge http://localhost:8080/hello \
//!         -H 'traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
//!
//! The traces are at http://localhost:16686, under `telemetry-server`. The
//! last request joins the caller's trace, `4bf92f35…`, rather than starting
//! one. `OTLP_ENDPOINT` sends the spans elsewhere than 127.0.0.1:4317; it is
//! an address, not a name. With nothing listening there, each batch fails and
//! is dropped, and the server carries on.

use std::net::SocketAddr;
use std::time::Duration;

use http::{HeaderMap, Method, StatusCode, header};
use popple_h2::otlp::{OtlpCollector, OtlpService};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::runtime::time::Sleep;
use runtime::tracing::{self, KeyValue, Level, Span, SpanKind, Status};

runtime::define_buf_ring!(
    ServerRing,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 128,
    pool_size = 512
);

// The exporter receives its responses into a ring of its own. One
// connection per worker, and small answers, so a small ring.
runtime::define_buf_ring!(OtlpRing, bgid = 2, buffer_size = 16384, ring_size = 16);

fn main() {
    let endpoint: SocketAddr = match std::env::var("OTLP_ENDPOINT") {
        Ok(value) => value
            .parse()
            .expect("OTLP_ENDPOINT is an address and a port, such as 127.0.0.1:4317"),
        Err(_) => ([127, 0, 0, 1], 4317).into(),
    };
    let service = OtlpService {
        name: "telemetry-server".into(),
        version: Some(env!("CARGO_PKG_VERSION").into()),
        host_name: None,
    };
    println!("listening on http://localhost:8080, exporting spans to {endpoint}");

    // Built on each worker, which exports its own spans with its index as
    // `service.instance.id`.
    let collector = move || OtlpCollector::<OtlpRing>::new(endpoint, &service);

    if std::env::var_os("PER_CORE").is_some() {
        runtime::thread_per_core_traced::<(ServerRing, OtlpRing), _, _>(collector, |_| {
            Box::pin(serve())
        });
    } else {
        runtime::main_thread_traced::<(ServerRing, OtlpRing), _, _>(collector, serve());
    }
}

async fn serve() {
    let settings = ServerSettings::new(([0, 0, 0, 0], 8080), ServerTransport::Plain);
    if let Err(e) = Server::new(settings).run::<ServerRing, _>(handle).await {
        eprintln!("server error: {e}");
    }
}

/// Each request runs in a task of its own, and a span belongs to its task:
/// the one opened here is the root of this request's spans, and the span
/// every event and attribute below goes to.
async fn handle(stream: Stream) {
    // Held for the whole exchange, the answer included: dropping it ends
    // the span, and the worker's collector exports it.
    let _request = request_span(&stream);

    let received = {
        // A child: it nests under the request span for as long as it is held.
        let _read = tracing::new_span("read body", Level::Info);
        read_body(&stream).await
    };
    tracing::span_set_attribute(KeyValue::new("http.request.body.size", received as i64));

    if stream.path() == Some("/slow") {
        // Spans are timed by the runtime's clock, read once per turn of the
        // event loop: one that ends in the turn it began lasts 0 µs, as
        // `read body` does for a small body. This one spans a sleep.
        let _wait = tracing::new_span("wait", Level::Info);
        Sleep::during(Duration::from_millis(100)).await;
    }

    let status = match stream.path() {
        Some("/fail") => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::OK,
    };
    tracing::span_set_attribute(KeyValue::new(
        "http.response.status_code",
        i64::from(status.as_u16()),
    ));
    // A server span fails on a 5xx only: a 4xx is the client's error.
    if status.is_server_error() {
        tracing::event(Level::Error, "failing on purpose");
        tracing::span_set_status(Status::Error("failed on purpose"));
    }

    stream.write_headers(status, &HeaderMap::new());
    let body = format!("{status}, {received} bytes of body read\n");
    stream.write_data_final(body.as_bytes()).await;
}

/// OpenTelemetry's HTTP server span. Named after the method alone, as the
/// conventions ask when there is no route, and a child of the caller's span
/// when the request carries a W3C `traceparent`.
fn request_span(stream: &Stream) -> Span {
    let name = span_name(stream.method());
    let caller = stream
        .fields()
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .and_then(tracing::extract);
    let span = match caller {
        Some(parent) => tracing::new_trace_with_parent(name, Level::Info, parent),
        None => tracing::new_trace(name, Level::Info),
    };

    let span = span
        .kind(SpanKind::Server)
        .attr_dyn(
            "http.request.method",
            stream.method().map_or("_OTHER", Method::as_str),
        )
        .attr_dyn("url.path", stream.path().unwrap_or(""))
        .attr(KeyValue::new("network.protocol.version", "2"));
    let span = match stream
        .fields()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
    {
        Some(agent) => span.attr_dyn("user_agent.original", agent),
        None => span,
    };
    match stream.peer_addr() {
        Some(peer) => span.attr_dyn("client.address", &peer.ip().to_string()),
        None => span,
    }
}

/// A span's name is a `&'static str`, so the method is matched, not copied.
fn span_name(method: Option<&Method>) -> &'static str {
    match method {
        Some(&Method::GET) => "GET",
        Some(&Method::POST) => "POST",
        Some(&Method::PUT) => "PUT",
        Some(&Method::DELETE) => "DELETE",
        Some(&Method::PATCH) => "PATCH",
        Some(&Method::HEAD) => "HEAD",
        Some(&Method::OPTIONS) => "OPTIONS",
        _ => "HTTP",
    }
}

async fn read_body(stream: &Stream) -> usize {
    if stream.body_is_oneshot() {
        return stream.body().await.map_or(0, |bytes| bytes.len());
    }
    let mut total = 0;
    while stream.readable().await {
        let taken = stream.peek(|bytes| bytes.len());
        stream.consume(taken);
        total += taken;
    }
    total
}
