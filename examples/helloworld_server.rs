//! The canonical gRPC service, to point a load generator at.
//!
//!     taskset -c 0 cargo run --release --example helloworld_server
//!     taskset -c 1 cargo run --release --example grpc_load
//!
//! Two cores, two processes: a server sharing a core with the client that is
//! measuring it measures the pair of them, and the number means nothing. The
//! `taskset` mask is what the runtime builds its workers from, so `-c 0` is
//! one worker on core 0 whether or not `PER_CORE` is set.
//!
//! `PORT` moves it, `PER_CORE=1` runs one worker per core of the mask — for
//! `taskset -c 0-3`, four workers sharing the listening socket.
//!
//! `helloworld.Greeter/SayHello` rather than an invention of our own, because
//! it is the one service every gRPC toolchain already has a `.proto` for:
//! `ghz`, `grpcurl` and tonic's own examples can all drive this without being
//! told anything about us.

use http::{HeaderMap, StatusCode};
use popple_h2::grpc::{GrpcCall, Status, service};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::{main_thread_with, thread_per_core_with};

runtime::define_buf_ring!(ServerRing, bgid = 0, buffer_size = 16384, ring_size = 2048);

/// `helloworld.HelloRequest`.
#[derive(Clone, PartialEq, prost::Message)]
struct HelloRequest {
    #[prost(string, tag = "1")]
    name: String,
}

/// `helloworld.HelloReply`.
#[derive(Clone, PartialEq, prost::Message)]
struct HelloReply {
    #[prost(string, tag = "1")]
    message: String,
}

fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8080);
    let per_core = std::env::var("PER_CORE").is_ok_and(|v| v != "0");

    println!("helloworld.Greeter on :{port} (h2c), per_core={per_core}");
    match per_core {
        true => thread_per_core_with::<ServerRing, _>(move |_| Box::pin(serve(port))),
        false => main_thread_with::<ServerRing, _>(serve(port)),
    }
}

async fn serve(port: u16) {
    let settings = ServerSettings {
        bind_port: port,
        transport: ServerTransport::Plain,
    };
    if let Err(e) = Server::new(settings)
        .run::<ServerRing, _>(service(route, plain_http))
        .await
    {
        eprintln!("server error: {e}");
    }
}

/// §9.1: the path is `/package.Service/Method`, and one this server does not
/// have is UNIMPLEMENTED rather than a 404 — the HTTP exchange went perfectly.
async fn route(call: &GrpcCall) -> Status {
    match call.path() {
        Some("/helloworld.Greeter/SayHello") => say_hello(call).await,
        _ => Status::unimplemented("no such method"),
    }
}

/// One message in, one out. Everything the request can fail to be is already
/// a `Status`, so there is nothing here to invent.
async fn say_hello(call: &GrpcCall) -> Status {
    let request = match call.message::<HelloRequest>().await {
        Ok(Some(request)) => request,
        Ok(None) => return Status::invalid_argument("no request message"),
        Err(status) => return status,
    };

    call.write_message(&HelloReply {
        message: format!("Hello {}", request.name),
    })
    .await;
    Status::ok()
}

/// Anything that is not gRPC. A load generator sends none, but a stray
/// health check from a browser deserves an answer rather than a hang.
async fn plain_http(stream: Stream) {
    stream.write_headers(StatusCode::NOT_FOUND, &HeaderMap::new());
    stream.write_data_final(b"this port speaks gRPC\n").await;
}
