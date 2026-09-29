//! The canonical gRPC service, to point a load generator at.
//!
//!     taskset -c 0 cargo run --release --example helloworld_server
//!     taskset -c 1 cargo run --release --example grpc_load

use http::{HeaderMap, StatusCode};
use popple_h2::grpc::{GrpcCall, GrpcRouter, Status, service};
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

/// gRPC §9.1: a method no route has is UNIMPLEMENTED rather than a 404.
async fn serve(port: u16) {
    let grpc = GrpcRouter::new().route("/helloworld.Greeter/SayHello", say_hello);

    let settings = ServerSettings::new(([0, 0, 0, 0], port), ServerTransport::Plain);
    if let Err(e) = Server::new(settings)
        .run::<ServerRing, _>(service(grpc, plain_http))
        .await
    {
        eprintln!("server error: {e}");
    }
}

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

async fn plain_http(stream: Stream) {
    stream.write_headers(StatusCode::NOT_FOUND, &HeaderMap::new());
    stream.write_data_final(b"this port speaks gRPC\n").await;
}
