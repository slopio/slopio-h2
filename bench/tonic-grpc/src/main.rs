//! The tonic counterpart of popple-h2's `examples/grpc_server`.
//!
//! The same two services, answering the same things, so that `ghz` pointed at
//! either measures the two stacks and not two different services: a unary
//! health check whose request is a message of no bytes, and a bidirectional
//! echo that answers one message per message.
//!
//!     THREADS=2 PORT=8081 tonic-grpc-bench
//!
//! `THREADS` is the tokio worker count, to be set to however many cores the
//! popple-h2 side is given.

use std::env;
use std::pin::Pin;

use tokio_stream::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming, transport::Server};

pub mod health {
    tonic::include_proto!("grpc.health.v1");
}
pub mod echo {
    tonic::include_proto!("popple.echo.v1");
}

use echo::echo_server::{Echo, EchoServer};
use echo::{EchoRequest, EchoResponse};
use health::health_server::{Health, HealthServer};
use health::{HealthCheckRequest, HealthCheckResponse};

/// Matches what `runtime` installs on the popple-h2 side.
#[cfg(feature = "mimalloc-global")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const SERVING: i32 = 1;
const NOT_SERVING: i32 = 2;

/// Exactly what the popple-h2 example answers.
fn status_of(service: &str) -> Option<i32> {
    match service {
        "" => Some(SERVING),
        "down" => Some(NOT_SERVING),
        "ready" | "grpc.health.v1.Health" => Some(SERVING),
        _ => None,
    }
}

#[derive(Default)]
struct HealthService;

#[tonic::async_trait]
impl Health for HealthService {
    async fn check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        match status_of(&request.into_inner().service) {
            Some(status) => Ok(Response::new(HealthCheckResponse { status })),
            None => Err(Status::not_found("unknown service")),
        }
    }

    type WatchStream = Pin<Box<dyn Stream<Item = Result<HealthCheckResponse, Status>> + Send>>;

    async fn watch(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<Self::WatchStream>, Status> {
        Err(Status::unimplemented("Watch is not implemented"))
    }
}

#[derive(Default)]
struct EchoService;

#[tonic::async_trait]
impl Echo for EchoService {
    type ChatStream = Pin<Box<dyn Stream<Item = Result<EchoResponse, Status>> + Send>>;

    async fn chat(
        &self,
        request: Request<Streaming<EchoRequest>>,
    ) -> Result<Response<Self::ChatStream>, Status> {
        let inbound = request.into_inner();
        let outbound = inbound.map(|message| {
            message.map(|request| EchoResponse {
                text: request.text.to_uppercase(),
                index: request.index,
            })
        });
        Ok(Response::new(Box::pin(outbound) as Self::ChatStream))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let threads: usize = env::var("THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8081);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()?;

    println!("tonic health and echo services on :{port}, {threads} worker(s)");
    rt.block_on(async move {
        Server::builder()
            .add_service(HealthServer::new(HealthService))
            .add_service(EchoServer::new(EchoService))
            .serve(format!("0.0.0.0:{port}").parse().unwrap())
            .await
    })?;
    Ok(())
}
