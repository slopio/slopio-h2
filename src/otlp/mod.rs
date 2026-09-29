//! Span export to an OTLP backend (Tempo, Jaeger, an OpenTelemetry collector)
//! over OTLP/gRPC, as a collector for the runtime's tracing:
//!
//! ```ignore
//! let endpoint = "127.0.0.1:4317".parse()?;
//! let service = OtlpService { name: "api".into(), version: None, host_name: None };
//! runtime::thread_per_core_traced::<Ring, _, _>(
//!     move || OtlpCollector::<Ring>::new(endpoint, &service),
//!     worker,
//! );
//! ```

mod encode;
pub mod proto;

use std::marker::PhantomData;
use std::net::SocketAddr;
use std::time::Duration;

use runtime::net::BufRingSpec;
use runtime::runtime::time::timeout;
use runtime::tracing::{Collector, SpanWrapper, thread_id};

use crate::client::{PlainText, PlainTextClient};
use crate::grpc::GrpcClient;

const EXPORT_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

/// A batch still unanswered after this is dropped.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

/// What the encoding buffer keeps between batches. A burst may grow it past
/// this; it is given back once the burst is sent.
const BUFFER_KEPT: usize = 256 * 1024;

/// What the backend files the spans under: OTLP's `service.*` and
/// `host.name` resource attributes.
#[derive(Clone, Debug)]
pub struct OtlpService {
    pub name: String,
    pub version: Option<String>,
    pub host_name: Option<String>,
}

/// One per worker. Responses are received into `U`'s buffers, so `U` must be
/// in the rings the runtime was started with.
pub struct OtlpCollector<U> {
    client: GrpcClient<PlainText>,
    /// Encoded once: the same for every batch this worker sends.
    resource: Vec<u8>,
    /// Each batch is encoded here, gRPC prefix and all.
    buffer: Vec<u8>,
    _ring: PhantomData<fn() -> U>,
}

impl<U: BufRingSpec + 'static> OtlpCollector<U> {
    /// `endpoint` is the backend's OTLP/gRPC port, typically 4317, not its
    /// OTLP/HTTP one (4318). Build it on the worker it exports for: the
    /// worker's index becomes `service.instance.id`.
    pub fn new(endpoint: SocketAddr, service: &OtlpService) -> Self {
        let client = GrpcClient::new(
            PlainTextClient::plaintext::<U>(),
            &format!("http://{endpoint}"),
        )
        .expect("a socket address makes a valid origin");
        Self {
            client,
            resource: resource(service),
            buffer: Vec::new(),
            _ring: PhantomData,
        }
    }
}

impl<U: BufRingSpec + 'static> Collector for OtlpCollector<U> {
    async fn process(&mut self, batch: Vec<SpanWrapper>) {
        encode::export_request(&mut self.buffer, &self.resource, &batch);
        drop(batch);
        // A failed export loses its batch; the client reconnects for the next one.
        let _ = timeout(EXPORT_TIMEOUT, self.export()).await;
        self.buffer.shrink_to(BUFFER_KEPT);
    }
}

impl<U: BufRingSpec + 'static> OtlpCollector<U> {
    /// The response is waited for, the call cancelled otherwise, but not read:
    /// a partial success is nothing this exporter could act on.
    async fn export(&self) -> Result<(), ()> {
        let call = self.client.call(EXPORT_PATH).await.map_err(drop)?;
        call.write_framed_final(&self.buffer).await.map_err(drop)?;
        match call.status().await.is_ok() {
            true => Ok(()),
            false => Err(()),
        }
    }
}

fn resource(service: &OtlpService) -> Vec<u8> {
    let mut out = Vec::new();
    encode::resource_attribute(&mut out, "service.name", &service.name);
    if let Some(version) = &service.version {
        encode::resource_attribute(&mut out, "service.version", version);
    }
    if let Some(host) = &service.host_name {
        encode::resource_attribute(&mut out, "host.name", host);
    }
    if let Some(worker) = thread_id() {
        encode::resource_attribute(&mut out, "service.instance.id", &worker.to_string());
    }
    out
}
