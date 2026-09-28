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
use proto::{ExportTraceServiceRequest, ExportTraceServiceResponse, Resource, any_value};

const EXPORT_PATH: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

/// A batch still unanswered after this is dropped.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(10);

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
    resource: Resource,
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
            _ring: PhantomData,
        }
    }
}

impl<U: BufRingSpec + 'static> Collector for OtlpCollector<U> {
    async fn process(&mut self, batch: Vec<SpanWrapper>) {
        let request = encode::export_request(&self.resource, &batch);
        drop(batch);
        // A failed export loses its batch; the client reconnects for the next one.
        let _ = timeout(
            EXPORT_TIMEOUT,
            self.client
                .unary::<ExportTraceServiceRequest, ExportTraceServiceResponse>(
                    EXPORT_PATH,
                    &request,
                ),
        )
        .await;
    }
}

fn resource(service: &OtlpService) -> Resource {
    use any_value::Value::StringValue;

    let mut attributes = vec![encode::key_value(
        "service.name",
        StringValue(service.name.clone()),
    )];
    if let Some(version) = &service.version {
        attributes.push(encode::key_value(
            "service.version",
            StringValue(version.clone()),
        ));
    }
    if let Some(host) = &service.host_name {
        attributes.push(encode::key_value("host.name", StringValue(host.clone())));
    }
    if let Some(worker) = thread_id() {
        attributes.push(encode::key_value(
            "service.instance.id",
            StringValue(worker.to_string()),
        ));
    }
    Resource { attributes }
}
