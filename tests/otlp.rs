//! The OTLP collector exporting a span to our gRPC server, over a real socket.

#![cfg(feature = "otlp")]

use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::Duration;

use slopio::http::{HeaderMap, StatusCode};
use slopio::runtime::time::Sleep;
use slopio::tracing::{Level, new_trace};
use slopio::{main_thread_traced, main_thread_with, spawn};
use slopio_h2::grpc::{GrpcCall, Status, service};
use slopio_h2::otlp::proto::{ExportTraceServiceRequest, ExportTraceServiceResponse};
use slopio_h2::otlp::{OtlpCollector, OtlpService};
use slopio_h2::server::{Server, ServerSettings, ServerTransport, Stream};

slopio::define_buf_ring!(ServerRing, bgid = 0, buffer_size = 16384, ring_size = 256);
slopio::define_buf_ring!(ClientRing, bgid = 1, buffer_size = 16384, ring_size = 64);

const EXPORT: &str = "/opentelemetry.proto.collector.trace.v1.TraceService/Export";

/// One export: `(trace id length, name)` per span.
type Export = Vec<(usize, String)>;

/// Each export, to the test thread.
static EXPORTS: OnceLock<Mutex<mpsc::Sender<Export>>> = OnceLock::new();
static RECEIVED: AtomicBool = AtomicBool::new(false);

async fn route(call: &GrpcCall) -> Status {
    if call.path() != Some(EXPORT) {
        return Status::unimplemented("no such method");
    }
    let request = match call.message::<ExportTraceServiceRequest>().await {
        Ok(Some(request)) => request,
        Ok(None) => return Status::invalid_argument("no request message"),
        Err(status) => return status,
    };
    let spans = request
        .resource_spans
        .iter()
        .flat_map(|r| &r.scope_spans)
        .flat_map(|s| &s.spans)
        .map(|s| (s.trace_id.len(), s.name.clone()))
        .collect();
    let _ = EXPORTS.get().unwrap().lock().unwrap().send(spans);
    RECEIVED.store(true, Ordering::Release);
    call.write_message(&ExportTraceServiceResponse::default())
        .await;
    Status::ok()
}

async fn not_grpc(stream: Stream) {
    stream.write_headers(StatusCode::NOT_FOUND, &HeaderMap::new());
    stream.write_data_final(b"").await;
}

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

#[test]
fn a_closed_span_reaches_the_otlp_endpoint() {
    let port = pick_port();
    let (names_tx, names_rx) = mpsc::channel();
    EXPORTS.set(Mutex::new(names_tx)).unwrap();

    // Detached: the accept loop runs until the process ends.
    thread::spawn(move || {
        main_thread_with::<ServerRing, _>(async move {
            let settings = ServerSettings::new(([127, 0, 0, 1], port), ServerTransport::Plain);
            let _ = Server::new(settings)
                .run::<ServerRing, _>(service(route, not_grpc))
                .await;
        });
    });

    let endpoint: SocketAddr = ([127, 0, 0, 1], port).into();
    let service = OtlpService {
        name: "otlp-test".into(),
        version: None,
        host_name: None,
    };
    let client = thread::spawn(move || {
        main_thread_traced::<ClientRing, _, _>(
            move || OtlpCollector::<ClientRing>::new(endpoint, &service),
            async move {
                spawn(async {
                    drop(new_trace("exported_span", Level::Info));
                });
                // The server binds in its own task; a failed export loses its
                // batch, so keep closing spans until one lands.
                for _ in 0..100 {
                    if RECEIVED.load(Ordering::Acquire) {
                        return;
                    }
                    Sleep::during(Duration::from_millis(50)).await;
                    spawn(async {
                        drop(new_trace("exported_span", Level::Info));
                    });
                }
            },
        );
    });

    let names = names_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("no export reached the server");
    assert!(!names.is_empty());
    for (trace_id_len, name) in names {
        assert_eq!(trace_id_len, 16);
        assert_eq!(name, "exported_span");
    }
    client.join().unwrap();
}
