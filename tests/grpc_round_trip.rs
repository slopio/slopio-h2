//! Our gRPC client against our gRPC server, over a real socket.
//!
//! Both halves have been tested against scripted bytes — the server against a
//! scripted client, the client against a scripted server — which proves each
//! one reads what the other is supposed to write. It does not prove they
//! agree, because the same person wrote both scripts. This runs the two for
//! real: a listener, a connection, and messages that cross a kernel.
//!
//! Cleartext on purpose. TLS has its own round trip; what is under test here
//! is gRPC, and a failure should not have two layers to be in.

#![cfg(feature = "grpc")]

use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use http::{HeaderMap, StatusCode};
use popple_h2::client;
use popple_h2::grpc::{Code, GrpcCall, GrpcClient, Status, service};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::main_thread_with;
use runtime::runtime::time::Sleep;

runtime::define_buf_ring!(ServerRing, bgid = 0, buffer_size = 16384, ring_size = 256);
runtime::define_buf_ring!(ClientRing, bgid = 1, buffer_size = 16384, ring_size = 64);

#[derive(Clone, PartialEq, prost::Message)]
struct HelloRequest {
    #[prost(string, tag = "1")]
    name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct HelloReply {
    #[prost(string, tag = "1")]
    message: String,
}

const UNARY: &str = "/test.Greeter/SayHello";
const STREAM: &str = "/test.Greeter/SayMany";
const FAILS: &str = "/test.Greeter/Fail";

/// A message that exercises §9.1's percent-encoding across the wire: the
/// server encodes it into `grpc-message`, the client decodes it back, and the
/// two halves have never met before now.
const AWKWARD: &str = "échec: 50% du flux";

async fn route(call: &GrpcCall) -> Status {
    match call.path() {
        Some(UNARY) => {
            let request = match call.message::<HelloRequest>().await {
                Ok(Some(request)) => request,
                Ok(None) => return Status::invalid_argument("no request message"),
                Err(status) => return status,
            };
            call.write_message(&HelloReply {
                message: format!("hello, {}", request.name),
            })
            .await;
            Status::ok()
        }
        Some(STREAM) => {
            for n in 1..=3 {
                call.write_message(&HelloReply {
                    message: format!("message {n}"),
                })
                .await;
            }
            Status::ok()
        }
        Some(FAILS) => Status::not_found(AWKWARD),
        // §9.1: a path this server does not have. The HTTP exchange went
        // perfectly; the call did not happen.
        _ => Status::unimplemented("no such method"),
    }
}

/// Anything that is not gRPC. Nothing under test sends one, but `service`
/// wants somewhere to put it.
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

/// What the client made of the four calls, reported back as plain data: the
/// test thread cannot hold anything from the runtime's thread.
type Outcome = (
    Result<String, (Code, String)>,
    Result<Vec<String>, (Code, String)>,
    Result<String, (Code, String)>,
    Result<String, (Code, String)>,
);

fn flatten(status: Status) -> (Code, String) {
    (status.code, status.message)
}

#[test]
fn the_client_and_the_server_agree_over_a_real_socket() {
    let port = pick_port();
    let (done_tx, done_rx) = mpsc::channel::<Outcome>();

    // Detached: the accept loop runs until the process ends, and the test
    // ends when the client has its answers.
    thread::spawn(move || {
        main_thread_with::<ServerRing, _>(async move {
            let settings = ServerSettings {
                bind_port: port,
                transport: ServerTransport::Plain,
            };
            let _ = Server::new(settings)
                .run::<ServerRing, _>(service(route, not_grpc))
                .await;
        });
    });

    let client = thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
            let addr = format!("127.0.0.1:{port}").parse().unwrap();

            // The listener binds inside the server's own task, so the first
            // attempts may arrive before it does.
            let mut connected = None;
            for _ in 0..50 {
                match client::connect::<ClientRing>(addr).await {
                    Ok(client) => {
                        connected = Some(client);
                        break;
                    }
                    Err(_) => Sleep::during(Duration::from_millis(20)).await,
                }
            }
            let grpc = GrpcClient::new(connected.expect("the server came up"));

            // One message out, one back.
            let unary = grpc
                .unary::<_, HelloReply>(
                    UNARY,
                    &HelloRequest {
                        name: "world".into(),
                    },
                )
                .await
                .map(|reply| reply.message)
                .map_err(flatten);

            // Several messages, then a status. The handle hands them over one
            // at a time and `None` is the end.
            let streamed = async {
                let call = grpc
                    .call(STREAM)
                    .map_err(|e| (Code::Unavailable, e.to_string()))?;
                call.write_message_final(&HelloRequest::default())
                    .await
                    .map_err(flatten)?;
                let mut said = Vec::new();
                while let Some(reply) = call.message::<HelloReply>().await.map_err(flatten)? {
                    said.push(reply.message);
                }
                match call.status().await {
                    status if status.is_ok() => Ok(said),
                    status => Err(flatten(status)),
                }
            }
            .await;

            // A call that ran and failed, with a message that has to survive
            // being encoded into a header and read back.
            let failed = grpc
                .unary::<_, HelloReply>(FAILS, &HelloRequest::default())
                .await
                .map(|reply| reply.message)
                .map_err(flatten);

            // §9.1's Trailers-Only: a status in the head, no body at all.
            let missing = grpc
                .unary::<_, HelloReply>("/test.Greeter/Nope", &HelloRequest::default())
                .await
                .map(|reply| reply.message)
                .map_err(flatten);

            done_tx
                .send((unary, streamed, failed, missing))
                .expect("the test is listening");
        });
    });

    let (unary, streamed, failed, missing) = done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the client reports");
    client.join().expect("client thread");

    assert_eq!(
        unary.expect("the unary call succeeded"),
        "hello, world",
        "one message out, one back"
    );
    assert_eq!(
        streamed.expect("the streaming call succeeded"),
        ["message 1", "message 2", "message 3"],
        "every message, in order, then an OK status"
    );
    assert_eq!(
        failed.expect_err("the call failed on purpose"),
        (Code::NotFound, AWKWARD.to_owned()),
        "§9.1's percent-encoding survived the round trip"
    );
    assert_eq!(
        missing.expect_err("there is no such method"),
        (Code::Unimplemented, "no such method".to_owned()),
        "a path the server does not have is a status, not a 404"
    );
}
