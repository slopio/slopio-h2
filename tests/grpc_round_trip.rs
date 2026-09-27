//! Our gRPC client against our gRPC server, over a real socket.

#![cfg(feature = "grpc")]

use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use http::{HeaderMap, StatusCode};
use popple_h2::client::{self, PlainText};
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
const REJECTS: &str = "/test.Greeter/Reject";

/// Exercises §9.1's percent-encoding across the wire.
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
        // Judged on the first message of a client stream: the status goes
        // out, and RST_STREAM(NO_ERROR) stops the upload behind it (§8.1).
        Some(REJECTS) => match call.message::<HelloRequest>().await {
            Ok(Some(_)) => Status::invalid_argument("rejected on sight"),
            Ok(None) => Status::invalid_argument("no request message"),
            Err(status) => status,
        },
        _ => Status::unimplemented("no such method"),
    }
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

/// Plain data: the test thread cannot hold anything from the runtime's thread.
type Outcome = (
    Result<String, (Code, String)>,
    Result<Vec<String>, (Code, String)>,
    Result<String, (Code, String)>,
    Result<String, (Code, String)>,
);

fn flatten(status: Status) -> (Code, String) {
    (status.code, status.message)
}

/// Once the server is up: it binds inside its own task, so the first
/// attempts may land before it does.
async fn connect(port: u16) -> GrpcClient<PlainText> {
    let origin = format!("http://127.0.0.1:{port}");
    let uri = origin.parse().unwrap();
    let client = client::PlainTextClient::plaintext::<ClientRing>();
    for _ in 0..50 {
        if client.preconnect(&uri).await.is_ok() {
            return GrpcClient::new(client, &origin).expect("an http origin");
        }
        Sleep::during(Duration::from_millis(20)).await;
    }
    panic!("the server never came up");
}

#[test]
fn the_client_and_the_server_agree_over_a_real_socket() {
    let port = pick_port();
    let (done_tx, done_rx) = mpsc::channel::<Outcome>();

    // Detached: the accept loop runs until the process ends.
    thread::spawn(move || {
        main_thread_with::<ServerRing, _>(async move {
            let settings = ServerSettings::new(([127, 0, 0, 1], port), ServerTransport::Plain);
            let _ = Server::new(settings)
                .run::<ServerRing, _>(service(route, not_grpc))
                .await;
        });
    });

    let client = thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
            let grpc = connect(port).await;

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

            let streamed = async {
                let call = grpc
                    .call(STREAM)
                    .await
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

/// §8.1: a status followed by RST_STREAM(NO_ERROR) is a response the client
/// keeps, not a failure of the stream.
#[test]
fn a_status_sent_before_the_upload_ends_is_the_one_reported() {
    let port = pick_port();
    let (done_tx, done_rx) = mpsc::channel::<(Code, String)>();

    thread::spawn(move || {
        main_thread_with::<ServerRing, _>(async move {
            let settings = ServerSettings::new(([127, 0, 0, 1], port), ServerTransport::Plain);
            let _ = Server::new(settings)
                .run::<ServerRing, _>(service(route, not_grpc))
                .await;
        });
    });

    let client = thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
            let grpc = connect(port).await;

            let call = grpc.call(REJECTS).await.expect("a call");
            call.write_message(&HelloRequest {
                name: "first of many".into(),
            })
            .await
            .expect("the first message went out");
            // Long enough for the status and the reset behind it to arrive
            // while the upload is, as far as the client knows, still going.
            Sleep::during(Duration::from_millis(200)).await;

            done_tx
                .send(flatten(call.status().await))
                .expect("the test is listening");
        });
    });

    let status = done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the client reports");
    client.join().expect("client thread");

    assert_eq!(
        status,
        (Code::InvalidArgument, "rejected on sight".to_owned()),
        "the server's own status, not the reset that followed it"
    );
}
