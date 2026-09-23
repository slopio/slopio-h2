//! Rapid Reset (CVE-2023-44487): the server counts resets against the streams
//! it has *finished*, not against a lifetime ceiling.
//!
//! Random, but seeded: a failure here reproduces. `SEED` overrides it.

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
struct Request {
    #[prost(string, tag = "1")]
    name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct Reply {
    #[prost(string, tag = "1")]
    message: String,
}

const STREAM: &str = "/test.Chaos/Stream";
const UNARY: &str = "/test.Chaos/Unary";

/// Enough messages that a cancellation lands while the server is still
/// writing.
const MESSAGES: usize = 20;

/// Far enough below `FAULT_LIMIT` that no seed can reach it.
const CANCELLATIONS: usize = 60;

/// `FAULT_LIMIT` in `server::connection::protocol`, not reachable from an
/// integration test: how far resets may run ahead of completed streams.
const FAULT_LIMIT: usize = 100;

async fn route(call: &GrpcCall) -> Status {
    match call.path() {
        Some(UNARY) => {
            call.write_message(&Reply {
                message: "one".into(),
            })
            .await;
            Status::ok()
        }
        Some(STREAM) => {
            for n in 0..MESSAGES {
                call.write_message(&Reply {
                    message: format!("message {n}"),
                })
                .await;
            }
            Status::ok()
        }
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

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn serve(port: u16) {
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
}

async fn connect(port: u16) -> client::Client {
    let addr = format!("127.0.0.1:{port}").parse().unwrap();
    for _ in 0..50 {
        if let Ok(client) = client::connect::<ClientRing>(addr).await {
            return client;
        }
        Sleep::during(Duration::from_millis(20)).await;
    }
    panic!("the server never came up");
}

#[derive(Debug, Default)]
struct Run {
    finished: usize,
    cancelled: usize,
    broken: Vec<String>,
    live_streams_at_end: usize,
    connection_closed: bool,
    still_usable: bool,
}

#[test]
fn cancelling_calls_at_random_leaves_the_connection_working() {
    let port = pick_port();
    serve(port);
    let seed: u64 = std::env::var("SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0x5ee_d10ad);
    let (tx, rx) = mpsc::channel::<Run>();

    thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
            let inner = connect(port).await;
            let grpc = GrpcClient::new(inner);
            let mut rng = Rng(seed);
            let mut run = Run::default();

            // Driven by the number of *cancellations*, not of calls: a fixed
            // call count would drift towards `FAULT_LIMIT` on some seeds.
            while run.cancelled < CANCELLATIONS {
                let call = match grpc.call(STREAM) {
                    Ok(call) => call,
                    Err(e) => {
                        run.broken.push(format!("could not open: {e}"));
                        break;
                    }
                };
                if call.write_message_final(&Request::default()).await.is_err() {
                    run.broken.push("the request would not go".into());
                    break;
                }

                match rng.below(4) {
                    0 => {
                        run.cancelled += 1;
                        drop(call); // §8.1: RST_STREAM CANCEL
                    }
                    n => {
                        let read_before_giving_up = match n {
                            1 => rng.below(MESSAGES as u64) as usize,
                            _ => MESSAGES,
                        };
                        let mut seen = 0;
                        let mut failed = None;
                        while seen < read_before_giving_up {
                            match call.message::<Reply>().await {
                                Ok(Some(_)) => seen += 1,
                                Ok(None) => break,
                                Err(status) => {
                                    failed = Some(format!("{status:?}"));
                                    break;
                                }
                            }
                        }
                        match failed {
                            Some(why) => run.broken.push(why),
                            None if seen == MESSAGES => {
                                let status = call.status().await;
                                match status.is_ok() {
                                    true => run.finished += 1,
                                    false => run.broken.push(format!("{status:?}")),
                                }
                            }
                            None => {
                                run.cancelled += 1;
                                drop(call);
                            }
                        }
                    }
                }
            }

            run.live_streams_at_end = grpc.connection().live_streams();
            run.connection_closed = grpc.connection().is_closed();
            run.still_usable = grpc
                .unary::<_, Reply>(UNARY, &Request::default())
                .await
                .is_ok();

            tx.send(run).unwrap();
        });
    });

    let run = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("the client reports");
    eprintln!("{run:?}");

    assert!(
        run.broken.is_empty(),
        "calls that were meant to finish did not: {:?}",
        run.broken
    );
    assert_eq!(
        run.cancelled, CANCELLATIONS,
        "the run cancelled what it set out to: {run:?}"
    );
    assert!(
        run.cancelled < FAULT_LIMIT,
        "and stayed under the server's limit: {run:?}"
    );
    assert!(
        run.finished > 20,
        "with plenty finishing beside them: {run:?}"
    );

    assert_eq!(
        run.live_streams_at_end, 0,
        "every cancelled stream left the client's map: {run:?}"
    );
    assert!(!run.connection_closed, "the connection survived: {run:?}");
    assert!(
        run.still_usable,
        "and still answers a call afterwards: {run:?}"
    );
}

/// The attack itself: open, cancel, repeat, and never finish anything. The
/// case the defence exists for, and not to be softened by letting honest
/// clients through.
#[test]
fn a_hundred_cancellations_end_the_connection() {
    let port = pick_port();
    serve(port);
    let (tx, rx) = mpsc::channel::<(usize, Option<Code>)>();

    thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
            let grpc = GrpcClient::new(connect(port).await);

            let mut cancelled = 0;
            let refused = loop {
                if cancelled > FAULT_LIMIT * 2 {
                    break None;
                }
                match grpc.call(STREAM) {
                    Ok(call) => {
                        let _ = call.write_message_final(&Request::default()).await;
                        cancelled += 1;
                        drop(call);
                    }
                    Err(_) => break Some(Code::Unavailable),
                }
                // Let the loop carry the frames, so the resets reach the
                // server rather than piling up in one flush.
                if cancelled % 8 == 0 {
                    Sleep::during(Duration::from_millis(10)).await;
                }
            };

            let refused = match refused {
                Some(code) => Some(code),
                // The connection may instead die while a call is in flight.
                None => grpc
                    .unary::<_, Reply>(UNARY, &Request::default())
                    .await
                    .err()
                    .map(|status| status.code),
            };
            tx.send((cancelled, refused)).unwrap();
        });
    });

    let (cancelled, refused) = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("the client reports");

    eprintln!("refused after {cancelled} cancellations: {refused:?}");
    assert_eq!(
        refused,
        Some(Code::Unavailable),
        "the server gave up on us, and the client says so: after {cancelled} cancellations"
    );
    assert!(
        cancelled >= FAULT_LIMIT,
        "and not before a hundred of them: {cancelled}"
    );
}

#[test]
fn a_client_that_finishes_its_work_may_keep_cancelling() {
    let port = pick_port();
    serve(port);
    let (tx, rx) = mpsc::channel::<(usize, bool, bool)>();

    thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
            let grpc = GrpcClient::new(connect(port).await);
            let mut cancelled = 0;
            let mut failed = false;

            while cancelled < FAULT_LIMIT * 3 {
                if grpc
                    .unary::<_, Reply>(UNARY, &Request::default())
                    .await
                    .is_err()
                {
                    failed = true;
                    break;
                }
                match grpc.call(STREAM) {
                    Ok(call) => {
                        let _ = call.write_message_final(&Request::default()).await;
                        cancelled += 1;
                        drop(call);
                    }
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }

            let still_usable = grpc
                .unary::<_, Reply>(UNARY, &Request::default())
                .await
                .is_ok();
            tx.send((cancelled, failed, still_usable)).unwrap();
        });
    });

    let (cancelled, failed, still_usable) = rx
        .recv_timeout(Duration::from_secs(60))
        .expect("the client reports");

    assert!(!failed, "nothing refused it: {cancelled} cancellations in");
    assert_eq!(
        cancelled,
        FAULT_LIMIT * 3,
        "it cancelled three times the flat limit"
    );
    assert!(
        still_usable,
        "and the connection answers afterwards, having finished as much as it abandoned"
    );
}
