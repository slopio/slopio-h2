//! A client that gives up on calls at random moments, against a real server.
//!
//! Cancelling is ordinary: a deadline passes, a user navigates away, one of
//! two hedged calls comes back first. §8.1 spells it RST_STREAM CANCEL, and
//! dropping a [`Call`] is how this client sends one. What the server must do
//! is stop working, forget the stream, and go on serving the calls beside it
//! — while it may well be part way through writing a response into a stream
//! that no longer exists.
//!
//! Two things are under test, and the second is a limit rather than a
//! success. Rapid Reset (CVE-2023-44487) is open-and-cancel in a loop, and
//! the defence against it counts resets: past `FAULT_LIMIT` — a hundred, for
//! the life of a connection — the server sends GOAWAY ENHANCE_YOUR_CALM. A
//! client that legitimately cancels a hundred calls on one long-lived
//! connection meets the same wall, which the constant's own comment says out
//! loud. This pins that behaviour so that a change to it is a decision and
//! not a surprise.
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
/// writing, which is the case worth testing rather than the tidy one.
const MESSAGES: usize = 20;

/// Cancellations the first half makes: enough to prove a reset is ordinary,
/// far enough below `FAULT_LIMIT` that no seed can reach it.
const CANCELLATIONS: usize = 60;

/// Whatever `FAULT_LIMIT` is over in `server::connection::protocol` — not
/// reachable from an integration test, so it is named here and checked
/// loosely.
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

/// xorshift64*, so that "at random" is the same run twice.
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

/// What the client made of a run, as plain data the test thread can hold.
#[derive(Debug, Default)]
struct Run {
    finished: usize,
    cancelled: usize,
    /// Calls that were meant to finish and did not.
    broken: Vec<String>,
    live_streams_at_end: usize,
    connection_closed: bool,
    /// Whether one last call worked once the chaos was over.
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

            // Driven by the number of *cancellations*, not of calls: this
            // half has to stay well under `FAULT_LIMIT`, and at roughly one
            // call in two being abandoned a fixed call count would drift
            // towards the wall on some seeds and fail for a reason that is
            // not the one under test.
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

                // Where to give up, if at all: before the head, after it, or
                // part way through the messages.
                match rng.below(4) {
                    // Three calls in four are read to the end.
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
                                // Read to the end, so the status is owed.
                                let status = call.status().await;
                                match status.is_ok() {
                                    true => run.finished += 1,
                                    false => run.broken.push(format!("{status:?}")),
                                }
                            }
                            // Stopped part way and walked away: a cancel.
                            None => {
                                run.cancelled += 1;
                                drop(call);
                            }
                        }
                    }
                }
            }

            // The chaos is over. Is this still a connection?
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
    // Printed under `--nocapture`, so that a passing run can still be read.
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

/// The other side of the same coin: past a hundred resets the server stops
/// believing in this client, whatever its reasons were.
///
/// Rapid Reset is open-and-cancel in a loop, and counting resets is what
/// catches it. The cost is that a long-lived connection which legitimately
/// cancels a hundred calls meets the same GOAWAY — the count is for the life
/// of the connection, not a rate. This asserts the behaviour as it is; a rate
/// would let an honest client keep going, and is what the constant's comment
/// says it wants to become.
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
                        // Opened and abandoned, which is the shape of the
                        // attack and of an impatient client alike.
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
