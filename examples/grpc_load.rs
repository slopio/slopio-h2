//! A load generator for `helloworld.Greeter/SayHello`, built on our own gRPC
//! client.
//!
//!     taskset -c 0 cargo run --release --example helloworld_server
//!     taskset -c 1 cargo run --release --example grpc_load

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use popple_h2::client::PlainTextClient;
use popple_h2::grpc::{Code, GrpcClient};
use runtime::{main_thread_with, thread_per_core_with};

runtime::define_buf_ring!(LoadRing, bgid = 0, buffer_size = 16384, ring_size = 1024);

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

const PATH: &str = "/helloworld.Greeter/SayHello";

struct Settings {
    addr: SocketAddr,
    connections: usize,
    concurrency: usize,
    duration: Duration,
}

fn env<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let settings = Settings {
        addr: env(
            "ADDR",
            "127.0.0.1:8080".parse().expect("a default that parses"),
        ),
        connections: env("CONNECTIONS", 1),
        concurrency: env("CONCURRENCY", 32),
        duration: Duration::from_secs(env("DURATION", 5)),
    };

    println!(
        "{} connections × {} calls in flight, {:?}, against {}",
        settings.connections, settings.concurrency, settings.duration, settings.addr,
    );

    match std::env::var("PER_CORE").is_ok_and(|v| v != "0") {
        true => thread_per_core_with::<LoadRing, _>(move |_| {
            let settings = Settings { ..settings };
            Box::pin(run(settings))
        }),
        false => main_thread_with::<LoadRing, _>(run(settings)),
    }
}

#[derive(Default)]
struct Outcomes {
    latencies: Vec<Duration>,
    failures: Vec<(Code, String)>,
}

async fn run(settings: Settings) {
    let outcomes = Rc::new(RefCell::new(Outcomes::default()));
    let mut workers = Vec::new();
    let started = Instant::now();
    let deadline = started + settings.duration;

    let origin = format!("http://{}", settings.addr);
    let uri = origin.parse().expect("an origin");
    for n in 0..settings.connections {
        // A client each, held to one connection: one client would spread the
        // calls as it saw fit, and this measures a fixed number of them. Calls
        // past the server's `max_concurrent_streams` (§5.1.2) are refused,
        // and counted as failures.
        let client = PlainTextClient::plaintext::<LoadRing>().with_max_connections(1);
        if let Err(e) = client.preconnect(&uri).await {
            return eprintln!("connection {n}: {e}");
        }

        let grpc = Rc::new(GrpcClient::new(client, &origin).expect("an http origin"));
        for _ in 0..settings.concurrency {
            let grpc = Rc::clone(&grpc);
            let outcomes = Rc::clone(&outcomes);
            workers.push(runtime::spawn(async move {
                let request = HelloRequest {
                    name: "world".into(),
                };
                while Instant::now() < deadline {
                    let at = Instant::now();
                    let outcome = grpc.unary::<_, HelloReply>(PATH, &request).await;
                    let took = at.elapsed();

                    let mut outcomes = outcomes.borrow_mut();
                    match outcome {
                        Ok(_) => outcomes.latencies.push(took),
                        Err(status) => {
                            outcomes.failures.push((status.code, status.message));
                            // A failing server answers fast: cap what is kept,
                            // or a tight loop fills memory.
                            if outcomes.failures.len() > 10_000 {
                                return;
                            }
                        }
                    }
                }
            }));
        }
    }

    for worker in workers {
        worker.await;
    }
    report(&mut outcomes.borrow_mut(), started.elapsed());
}

fn report(outcomes: &mut Outcomes, elapsed: Duration) {
    let latencies = &mut outcomes.latencies;
    latencies.sort_unstable();

    let completed = latencies.len();
    let failed = outcomes.failures.len();
    println!("\n{completed} calls in {elapsed:.2?}, {failed} failed");

    if completed > 0 {
        let rate = completed as f64 / elapsed.as_secs_f64();
        println!("  {rate:.0} calls/s");
        for (label, at) in [
            ("p50", 0.50),
            ("p90", 0.90),
            ("p99", 0.99),
            ("p99.9", 0.999),
        ] {
            let index = ((completed as f64 * at).ceil() as usize).clamp(1, completed) - 1;
            println!("  {label:>6}  {:?}", latencies[index]);
        }
        println!("  {:>6}  {:?}", "max", latencies[completed - 1]);
    }

    if failed > 0 {
        let mut by_code: Vec<(Code, String, usize)> = Vec::new();
        for (code, message) in &outcomes.failures {
            match by_code
                .iter_mut()
                .find(|(seen, said, _)| seen == code && said == message)
            {
                Some((_, _, count)) => *count += 1,
                None => by_code.push((*code, message.clone(), 1)),
            }
        }
        println!("\nfailures:");
        for (code, message, count) in by_code {
            println!("  {count:>8} × {code:?}: {message}");
        }
    }
}
