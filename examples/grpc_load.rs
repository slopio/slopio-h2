//! A load generator for `helloworld.Greeter/SayHello`, built on our own gRPC
//! client.
//!
//!     taskset -c 0 cargo run --release --example helloworld_server
//!     taskset -c 1 cargo run --release --example grpc_load
//!
//! Two cores, two processes, and never the same core: a client sharing a core
//! with the server it is measuring measures the pair of them, and the number
//! that comes out is not the server's.
//!
//! What it reports is what a load generator owes its reader — how many calls
//! completed, how long they took at the percentiles that matter, and what the
//! ones that failed said. A throughput figure with no latency beside it says
//! nothing about whether the server was keeping up or simply queuing.
//!
//! | variable | default | what it does |
//! |---|---|---|
//! | `ADDR` | `127.0.0.1:8080` | where the server is |
//! | `CONNECTIONS` | 1 | how many HTTP/2 connections to open |
//! | `CONCURRENCY` | 32 | calls in flight per connection |
//! | `DURATION` | 5 | seconds to keep it up |
//! | `PER_CORE` | off | one generator per core of the affinity mask |
//!
//! Calls in flight are bounded by the peer's `SETTINGS_MAX_CONCURRENT_STREAMS`
//! (§5.1.2), which this reads and clamps to rather than discovering by being
//! refused: a generator that spent its time being told to wait would be
//! measuring its own impatience.
//!
//! # Which side did you measure?
//!
//! Watch the *server's* CPU, not this one's. A number taken while the server
//! had a core to spare is this generator's ceiling wearing the server's name.
//!
//!     PID=$(pgrep -f '[h]elloworld_server')
//!     awk '{print $14+$15}' /proc/$PID/stat   # before and after, in ticks
//!
//! On a 10-core box, loopback, one connection of 32 in flight: 317k calls/s
//! with the server at 70% of its core — so the generator was the limit.
//! Four connections of 16 reached 588k with the server still at 70%. Two
//! generator cores against two server workers reached 717k, and the server's
//! two workers were using 92% of a core *between them* — under half a core
//! each, and still not the thing that was full. Our client costs more per
//! call than our server does, which is worth knowing before reading any of
//! these numbers as the server's answer.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::{Duration, Instant};

use popple_h2::client;
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

/// Every call's outcome, kept as it happens and read once at the end.
///
/// A `Vec` of durations rather than a histogram: any percentile can be taken
/// afterwards, rather than the ones a bucket layout decided in advance.
///
/// It costs 16 bytes a call, which at 650k calls/s is 10 MB a second — a
/// minute-long run is a gigabyte, and the reason `DURATION` defaults to five.
/// Sorted in place rather than copied, because copying it at the end is how
/// a measurement doubles its own peak.
#[derive(Default)]
struct Outcomes {
    latencies: Vec<Duration>,
    /// Failures by code, since a load test that fails fast looks exactly like
    /// one that is very quick until the codes are read.
    failures: Vec<(Code, String)>,
}

async fn run(settings: Settings) {
    let outcomes = Rc::new(RefCell::new(Outcomes::default()));
    let mut workers = Vec::new();
    let started = Instant::now();
    let deadline = started + settings.duration;

    for n in 0..settings.connections {
        let client = match client::connect::<LoadRing>(settings.addr).await {
            Ok(client) => client,
            Err(e) => return eprintln!("connection {n}: {e}"),
        };

        // §5.1.2: the peer's limit is the peer's to set. Asking for more in
        // flight than it allows earns a refusal per call, which would be a
        // measurement of nothing.
        let allowed = client
            .peer_settings()
            .max_concurrent_streams
            .unwrap_or(u32::MAX) as usize;
        let concurrency = settings.concurrency.min(allowed);
        if n == 0 && concurrency < settings.concurrency {
            println!(
                "  the server allows {allowed} streams per connection; using that instead of {}",
                settings.concurrency
            );
        }

        let grpc = Rc::new(GrpcClient::new(client));
        for _ in 0..concurrency {
            let grpc = Rc::clone(&grpc);
            let outcomes = Rc::clone(&outcomes);
            workers.push(runtime::spawn(async move {
                // One call at a time per worker: the concurrency is the
                // number of workers, so that a slow call holds exactly one
                // of them and the in-flight count is the number asked for.
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
                            // A failing server answers far faster than a
                            // working one, and a tight loop against it would
                            // fill memory with the same message.
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
            // The nearest-rank percentile: the smallest sample with at least
            // that share of the run at or below it.
            let index = ((completed as f64 * at).ceil() as usize).clamp(1, completed) - 1;
            println!("  {label:>6}  {:?}", latencies[index]);
        }
        println!("  {:>6}  {:?}", "max", latencies[completed - 1]);
    }

    // Grouped, because ten thousand copies of one message is one fact.
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
