//! `examples/server.rs` with the two knobs a benchmark needs: the port, and
//! the geometry of the buffer ring every inbound read lands in.
//!
//!     RING=64x512 PER_CORE=1 taskset -c 0,1 cargo run --release --example bench_server
//!
//! The ring matters here in a way it does not in the plain example. A buffer
//! is pinned from the moment its CQE arrives to the moment the loop recycles
//! it, so the slot count bounds how many connections can have unread data at
//! once, not how many can be open. Run out and the multishot recv completes
//! ENOBUFS, which this runtime does not treat as resubmittable — the
//! connection dies. `RING` is here so that a connection count that outgrows
//! the shipped 512 slots can be told apart from a connection count that
//! outgrows the server.
//!
//! `PORT` defaults to 8080, `RING` to the `64x512` the plain example ships.

use http::{HeaderMap, StatusCode};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::net::BufRingSpec;
use runtime::{main_thread_with, thread_per_core_with};

// Only the ring actually selected is ever installed: each of these is its own
// type with its own thread-local, and `init` runs on the one the server is
// instantiated with.
runtime::define_buf_ring!(Ring64x512, bgid = 1, buffer_size = 65536, ring_size = 512);
runtime::define_buf_ring!(Ring64x4096, bgid = 1, buffer_size = 65536, ring_size = 4096);
runtime::define_buf_ring!(Ring16x4096, bgid = 1, buffer_size = 16384, ring_size = 4096);
runtime::define_buf_ring!(
    Ring16x16384,
    bgid = 1,
    buffer_size = 16384,
    ring_size = 16384
);

fn main() {
    let port = env_u16("PORT", 8080);
    let ring = std::env::var("RING").unwrap_or_else(|_| "64x512".into());
    let per_core = std::env::var_os("PER_CORE").is_some();

    println!("popple-h2 on :{port}, ring {ring}, per_core={per_core}");

    match ring.as_str() {
        "64x512" => start::<Ring64x512>(port, per_core),
        "64x4096" => start::<Ring64x4096>(port, per_core),
        "16x4096" => start::<Ring16x4096>(port, per_core),
        "16x16384" => start::<Ring16x16384>(port, per_core),
        other => panic!("unknown RING `{other}`: 64x512, 64x4096, 16x4096, 16x16384"),
    }
}

fn start<U: BufRingSpec + 'static>(port: u16, per_core: bool) {
    if per_core {
        thread_per_core_with::<U, _>(move |_| Box::pin(serve::<U>(port)));
    } else {
        main_thread_with::<U, _>(serve::<U>(port));
    }
}

async fn serve<U: BufRingSpec + 'static>(port: u16) {
    let settings = ServerSettings {
        bind_port: port,
        transport: ServerTransport::Plain,
    };
    if let Err(e) = Server::new(settings).run::<U, _>(bench_route).await {
        eprintln!("server error: {e}");
    }
}

fn env_u16(name: &str, default: u16) -> u16 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Bytes a sized request is answered from.
///
/// Sliced, never allocated: a benchmark that asks for a 10 KiB body and gets a
/// `vec![]` per request is measuring the allocator. 64 KiB because that is the
/// default stream window — past it a response needs a WINDOW_UPDATE to finish,
/// which is a different thing to measure and wants asking for on purpose.
static FILLER: [u8; 64 * 1024] = [b'x'; 64 * 1024];

/// How many bytes `/<n>` asks for, if it asks for a number.
///
/// The size comes from the request rather than from the process, so one server
/// serves every payload a benchmark wants without being restarted, and the two
/// sides of a comparison are told what to send by the same URL. Anything else —
/// `/`, a real path — gets the echo below.
fn requested_size(path: Option<&str>) -> Option<usize> {
    let n: usize = path?.strip_prefix('/')?.parse().ok()?;
    (n > 0).then(|| n.min(FILLER.len()))
}

/// `200` and a body whose size the URL chose, after reading whatever the
/// request sent.
///
/// This lived in the library until the server took a handler, which is where
/// it belonged all along: the routes exist for `bench/run.sh` and for nothing
/// else. Note what the echo costs — a `format!` per request — and that the
/// sized route deliberately does not.
async fn bench_route(stream: Stream) {
    // The two body contracts, picked by the request's `content-length`.
    let received = if stream.body_is_oneshot() {
        // Small enough to hold: wait for all of it, take it in one piece. No
        // credit goes back while it fills — that is what this form buys.
        stream.body().await.map_or(0, |body| body.len())
    } else {
        // Too large, or of unknown length: drained as it arrives. Taking
        // bytes is what hands the peer its credit back, so a handler that
        // stops taking is a handler that stops the upload.
        let mut total = 0;
        while stream.readable().await {
            let taken = stream.peek(|bytes| bytes.len());
            stream.consume(taken);
            total += taken;
        }
        total
    };

    stream.respond(StatusCode::OK, &HeaderMap::new(), false);
    match requested_size(stream.path()) {
        Some(n) => stream.write(&FILLER[..n], true).await,
        None => {
            let body = format!("read {received} bytes\n");
            stream.write(body.as_bytes(), true).await;
        }
    }
}
