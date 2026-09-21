//! `examples/server.rs` with the two knobs a benchmark needs: the port, and
//! the geometry of the buffer ring every inbound read lands in.
//!
//!     RING=64x128+512 PER_CORE=1 taskset -c 0,1 cargo run --release --example bench_server
//!
//! The ring matters here in a way it does not in the plain example. A buffer
//! is pinned from the moment its CQE arrives to the moment the loop recycles
//! it, so the slot count bounds how many connections can have unread data at
//! once, not how many can be open. Run out and the multishot recv completes
//! ENOBUFS, which this runtime does not treat as resubmittable — the
//! connection dies. `RING` is here so that a connection count that outgrows
//! the shipped 512 buffers can be told apart from a connection count that
//! outgrows the server.
//!
//! `PORT` defaults to 8080, `RING` to the `64x128+512` the plain example ships:
//! 64 KiB buffers, a ring of 128, a pool of 512 behind it (`pool_size`).
//!
//! The routes are at the bottom of this file rather than in the library: they
//! exist for `bench/run.sh` and for nothing else, and one of them allocates per
//! request, which is a thing a benchmark's reader should be able to see.

use http::{HeaderMap, StatusCode};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::net::BufRingSpec;
use runtime::{main_thread_with, thread_per_core_with};

// Only the ring actually selected is ever installed: each of these is its own
// type with its own thread-local, and `init` runs on the one the server is
// instantiated with.
runtime::define_buf_ring!(Ring64x512, bgid = 1, buffer_size = 65536, ring_size = 512);
// The two small ones are a measurement, not a recommendation. The kernel takes
// ring buffers in order, so a recycled buffer waits behind every other one and
// a ring's whole size is its working set: 512 x 64 KiB is 32 MiB of memory
// that each inbound byte lands in cold. 16 KiB POSTs on two cores went from
// 211k req/s at `64x512` to ~450k at `64x16`, and peak RSS from 85 MB to 12 —
// while `GET /` lost 15% at `64x16`, which is too few buffers for 100
// connections.
runtime::define_buf_ring!(Ring64x16, bgid = 1, buffer_size = 65536, ring_size = 16);
runtime::define_buf_ring!(Ring64x64, bgid = 1, buffer_size = 65536, ring_size = 64);
// `pool_size` is the runtime's answer: a reserve behind the ring, so the
// kernel sees 16 or 64 buffers while 512 exist, and the reserve is a stack, so
// the buffer that goes back in is the one released last. Same load, three runs
// each, against `64x512` at 1.78-1.82M `GET /`, 219-238k POSTs and 85 MB:
//
//   64x64+512   1.68-1.83M   228-245k   70-76 MB   (GET peak RSS 7.6 MB, from 10.7)
//   64x16+512   1.43-1.49M   277-300k   33-35 MB
//
// That is 100 connections, and it flatters a small ring. The reserve stands in
// for buffers that are *held*; it does not widen what the kernel can serve
// between two submits, which is `ring_size` and nothing else. At 20 000
// connections every socket past the first `ring_size` reads ENOBUFS, and one
// that does so `MAX_DRY_READS` times running is closed — silently, and h2load
// in `-D` mode reports `0 failed` for it:
//
//                 2 cores, 20k          1 core, 20k
//   64x512        247-272k, all kept    155k, all kept
//   64x256+512    248-275k, all kept    133-141k, all kept
//   64x128+512    239-254k, all kept    141-149k, all kept
//   64x64+512     239-254k, all kept    114-118k, 462 closed in one run of two
//   64x16+512     ~150 connections left of 20 000
//
// `64x16+512`'s POST figure above is therefore not a reason to pick it. What
// ships is `64x128+512`: level with `64x512` at 100 connections on GET and
// POST, 7 MB of peak RSS for 10 on GETs, nothing closed at 20 000, and 4-9%
// under it on the one-core case, which is the price of the smaller ring.
runtime::define_buf_ring!(
    Ring64x16p512,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 16,
    pool_size = 512
);
runtime::define_buf_ring!(
    Ring64x64p512,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 64,
    pool_size = 512
);
runtime::define_buf_ring!(
    Ring64x128p512,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 128,
    pool_size = 512
);
runtime::define_buf_ring!(
    Ring64x256p512,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 256,
    pool_size = 512
);
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
    let ring = std::env::var("RING").unwrap_or_else(|_| "64x128+512".into());
    let per_core = std::env::var_os("PER_CORE").is_some();

    println!("popple-h2 on :{port}, ring {ring}, per_core={per_core}");

    match ring.as_str() {
        "64x512" => start::<Ring64x512>(port, per_core),
        "64x16" => start::<Ring64x16>(port, per_core),
        "64x64" => start::<Ring64x64>(port, per_core),
        "64x16+512" => start::<Ring64x16p512>(port, per_core),
        "64x64+512" => start::<Ring64x64p512>(port, per_core),
        "64x128+512" => start::<Ring64x128p512>(port, per_core),
        "64x256+512" => start::<Ring64x256p512>(port, per_core),
        "64x4096" => start::<Ring64x4096>(port, per_core),
        "16x4096" => start::<Ring16x4096>(port, per_core),
        "16x16384" => start::<Ring16x16384>(port, per_core),
        other => panic!(
            "unknown RING `{other}`: 64x16, 64x64, 64x16+512, 64x64+512, 64x128+512, \
             64x256+512, 64x512, 64x4096, 16x4096, 16x16384"
        ),
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

    stream.write_headers(StatusCode::OK, &HeaderMap::new());
    match requested_size(stream.path()) {
        Some(n) => stream.write_data_final(&FILLER[..n]).await,
        None => {
            let body = format!("read {received} bytes\n");
            stream.write_data_final(body.as_bytes()).await;
        }
    }
}
