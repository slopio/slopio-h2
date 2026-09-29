//! `examples/server.rs` with the two knobs a benchmark needs: the port, and
//! the geometry of the buffer ring every inbound read lands in.
//!
//!     RING=64x128+512 PER_CORE=1 taskset -c 0,1 cargo run --release --example bench_server

use http::{HeaderMap, StatusCode};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::net::BufRingSpec;
use runtime::{main_thread_with, thread_per_core_with};

// Only the ring actually selected is ever installed: each of these is its own
// type with its own thread-local.
runtime::define_buf_ring!(Ring64x512, bgid = 1, buffer_size = 65536, ring_size = 512);
runtime::define_buf_ring!(Ring64x16, bgid = 1, buffer_size = 65536, ring_size = 16);
runtime::define_buf_ring!(Ring64x64, bgid = 1, buffer_size = 65536, ring_size = 64);
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
    let settings = ServerSettings::new(([0, 0, 0, 0], port), ServerTransport::Plain);
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

/// 64 KiB because that is the default stream window — past it a response
/// needs a WINDOW_UPDATE to finish, which is a different thing to measure.
static FILLER: [u8; 64 * 1024] = [b'x'; 64 * 1024];

fn requested_size(path: Option<&str>) -> Option<usize> {
    let n: usize = path?.strip_prefix('/')?.parse().ok()?;
    (n > 0).then(|| n.min(FILLER.len()))
}

async fn bench_route(stream: Stream) {
    let received = if stream.body_is_oneshot() {
        // No credit goes back while it fills.
        stream.body(usize::MAX).await.map_or(0, |body| body.len())
    } else {
        // Taking bytes is what hands the peer its credit back, so a handler
        // that stops taking is a handler that stops the upload.
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
