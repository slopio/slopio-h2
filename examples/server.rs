//! The smallest server that accepts HTTP/2 connections.
//!
//! Cleartext (h2c) on 8080. HTTP/2 without TLS is prior-knowledge only — the
//! client sends the connection preface as its first bytes, which is what
//! `--http2-prior-knowledge` does:
//!
//!     cargo run --example server
//!     curl --http2-prior-knowledge http://localhost:8080/ -v
//!
//! No handler yet: a connection is accepted, its transport and protocol
//! state are built, and `Connection::run` — the loop — is what remains.
//!
//! `PER_CORE=1` runs one worker per core of the affinity mask, worker `n`
//! pinned to core `n` — so under `taskset -c 0,1`, cores 0 and 1.

use popple_h2::server::{Server, ServerSettings, ServerTransport};
use runtime::main_thread_with;

// 64 KiB buffers × 512 slots — the ring every inbound read lands in.
//
// The buffer size is what a request body pays: a chunk is one dispatch
// through the decoder and one wake of the stream task, so four times the
// buffer is a quarter of the per-chunk cost. Measured on 1 MiB uploads, one
// core, ingest against buffer size: 3.09 GB/s at 4 KiB, 4.52 at 16 KiB, 5.41
// at 32 KiB, 6.20 at 64 KiB, 6.26 at 128 KiB — a knee at 64. Request rate on
// small responses is flat across all of them (1.80-1.83M req/s, four runs
// each), so this costs nothing on the other side.
//
// The slot count is what connections pay, and 32 MiB buys either. It is not
// the throughput knob: 64 KiB × 2048 measured the same ingest as × 512 for
// four times the memory. What it buys is headroom for connections that stop
// being read — a long `drain` leaves a connection's inbound CQEs unpopped,
// and each pins its buffer until the loop comes back. 512 slots served 512
// connections here with no ENOBUFS, because the loop recycles each chunk as
// soon as it is decoded.
runtime::define_buf_ring!(MyBufRing, bgid = 1, buffer_size = 65536, ring_size = 512);

fn main() {
    println!("listening on http://localhost:8080 (HTTP/2 cleartext, prior knowledge)");
    println!("try: curl --http2-prior-knowledge http://localhost:8080/ -v");

    if std::env::var_os("PER_CORE").is_some() {
        runtime::thread_per_core_with::<MyBufRing, _>(|_| Box::pin(serve()));
    } else {
        main_thread_with::<MyBufRing, _>(serve());
    }
}

async fn serve() {
    let settings = ServerSettings {
        bind_port: 8080,
        transport: ServerTransport::Plain,
    };
    if let Err(e) = Server::new(settings).run::<MyBufRing>().await {
        eprintln!("server error: {e}");
    }
}
