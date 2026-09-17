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

// 16 KiB buffers × 2048 slots — the ring every inbound read lands in.
runtime::define_buf_ring!(MyBufRing, bgid = 1, buffer_size = 16384, ring_size = 2048);

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
