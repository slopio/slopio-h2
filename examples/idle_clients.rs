//! What a connection costs a server before it has served anything.
//!
//! Opens `N` connections, finishes their handshakes and holds them, so the
//! server's RSS delta over its own baseline, divided by `N`, is the cost of an
//! idle connection. That is the number [`accept_only`] asks for and never
//! provided a way to produce.
//!
//!     PORT=8090 cargo run --release --example bench_server &
//!     N=2000 ADDR=127.0.0.1:8090 cargo run --release --example idle_clients
//!
//! It measured 12.73 KiB before the HPACK arenas moved to one set per worker
//! and 8.78 after — reproducible to the byte across runs, and within a
//! rounding error of the 4 KiB the decoder used to allocate per connection at
//! birth. The staging arena is not in that figure: it is allocated at the
//! first header block, which an idle connection never sends.
//!
//! It is also the only thing that drives the client at this scale, which is
//! worth something on its own: 2000 connections, 2000 loop tasks, one thread.
//!
//! [`accept_only`]: ../accept_only/index.html

use std::net::SocketAddr;

use popple_h2::client;
use runtime::main_thread_with;

runtime::define_buf_ring!(IdleRing, bgid = 1, buffer_size = 16384, ring_size = 64);

fn main() {
    let addr: SocketAddr = std::env::var("ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8090".into())
        .parse()
        .expect("ADDR must be host:port");
    let n: usize = std::env::var("N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);

    main_thread_with::<IdleRing, _>(async move {
        let mut held = Vec::with_capacity(n);
        for i in 0..n {
            match client::connect::<IdleRing>(addr).await {
                Ok(client) => held.push(client),
                Err(e) => {
                    eprintln!("connection {i} failed: {e}");
                    break;
                }
            }
        }
        println!("{} connections up and idle", held.len());
        // Held, not dropped: dropping the last handle is what ends a
        // connection, and the point is to keep the server holding them.
        std::future::pending::<()>().await;
    });
}
