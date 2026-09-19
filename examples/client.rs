//! Opens one HTTP/2 connection and reports what the server said it accepts.
//!
//!     cargo run --release --example bench_server          # in one terminal
//!     cargo run --release --example client                # in another
//!
//! `ADDR` overrides the default of `127.0.0.1:8080`, so this also points at
//! anything else speaking cleartext h2 with prior knowledge.

use std::net::SocketAddr;

use popple_h2::client;
use runtime::main_thread_with;

// Smaller than the server's: a client holding one connection has nothing to
// share the ring with.
runtime::define_buf_ring!(ClientRing, bgid = 1, buffer_size = 16384, ring_size = 64);

fn main() {
    let addr: SocketAddr = std::env::var("ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8080".into())
        .parse()
        .expect("ADDR must be host:port");

    main_thread_with::<ClientRing, _>(async move {
        match client::connect::<ClientRing>(addr).await {
            Ok(conn) => {
                let peer = conn.peer_settings();
                println!("connected to {addr}");
                println!("  the server accepts:");
                println!("    max_concurrent_streams  {:?}", peer.max_concurrent_streams);
                println!("    initial_window_size     {}", peer.initial_window_size);
                println!("    max_frame_size          {}", peer.max_frame_size);
                println!("    max_header_list_size    {:?}", peer.max_header_list_size);
                println!("    header_table_size       {}", peer.header_table_size);
                println!("    enable_push             {}", peer.enable_push);
            }
            Err(e) => eprintln!("could not connect to {addr}: {e}"),
        }
    });
}
