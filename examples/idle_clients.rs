//! What a connection costs a server before it has served anything.
//!
//!     PORT=8090 cargo run --release --example bench_server &
//!     N=2000 ADDR=127.0.0.1:8090 cargo run --release --example idle_clients

use std::net::SocketAddr;

use popple_h2::client::PlainTextClient;
use runtime::main_thread_with;

runtime::define_buf_ring!(IdleRing, bgid = 1, buffer_size = 16384, ring_size = 64);

fn main() {
    let addr: SocketAddr = std::env::var("ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8090".into())
        .parse()
        .expect("ADDR must be ip:port");
    let n: usize = std::env::var("N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    let uri: http::Uri = format!("http://{addr}/").parse().expect("a URI");

    main_thread_with::<IdleRing, _>(async move {
        // A client each: one client would share a single connection between
        // them all, which is the point of a client.
        let mut held = Vec::with_capacity(n);
        for i in 0..n {
            let client = PlainTextClient::plaintext::<IdleRing>();
            match client.preconnect(&uri).await {
                Ok(()) => held.push(client),
                Err(e) => {
                    eprintln!("connection {i} failed: {e}");
                    break;
                }
            }
        }
        println!("{} connections up and idle", held.len());
        // Held, not dropped: dropping a client is what ends its connection,
        // and the point is to keep the server holding them.
        std::future::pending::<()>().await;
    });
}
