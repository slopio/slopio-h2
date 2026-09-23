//! What an accepted connection costs before any HTTP/2 exists — the floor to
//! measure a real connection's RSS against.
//!
//!     MODE=hold cargo run --release --example accept_only   # accept + spawn
//!     MODE=recv cargo run --release --example accept_only   # + arm MultiRecv

use runtime::net::{MultiAccept, MultiRecv};
use runtime::{spawn, thread_per_core_with};
use runtime_streams::StreamExt;

// The geometry `examples/server.rs` ships, so the floor is measured on it.
runtime::define_buf_ring!(
    Ring,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 128,
    pool_size = 512
);

fn main() {
    let mode = std::env::var("MODE").unwrap_or_else(|_| "recv".into());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8082);
    println!("accept_only mode={mode} port={port}");
    thread_per_core_with::<Ring, _>(move |_| {
        let mode = mode.clone();
        Box::pin(serve(port, mode))
    });
}

async fn serve(port: u16, mode: String) {
    let mut acceptor = MultiAccept::new(port).expect("bind");
    while let Some(socket) = acceptor.next().await {
        match mode.as_str() {
            "hold" => spawn(async move {
                let _socket = socket;
                std::future::pending::<()>().await;
            }),
            // What `PlainMessages::new` does.
            _ => spawn(async move {
                let mut recv = MultiRecv::<Ring>::new(socket);
                while let Some(chunk) = recv.next().await {
                    drop(chunk);
                }
            }),
        };
    }
}
