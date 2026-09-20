//! What an accepted connection costs before any HTTP/2 exists — the floor to
//! measure a real connection's RSS against.
//!
//!     MODE=hold cargo run --release --example accept_only   # accept + spawn
//!     MODE=recv cargo run --release --example accept_only   # + arm MultiRecv
//!
//! `hold` spawns a task that owns the socket and parks forever. `recv` also
//! arms the multishot recv, which is the one other thing a real connection
//! does at birth. Drive either with 2000 idle sockets and the per-connection
//! cost is the RSS delta over the baseline.
//!
//! This is what found the HPACK encoder sizing bug: a connection that had
//! sent a preface and nothing else cost 211 KiB, where `hold` measured 0.16
//! KiB and `recv` 3.11 KiB. That gap said the runtime was not the problem and
//! sent the search into `SharedConnection::new`.
//!
//! An idle HTTP/2 connection costs **8.78 KiB** today, and cost 12.73 before
//! the HPACK arenas moved to one set per worker — both measured with
//! `examples/idle_clients`, which is the driver this file's method asks for. A
//! number far above that again means a new per-connection allocation, and the
//! two modes here say whether it is ours or the runtime's.

use runtime::net::{BufRingSpec, MultiAccept, MultiRecv};
use runtime::{spawn, thread_per_core_with};
use runtime_streams::StreamExt;

runtime::define_buf_ring!(Ring, bgid = 1, buffer_size = 65536, ring_size = 512);

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
            // Accept and spawn: the socket is owned by a parked task, no
            // io_uring operation armed on it.
            "hold" => spawn(async move {
                let _socket = socket;
                std::future::pending::<()>().await;
            }),
            // Accept, spawn, and arm the multishot recv — what
            // `PlainMessages::new` does.
            _ => spawn(async move {
                let mut recv = MultiRecv::<Ring>::new(socket);
                while let Some(chunk) = recv.next().await {
                    // Drop each chunk straight back to the ring; nothing is
                    // parsed and nothing is answered.
                    drop(chunk);
                }
            }),
        };
    }
}
