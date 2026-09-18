//! The tokio+h2 counterpart of popple-h2's `examples/server.rs`.
//!
//! It answers exactly what popple-h2's placeholder handler answers: drain the
//! request body, then `200` with `read {n} bytes\n` and no headers of its own.
//! Anything else — a `Date`, a `server`, a content-length — would be bytes on
//! the wire one side pays for and the other does not.
//!
//!     THREADS=2 PORT=8081 tokio-h2-bench
//!
//! `THREADS` is the tokio worker count, to be set to however many cores the
//! popple-h2 side is given.

use std::env;

use bytes::Bytes;
use h2::server;
use tokio::net::{TcpListener, TcpStream};

/// Matches what `runtime` installs on the popple-h2 side, so a memory
/// comparison is between two servers and not between two allocators.
#[cfg(feature = "mimalloc-global")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let threads: usize = env::var("THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()));
    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8081);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
        .unwrap();

    println!("tokio+h2 on :{port}, {threads} worker thread(s)");
    rt.block_on(serve(port));
}

async fn serve(port: u16) {
    let listener = TcpListener::bind(("0.0.0.0", port)).await.unwrap();
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                tokio::spawn(connection(socket));
            }
            Err(e) => eprintln!("accept: {e}"),
        }
    }
}

/// Nagle off, as io_uring sends on the popple-h2 side are not batched by the
/// kernel either. With it on, a one-frame response waits for an ack.
async fn connection(socket: TcpStream) {
    let _ = socket.set_nodelay(true);

    let mut conn = match server::handshake(socket).await {
        Ok(conn) => conn,
        Err(_) => return,
    };

    while let Some(request) = conn.accept().await {
        let (request, mut respond) = match request {
            Ok(pair) => pair,
            Err(_) => return,
        };

        // A task per stream, as popple-h2 spawns one per stream.
        tokio::spawn(async move {
            let mut body = request.into_body();
            let mut received = 0usize;
            while let Some(chunk) = body.data().await {
                let Ok(chunk) = chunk else { return };
                received += chunk.len();
                // Taking the bytes is what hands the peer its credit back.
                let _ = body.flow_control().release_capacity(chunk.len());
            }

            let response = http::Response::builder().status(200).body(()).unwrap();
            let Ok(mut stream) = respond.send_response(response, false) else {
                return;
            };
            let payload = Bytes::from(format!("read {received} bytes\n"));
            let _ = stream.send_data(payload, true);
        });
    }
}
