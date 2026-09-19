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

    // Defaults match popple-h2: one listener per worker, 1024 backlog each.
    let listeners: usize = env::var("LISTENERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(threads);
    let backlog: i32 = env::var("BACKLOG")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024);

    println!("tokio+h2 on :{port}, {threads} worker(s), {listeners} listener(s), backlog {backlog}");
    rt.block_on(serve(port, listeners, backlog));
}

/// One `SO_REUSEPORT` listener per accept task, with an explicit backlog.
///
/// Not a detail: popple-h2's `MultiAccept` sets `SO_REUSEPORT` and binds one
/// listener per worker, so a single-listener tokio is being compared on accept
/// capacity as much as on request handling. At 20 000 connections that showed
/// up as 68 462 `ListenOverflows` against popple's 4 903, and the dropped SYNs
/// come back as client retransmit backoff — a 7s tail that has nothing to do
/// with how fast a request is served.
fn listener_for(port: u16, backlog: i32) -> TcpListener {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    socket.set_reuse_address(true).unwrap();
    socket.set_reuse_port(true).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket
        .bind(&std::net::SocketAddr::from(([0, 0, 0, 0], port)).into())
        .unwrap();
    socket.listen(backlog).unwrap();
    TcpListener::from_std(std::net::TcpListener::from(socket)).unwrap()
}

async fn serve(port: u16, listeners: usize, backlog: i32) {
    for _ in 0..listeners {
        let listener = listener_for(port, backlog);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, _)) => {
                        tokio::spawn(connection(socket));
                    }
                    Err(e) => eprintln!("accept: {e}"),
                }
            }
        });
    }
    std::future::pending::<()>().await
}

/// Bytes a sized request is answered from. Sliced, never allocated — the same
/// reasoning as the popple-h2 side, and the same 64 KiB for the same reason.
static FILLER: [u8; 64 * 1024] = [b'x'; 64 * 1024];

/// How many bytes `/<n>` asks for, if it asks for a number.
///
/// Matches popple-h2 exactly, so a payload sweep points both servers at the
/// same URL and varies one thing.
fn requested_size(path: &str) -> Option<usize> {
    let n: usize = path.strip_prefix('/')?.parse().ok()?;
    (n > 0).then(|| n.min(FILLER.len()))
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
            let size = requested_size(request.uri().path());
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
            let payload = match size {
                Some(n) => Bytes::from_static(&FILLER[..n]),
                None => Bytes::from(format!("read {received} bytes\n")),
            };
            let _ = stream.send_data(payload, true);
        });
    }
}
