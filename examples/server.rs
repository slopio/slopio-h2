//! The smallest server that accepts HTTP/2 connections.
//!
//! Cleartext (h2c) on 8080. HTTP/2 without TLS is prior-knowledge only — the
//! client sends the connection preface as its first bytes, which is what
//! `--http2-prior-knowledge` does:
//!
//!     cargo run --example server
//!     curl --http2-prior-knowledge http://localhost:8080/ -v
//!
//! The handler is an `async fn` taking a [`Stream`]: one call per request, and
//! it owns that stream until it returns. Everything under it — accepting the
//! socket, the preface, the frame loop, flow control, retiring the stream — is
//! the library's, and none of it appears here.
//!
//! `PER_CORE=1` runs one worker per core of the affinity mask, worker `n`
//! pinned to core `n` — so under `taskset -c 0,1`, cores 0 and 1.

use http::{HeaderMap, StatusCode};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::main_thread_with;

// 64 KiB buffers × 512, 128 of them in the ring at once — where every inbound
// read lands.
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
//
// Those 512 are the pool, not the ring. The kernel takes ring entries in
// order, so a ring of 512 walks all 32 MiB before it reuses a byte of it. With
// `ring_size = 128` it sees 128 buffers, the rest wait in a reserve that hands
// back the one released last, and the headroom above is still there for
// whoever holds a buffer. Against a plain ring of 512 this measured the same
// request rate and 7 MB of peak RSS for 10 on small requests.
//
// Not smaller than that: `ring_size` is how many sockets the kernel can serve
// between two submits, reserve or no reserve. At 20 000 connections a ring of
// 64 started closing them and a ring of 16 kept 150 (`bench_server` has the
// table). `bgid` must be below 4.
runtime::define_buf_ring!(
    MyBufRing,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 128,
    pool_size = 512
);

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
    if let Err(e) = Server::new(settings).run::<MyBufRing, _>(hello).await {
        eprintln!("server error: {e}");
    }
}

/// One exchange, and the whole shape of a handler.
///
/// The head first, then the body: DATA on a stream whose peer has had no
/// HEADERS is a stream the peer cannot make sense of. `end_stream` goes on the
/// last thing written, which is what §8.1 means by the message ending — here
/// the body, but it would be the head for a response that has none.
///
/// Returning is what ends the server's half (§5.1): the stream is dropped, and
/// its token retires it. A handler that returns without answering gets a `500`
/// written for it rather than leaving the peer waiting.
async fn hello(stream: Stream) {
    // A request body, if there is one. `body_is_oneshot` is the request's
    // `content-length` deciding which contract applies: small enough to hand
    // over whole, or large enough that it has to be drained as it arrives.
    let body = match stream.body_is_oneshot() {
        true => stream.body().await.map_or(0, |bytes| bytes.len()),
        false => {
            let mut total = 0;
            while stream.readable().await {
                let taken = stream.peek(|bytes| bytes.len());
                // Taking the bytes is what credits the peer for them, so a
                // handler that stops consuming is a handler that stops the
                // upload (§6.9.1).
                stream.consume(taken);
                total += taken;
            }
            total
        }
    };

    let greeting = format!(
        "{} {} — {body} bytes of body\n",
        stream.method().map_or("?", |m| m.as_str()),
        stream.path().unwrap_or("?"),
    );

    stream.write_headers(StatusCode::OK, &HeaderMap::new());
    stream.write_data_final(greeting.as_bytes()).await;
}
