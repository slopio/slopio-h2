//! The smallest server that accepts HTTP/2 connections.
//!
//!     cargo run --example server
//!     curl --http2-prior-knowledge http://localhost:8080/ -v

use http::{HeaderMap, StatusCode};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::main_thread_with;

// Not a smaller ring: `ring_size` is how many sockets the kernel can serve
// between two submits, reserve or no reserve. `bgid` must be below 4.
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
    let settings = ServerSettings::new(([0, 0, 0, 0], 8080), ServerTransport::Plain);
    if let Err(e) = Server::new(settings).run::<MyBufRing, _>(hello).await {
        eprintln!("server error: {e}");
    }
}

/// The head first, then the body: DATA on a stream whose peer has had no
/// HEADERS is a stream the peer cannot make sense of.
async fn hello(stream: Stream) {
    let body = match stream.body_is_oneshot() {
        true => stream.body().await.map_or(0, |bytes| bytes.len()),
        false => {
            let mut total = 0;
            while stream.readable().await {
                let taken = stream.peek(|bytes| bytes.len());
                // Taking the bytes is what credits the peer for them, so a
                // handler that stops consuming stops the upload (§6.9.1).
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
