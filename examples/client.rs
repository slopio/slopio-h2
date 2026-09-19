//! Opens one HTTP/2 connection, makes a request on it and reads the response.
//!
//!     cargo run --release --example bench_server          # in one terminal
//!     cargo run --release --example client                # in another
//!
//! `ADDR` overrides the default of `127.0.0.1:8080` and `TARGET` the request
//! path, so this also points at anything else speaking cleartext h2 with
//! prior knowledge. `BODY` makes it a POST carrying that text, which is the
//! other half of the stream API:
//!
//!     BODY=hello TARGET=/echo cargo run --release --example client

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
    let path = std::env::var("TARGET").unwrap_or_else(|_| "/".into());
    let body = std::env::var("BODY").ok();

    main_thread_with::<ClientRing, _>(async move {
        let client = match client::connect::<ClientRing>(addr).await {
            Ok(client) => client,
            Err(e) => return eprintln!("could not connect to {addr}: {e}"),
        };

        let peer = client.peer_settings();
        println!("connected to {addr}");
        println!("  the server accepts:");
        println!(
            "    max_concurrent_streams  {:?}",
            peer.max_concurrent_streams
        );
        println!("    initial_window_size     {}", peer.initial_window_size);
        println!("    max_frame_size          {}", peer.max_frame_size);
        println!(
            "    max_header_list_size    {:?}",
            peer.max_header_list_size
        );
        println!("    header_table_size       {}", peer.header_table_size);
        println!("    enable_push             {}", peer.enable_push);

        // §8.1: with no body, the head ends the stream. With one, it does
        // not, and the last `write` is what does.
        let method = if body.is_some() { "POST" } else { "GET" };
        let request = http::Request::builder()
            .method(method)
            .uri(format!("http://localhost{path}"))
            .body(())
            .expect("a valid request");
        let stream = match client.send_request(&request, body.is_none()) {
            Ok(stream) => stream,
            Err(e) => return eprintln!("  no stream could be opened: {e}"),
        };
        println!("  sent a {method} on stream {}", u32::from(stream.id()));

        // In two writes, because a body does not have to be in one place to
        // be one message — each is its own DATA frame, and only the last
        // carries END_STREAM.
        if let Some(body) = &body {
            let (first, rest) = body.split_at(body.len() / 2);
            for (chunk, last) in [(first, false), (rest, true)] {
                if let Err(e) = stream.write(chunk.as_bytes(), last).await {
                    return eprintln!("  body failed: {e}");
                }
            }
            println!("  sent {} bytes of request body", body.len());
        }

        let response = match stream.response().await {
            Ok(response) => response,
            Err(e) => return eprintln!("  no response: {e}"),
        };
        println!("  {} {:?}", response.status(), response.version());
        for (name, value) in response.headers() {
            println!("    {name}: {}", value.to_str().unwrap_or("<binary>"));
        }

        // Body, a chunk at a time. Taking a chunk is what credits the peer
        // for it, so a reader that stops reading stops the download.
        let mut received = 0usize;
        loop {
            match stream.read().await {
                Ok(Some(chunk)) => received += chunk.len(),
                Ok(None) => break,
                Err(e) => return eprintln!("  body failed after {received} bytes: {e}"),
            }
        }
        println!("  read {received} bytes of body");

        // Done with the connection: no more requests, the loop finishes what
        // is on it and says goodbye, and this is where that end is heard.
        drop(stream);
        client.close();
        match client.closed().await {
            Ok(()) => println!("  connection closed"),
            Err(e) => eprintln!("  connection ended badly: {e}"),
        }
    });
}
