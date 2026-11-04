//! Fetches one URL over HTTP/2 in cleartext.
//!
//!     cargo run --release --example bench_server          # in one terminal
//!     cargo run --release --example client                # in another
//!     URL=http://127.0.0.1:8080/upload BODY=hello cargo run --release --example client
//!
//! A host that is a name is resolved by slopio-dns, against `DNS` (ip:port)
//! or else the first `nameserver` of /etc/resolv.conf.

use slopio::http;
use std::net::{IpAddr, SocketAddr};

use slopio::main_thread_with;
use slopio_h2::client::{DnsClient, PlainTextClient};

slopio::define_buf_ring!(ClientRing, bgid = 1, buffer_size = 16384, ring_size = 64);

/// slopio-dns reads no system configuration, so this does.
fn dns_server() -> SocketAddr {
    if let Some(addr) = std::env::var("DNS").ok().and_then(|v| v.parse().ok()) {
        return addr;
    }
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()
        .and_then(|conf| {
            conf.lines().find_map(|line| {
                line.strip_prefix("nameserver")?
                    .trim()
                    .parse::<IpAddr>()
                    .ok()
            })
        })
        .map_or(SocketAddr::from(([1, 1, 1, 1], 53)), |ip| {
            SocketAddr::new(ip, 53)
        })
}

fn main() {
    let url = std::env::var("URL").unwrap_or_else(|_| "http://127.0.0.1:8080/".into());
    let body = std::env::var("BODY").ok();

    main_thread_with::<ClientRing, _>(async move {
        // Datagrams land in the connections' ring: a DNS answer fits a buffer.
        let dns = match DnsClient::<ClientRing>::new(dns_server()) {
            Ok(dns) => dns,
            Err(e) => return eprintln!("no DNS client: {e}"),
        };
        let client = PlainTextClient::plaintext::<ClientRing>().with_dns(dns);

        // §8.1: with no body, the head ends the stream.
        let method = if body.is_some() { "POST" } else { "GET" };
        let request = match http::Request::builder().method(method).uri(&url).body(()) {
            Ok(request) => request,
            Err(e) => return eprintln!("{url}: {e}"),
        };
        // The connection is opened here, by the first request that needs it.
        let stream = match client.send_request(&request, body.is_none()).await {
            Ok(stream) => stream,
            Err(e) => return eprintln!("{url}: {e}"),
        };
        println!(
            "sent a {method} to {url} on stream {}",
            u32::from(stream.id())
        );

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

        // Taking a chunk is what credits the peer for it, so a reader that
        // stops reading stops the download.
        let mut received = 0usize;
        loop {
            match stream.read().await {
                Ok(Some(chunk)) => received += chunk.len(),
                Ok(None) => break,
                Err(e) => return eprintln!("  body failed after {received} bytes: {e}"),
            }
        }
        println!("  read {received} bytes of body");

        drop(stream);
        client.close();
        match client.closed().await {
            Ok(()) => println!("  connection closed"),
            Err(e) => eprintln!("  connection ended badly: {e}"),
        }
    });
}
