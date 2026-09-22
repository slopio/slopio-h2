//! Opens one HTTP/2 connection over TLS, makes a request on it and reads the
//! response.
//!
//!     cargo run --release --features tls --example tls_client
//!
//! `ADDR` overrides the default of `127.0.0.1:8443`, `HOST` the name the
//! certificate is checked against (and the one in `:authority`), and `TARGET`
//! the path. Those three are separate on purpose: the address says where to
//! send the packets, the host says who the peer must prove to be.
//!
//! It points at anything speaking h2 over TLS, which is the useful thing about
//! it — a server of ours, or nghttpd:
//!
//!     openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
//!         -days 1 -nodes -subj /CN=localhost
//!     nghttpd -d /tmp/docroot 8443 key.pem cert.pem
//!     TARGET=/hello.txt cargo run --features tls --example tls_client
//!
//! **This example does not verify the server's certificate.** That is what
//! lets it talk to the self-signed one above, and it is exactly what a real
//! client must not do: build a `ClientConfig` over a `RootCertStore` instead,
//! with `popple_tls::client_config`.

use std::net::SocketAddr;

use popple_h2::client;
use popple_tls::{ServerName, client_config_dangerous_no_verification};
use runtime::main_thread_with;

// Smaller than the server's: a client holding one connection has nothing to
// share the ring with.
runtime::define_buf_ring!(ClientRing, bgid = 1, buffer_size = 16384, ring_size = 64);

/// §3.3: ALPN is not optional over TLS, and `h2` is the only thing we speak.
/// A server that will not agree to it is refused by `connect_tls` rather than
/// spoken HTTP/2 at.
const H2: &[&[u8]] = &[b"h2"];

fn main() {
    // rustls needs a crypto provider installed before any config is built.
    // The application's job, once, at startup — not the library's.
    if rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .is_err()
    {
        eprintln!("a crypto provider was already installed");
    }

    let addr: SocketAddr = std::env::var("ADDR")
        .unwrap_or_else(|_| "127.0.0.1:8443".into())
        .parse()
        .expect("ADDR must be host:port");
    let host = std::env::var("HOST").unwrap_or_else(|_| "localhost".into());
    let path = std::env::var("TARGET").unwrap_or_else(|_| "/".into());

    main_thread_with::<ClientRing, _>(async move {
        let config = client_config_dangerous_no_verification(Some(H2)).expect("a client config");
        let name = ServerName::try_from(host.clone()).expect("HOST must be a valid server name");

        let client = match client::connect_tls::<ClientRing>(addr, name, config).await {
            Ok(client) => client,
            Err(e) => return eprintln!("could not connect to {addr}: {e}"),
        };

        let peer = client.peer_settings();
        println!("connected to {addr} as {host}, over TLS");
        println!(
            "  max_concurrent_streams  {:?}",
            peer.max_concurrent_streams
        );
        println!("  initial_window_size     {}", peer.initial_window_size);
        println!("  max_frame_size          {}", peer.max_frame_size);

        let request = http::Request::get(format!("https://{host}{path}"))
            .body(())
            .expect("a valid request");
        let stream = match client.send_request(&request, true) {
            Ok(stream) => stream,
            Err(e) => return eprintln!("could not open a stream: {e}"),
        };

        let response = match stream.response().await {
            Ok(response) => response,
            Err(e) => return eprintln!("no response: {e}"),
        };
        println!("\n{} {}", response.status().as_u16(), path);
        for (name, value) in response.headers() {
            println!("  {name}: {}", value.to_str().unwrap_or("<binary>"));
        }

        let mut body = Vec::new();
        loop {
            match stream.read().await {
                Ok(Some(chunk)) => body.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(e) => return eprintln!("body ended early: {e}"),
            }
        }
        println!("\n{} bytes:", body.len());
        println!("{}", String::from_utf8_lossy(&body));

        if let Some(trailers) = stream.trailers() {
            println!("trailers: {trailers:?}");
        }

        // §6.8: say goodbye and wait for the peer's, rather than vanishing.
        client.close();
        if let Err(e) = client.closed().await {
            eprintln!("the connection ended: {e}");
        }
    });
}
