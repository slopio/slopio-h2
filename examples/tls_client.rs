//! Fetches one URL over HTTP/2 and TLS, verifying the server on the way in.
//!
//!     cargo run --release --features tls --example tls_client
//!     cargo run --release --features tls --example tls_client https://cloudflare.com/

use std::net::{SocketAddr, ToSocketAddrs};

use popple_h2::client;
use popple_tls::{
    ClientSettings, ServerName, client_config, client_config_dangerous_no_verification,
};
use runtime::main_thread_with;

runtime::define_buf_ring!(ClientRing, bgid = 1, buffer_size = 16384, ring_size = 64);

/// §3.3: ALPN is not optional over TLS. A server that will not agree to `h2`
/// is refused by `connect_tls` rather than spoken HTTP/2 at.
const H2: &[&[u8]] = &[b"h2"];

struct Target {
    host: String,
    port: u16,
    path: String,
}

fn parse(url: &str) -> Result<Target, String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("{url}: only https:// URLs, since this is the TLS example"))?;
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse().map_err(|_| format!("{port}: not a port"))?,
        ),
        None => (authority, 443),
    };
    if host.is_empty() {
        return Err(format!("{url}: no host"));
    }
    Ok(Target {
        host: host.to_owned(),
        port,
        path: path.to_owned(),
    })
}

fn main() {
    // rustls needs a crypto provider installed before any config is built.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://www.google.com/".into());
    let target = match parse(&url) {
        Ok(target) => target,
        Err(e) => return eprintln!("{e}"),
    };

    // Resolution happens before the runtime starts: this runtime has no
    // resolver.
    let addr: SocketAddr = match std::env::var("ADDR") {
        Ok(addr) => match addr.parse() {
            Ok(addr) => addr,
            Err(_) => return eprintln!("ADDR must be ip:port"),
        },
        Err(_) => match (target.host.as_str(), target.port).to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => return eprintln!("{}: resolved to nothing", target.host),
            },
            Err(e) => return eprintln!("{}: {e}", target.host),
        },
    };

    let insecure = std::env::var_os("INSECURE").is_some();
    let config = match insecure {
        // Never right off a loopback address.
        true => {
            eprintln!("INSECURE: the server's certificate is not being checked\n");
            client_config_dangerous_no_verification(Some(H2))
        }
        false => client_config(ClientSettings {
            roots: rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            },
            alpn_protocols: Some(H2),
        }),
    };
    let config = match config {
        Ok(config) => config,
        Err(e) => return eprintln!("could not build a TLS config: {e}"),
    };

    let name = match ServerName::try_from(target.host.clone()) {
        Ok(name) => name,
        Err(_) => return eprintln!("{}: not a valid server name", target.host),
    };

    main_thread_with::<ClientRing, _>(async move {
        let client = match client::connect_tls::<ClientRing>(addr, name, config).await {
            Ok(client) => client,
            Err(e) => return eprintln!("could not connect to {addr}: {e}"),
        };
        println!(
            "{} via {addr}, {} over TLS, h2 agreed\n",
            target.host,
            match insecure {
                true => "UNVERIFIED",
                false => "verified",
            }
        );

        let request = http::Request::get(&url).body(()).expect("a valid request");
        let stream = match client.send_request(&request, true) {
            Ok(stream) => stream,
            Err(e) => return eprintln!("could not open a stream: {e}"),
        };

        let response = match stream.response().await {
            Ok(response) => response,
            Err(e) => return eprintln!("no response: {e}"),
        };
        println!("{} {}", response.status().as_u16(), target.path);
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
        println!("\n{} bytes of body", body.len());
        let head: String = String::from_utf8_lossy(&body).chars().take(200).collect();
        println!("{head}");

        if let Some(trailers) = stream.trailers() {
            println!("\ntrailers: {trailers:?}");
        }

        // §6.8: say goodbye and wait for the peer's, rather than vanishing.
        client.close();
        if let Err(e) = client.closed().await {
            eprintln!("\nthe connection ended: {e}");
        }
    });
}
