//! Fetches one URL over HTTP/2 and TLS, verifying the server on the way in.
//!
//!     cargo run --release --features tls --example tls_client
//!     cargo run --release --features tls --example tls_client https://cloudflare.com/
//!
//! The host is resolved by slopio-dns, against `DNS` (ip:port) or else the
//! first `nameserver` of /etc/resolv.conf. `INSECURE=1` skips checking the
//! certificate, for a local server: `https://127.0.0.1:8443/`.

use std::net::{IpAddr, SocketAddr};

use runtime::main_thread_with;
use slopio_h2::client::{DnsClient, TlsClient};
use slopio_tls::{ClientSettings, client_config, client_config_dangerous_no_verification};

runtime::define_buf_ring!(ClientRing, bgid = 1, buffer_size = 16384, ring_size = 64);

/// §3.3: ALPN is not optional over TLS. A server that will not agree to `h2`
/// is refused rather than spoken HTTP/2 at.
const H2: &[&[u8]] = &[b"h2"];

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
    // rustls needs a crypto provider installed before any config is built.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://www.google.com/".into());
    let uri: http::Uri = match url.parse() {
        Ok(uri) => uri,
        Err(e) => return eprintln!("{url}: {e}"),
    };
    if uri.scheme_str() != Some("https") {
        return eprintln!("{url}: only https:// URLs, since this is the TLS example");
    }

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

    main_thread_with::<ClientRing, _>(async move {
        // Datagrams land in the connections' ring: a DNS answer fits a buffer.
        let dns = match DnsClient::<ClientRing>::new(dns_server()) {
            Ok(dns) => dns,
            Err(e) => return eprintln!("no DNS client: {e}"),
        };
        let client = TlsClient::tls::<ClientRing>(config).with_dns(dns);

        // The connection is opened here: resolution, TCP, TLS with the
        // certificate checked against the URL's host, then HTTP/2.
        let request = http::Request::get(uri).body(()).expect("a valid request");
        let stream = match client.send_request(&request, true).await {
            Ok(stream) => stream,
            Err(e) => return eprintln!("{url}: {e}"),
        };
        println!(
            "{url}: {} over TLS, h2 agreed\n",
            match insecure {
                true => "UNVERIFIED",
                false => "verified",
            }
        );

        let response = match stream.response().await {
            Ok(response) => response,
            Err(e) => return eprintln!("no response: {e}"),
        };
        println!("{} {}", response.status().as_u16(), request.uri().path());
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
        drop(stream);
        client.close();
        if let Err(e) = client.closed().await {
            eprintln!("\nthe connection ended: {e}");
        }
    });
}
