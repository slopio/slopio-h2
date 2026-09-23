//! HTTP/2 over TLS, both ends ours, against a real kernel: kTLS cannot be
//! simulated. Skips itself on a kernel without the `tls` ULP.
//!
//! What it catches is the seam: that ALPN settles on `h2`, and that the
//! preface a client writes immediately after its Finished record arrives as
//! the first thing the server decodes.

#![cfg(feature = "tls")]

use std::net::TcpListener;
use std::sync::Once;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use http::{HeaderMap, StatusCode};
use popple_h2::client;
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use popple_tls::{
    Config, ServerName, ServerSettings as TlsServerSettings,
    client_config_dangerous_no_verification, server_config,
};
use rcgen::{CertificateParams, KeyPair};
use runtime::main_thread_with;
use runtime::runtime::time::Sleep;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

runtime::define_buf_ring!(ServerRing, bgid = 0, buffer_size = 16384, ring_size = 256);
runtime::define_buf_ring!(ClientRing, bgid = 1, buffer_size = 16384, ring_size = 64);

const H2: &[&[u8]] = &[b"h2"];

const BODY: &[u8] = b"hello over tls\n";

static INIT: Once = Once::new();

fn init_provider() {
    INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .ok();
    });
}

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// The client does not check it, so this only has to be well-formed.
fn make_server_config() -> Config {
    let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key).unwrap();
    server_config(TlsServerSettings {
        certs: vec![CertificateDer::from(cert.der().to_vec())],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        alpn_protocols: Some(H2),
    })
    .expect("server config")
}

async fn answer(stream: Stream) {
    stream.write_headers(StatusCode::OK, &HeaderMap::new());
    stream.write_data_final(BODY).await;
}

#[test]
fn a_request_and_its_response_cross_a_tls_connection() {
    if !popple_tls::ktls_available() {
        eprintln!("skipped: this kernel has no kTLS (`modprobe tls`)");
        return;
    }
    init_provider();

    let port = pick_port();
    let (done_tx, done_rx) = mpsc::channel::<Result<(u16, Vec<u8>), String>>();

    // Detached on purpose: `Server::run` accepts for ever.
    thread::spawn(move || {
        main_thread_with::<ServerRing, _>(async move {
            let settings = ServerSettings {
                bind_port: port,
                transport: ServerTransport::Tls(make_server_config()),
            };
            let _ = Server::new(settings).run::<ServerRing, _>(answer).await;
        });
    });

    let client = thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
            init_provider();
            let config = client_config_dangerous_no_verification(Some(H2)).expect("client config");
            let addr = format!("127.0.0.1:{port}").parse().unwrap();
            let name = ServerName::try_from("localhost").unwrap();

            // The server binds inside its own task, so the first attempts may
            // land before the listener does.
            let mut client = None;
            for _ in 0..50 {
                match client::connect_tls::<ClientRing>(addr, name.clone(), config.clone()).await {
                    Ok(c) => {
                        client = Some(c);
                        break;
                    }
                    Err(_) => Sleep::during(Duration::from_millis(20)).await,
                }
            }
            let Some(client) = client else {
                return done_tx.send(Err("never connected".into())).unwrap();
            };

            let request = http::Request::get("https://localhost/hello")
                .body(())
                .unwrap();
            let outcome = async {
                let stream = client
                    .send_request(&request, true)
                    .map_err(|e| e.to_string())?;
                let response = stream.response().await.map_err(|e| e.to_string())?;
                let mut body = Vec::new();
                while let Some(chunk) = stream.read().await.map_err(|e| e.to_string())? {
                    body.extend_from_slice(&chunk);
                }
                Ok((response.status().as_u16(), body))
            }
            .await;

            done_tx.send(outcome).unwrap();
        });
    });

    let outcome = done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the client reports");
    client.join().expect("client thread");

    let (status, body) = outcome.expect("the exchange completed");
    assert_eq!(status, 200);
    assert_eq!(body, BODY, "the response body crossed intact");
}
