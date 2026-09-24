//! The handler sees who connected, over a real socket: the address is read at
//! accept, so nothing short of `Server::run` exercises it.

use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use http::{HeaderMap, StatusCode};
use popple_h2::client;
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::main_thread_with;
use runtime::runtime::time::Sleep;

runtime::define_buf_ring!(ServerRing, bgid = 0, buffer_size = 16384, ring_size = 256);
runtime::define_buf_ring!(ClientRing, bgid = 1, buffer_size = 16384, ring_size = 64);

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

async fn tell_the_peer(stream: Stream) {
    let peer = stream.peer_addr().map(|addr| addr.to_string());
    stream.write_headers(StatusCode::OK, &HeaderMap::new());
    stream
        .write_data_final(peer.unwrap_or_default().as_bytes())
        .await;
}

#[test]
fn a_handler_sees_the_address_its_peer_connected_from() {
    let port = pick_port();
    let (done_tx, done_rx) = mpsc::channel::<Result<String, String>>();

    // Detached on purpose: `Server::run` accepts for ever.
    thread::spawn(move || {
        main_thread_with::<ServerRing, _>(async move {
            let settings = ServerSettings::new(([127, 0, 0, 1], port), ServerTransport::Plain);
            let _ = Server::new(settings).run::<ServerRing, _>(tell_the_peer).await;
        });
    });

    let client = thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
            let addr = format!("127.0.0.1:{port}").parse().unwrap();

            // The server binds inside its own task, so the first attempts may
            // land before the listener does.
            let mut client = None;
            for _ in 0..50 {
                match client::connect::<ClientRing>(addr).await {
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

            let request = http::Request::get("http://localhost/").body(()).unwrap();
            let outcome = async {
                let stream = client
                    .send_request(&request, true)
                    .map_err(|e| e.to_string())?;
                stream.response().await.map_err(|e| e.to_string())?;
                let mut body = Vec::new();
                while let Some(chunk) = stream.read().await.map_err(|e| e.to_string())? {
                    body.extend_from_slice(&chunk);
                }
                String::from_utf8(body).map_err(|e| e.to_string())
            }
            .await;

            done_tx.send(outcome).unwrap();
        });
    });

    let outcome = done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the client reports");
    client.join().expect("client thread");

    let seen = outcome.expect("the exchange completed");
    let peer: SocketAddr = seen
        .parse()
        .unwrap_or_else(|_| panic!("the handler saw an address, not {seen:?}"));
    assert_eq!(peer.ip().to_string(), "127.0.0.1");
    assert_ne!(peer.port(), 0, "the client's ephemeral port");
    assert_ne!(peer.port(), port, "the peer's side, not ours");
}
