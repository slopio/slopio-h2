//! Closing an origin over a real socket: the connection's loop must end, and
//! only a real one has a loop to wait for.

use std::io;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use http::{HeaderMap, StatusCode};
use runtime::main_thread_with;
use runtime::runtime::time::Sleep;
use slopio_h2::client::{Origin, PlainTextClient};
use slopio_h2::server::{Server, ServerSettings, ServerTransport, Stream};

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

/// What the server saw of us: our side of the connection.
async fn ask(client: &PlainTextClient, uri: &http::Uri) -> Result<String, String> {
    let request = http::Request::get(uri).body(()).unwrap();
    let stream = client
        .send_request(&request, true)
        .await
        .map_err(|e| e.to_string())?;
    stream.response().await.map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.read().await.map_err(|e| e.to_string())? {
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).map_err(|e| e.to_string())
}

#[test]
fn a_closed_origin_ends_its_connection_and_opens_a_new_one() {
    let port = pick_port();
    let (done_tx, done_rx) = mpsc::channel::<Result<(String, usize, String), String>>();

    // Detached on purpose: `Server::run` accepts for ever.
    thread::spawn(move || {
        main_thread_with::<ServerRing, _>(async move {
            let settings = ServerSettings::new(([127, 0, 0, 1], port), ServerTransport::Plain);
            let _ = Server::new(settings)
                .run::<ServerRing, _>(tell_the_peer)
                .await;
        });
    });

    let client = thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
            let uri: http::Uri = format!("http://127.0.0.1:{port}/").parse().unwrap();
            let origin = Origin::of(&uri).unwrap();
            let client = PlainTextClient::plaintext::<ClientRing>();

            // The server binds inside its own task, so the first attempts may
            // land before the listener does.
            let mut up = false;
            for _ in 0..50 {
                if client.preconnect(&uri).await.is_ok() {
                    up = true;
                    break;
                }
                Sleep::during(Duration::from_millis(20)).await;
            }
            if !up {
                return done_tx.send(Err("never connected".into())).unwrap();
            }

            let outcome = async {
                let first = ask(&client, &uri).await?;
                client
                    .close_origin(&origin, Duration::from_secs(5))
                    .await
                    .map_err(|e| e.to_string())?;
                let after = client.connections(&origin);
                let second = ask(&client, &uri).await?;
                Ok((first, after, second))
            }
            .await;
            done_tx.send(outcome).unwrap();
        });
    });

    let outcome = done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the client reports");
    client.join().expect("client thread");

    let (first, after, second) = outcome.expect("both exchanges completed");
    assert_eq!(after, 0, "nothing held once it ended");
    assert_ne!(first, second, "the second request came on a new connection");
}

/// Starts the response and never ends it, answering keepalive all the while.
async fn never_finish(stream: Stream) {
    stream.write_headers(StatusCode::OK, &HeaderMap::new());
    std::future::pending::<()>().await;
}

#[test]
fn a_response_that_never_ends_does_not_hold_the_close_past_its_drain() {
    let port = pick_port();
    let (done_tx, done_rx) = mpsc::channel::<Result<(io::ErrorKind, Duration, String), String>>();

    thread::spawn(move || {
        main_thread_with::<ServerRing, _>(async move {
            let settings = ServerSettings::new(([127, 0, 0, 1], port), ServerTransport::Plain);
            let _ = Server::new(settings)
                .run::<ServerRing, _>(never_finish)
                .await;
        });
    });

    let client = thread::spawn(move || {
        main_thread_with::<ClientRing, _>(async move {
            let uri: http::Uri = format!("http://127.0.0.1:{port}/").parse().unwrap();
            let origin = Origin::of(&uri).unwrap();
            let client = PlainTextClient::plaintext::<ClientRing>();

            let mut up = false;
            for _ in 0..50 {
                if client.preconnect(&uri).await.is_ok() {
                    up = true;
                    break;
                }
                Sleep::during(Duration::from_millis(20)).await;
            }
            if !up {
                return done_tx.send(Err("never connected".into())).unwrap();
            }

            let outcome = async {
                let request = http::Request::get(&uri).body(()).unwrap();
                let stream = client
                    .send_request(&request, true)
                    .await
                    .map_err(|e| e.to_string())?;
                stream.response().await.map_err(|e| e.to_string())?;

                let start = std::time::Instant::now();
                let closed = client
                    .close_origin(&origin, Duration::from_millis(200))
                    .await
                    .expect_err("the response never ended");
                let took = start.elapsed();
                let read = stream.read().await.expect_err("the stream was cut");
                Ok((closed.kind(), took, read.to_string()))
            }
            .await;
            done_tx.send(outcome).unwrap();
        });
    });

    let outcome = done_rx
        .recv_timeout(Duration::from_secs(30))
        .expect("the client reports");
    client.join().expect("client thread");

    let (kind, took, read) = outcome.expect("the exchange started");
    assert_eq!(kind, io::ErrorKind::TimedOut);
    assert!(took < Duration::from_secs(2), "held for {took:?}");
    assert!(
        read.contains("origin was closed"),
        "the stream is told why: {read}"
    );
}
