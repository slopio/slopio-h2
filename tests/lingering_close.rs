//! A server that closes first must end the connection, not reset it: closed
//! with the peer's input unread, a Linux socket answers with RST instead of
//! FIN, and the peer may lose what we sent last. Only a real socket shows it.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use slopio::main_thread_with;
use slopio_h2::server::{Server, ServerSettings, ServerTransport, Stream};

slopio::define_buf_ring!(ServerRing, bgid = 0, buffer_size = 16384, ring_size = 256);

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const SETTINGS: u8 = 4;
const PING: u8 = 6;
const GOAWAY: u8 = 7;

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
}

fn connect(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) {
            return stream;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("the server never listened");
}

/// h2spec 7.1's case. The peer sends a GOAWAY with an error code, which the
/// server closes on, and right behind it, in a write of its own, a PING. Now
/// and then the PING lands after the server's last read and before its
/// close; closed with it unread, the socket resets the connection instead of
/// ending it, and the peer reads the reset where our last frames and end
/// should be. A race, so it is run many times: about 1 % of connections met
/// it before the server read out what follows its FIN.
#[test]
fn a_server_closing_first_never_resets_the_connection() {
    let port = pick_port();
    // Detached on purpose: `Server::run` accepts for ever.
    thread::spawn(move || {
        main_thread_with::<ServerRing, _>(async move {
            let settings = ServerSettings::new(([127, 0, 0, 1], port), ServerTransport::Plain);
            let _ = Server::new(settings)
                .run::<ServerRing, _>(|_: Stream| async {})
                .await;
        });
    });

    let mut opening = PREFACE.to_vec();
    frame(&mut opening, SETTINGS, 0, 0, &[]);
    let mut goaway = Vec::new();
    // Acknowledging the server's SETTINGS, as h2spec does before each case.
    frame(&mut goaway, SETTINGS, 0x1, 0, &[]);
    // Last stream 0, an error code no one defines.
    frame(&mut goaway, GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0xff]);
    let mut ping = Vec::new();
    frame(&mut ping, PING, 0, 0, b"h2spec\0\0");

    let mut resets = Vec::new();
    for round in 0..ROUNDS {
        let mut client = connect(port);
        client.set_nodelay(true).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        // The handshake first, so that the GOAWAY finds the server idle.
        client.write_all(&opening).unwrap();
        let mut head = [0u8; 9];
        client.read_exact(&mut head).unwrap();
        assert_eq!(head[3], SETTINGS, "round {round}: the server's preface");
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        client.read_exact(&mut vec![0; len]).unwrap();

        // A write that meets the reset is the read's failure, met early.
        let wrote = client
            .write_all(&goaway)
            .and_then(|()| client.write_all(&ping));
        if let Err(e) = wrote.and_then(|()| read_to_end(&mut client).map(drop)) {
            resets.push((round, e.kind()));
        }
    }
    assert!(
        resets.is_empty(),
        "{} of {ROUNDS} connections reset: {resets:?}",
        resets.len()
    );
}

const ROUNDS: usize = 500;

/// Up to the peer's end, or the error that cut it short.
fn read_to_end(client: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut got = Vec::new();
    let mut chunk = [0u8; 16384];
    loop {
        match client.read(&mut chunk) {
            Ok(0) => return Ok(got),
            Ok(n) => got.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}
