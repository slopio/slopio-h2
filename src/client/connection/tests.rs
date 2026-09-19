//! The handshake, against a scripted server.
//!
//! The same simulated ring the server's tests run on, pointed the other way:
//! what the script declares is now what a *server* would send, and what comes
//! back is what the client put on the wire.
//!
//! Verified by hand against three implementations — popple-h2, tokio's `h2`,
//! and nghttpd — which agree on the handshake and disagree about everything
//! else they advertise. That is worth having done once and is not worth doing
//! in a test, which is what this is for.

use std::io;

use std::time::Duration;

use runtime_core::deterministic_testing::{FakeRing, ReadEvent, Scripted, simulated_socket};
use runtime_core::runtime::RuntimeInner;

use super::Connection;
use crate::shared::codec::frames::CLIENT_PREFACE;
use crate::shared::connection::settings::Settings;
use crate::shared::transport::PlainMessages;

runtime_core::define_buf_ring!(TestRing, bgid = 9, buffer_size = 16384, ring_size = 4);

const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const FLAG_ACK: u8 = 0x1;

fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// What a well-behaved server sends at the start: its own SETTINGS, then an
/// acknowledgement of ours.
fn server_opening() -> Vec<u8> {
    let mut bytes = frame(SETTINGS, 0, 0, &[0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);
    bytes.extend_from_slice(&frame(SETTINGS, FLAG_ACK, 0, &[]));
    bytes
}

/// Runs a handshake against `inbound`, and hands back its result with the
/// peer's settings and every byte the client wrote.
///
/// The script is closed with an EOF: a handshake that succeeds leaves its
/// recv armed, and the simulator refuses to let the runtime sleep with an op
/// nothing can complete. A peer that hangs up once the connection is open is
/// the cheapest way to say "the test is over".
fn handshake(mut inbound: Vec<ReadEvent>) -> (io::Result<Settings>, Vec<u8>) {
    if !matches!(inbound.last(), Some(ReadEvent::Eof)) {
        inbound.push(ReadEvent::Eof);
    }
    // Held back a moment, and not as a convenience. A client sends before it
    // reads — the preface goes out first — so its recv is not armed when the
    // run starts, and a reply that is due immediately has nothing to be
    // delivered to. On a real connection the server's SETTINGS cannot arrive
    // before the preface that prompted them either.
    let mut due = Duration::ZERO;
    let inbound: Vec<Scripted> = inbound
        .into_iter()
        .map(|event| {
            due += Duration::from_millis(1);
            event.after(due)
        })
        .collect();

    let (fake, handle) = FakeRing::builder().virtual_time().build();
    let socket = simulated_socket();
    let fd = socket.fd();
    handle.on_multishot_read(fd, inbound);

    let result = RuntimeInner::simulated(fake).block_on::<TestRing, _>(
        async move {
            // Spawned rather than awaited inline, for the reason the server's
            // harness gives: a root future that yields with an empty task list
            // puts the runtime to sleep with nothing armed to wake it, and the
            // scripted reads never arrive.
            runtime_core::runtime::spawn(async move {
                Connection::handshake(PlainMessages::<TestRing, false>::new(socket))
                    .await
                    .map(|conn| conn.peer_settings().clone())
            })
            .await
        },
        None,
        |run| run(),
    );

    (result, handle.writes(fd).concat())
}

#[test]
fn the_preface_goes_out_before_anything_is_read() {
    let (result, written) = handshake(vec![ReadEvent::Data(server_opening())]);

    assert!(result.is_ok(), "the handshake completed: {:?}", result.as_ref().err());

    // §3.4: the magic string first, and immediately a SETTINGS frame — not
    // after a round trip, which is a server holding a connection open for
    // nothing.
    assert!(
        written.starts_with(CLIENT_PREFACE),
        "the preface leads: {:?}",
        &written[..CLIENT_PREFACE.len().min(written.len())]
    );
    assert_eq!(
        written[CLIENT_PREFACE.len() + 3],
        SETTINGS,
        "a SETTINGS frame follows it with nothing in between"
    );
}

#[test]
fn the_peers_settings_are_taken_and_acknowledged() {
    let (result, written) = handshake(vec![ReadEvent::Data(server_opening())]);

    // 0x03 is MAX_CONCURRENT_STREAMS, and the script said 100.
    let peer = result.expect("the handshake completed");
    assert_eq!(peer.max_concurrent_streams, Some(100));

    // §6.5.3: and acknowledged. Two SETTINGS frames go out — ours, then the
    // ack — so the last one carries ACK and no payload.
    let tail = &written[written.len() - 9..];
    assert_eq!(tail[3], SETTINGS);
    assert_eq!(tail[4], FLAG_ACK);
    assert_eq!(&tail[..3], &[0, 0, 0], "an ack carries no payload");
}

/// §6.5.3 makes the exchange two-way and the halves independent: a server may
/// acknowledge ours before sending its own, and a client that treated either
/// as "established" would run on limits it had not been told.
#[test]
fn an_acknowledgement_alone_does_not_establish_the_connection() {
    let mut inbound = vec![ReadEvent::Data(frame(SETTINGS, FLAG_ACK, 0, &[]))];
    // The peer's own SETTINGS never arrive; it closes instead.
    inbound.push(ReadEvent::Eof);

    let (result, _) = handshake(inbound);
    let err = result.expect_err("half an exchange is not a handshake");
    assert!(err.to_string().contains("closed"), "said why: {err}");
}

/// A server may refuse before it says anything else, and the reason it gives
/// is more use than "the connection ended".
#[test]
fn a_goaway_during_the_handshake_is_reported_as_the_peers_reason() {
    let inbound = vec![ReadEvent::Data(frame(
        GOAWAY,
        0,
        0,
        &[0, 0, 0, 0, 0, 0, 0, 0],
    ))];

    let (result, _) = handshake(inbound);
    assert!(result.is_err(), "a GOAWAY is not a connection");
}

/// §6.7: a PING before the handshake finishes is still a PING. Answering it
/// is what keeps a server that probes early from timing us out.
#[test]
fn a_ping_during_the_handshake_is_answered() {
    let mut bytes = frame(PING, 0, 0, b"probe!!!");
    bytes.extend_from_slice(&server_opening());

    let (result, written) = handshake(vec![ReadEvent::Data(bytes)]);
    assert!(result.is_ok(), "the handshake still completed: {:?}", result.as_ref().err());

    let answered = written
        .windows(9 + 8)
        .any(|w| w[3] == PING && w[4] == FLAG_ACK && &w[9..17] == b"probe!!!");
    assert!(answered, "the probe came back with ACK set");
}

/// A server that accepts and then says nothing must not hold us for ever.
///
/// The hazard the deadline exists for, and the one nothing else bounds: the
/// TCP connect is at least limited by the kernel's SYN retries, but a peer
/// that completes the connection and goes quiet is unbounded. It costs the
/// peer one `accept`.
///
/// Scripted with a reply well past the deadline, so the deadline is what
/// decides rather than the script running out. Virtual time, so ten seconds
/// cost the test nothing.
#[test]
fn a_silent_server_does_not_hold_the_connection_for_ever() {
    use crate::client::CONNECT_TIMEOUT;
    use runtime::runtime::time::timeout;

    let (fake, handle) = FakeRing::builder().virtual_time().build();
    let socket = simulated_socket();
    let fd = socket.fd();
    handle.on_multishot_read(
        fd,
        vec![ReadEvent::Data(server_opening()).after(CONNECT_TIMEOUT * 10)],
    );

    let result = RuntimeInner::simulated(fake).block_on::<TestRing, _>(
        async move {
            runtime_core::runtime::spawn(async move {
                timeout(
                    CONNECT_TIMEOUT,
                    Connection::handshake(PlainMessages::<TestRing, false>::new(socket)),
                )
                .await
                .is_err()
            })
            .await
        },
        None,
        |run| run(),
    );

    assert!(result, "the deadline fired rather than the handshake finishing");
}

/// A request goes out as one HEADERS frame on stream 1, with the pseudo-headers
/// §8.3 requires and in the order it requires them.
#[test]
fn a_request_opens_stream_one_and_carries_its_pseudo_headers() {
    let (fake, handle) = FakeRing::builder().virtual_time().build();
    let socket = simulated_socket();
    let fd = socket.fd();
    handle.on_multishot_read(
        fd,
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(50)),
        ],
    );

    let sent = RuntimeInner::simulated(fake).block_on::<TestRing, _>(
        async move {
            runtime_core::runtime::spawn(async move {
                let mut conn =
                    Connection::handshake(PlainMessages::<TestRing, false>::new(socket))
                        .await
                        .expect("the handshake completed");
                let request = http::Request::get("http://example.test/hello")
                    .body(())
                    .unwrap();
                conn.send_request(&request, true).await.expect("written")
            })
            .await
        },
        None,
        |run| run(),
    );

    // §5.1.1: a client's first stream is 1.
    assert_eq!(sent.map(u32::from), Some(1));

    let written = handle.writes(fd).concat();
    let head = find_frame(&written, HEADERS).expect("a HEADERS frame went out");
    assert_eq!(head.stream_id, 1);
    // §8.1: no body was offered, so the head ends the stream, and §4.3 wants
    // the block whole — one frame, END_HEADERS set.
    assert_eq!(head.flags & 0x1, 0x1, "END_STREAM");
    assert_eq!(head.flags & 0x4, 0x4, "END_HEADERS");

    let decoded = decode_block(&head.payload);
    assert_eq!(decoded.get(":method").map(String::as_str), Some("GET"));
    assert_eq!(decoded.get(":scheme").map(String::as_str), Some("http"));
    assert_eq!(decoded.get(":path").map(String::as_str), Some("/hello"));
    assert_eq!(
        decoded.get(":authority").map(String::as_str),
        Some("example.test"),
        "§8.3.1: where a request carries what HTTP/1.1 put in Host"
    );
}

/// §5.1.2: the peer's limit is the peer's to set and ours to respect. Asking
/// past it earns a REFUSED_STREAM, and a refusal we could have predicted is
/// worse than a wait.
#[test]
fn no_stream_is_opened_past_the_peers_concurrency_limit() {
    let (fake, handle) = FakeRing::builder().virtual_time().build();
    let socket = simulated_socket();
    let fd = socket.fd();
    // The server allows exactly one.
    let mut opening = frame(SETTINGS, 0, 0, &[0x00, 0x03, 0x00, 0x00, 0x00, 0x01]);
    opening.extend_from_slice(&frame(SETTINGS, FLAG_ACK, 0, &[]));
    handle.on_multishot_read(
        fd,
        vec![
            ReadEvent::Data(opening).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(50)),
        ],
    );

    let ids = RuntimeInner::simulated(fake).block_on::<TestRing, _>(
        async move {
            runtime_core::runtime::spawn(async move {
                let mut conn =
                    Connection::handshake(PlainMessages::<TestRing, false>::new(socket))
                        .await
                        .expect("the handshake completed");
                let request = http::Request::get("http://example.test/").body(()).unwrap();
                let first = conn.send_request(&request, true).await.expect("written");
                let second = conn.send_request(&request, true).await.expect("written");
                (first, second)
            })
            .await
        },
        None,
        |run| run(),
    );

    assert_eq!(ids.0.map(u32::from), Some(1), "the one it allowed");
    assert_eq!(ids.1, None, "and no more, without asking");
}

/// The frames the client wrote, parsed back.
///
/// The preface is skipped first: it is 24 bytes of magic string and not a
/// frame, so a walker that starts at zero reads its bytes as a frame header
/// and every offset after it is wrong.
fn find_frame(bytes: &[u8], kind: u8) -> Option<Frame> {
    let mut at = if bytes.starts_with(CLIENT_PREFACE) {
        CLIENT_PREFACE.len()
    } else {
        0
    };
    while at + 9 <= bytes.len() {
        let len = u32::from_be_bytes([0, bytes[at], bytes[at + 1], bytes[at + 2]]) as usize;
        let end = at + 9 + len;
        if end > bytes.len() {
            return None;
        }
        if bytes[at + 3] == kind {
            return Some(Frame {
                flags: bytes[at + 4],
                stream_id: u32::from_be_bytes([
                    bytes[at + 5] & 0x7f,
                    bytes[at + 6],
                    bytes[at + 7],
                    bytes[at + 8],
                ]),
                payload: bytes[at + 9..end].to_vec(),
            });
        }
        at = end;
    }
    None
}

struct Frame {
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

/// The fields of an encoded block, by name.
fn decode_block(payload: &[u8]) -> std::collections::HashMap<String, String> {
    use crate::shared::hpack::{Decoder, Header};
    use bytes::BytesMut;

    let mut buf = BytesMut::from(payload);
    let mut cursor = std::io::Cursor::new(&mut buf);
    let mut out = std::collections::HashMap::new();
    Decoder::new(4096)
        .decode(&mut cursor, |header| {
            let (name, value) = match header {
                Header::Field { name, value } => (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                ),
                Header::Method(v) => (":method".into(), v.as_str().to_owned()),
                Header::Scheme(v) => (":scheme".into(), v.to_string()),
                Header::Path(v) => (":path".into(), v.to_string()),
                Header::Authority(v) => (":authority".into(), v.to_string()),
                other => (format!("{other:?}"), String::new()),
            };
            out.insert(name, value);
        })
        .expect("the block we just encoded decodes");
    out
}
