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
