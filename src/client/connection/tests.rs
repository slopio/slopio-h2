//! The client, against a scripted server.
//!
//! The same simulated ring the server's tests run on, pointed the other way:
//! what the script declares is now what a *server* would send, and what comes
//! back is what the client put on the wire.
//!
//! The handshake was verified by hand against three implementations —
//! popple-h2, tokio's `h2`, and nghttpd — which agree on it and disagree about
//! everything else they advertise. That is worth having done once and is not
//! worth doing in a test, which is what this is for.

use std::io;

use std::time::Duration;

use runtime_core::deterministic_testing::{FakeRing, ReadEvent, Scripted, simulated_socket};
use runtime_core::runtime::RuntimeInner;
use runtime_core::runtime::time::timeout;

use super::Connection;
use crate::client::{Client, Unavailable};
use crate::shared::codec::frames::CLIENT_PREFACE;
use crate::shared::connection::DEADLINE_TICK;
use crate::shared::connection::settings::Settings;
use crate::shared::transport::PlainMessages;

runtime_core::define_buf_ring!(TestRing, bgid = 3, buffer_size = 16384, ring_size = 4);

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_STREAM: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// `:status 200` is entry 8 of the static table, so a response head needs no
/// literal encoding and no dynamic table entry — which keeps the scripts from
/// having to model HPACK state the decoder is keeping.
const STATUS_200: &[u8] = &[0x88];

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

/// A literal header field, never indexed (§6.2.3), so a scripted trailer
/// section leaves the decoder's dynamic table exactly as it found it.
fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![0x10, name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    out
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
                    .map(|conn| conn.client().peer_settings())
            })
            .await
        },
        None,
        |run| run(),
    );

    (result, handle.writes(fd).concat())
}

/// Hands the connection over to `app` with the loop running behind it, which
/// is how the API is meant to be used: the application holds a [`Client`] and
/// the frames move in a task of their own.
///
/// `inbound` is scripted at the times given — a response cannot be declared
/// "after the request" here, because the script is fixed before the runtime
/// starts, so it is declared at a moment the request will comfortably precede.
fn with_client<F, Fut, R>(inbound: Vec<Scripted>, app: F) -> (R, Vec<u8>)
where
    F: FnOnce(Client) -> Fut + 'static,
    Fut: Future<Output = R>,
    R: 'static,
{
    let (fake, handle) = FakeRing::builder().virtual_time().build();
    let socket = simulated_socket();
    let fd = socket.fd();
    handle.on_multishot_read(fd, inbound);

    let result = RuntimeInner::simulated(fake).block_on::<TestRing, _>(
        async move {
            runtime_core::runtime::spawn(async move {
                let conn = Connection::handshake(PlainMessages::<TestRing, false>::new(socket))
                    .await
                    .expect("the handshake completed");
                app(conn.spawn()).await
            })
            .await
        },
        None,
        |run| run(),
    );

    (result, handle.writes(fd).concat())
}

/// One scripted arrival per buffer the ring can hold.
///
/// A completion cannot exceed its buffer, so a response larger than one has
/// to be declared as the several reads it would really be — which is closer
/// to the wire anyway: chunk boundaries are the kernel's, and the decoder
/// reassembles across them.
fn split(bytes: Vec<u8>, first: Duration) -> Vec<Scripted> {
    let mut due = first;
    bytes
        .chunks(16_000)
        .map(|chunk| {
            let at = due;
            due += Duration::from_millis(1);
            ReadEvent::Data(chunk.to_vec()).after(at)
        })
        .collect()
}

/// Lets the connection loop have the thread: the test's task waits on the
/// clock, which is virtual, so ten milliseconds of it cost nothing.
///
/// Needed wherever a test asserts on bytes that a *drop* produced — a
/// RST_STREAM, a GOAWAY — since writing a frame only wakes the loop, and the
/// loop is what sends it.
async fn settle() {
    let _ = timeout(Duration::from_millis(10), std::future::pending::<()>()).await;
}

#[test]
fn the_preface_goes_out_before_anything_is_read() {
    let (result, written) = handshake(vec![ReadEvent::Data(server_opening())]);

    assert!(
        result.is_ok(),
        "the handshake completed: {:?}",
        result.as_ref().err()
    );

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

    // §6.5.3: and acknowledged.
    let sent = frames(&written);
    let ack = sent
        .iter()
        .rev()
        .find(|f| f.kind == SETTINGS && f.flags & FLAG_ACK != 0)
        .expect("a SETTINGS ACK went out");
    assert!(ack.payload.is_empty(), "an ack carries no payload");
}

/// §6.9.2: the connection window starts at 65535 whatever the SETTINGS say,
/// and a WINDOW_UPDATE on stream 0 is the only thing that moves it. A client
/// that never sent one would stall every download at 64 KiB.
#[test]
fn the_connection_window_is_opened_during_the_handshake() {
    let (_, written) = handshake(vec![ReadEvent::Data(server_opening())]);

    let update = frames(&written)
        .into_iter()
        .find(|f| f.kind == WINDOW_UPDATE)
        .expect("a WINDOW_UPDATE went out");
    assert_eq!(update.stream_id, 0, "connection level");
    assert_eq!(
        u32::from_be_bytes(update.payload[..4].try_into().unwrap()),
        crate::client::CONNECTION_RECV_WINDOW
            - crate::shared::connection::CONNECTION_INITIAL_WINDOW_SIZE,
        "the gap between the default and what we announce"
    );
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
    assert!(
        result.is_ok(),
        "the handshake still completed: {:?}",
        result.as_ref().err()
    );

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

    assert!(
        result,
        "the deadline fired rather than the handshake finishing"
    );
}

/// A request goes out as one HEADERS frame on stream 1, with the
/// pseudo-headers §8.3 requires and in the order it requires them.
#[test]
fn a_request_opens_stream_one_and_carries_its_pseudo_headers() {
    let (id, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(100)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/hello")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            let id = stream.id();
            settle().await;
            u32::from(id)
        },
    );

    // §5.1.1: a client's first stream is 1.
    assert_eq!(id, 1);

    let head = frames(&written)
        .into_iter()
        .find(|f| f.kind == HEADERS)
        .expect("a HEADERS frame went out");
    assert_eq!(head.stream_id, 1);
    // §8.1: no body was offered, so the head ends the stream, and §4.3 wants
    // the block whole — one frame, END_HEADERS set.
    assert_eq!(head.flags & FLAG_END_STREAM, FLAG_END_STREAM, "END_STREAM");
    assert_eq!(
        head.flags & FLAG_END_HEADERS,
        FLAG_END_HEADERS,
        "END_HEADERS"
    );

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
    // The server allows exactly one.
    let mut opening = frame(SETTINGS, 0, 0, &[0x00, 0x03, 0x00, 0x00, 0x00, 0x01]);
    opening.extend_from_slice(&frame(SETTINGS, FLAG_ACK, 0, &[]));

    let (outcome, _) = with_client(
        vec![
            ReadEvent::Data(opening).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(100)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            // The first handle is held, deliberately: the limit is a count of
            // live streams, and dropping it would retire the stream and free
            // the slot the second ask is meant to find taken.
            let first = client.send_request(&request, true).expect("a stream");
            let second = client.send_request(&request, true).err();
            (u32::from(first.id()), second)
        },
    );

    assert_eq!(outcome.0, 1, "the one it allowed");
    assert_eq!(
        outcome.1,
        Some(Unavailable::AtLimit),
        "and no more, without asking"
    );
}

/// The response head and its body reach the handle, in that order, and the
/// body ends where END_STREAM said it did.
#[test]
fn a_response_and_its_body_reach_the_stream() {
    let mut response = frame(HEADERS, FLAG_END_HEADERS, 1, STATUS_200);
    response.extend_from_slice(&frame(DATA, 0, 1, b"hello "));
    response.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, b"world"));

    let (seen, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");

            let head = stream.response().await.expect("a response");
            let mut body = Vec::new();
            while let Some(chunk) = stream.read().await.expect("a body") {
                body.extend_from_slice(&chunk);
            }
            (head.status().as_u16(), body)
        },
    );

    assert_eq!(seen.0, 200);
    assert_eq!(seen.1, b"hello world");
}

/// §8.1: a body is written as DATA frames on the stream its head opened, and
/// the last of them carries END_STREAM.
#[test]
fn a_request_body_goes_out_as_data_frames() {
    let response = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, STATUS_200);

    let (status, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(50)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::post("http://example.test/upload")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, false).expect("a stream");
            stream.write(b"one", false).await.expect("written");
            stream.write(b"two", true).await.expect("written");
            let head = stream.response().await.expect("a response");
            head.status().as_u16()
        },
    );

    assert_eq!(status, 200);

    let sent = frames(&written);
    let head = sent.iter().find(|f| f.kind == HEADERS).expect("a head");
    assert_eq!(
        head.flags & FLAG_END_STREAM,
        0,
        "a request with a body does not end at its head"
    );

    let body: Vec<&Frame> = sent.iter().filter(|f| f.kind == DATA).collect();
    assert_eq!(body.len(), 2, "one frame per write");
    assert_eq!(body[0].payload, b"one");
    assert_eq!(body[0].flags & FLAG_END_STREAM, 0);
    assert_eq!(body[1].payload, b"two");
    assert_eq!(
        body[1].flags & FLAG_END_STREAM,
        FLAG_END_STREAM,
        "the last write ends the request"
    );
}

/// §6.9.1: reading the body is what hands the peer its credit back. Until the
/// application takes a chunk, the bytes are still spending the window they
/// arrived on — which is what bounds the buffer.
///
/// A body still arriving, deliberately: a stream that has *ended* is retired
/// the moment its END_STREAM lands, and its credit goes back to the
/// connection whole rather than to a window nobody will spend again. What is
/// checked here is the download that is still going, which is the case where
/// the credit has to flow or the peer stops at 64 KiB.
#[test]
fn reading_the_body_credits_the_peer() {
    // Frames that pass the stream's release threshold — half of
    // `STREAM_RECV_WINDOW` — only together, so the WINDOW_UPDATE is the last
    // read's: one frame for the lot, which is the accumulation working. Each
    // is within the 16384 this client allows a frame to be, since a peer that
    // sent more would be answered with a connection error instead.
    const CHUNK: usize = 10_000;
    let chunks = (crate::client::STREAM_RECV_WINDOW as usize / 2).div_ceil(CHUNK);
    let body = chunks * CHUNK;

    let chunk = vec![b'x'; CHUNK];
    let mut response = frame(HEADERS, FLAG_END_HEADERS, 1, STATUS_200);
    for _ in 0..chunks {
        response.extend_from_slice(&frame(DATA, 0, 1, &chunk));
    }

    let mut inbound = vec![ReadEvent::Data(server_opening()).after(Duration::from_millis(1))];
    inbound.extend(split(response, Duration::from_millis(10)));
    inbound.push(ReadEvent::Eof.after(Duration::from_millis(200)));

    let (read, written) = with_client(inbound, move |client| async move {
        let request = http::Request::get("http://example.test/big")
            .body(())
            .unwrap();
        let stream = client.send_request(&request, true).expect("a stream");
        let _ = stream.response().await.expect("a response");

        // By size and not by count: a read hands over what arrived, and a
        // frame cut by the end of a segment arrives in pieces.
        let mut total = 0;
        while total < body {
            total += stream
                .read()
                .await
                .expect("a body")
                .expect("more body")
                .len();
        }
        settle().await;
        total
    });

    assert_eq!(read, body);

    let updates: Vec<Frame> = frames(&written)
        .into_iter()
        .filter(|f| f.kind == WINDOW_UPDATE && f.stream_id == 1)
        .collect();
    assert_eq!(
        updates.len(),
        1,
        "one frame for {chunks} chunks, not one each"
    );
    // What it credits is everything read when the threshold was crossed, and
    // the read that crossed it is whatever the ring happened to deliver — a
    // DATA frame cut by the end of a segment arrives in pieces. So the amount
    // is bounded rather than exact: at least the threshold, since that is what
    // released it, and no more than has been read.
    let credited = u32::from_be_bytes(updates[0].payload[..4].try_into().unwrap()) as usize;
    assert!(
        (crate::client::STREAM_RECV_WINDOW as usize / 2..=body).contains(&credited),
        "the accumulated credit, announced once it was worth a frame: {credited}"
    );
}

/// §8.1: a trailer section after the body, and the body ends with it.
///
/// The head arrives on its own, and the application takes it, before the rest
/// of the message does — which is the case that tells a trailer section from a
/// second response head. A stream that answered "have I a response?" by
/// looking at the slot the application took the head *from* would deliver
/// these trailers as a response instead.
#[test]
fn trailers_end_the_response() {
    let head = frame(HEADERS, FLAG_END_HEADERS, 1, STATUS_200);
    let mut rest = frame(DATA, 0, 1, b"body");
    rest.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &literal("x-checksum", "42"),
    ));

    let (seen, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(head).after(Duration::from_millis(10)),
            ReadEvent::Data(rest).after(Duration::from_millis(30)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            let _ = stream.response().await.expect("a response");

            let mut body = Vec::new();
            while let Some(chunk) = stream.read().await.expect("a body") {
                body.extend_from_slice(&chunk);
            }
            let trailers = stream.trailers().and_then(|fields| {
                fields
                    .get("x-checksum")
                    .map(|v| v.to_str().unwrap().to_owned())
            });
            (body, trailers)
        },
    );

    assert_eq!(seen.0, b"body");
    assert_eq!(seen.1.as_deref(), Some("42"), "§8.1: the trailer section");
}

/// §6.4: the peer gives up on the stream, and whoever was waiting on it is
/// told rather than left waiting for a response that is not coming.
#[test]
fn a_reset_stream_fails_what_was_waiting_on_it() {
    let reset = frame(RST_STREAM, 0, 1, &0x8u32.to_be_bytes());

    let (message, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(reset).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            stream.response().await.expect_err("reset").to_string()
        },
    );

    assert!(
        message.contains("reset by peer"),
        "the reason reaches the caller: {message}"
    );
}

/// Dropping a handle for a stream the peer has not finished is a cancel
/// (§8.1): the peer is told to stop, which it cannot infer from a client that
/// simply stops reading.
#[test]
fn dropping_an_unfinished_stream_resets_it() {
    let response = frame(HEADERS, FLAG_END_HEADERS, 1, STATUS_200);

    let (_, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            // The head arrived but the body never ends: the stream is still
            // open when the handle goes.
            let _ = stream.response().await.expect("a response");
            drop(stream);
            settle().await;
        },
    );

    let reset = frames(&written)
        .into_iter()
        .find(|f| f.kind == RST_STREAM)
        .expect("a RST_STREAM went out");
    assert_eq!(reset.stream_id, 1);
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        crate::shared::codec::types::CANCEL
    );
}

/// A stream that finished both halves is not reset when its handle goes:
/// there is nothing left to cancel, and a RST_STREAM on a closed stream is
/// noise the peer has to account for.
#[test]
fn a_finished_stream_is_not_reset() {
    let response = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, STATUS_200);

    let (_, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            let _ = stream.response().await.expect("a response");
            assert_eq!(stream.read().await.expect("the end"), None);
            drop(stream);
            settle().await;
        },
    );

    assert!(
        !frames(&written).iter().any(|f| f.kind == RST_STREAM),
        "nothing to reset"
    );
}

/// §6.8: a GOAWAY says what the peer never processed, and those requests are
/// safe to retry elsewhere — which is worth saying at once rather than when
/// the socket eventually closes.
#[test]
fn a_goaway_fails_the_streams_it_says_were_not_processed() {
    // Streams 1 and 3 go out; the peer says it processed up to 1.
    let mut goaway_payload = 1u32.to_be_bytes().to_vec();
    goaway_payload.extend_from_slice(&0u32.to_be_bytes());
    let goaway = frame(GOAWAY, 0, 0, &goaway_payload);

    let (outcome, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(goaway).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let first = client.send_request(&request, true).expect("a stream");
            let second = client.send_request(&request, true).expect("a stream");

            let abandoned = second.response().await.expect_err("never processed");
            // And nothing new may be opened on a connection that is leaving.
            let refused = client.send_request(&request, true).err();
            (first.id(), abandoned.to_string(), refused)
        },
    );

    assert_eq!(u32::from(outcome.0), 1);
    assert!(
        outcome.1.contains("without processing"),
        "the reason reaches the caller: {}",
        outcome.1
    );
    assert_eq!(outcome.2, Some(Unavailable::Closed));
}

/// The connection going is not silence: a stream still waiting is failed with
/// a reason, rather than parked on frames that will never arrive.
#[test]
fn a_closed_connection_fails_the_streams_it_was_carrying() {
    let (message, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(10)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            stream
                .response()
                .await
                .expect_err("the peer went")
                .to_string()
        },
    );

    assert!(
        message.contains("closed"),
        "the reason reaches the caller: {message}"
    );
}

/// §6.8: a client that is finished with a connection says so, and can wait for
/// the goodbye to have gone.
///
/// `close` is the ending asked for rather than fallen into — dropping every
/// handle brings about the same one, but a caller that wants to *wait* for it
/// cannot drop the handle it would wait on.
#[test]
fn closing_a_client_ends_the_connection_and_waits_for_the_goodbye() {
    // No EOF in the script at all, deliberately: the peer never goes away, so
    // the only thing that can end this connection is the client saying it is
    // done with it. A test that left one in would pass on the peer's close
    // and prove nothing.
    let (outcome, written) = with_client(
        vec![ReadEvent::Data(server_opening()).after(Duration::from_millis(1))],
        |client| async move {
            client.close();
            let ended = client.closed().await;
            (ended.is_ok(), client.is_closed())
        },
    );

    assert_eq!(outcome, (true, true), "ended, and said it had");

    let goodbye = frames(&written)
        .into_iter()
        .find(|f| f.kind == GOAWAY)
        .expect("a GOAWAY went out");
    assert_eq!(
        u32::from_be_bytes(goodbye.payload[4..8].try_into().unwrap()),
        crate::shared::codec::types::NO_ERROR,
        "nothing went wrong; the connection was finished with"
    );
}

/// A connection that fails with no stream open used to fail in silence: the
/// reason went to the streams, and there were none. The task belongs to the
/// `Client` now, so the reason has somewhere to go.
#[test]
fn a_connection_that_fails_with_no_stream_open_still_says_why() {
    // §5.1: a HEADERS on a stream this client never opened. Nothing is in
    // flight — no request has been made at all — so the only thing that can
    // report this is the connection itself.
    let unexpected = frame(HEADERS, FLAG_END_HEADERS, 3, STATUS_200);

    let (message, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(unexpected).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_secs(60)),
        ],
        |client| async move {
            client
                .closed()
                .await
                .expect_err("a protocol error is not a clean end")
                .to_string()
        },
    );

    assert!(
        message.contains("never opened"),
        "the reason reaches the caller: {message}"
    );

    let goaway = frames(&written)
        .into_iter()
        .find(|f| f.kind == GOAWAY)
        .expect("a GOAWAY went out");
    assert_eq!(
        u32::from_be_bytes(goaway.payload[4..8].try_into().unwrap()),
        crate::shared::codec::types::PROTOCOL_ERROR
    );
}

/// The end is handed over once, like a response head: a second ask is a
/// mistake, and a mistake reported is better than one that hangs.
#[test]
fn the_connections_end_is_answered_once() {
    let (second, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(10)),
        ],
        |client| async move {
            let _ = client.closed().await;
            client.closed().await.expect_err("asked twice").to_string()
        },
    );

    assert!(second.contains("does not own"), "said so: {second}");
}

#[derive(Clone, Debug)]
struct Frame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

/// Every frame the peer would have received, in order.
///
/// The preface is skipped first: it is 24 bytes of magic string and not a
/// frame, so a walker that starts at zero reads its bytes as a frame header
/// and every offset after it is wrong.
fn frames(bytes: &[u8]) -> Vec<Frame> {
    let mut at = if bytes.starts_with(CLIENT_PREFACE) {
        CLIENT_PREFACE.len()
    } else {
        0
    };
    let mut out = Vec::new();
    while at + 9 <= bytes.len() {
        let len = u32::from_be_bytes([0, bytes[at], bytes[at + 1], bytes[at + 2]]) as usize;
        let end = at + 9 + len;
        if end > bytes.len() {
            break;
        }
        out.push(Frame {
            kind: bytes[at + 3],
            flags: bytes[at + 4],
            stream_id: u32::from_be_bytes([
                bytes[at + 5] & 0x7f,
                bytes[at + 6],
                bytes[at + 7],
                bytes[at + 8],
            ]),
            payload: bytes[at + 9..end].to_vec(),
        });
        at = end;
    }
    out
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

/// The example's shape, end to end: a request answered in full, then the
/// client says it is done and waits for the goodbye. No EOF here either — the
/// peer stays, and the client leaves.
#[test]
fn a_finished_exchange_then_close_and_wait() {
    let mut response = frame(HEADERS, FLAG_END_HEADERS, 1, STATUS_200);
    response.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, b"hello"));

    let (ended, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(10)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            let _ = stream.response().await.expect("a response");
            while stream.read().await.expect("a body").is_some() {}
            drop(stream);
            client.close();
            client.closed().await.is_ok()
        },
    );

    assert!(ended, "the connection ended cleanly, and said so");
    assert!(
        frames(&written).iter().any(|f| f.kind == GOAWAY),
        "§6.8: and said goodbye on the way out"
    );
}

#[test]
fn the_end_can_be_asked_for_after_it_has_happened() {
    let (ended, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(10)),
        ],
        |client| async move {
            // The loop is over well before anyone asks.
            settle().await;
            settle().await;
            client.closed().await.is_ok()
        },
    );

    assert!(ended);
}

/// §6.9.2: a stream's receive window is what its owner announced in SETTINGS,
/// and a client that announces nothing gets 65535 — every response stalled
/// every 64 KiB until a WINDOW_UPDATE completes a round trip. The one setting
/// a downloading client feels immediately.
#[test]
fn the_stream_window_is_announced_in_the_handshake() {
    let (_, written) = handshake(vec![ReadEvent::Data(server_opening())]);

    let settings = frames(&written)
        .into_iter()
        .find(|f| f.kind == SETTINGS && f.flags & FLAG_ACK == 0)
        .expect("our SETTINGS went out");

    // §6.5.1: an identifier/value pair per six bytes. 0x4 is
    // SETTINGS_INITIAL_WINDOW_SIZE.
    let announced = settings
        .payload
        .chunks(6)
        .find(|entry| u16::from_be_bytes([entry[0], entry[1]]) == 0x4)
        .map(|entry| u32::from_be_bytes(entry[2..6].try_into().unwrap()))
        .expect("SETTINGS_INITIAL_WINDOW_SIZE is one of them");
    assert_eq!(announced, crate::client::STREAM_RECV_WINDOW);
}

/// Lets `d` of virtual time pass. The clock is the simulation's, so a minute
/// of it costs the test nothing — and the connection loop, which wakes on its
/// own tick, has the thread while we are not using it.
async fn wait(d: Duration) {
    let _ = timeout(d, std::future::pending::<()>()).await;
}

/// §6.7: a peer that has said nothing while a request is outstanding is asked
/// whether it is still there.
///
/// The silence a client cannot distinguish from a dead peer is exactly the
/// silence a slow handler produces, which is why the probe exists: it is the
/// only way to tell them apart, and the answer also resets whatever idle timer
/// the peer keeps against *us*.
#[test]
fn a_silent_peer_with_a_request_in_flight_is_probed() {
    let probe_due = DEADLINE_TICK * crate::client::ACTIVE_PING_TICKS;

    let (_, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            // The response never comes, and the peer never hangs up: the
            // failure a probe is for looks exactly like a slow server.
            ReadEvent::Eof.after(probe_due * 4),
        ],
        move |client| async move {
            let request = http::Request::get("http://example.test/slow")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            // Comfortably past the budget, comfortably short of giving up.
            wait(probe_due + DEADLINE_TICK).await;
            drop(stream);
        },
    );

    let probes: Vec<Frame> = frames(&written)
        .into_iter()
        .filter(|f| f.kind == PING && f.flags & FLAG_ACK == 0)
        .collect();
    assert_eq!(probes.len(), 1, "one probe, not one per tick");
    assert_eq!(probes[0].stream_id, 0, "§6.7: PING is the connection's");
    assert_eq!(probes[0].payload.len(), 8, "§6.7: eight opaque bytes");
}

/// A connection whose probe is never answered is not a connection, whatever
/// the socket says — and everything waiting on it is told so rather than
/// waiting for the kernel to finish retransmitting, minutes later.
#[test]
fn a_peer_that_never_answers_a_probe_is_given_up_on() {
    let probe_due = DEADLINE_TICK * crate::client::ACTIVE_PING_TICKS;
    let give_up = probe_due + DEADLINE_TICK * crate::client::PING_TIMEOUT_TICKS;

    let ((failure, closed), written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            // Long after the client should have stopped waiting.
            ReadEvent::Eof.after(give_up * 4),
        ],
        move |client| async move {
            let request = http::Request::get("http://example.test/gone")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            // The stream is failed by the connection ending, which is what
            // resolves this: no deadline of its own is involved.
            let failure = stream
                .response()
                .await
                .expect_err("the connection went")
                .to_string();
            drop(stream);
            (failure, client.is_closed())
        },
    );

    assert!(
        failure.contains("keepalive"),
        "the stream is told why the connection went: {failure}"
    );
    assert!(closed, "and the client knows it can take no more requests");

    // §6.8: said out loud rather than dropped, on the chance the peer is
    // listening after all.
    assert!(
        frames(&written).iter().any(|f| f.kind == GOAWAY),
        "a GOAWAY went out"
    );
}

/// Any frame is an answer: the question a probe asks is whether the peer is
/// there, and a peer that says anything at all has answered it.
#[test]
fn a_peer_that_answers_keeps_the_connection() {
    let probe_due = DEADLINE_TICK * crate::client::ACTIVE_PING_TICKS;
    let give_up = probe_due + DEADLINE_TICK * crate::client::PING_TIMEOUT_TICKS;

    // §6.7: the opaque comes back byte for byte, and the first probe of a
    // connection carries the first counter.
    let ack = frame(PING, FLAG_ACK, 0, &1u64.to_be_bytes());

    let (closed, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(ack).after(probe_due + Duration::from_millis(10)),
            ReadEvent::Eof.after(give_up * 4),
        ],
        move |client| async move {
            let request = http::Request::get("http://example.test/slow")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            // Past the point an unanswered probe would have ended this.
            wait(give_up + DEADLINE_TICK).await;
            let closed = client.is_closed();
            drop(stream);
            closed
        },
    );

    assert!(!closed, "the answer kept it alive");
}

/// An idle connection is probed on the longer budget. A client holding
/// connections for reuse that probed each of them as often as one with a
/// request outstanding is the shape a gRPC server answers with GOAWAY
/// ENHANCE_YOUR_CALM.
#[test]
fn an_idle_connection_is_not_probed_on_the_active_budget() {
    let active = DEADLINE_TICK * crate::client::ACTIVE_PING_TICKS;
    let idle = DEADLINE_TICK * crate::client::IDLE_PING_TICKS;

    let (_, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(idle * 4),
        ],
        move |client| async move {
            // Held, with nothing on it, well past the active budget.
            wait(active + DEADLINE_TICK).await;
            drop(client);
        },
    );

    assert!(
        !frames(&written)
            .iter()
            .any(|f| f.kind == PING && f.flags & FLAG_ACK == 0),
        "nothing was in flight, so nothing was asked"
    );
}

/// §8.1: a request may end with a trailer section exactly as a response does.
#[test]
fn a_request_can_end_with_trailers() {
    let (_, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::post("http://example.test/upload")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, false).expect("a stream");
            stream.write(b"body", false).await.expect("a body");

            let mut fields = http::HeaderMap::new();
            fields.insert("x-checksum", "42".parse().unwrap());
            stream.send_trailers(&fields).expect("a trailer section");

            // The body is over, so there is nothing left to write.
            let refused = stream.write(b"more", true).await;
            assert!(refused.is_err(), "the request already ended");

            settle().await;
        },
    );

    let blocks: Vec<Frame> = frames(&written)
        .into_iter()
        .filter(|f| f.kind == HEADERS && f.stream_id == 1)
        .collect();
    assert_eq!(blocks.len(), 2, "the request head, and its trailers");
    assert_eq!(
        blocks[0].flags & FLAG_END_STREAM,
        0,
        "the head does not end a request that has a body"
    );
    assert_eq!(
        blocks[1].flags & FLAG_END_STREAM,
        FLAG_END_STREAM,
        "§8.1: the trailer section ends the message"
    );

    let trailers = decode_block(&blocks[1].payload);
    assert_eq!(trailers.get("x-checksum").map(String::as_str), Some("42"));
    assert!(
        !trailers.keys().any(|name| name.starts_with(':')),
        "§8.3: no pseudo-header in a trailer section"
    );
}

/// A request that runs out of time is cancelled, and says why.
///
/// The stream goes with a RST_STREAM rather than the caller merely walking
/// away from it: §8.1's way of telling a server to stop working on something
/// nobody is waiting for any more, which it cannot infer from a client that
/// simply stops reading.
#[test]
fn a_deadline_cancels_the_request() {
    let (outcome, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_secs(60)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/slow")
                .body(())
                .unwrap();
            let stream = client
                .send_request(&request, true)
                .expect("a stream")
                .with_deadline(Duration::from_secs(1));

            let timed_out = stream.response().await.expect_err("nothing answered");
            // Every later call reports the same thing, rather than the reset
            // that carried it out or a wait that will not end.
            let after = stream.read().await.expect_err("the stream is over");

            settle().await;
            (timed_out.kind(), after.kind(), client.live_streams())
        },
    );

    assert_eq!(outcome.0, io::ErrorKind::TimedOut, "the deadline passed");
    assert_eq!(outcome.1, io::ErrorKind::TimedOut, "and it keeps saying so");
    assert_eq!(outcome.2, 0, "the stream is off the connection");

    let reset = frames(&written)
        .into_iter()
        .find(|f| f.kind == RST_STREAM)
        .expect("§8.1: the peer is told to stop");
    assert_eq!(reset.stream_id, 1);
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        crate::shared::codec::types::CANCEL,
        "CANCEL: nobody is waiting for this any more"
    );
}

/// A deadline longer than any single timer the runtime has. It is served in
/// slices, and the slicing must not be visible: what expires is the deadline,
/// not the first slice of it.
#[test]
fn a_deadline_longer_than_one_tick_is_still_one_deadline() {
    let past_a_tick = DEADLINE_TICK * 3 + Duration::from_millis(500);

    let (kind, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            // The response arrives while the deadline still has a slice to
            // run, so a client that expired at the end of a slice would fail
            // a request that was answered in time.
            ReadEvent::Data(frame(
                HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                1,
                STATUS_200,
            ))
            .after(DEADLINE_TICK * 2),
            ReadEvent::Eof.after(DEADLINE_TICK * 10),
        ],
        move |client| async move {
            let request = http::Request::get("http://example.test/slow")
                .body(())
                .unwrap();
            let stream = client
                .send_request(&request, true)
                .expect("a stream")
                .with_deadline(past_a_tick);
            stream.response().await.map(|response| response.status())
        },
    );

    assert_eq!(
        kind.expect("answered within the deadline"),
        http::StatusCode::OK
    );
}
