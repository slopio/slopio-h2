use std::io;

use std::time::Duration;

use runtime::Bytes;
use runtime_core::deterministic_testing::{
    FakeRing, ReadEvent, Scripted, WriteEvent, simulated_socket,
};
use runtime_core::runtime::RuntimeInner;
use runtime_core::runtime::time::timeout;

use super::Driver;
use crate::client::{Body, Connection, PlainText, Unavailable};
use crate::shared::codec::frames::CLIENT_PREFACE;
use crate::shared::connection::DEADLINE_TICK;
use crate::shared::connection::input_data::InputData;
use crate::shared::connection::settings::Settings;
use crate::shared::transport::PlainMessages;

mod dst;
mod dst_peer;
#[cfg(feature = "grpc")]
mod grpc;

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

/// Static table entry 8, so scripts need not model the decoder's HPACK state.
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

fn server_opening() -> Vec<u8> {
    let mut bytes = frame(SETTINGS, 0, 0, &[0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);
    bytes.extend_from_slice(&frame(SETTINGS, FLAG_ACK, 0, &[]));
    bytes
}

/// Never indexed (§6.2.3), so the decoder's dynamic table is left untouched.
fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut out = vec![0x10, name.len() as u8];
    out.extend_from_slice(name.as_bytes());
    out.push(value.len() as u8);
    out.extend_from_slice(value.as_bytes());
    out
}

/// The script is closed with an EOF: a successful handshake leaves its recv
/// armed, and the simulator refuses to sleep with an op nothing can complete.
fn handshake(mut inbound: Vec<ReadEvent>) -> (io::Result<Settings>, Vec<u8>) {
    if !matches!(inbound.last(), Some(ReadEvent::Eof)) {
        inbound.push(ReadEvent::Eof);
    }
    // Delayed: the client's recv is not armed until the preface is sent, so a
    // reply due immediately would have nothing to be delivered to.
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
            // Spawned: a root future that yields with an empty task list puts
            // the runtime to sleep with nothing armed to wake it.
            runtime_core::runtime::spawn(async move {
                Driver::handshake(PlainMessages::<TestRing, false>::new(socket))
                    .await
                    .map(|conn| conn.connection().peer_settings())
            })
            .await
        },
        None,
        |run| run(),
    );

    (result, handle.writes(fd).concat())
}

/// The script is fixed before the runtime starts, so responses are declared at
/// a time the request will comfortably precede.
fn with_client<F, Fut, R>(inbound: Vec<Scripted>, app: F) -> (R, Vec<u8>)
where
    F: FnOnce(Connection<PlainText>) -> Fut + 'static,
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
                let conn = Driver::handshake(PlainMessages::<TestRing, false>::new(socket))
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

/// A completion cannot exceed its ring buffer, so larger responses must be
/// split into several reads.
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

/// Needed wherever a test asserts on bytes a drop produced: writing a frame
/// only wakes the loop, and the loop is what sends it.
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

    // §3.4.
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

    let peer = result.expect("the handshake completed");
    assert_eq!(peer.max_concurrent_streams, Some(100));

    // §6.5.3.
    let sent = frames(&written);
    let ack = sent
        .iter()
        .rev()
        .find(|f| f.kind == SETTINGS && f.flags & FLAG_ACK != 0)
        .expect("a SETTINGS ACK went out");
    assert!(ack.payload.is_empty(), "an ack carries no payload");
}

/// §6.9.2: only a WINDOW_UPDATE on stream 0 moves the connection window.
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

/// §6.5.3.
#[test]
fn the_servers_settings_alone_do_not_establish_the_connection() {
    let mut inbound = vec![ReadEvent::Data(frame(SETTINGS, 0, 0, &[]))];
    inbound.push(ReadEvent::Eof);

    let (result, _) = handshake(inbound);
    let err = result.expect_err("half an exchange is not a handshake");
    assert!(err.to_string().contains("closed"), "said why: {err}");
}

/// §3.4: an ACK of ours is not the server's preface.
#[test]
fn a_server_that_does_not_open_with_its_settings_is_refused() {
    let (result, _) = handshake(vec![ReadEvent::Data(frame(SETTINGS, FLAG_ACK, 0, &[]))]);
    let err = result.expect_err("an ACK is not a server preface");
    assert!(err.to_string().contains("SETTINGS"), "said why: {err}");
}

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

/// §6.7. Placed after the server's SETTINGS, since §3.4 requires those first.
#[test]
fn a_ping_during_the_handshake_is_answered() {
    let mut bytes = frame(SETTINGS, 0, 0, &[]);
    bytes.extend_from_slice(&frame(PING, 0, 0, b"probe!!!"));
    bytes.extend_from_slice(&frame(SETTINGS, FLAG_ACK, 0, &[]));

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

/// Scripted with a reply well past the deadline, so the deadline decides
/// rather than the script running out.
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
                    Driver::handshake(PlainMessages::<TestRing, false>::new(socket)),
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

/// §8.3.
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
    // §8.1, §4.3.
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

/// §8.3.1: `:scheme` is never omitted, so a bare path takes the transport's.
#[test]
fn a_request_with_no_scheme_takes_the_connections() {
    let ((), written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(100)),
        ],
        |client| async move {
            let request = http::Request::get("/hello").body(()).unwrap();
            let _stream = client.send_request(&request, true).expect("a stream");
            settle().await;
        },
    );

    let head = frames(&written)
        .into_iter()
        .find(|f| f.kind == HEADERS)
        .expect("a HEADERS frame went out");
    let decoded = decode_block(&head.payload);
    assert_eq!(decoded.get(":scheme").map(String::as_str), Some("http"));
}

/// §5.1.2.
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
            // Held: dropping it would retire the stream and free the slot.
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

/// A response head declaring `length`, and its body in two DATA frames that
/// arrive apart.
fn declared_in_two_frames(length: Option<&str>) -> Vec<Scripted> {
    let block = match length {
        Some(length) => head_with_length(STATUS_200[0], length),
        None => STATUS_200.to_vec(),
    };
    let mut first = frame(HEADERS, FLAG_END_HEADERS, 1, &block);
    first.extend_from_slice(&frame(DATA, 0, 1, b"hello "));
    vec![
        ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
        ReadEvent::Data(first).after(Duration::from_millis(10)),
        ReadEvent::Data(frame(DATA, FLAG_END_STREAM, 1, b"world")).after(Duration::from_millis(20)),
        ReadEvent::Eof.after(Duration::from_millis(200)),
    ]
}

#[test]
fn a_short_declared_body_comes_whole() {
    let (body, _) = with_client(declared_in_two_frames(Some("11")), |client| async move {
        let request = http::Request::get("http://example.test/").body(()).unwrap();
        let stream = client.send_request(&request, true).expect("a stream");
        stream.response().await.expect("a response");
        let body = stream.body().await.expect("a body");
        let after = stream.read().await.expect("nothing more");
        (body, after)
    });

    assert_eq!(body.0, Body::Complete(Box::from(&b"hello world"[..])));
    assert_eq!(body.1, None, "it was all taken");
}

/// Read rather than taken whole, it still comes in one piece, once complete.
#[test]
fn a_short_declared_body_is_one_read() {
    let (chunks, _) = with_client(declared_in_two_frames(Some("11")), |client| async move {
        let request = http::Request::get("http://example.test/").body(()).unwrap();
        let stream = client.send_request(&request, true).expect("a stream");
        let mut chunks = Vec::new();
        while let Some(chunk) = stream.read().await.expect("a body") {
            chunks.push(chunk);
        }
        chunks
    });

    assert_eq!(chunks, vec![b"hello world".to_vec()]);
}

#[test]
fn a_body_of_no_declared_length_streams() {
    let (seen, _) = with_client(declared_in_two_frames(None), |client| async move {
        let request = http::Request::get("http://example.test/").body(()).unwrap();
        let stream = client.send_request(&request, true).expect("a stream");
        let body = stream.body().await.expect("a body");
        let mut chunks = Vec::new();
        while let Some(chunk) = stream.read().await.expect("a body") {
            chunks.push(chunk);
        }
        (body, chunks)
    });

    assert_eq!(seen.0, Body::Streaming);
    assert_eq!(
        seen.1,
        vec![b"hello ".to_vec(), b"world".to_vec()],
        "each as it came"
    );
}

/// Past `ONESHOT_LIMIT` nothing is gathered, however exact the length.
#[test]
fn a_long_declared_body_streams() {
    let long = InputData::ONESHOT_LIMIT + 1;
    let mut head = frame(
        HEADERS,
        FLAG_END_HEADERS,
        1,
        &head_with_length(STATUS_200[0], &long.to_string()),
    );
    head.extend_from_slice(&frame(DATA, 0, 1, &[7; 1000]));

    let (body, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(head).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            let body = stream.body().await.expect("a body");
            let first = stream.read().await.expect("some of it");
            (body, first.map(|chunk| chunk.len()))
        },
    );

    assert_eq!(body.0, Body::Streaming);
    assert_eq!(body.1, Some(1000), "readable before the rest arrives");
}

/// RFC 9110 §9.3.2: the length a HEAD's response declares is not its body's.
#[test]
fn a_head_requests_body_is_whole_and_empty() {
    let answer = frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &head_with_length(STATUS_200[0], "1000"),
    );
    let (body, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(answer).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::head("http://example.test/")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            stream.body().await.expect("a body")
        },
    );

    assert_eq!(body, Body::Complete(Box::default()));
}

/// §8.1.
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

/// A buffer handed over goes out as a lent one does: framed at
/// `max_frame_size`, whole, and ended by its last frame. Whether it was
/// copied is `shared_connection`'s tests' to see; the wire cannot tell.
#[test]
fn an_owned_body_goes_out_whole() {
    let response = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, STATUS_200);
    let body: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
    let expected = body.clone();

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
            stream
                .write_owned(Bytes::copy_from_slice(&body), true)
                .await
                .expect("written");
            let head = stream.response().await.expect("a response");
            head.status().as_u16()
        },
    );

    assert_eq!(status, 200);
    let data: Vec<Frame> = frames(&written)
        .into_iter()
        .filter(|f| f.kind == DATA)
        .collect();
    assert_eq!(
        data.iter().map(|f| f.payload.len()).collect::<Vec<_>>(),
        [16_384, 16_384, 7_232]
    );
    let sent: Vec<u8> = data.iter().flat_map(|f| f.payload.clone()).collect();
    assert_eq!(sent, expected);
    assert_eq!(
        data.last().expect("a frame").flags & FLAG_END_STREAM,
        FLAG_END_STREAM
    );
}

/// §6.9.1. No END_STREAM, deliberately: an ended stream is retired and its
/// credit goes to the connection only.
#[test]
fn reading_the_body_credits_the_peer() {
    // Together the frames pass the release threshold (half of
    // `STREAM_RECV_WINDOW`), so one WINDOW_UPDATE covers them all. Each stays
    // within the 16384 max frame size.
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

        // By size, not count: a frame cut by a segment end arrives in pieces.
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
    // Bounded rather than exact: the crossing read's size depends on where
    // the ring cut the segments.
    let credited = u32::from_be_bytes(updates[0].payload[..4].try_into().unwrap()) as usize;
    assert!(
        (crate::client::STREAM_RECV_WINDOW as usize / 2..=body).contains(&credited),
        "the accumulated credit, announced once it was worth a frame: {credited}"
    );
}

/// §6.9.1: padding is never read, so it must be credited on arrival or the
/// stream's window shrinks for good. The padding alone passes the release
/// threshold here, so a stream WINDOW_UPDATE can only be the padding's.
#[test]
fn padding_is_credited_back_on_the_stream() {
    const FLAG_PADDED: u8 = 0x8;
    const PADDING: usize = 255;
    let frames_needed = (crate::client::STREAM_RECV_WINDOW as usize / 2).div_ceil(PADDING + 1);

    let mut padded = vec![PADDING as u8, b'x'];
    padded.resize(2 + PADDING, 0);
    let mut response = frame(HEADERS, FLAG_END_HEADERS, 1, STATUS_200);
    for _ in 0..frames_needed {
        response.extend_from_slice(&frame(DATA, FLAG_PADDED, 1, &padded));
    }

    let mut inbound = vec![ReadEvent::Data(server_opening()).after(Duration::from_millis(1))];
    inbound.extend(split(response, Duration::from_millis(10)));
    inbound.push(ReadEvent::Eof.after(Duration::from_millis(500)));

    let (read, written) = with_client(inbound, move |client| async move {
        let request = http::Request::get("http://example.test/padded")
            .body(())
            .unwrap();
        let stream = client.send_request(&request, true).expect("a stream");
        let _ = stream.response().await.expect("a response");
        let mut total = 0;
        while total < frames_needed {
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

    assert_eq!(
        read, frames_needed,
        "one byte a frame reached the application"
    );
    assert!(
        frames(&written)
            .iter()
            .any(|f| f.kind == WINDOW_UPDATE && f.stream_id == 1),
        "the stream was credited for the padding it will never read"
    );
}

/// `status` is a static-table index byte.
fn head_with_length(status: u8, length: &str) -> Vec<u8> {
    let mut block = vec![status];
    block.extend_from_slice(&literal("content-length", length));
    block
}

/// §8.1.1. Stream 1 is short, stream 3 is long, stream 5 is exact.
#[test]
fn a_body_that_breaks_its_content_length_is_refused() {
    let mut answers = Vec::new();
    for (id, body) in [
        (1, &b"short"[..]),
        (3, &b"too long"[..]),
        (5, &b"exact"[..]),
    ] {
        let declared = match id {
            1 => "10",
            3 => "3",
            _ => "5",
        };
        answers.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS,
            id,
            &head_with_length(STATUS_200[0], declared),
        ));
        answers.extend_from_slice(&frame(DATA, FLAG_END_STREAM, id, body));
    }

    let (outcomes, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(answers).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let mut outcomes = Vec::new();
            let streams: Vec<_> = (0..3)
                .map(|_| {
                    let request = http::Request::get("http://example.test/").body(()).unwrap();
                    client.send_request(&request, true).expect("a stream")
                })
                .collect();
            settle().await;
            for stream in &streams {
                let mut body = Vec::new();
                let ended = loop {
                    match stream.read().await {
                        Ok(Some(chunk)) => body.extend_from_slice(&chunk),
                        Ok(None) => break Ok(body),
                        Err(e) => break Err(e.to_string()),
                    }
                };
                outcomes.push(ended);
            }
            settle().await;
            outcomes
        },
    );

    for (outcome, id) in outcomes[..2].iter().zip([1, 3]) {
        let refused = outcome.as_ref().expect_err("the body broke its length");
        assert!(
            refused.contains("content-length"),
            "stream {id} says why: {refused}"
        );
    }
    assert_eq!(
        outcomes[2].as_deref(),
        Ok(&b"exact"[..]),
        "a kept promise is kept"
    );

    let resets: Vec<u32> = frames(&written)
        .iter()
        .filter(|f| f.kind == RST_STREAM)
        .map(|f| f.stream_id)
        .collect();
    assert_eq!(
        resets,
        [1, 3],
        "§8.1.1: a stream error, on the two that broke it"
    );
}

/// RFC 9110 §9.3.2 (HEAD) and §15.4.5 (304).
#[test]
fn a_bodiless_response_is_not_held_to_its_content_length() {
    const STATUS_304: u8 = 0x8b;
    let mut answers = frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &head_with_length(STATUS_200[0], "1000"),
    );
    answers.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        3,
        &head_with_length(STATUS_304, "1000"),
    ));

    let (outcomes, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(answers).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let head = http::Request::head("http://example.test/")
                .body(())
                .unwrap();
            let conditional = http::Request::get("http://example.test/")
                .header("if-none-match", "\"v1\"")
                .body(())
                .unwrap();
            let streams = [
                client.send_request(&head, true).expect("a stream"),
                client.send_request(&conditional, true).expect("a stream"),
            ];
            settle().await;
            let mut outcomes = Vec::new();
            for stream in &streams {
                let status = stream.response().await.map(|r| r.status().as_u16());
                let end = stream.read().await.map(|chunk| chunk.is_none());
                outcomes.push((
                    status.map_err(|e| e.to_string()),
                    end.map_err(|e| e.to_string()),
                ));
            }
            outcomes
        },
    );

    assert_eq!(
        outcomes[0],
        (Ok(200), Ok(true)),
        "the HEAD's response, whole"
    );
    assert_eq!(outcomes[1], (Ok(304), Ok(true)), "the 304, whole");
}

/// §6.5.2.
#[test]
fn a_server_that_enables_push_is_refused() {
    // Id 0x2, value 1.
    let mut bytes = frame(SETTINGS, 0, 0, &[0x00, 0x02, 0x00, 0x00, 0x00, 0x01]);
    bytes.extend_from_slice(&frame(SETTINGS, FLAG_ACK, 0, &[]));

    let (result, written) = handshake(vec![ReadEvent::Data(bytes)]);
    let err = result.expect_err("a server cannot enable push");
    assert!(err.to_string().contains("ENABLE_PUSH"), "said why: {err}");
    assert!(
        frames(&written).iter().any(|f| f.kind == GOAWAY),
        "and told the peer"
    );
}

/// §8.1.
#[test]
fn data_before_the_response_head_is_refused() {
    let answer = frame(DATA, FLAG_END_STREAM, 1, b"headless");

    let (outcome, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(answer).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            let outcome = stream
                .response()
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            settle().await;
            outcome
        },
    );

    let refused = outcome.expect_err("no response came");
    assert!(
        refused.contains("malformed response"),
        "said why: {refused}"
    );
    assert!(
        frames(&written)
            .iter()
            .any(|f| f.kind == RST_STREAM && f.stream_id == 1),
        "the stream was reset"
    );
}

/// §5.1.
#[test]
fn headers_after_the_peers_end_stream_are_refused() {
    let mut answer = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, STATUS_200);
    answer.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &literal("x-late", "1"),
    ));

    let (_, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(answer).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::post("http://example.test/")
                .body(())
                .unwrap();
            // The upload stays open, so the stream is still live when the
            // late trailers arrive.
            let stream = client.send_request(&request, false).expect("a stream");
            settle().await;
            settle().await;
            drop(stream);
        },
    );

    let reset = frames(&written)
        .into_iter()
        .find(|f| f.kind == RST_STREAM && f.stream_id == 1)
        .expect("the stream was reset");
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        crate::shared::codec::types::STREAM_CLOSED
    );
}

/// §5.1: with push refused, every even id is idle, however low.
#[test]
fn a_frame_on_a_server_initiated_id_ends_the_connection() {
    let answer = frame(WINDOW_UPDATE, 0, 2, &1u32.to_be_bytes());

    let (failure, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(answer).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            // Streams 1 and 3 opened, so 2 is below the next id.
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let one = client.send_request(&request, true).expect("a stream");
            let three = client.send_request(&request, true).expect("a stream");
            let failure = one.response().await.map(|_| ()).map_err(|e| e.to_string());
            drop((one, three));
            failure
        },
    );

    assert!(
        failure.is_err(),
        "the connection went, and the stream with it"
    );
    let goaway = frames(&written)
        .into_iter()
        .find(|f| f.kind == GOAWAY)
        .expect("§5.4.1: said with a GOAWAY");
    assert_eq!(
        u32::from_be_bytes(goaway.payload[4..8].try_into().unwrap()),
        crate::shared::codec::types::PROTOCOL_ERROR
    );
}

/// §8.2.2.
#[test]
fn connection_specific_fields_do_not_go_out() {
    let (_, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/")
                .header("connection", "keep-alive")
                .header("keep-alive", "timeout=5")
                .header("proxy-connection", "keep-alive")
                .header("transfer-encoding", "chunked")
                .header("upgrade", "h2c")
                .header("te", "gzip")
                .header("x-kept", "yes")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            settle().await;
            drop(stream);

            let request = http::Request::get("http://example.test/")
                .header("te", "trailers")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            settle().await;
            drop(stream);
        },
    );

    // One decoder for the connection: the second head indexes the first.
    let mut decoder = crate::shared::hpack::Decoder::new(4096);
    let heads: Vec<_> = frames(&written)
        .into_iter()
        .filter(|f| f.kind == HEADERS)
        .map(|f| decode_block_with(&mut decoder, &f.payload))
        .collect();
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
        "te",
    ] {
        assert!(
            !heads[0].contains_key(name),
            "{name} was dropped: {:?}",
            heads[0]
        );
    }
    assert_eq!(heads[0].get("x-kept").map(String::as_str), Some("yes"));
    assert_eq!(
        heads[1].get("te").map(String::as_str),
        Some("trailers"),
        "the one TE value an HTTP/2 request may carry"
    );
}

/// §5.1.1.
#[test]
fn a_connection_out_of_stream_ids_says_it_is_closed() {
    let (states, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            client.shared.skip_to_stream_id((1 << 31) - 1);
            let before = client.is_closed();
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let last = client.send_request(&request, true).expect("the last id");
            let after = client.is_closed();
            let refused = client.send_request(&request, true).is_err();
            drop(last);
            (before, after, refused)
        },
    );

    assert_eq!(states, (false, true, true));
}

/// The decoder keeps dispatching the rest of the chunk after an error the
/// handler found, so the handler must ignore it.
#[test]
fn nothing_is_delivered_after_a_connection_error() {
    // §6.5.2: an initial window past 2^31-1 is a FLOW_CONTROL_ERROR.
    let mut bytes = frame(SETTINGS, 0, 0, &[0x00, 0x04, 0x80, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        STATUS_200,
    ));

    let (outcome, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(bytes).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            settle().await;
            stream
                .response()
                .await
                .map(|r| r.status().as_u16())
                .map_err(|e| e.to_string())
        },
    );

    assert!(
        outcome.is_err(),
        "the response behind the error was not delivered: {outcome:?}"
    );
}

/// §8.1. The head is taken before the trailers arrive, which is the case that
/// tells a trailer section from a second response head.
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

/// §6.4.
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

/// §8.1: clients MUST NOT discard a complete response for a
/// RST_STREAM(NO_ERROR) that stops the upload. The upload is still stopped.
#[test]
fn a_reset_after_a_complete_response_leaves_the_response_whole() {
    let mut answer = frame(HEADERS, FLAG_END_HEADERS, 1, STATUS_200);
    answer.extend_from_slice(&frame(DATA, 0, 1, b"body"));
    answer.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &literal("x-checksum", "42"),
    ));
    // In the same chunk: by the time anything is read, the reset is in.
    answer.extend_from_slice(&frame(RST_STREAM, 0, 1, &0u32.to_be_bytes()));

    let (seen, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(answer).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::post("http://example.test/")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, false).expect("a stream");
            stream.write(b"the start of", false).await.expect("written");
            settle().await;
            settle().await;

            let status = stream.response().await.expect("a response").status();
            let mut body = Vec::new();
            while let Some(chunk) = stream.read().await.expect("the body, to its end") {
                body.extend_from_slice(&chunk);
            }
            let trailers = stream.trailers().and_then(|fields| {
                fields
                    .get("x-checksum")
                    .map(|v| v.to_str().unwrap().to_owned())
            });
            let upload = stream
                .write(b" an upload", true)
                .await
                .map_err(|e| e.to_string());
            (status, body, trailers, upload)
        },
    );

    let (status, body, trailers, upload) = seen;
    assert_eq!(status, 200);
    assert_eq!(body, b"body");
    assert_eq!(trailers.as_deref(), Some("42"));
    let refused = upload.expect_err("the upload was stopped");
    assert!(refused.contains("code 0x0"), "and says by what: {refused}");
}

#[test]
fn a_reset_before_the_end_still_fails_the_body() {
    let mut answer = frame(HEADERS, FLAG_END_HEADERS, 1, STATUS_200);
    answer.extend_from_slice(&frame(DATA, 0, 1, b"half"));
    answer.extend_from_slice(&frame(RST_STREAM, 0, 1, &0u32.to_be_bytes()));

    let (seen, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(answer).after(Duration::from_millis(10)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::get("http://example.test/").body(()).unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            settle().await;
            settle().await;

            let _ = stream.response().await.expect("a response");
            let first = stream.read().await.expect("what arrived");
            let then = stream.read().await.map_err(|e| e.to_string());
            (first, then)
        },
    );

    assert_eq!(seen.0.as_deref(), Some(&b"half"[..]));
    let cut = seen.1.expect_err("the body was cut short");
    assert!(cut.contains("reset by peer"), "and says so: {cut}");
}

/// §8.1.
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
            // The body never ends, so the stream is still open when dropped.
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

/// §6.8.
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

/// §6.8.
#[test]
fn closing_a_client_ends_the_connection_and_waits_for_the_goodbye() {
    // No EOF, deliberately: with one the test would pass on the peer's close.
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

#[test]
fn a_connection_that_fails_with_no_stream_open_still_says_why() {
    // §5.1: a HEADERS on a stream this client never opened.
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

/// A second ask must error, not hang.
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

/// The preface is skipped first: it is not a frame.
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

fn decode_block(payload: &[u8]) -> std::collections::HashMap<String, String> {
    decode_block_with(&mut crate::shared::hpack::Decoder::new(4096), payload)
}

/// For a connection's later heads, which may index what earlier ones added.
fn decode_block_with(
    decoder: &mut crate::shared::hpack::Decoder,
    payload: &[u8],
) -> std::collections::HashMap<String, String> {
    use crate::shared::hpack::Header;
    use runtime::bytes::BytesMut;

    let mut buf = BytesMut::from(payload);
    let mut cursor = std::io::Cursor::new(&mut buf);
    let mut out = std::collections::HashMap::new();
    decoder
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

/// No EOF, deliberately: the peer stays, and the client leaves.
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

/// §6.9.2.
#[test]
fn the_stream_window_is_announced_in_the_handshake() {
    let (_, written) = handshake(vec![ReadEvent::Data(server_opening())]);

    let settings = frames(&written)
        .into_iter()
        .find(|f| f.kind == SETTINGS && f.flags & FLAG_ACK == 0)
        .expect("our SETTINGS went out");

    // §6.5.1: six bytes per pair. 0x4 is SETTINGS_INITIAL_WINDOW_SIZE.
    let announced = settings
        .payload
        .chunks(6)
        .find(|entry| u16::from_be_bytes([entry[0], entry[1]]) == 0x4)
        .map(|entry| u32::from_be_bytes(entry[2..6].try_into().unwrap()))
        .expect("SETTINGS_INITIAL_WINDOW_SIZE is one of them");
    assert_eq!(announced, crate::client::STREAM_RECV_WINDOW);
}

async fn wait(d: Duration) {
    let _ = timeout(d, std::future::pending::<()>()).await;
}

/// §6.7.
#[test]
fn a_silent_peer_with_a_request_in_flight_is_probed() {
    let probe_due = DEADLINE_TICK * crate::client::ACTIVE_PING_TICKS;

    let (_, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(probe_due * 4),
        ],
        move |client| async move {
            let request = http::Request::get("http://example.test/slow")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            // Past the budget, short of giving up.
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

#[test]
fn a_peer_that_never_answers_a_probe_is_given_up_on() {
    let probe_due = DEADLINE_TICK * crate::client::ACTIVE_PING_TICKS;
    let give_up = probe_due + DEADLINE_TICK * crate::client::PING_TIMEOUT_TICKS;

    let ((failure, closed), written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(give_up * 4),
        ],
        move |client| async move {
            let request = http::Request::get("http://example.test/gone")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            // No stream deadline: only the connection ending resolves this.
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

    // §6.8.
    assert!(
        frames(&written).iter().any(|f| f.kind == GOAWAY),
        "a GOAWAY went out"
    );
}

#[test]
fn a_peer_that_answers_keeps_the_connection() {
    let probe_due = DEADLINE_TICK * crate::client::ACTIVE_PING_TICKS;
    let give_up = probe_due + DEADLINE_TICK * crate::client::PING_TIMEOUT_TICKS;

    // §6.7: the first probe of a connection carries counter 1.
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
            wait(give_up + DEADLINE_TICK).await;
            let closed = client.is_closed();
            drop(stream);
            closed
        },
    );

    assert!(!closed, "the answer kept it alive");
}

#[test]
fn our_own_requests_do_not_keep_a_silent_peer_from_being_probed() {
    let probe_due = DEADLINE_TICK * crate::client::ACTIVE_PING_TICKS;
    let give_up = probe_due + DEADLINE_TICK * crate::client::PING_TIMEOUT_TICKS;

    let (closed, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(give_up * 10),
        ],
        move |client| async move {
            // Under a tick apart, so no idle tick ever passes.
            for _ in 0..(give_up * 2).as_secs() / 3 {
                let request = http::Request::get("http://example.test/").body(()).unwrap();
                let Ok(stream) = client.send_request(&request, true) else {
                    break;
                };
                wait(Duration::from_secs(3)).await;
                drop(stream);
            }
            client.is_closed()
        },
    );

    assert!(
        frames(&written)
            .iter()
            .any(|f| f.kind == PING && f.flags & FLAG_ACK == 0),
        "the silent peer was asked"
    );
    assert!(closed, "and given up on when it did not answer");
}

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

/// A peer that pings every ten seconds for `pings` of them, so keepalive
/// never probes or gives up, and only idleness can end the connection. Each
/// delay runs from the read before it.
fn a_chatty_peer(pings: u32) -> Vec<Scripted> {
    let every = Duration::from_secs(10);
    let mut script = vec![ReadEvent::Data(server_opening()).after(Duration::from_millis(1))];
    for _ in 0..pings {
        script.push(ReadEvent::Data(frame(PING, 0, 0, &[0; 8])).after(every));
    }
    script.push(ReadEvent::Eof.after(every));
    script
}

#[test]
fn an_idle_connection_is_closed() {
    let idle = DEADLINE_TICK * crate::client::IDLE_CLOSE_TICKS;

    let ((before, after, end), written) =
        with_client(a_chatty_peer(40), move |client| async move {
            wait(idle - DEADLINE_TICK).await;
            let before = client.is_closed();
            wait(DEADLINE_TICK * 3).await;
            let after = client.is_closed();
            (before, after, client.closed().await.is_ok())
        });

    assert!(!before, "kept until it had been idle long enough");
    assert!(after, "then it takes no more requests");
    assert!(end, "and ends cleanly, before the peer goes");
    assert!(
        frames(&written).iter().any(|f| f.kind == GOAWAY),
        "§6.8: a GOAWAY went out"
    );
}

#[test]
fn a_request_restarts_the_idle_count() {
    let idle = DEADLINE_TICK * crate::client::IDLE_CLOSE_TICKS;

    let ((kept, closed), _) = with_client(a_chatty_peer(40), move |client| async move {
        wait(idle - DEADLINE_TICK * 2).await;
        let request = http::Request::get("http://example.test/").body(()).unwrap();
        let stream = client.send_request(&request, true).expect("a stream");
        // Open far past the idle budget: in use is not idle.
        wait(idle + DEADLINE_TICK).await;
        drop(stream);
        wait(idle - DEADLINE_TICK * 2).await;
        let kept = !client.is_closed();
        wait(DEADLINE_TICK * 4).await;
        (kept, client.is_closed())
    });

    assert!(
        kept,
        "idle counted from the stream's end, not from the start"
    );
    assert!(closed, "and closed once idle long enough after it");
}

/// The GOAWAY is scripted once the handshake is done, so it is the write
/// that stalls, and nothing before it.
#[test]
fn a_peer_that_stops_reading_does_not_hold_the_goodbye() {
    let farewell = crate::client::FLUSH_TIMEOUT;
    let (fake, handle) = FakeRing::builder().virtual_time().build();
    let socket = simulated_socket();
    let fd = socket.fd();
    handle.on_multishot_read(
        fd,
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Eof.after(farewell * 100),
        ],
    );
    let script = handle.clone();

    let (outcome, took) = RuntimeInner::simulated(fake).block_on::<TestRing, _>(
        async move {
            runtime_core::runtime::spawn(async move {
                let conn = Driver::handshake(PlainMessages::<TestRing, false>::new(socket))
                    .await
                    .expect("the handshake completed");
                let client = conn.spawn();
                script.on_write(fd, WriteEvent::All.after(farewell * 60));

                let start = runtime_core::runtime::now();
                client.close();
                let outcome = client.closed().await.map_err(|e| e.to_string());
                let took = runtime_core::runtime::now().duration_since(start).unwrap();
                (outcome, took)
            })
            .await
        },
        None,
        |run| run(),
    );

    let failure = outcome.expect_err("the GOAWAY never went");
    assert!(failure.contains("GOAWAY"), "{failure}");
    assert!(
        took < farewell * 2,
        "given up at the timeout, not the peer's pace: {took:?}"
    );
}

/// §8.1.
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

/// §8.1.
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

#[test]
fn a_deadline_longer_than_one_tick_is_still_one_deadline() {
    let past_a_tick = DEADLINE_TICK * 3 + Duration::from_millis(500);

    let (kind, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            // Arrives after two ticks, before the deadline.
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

/// An upload larger than the connection window: the writer parks on the
/// spent window, in its stream's slot, and goes on when stream 0 is credited.
#[test]
fn a_writer_parked_on_the_connection_window_goes_on_when_it_is_credited() {
    // MAX_CONCURRENT_STREAMS 100, and INITIAL_WINDOW_SIZE 1 MiB to take the
    // stream window out of the way, so the connection's is what runs out.
    let mut opening = frame(
        SETTINGS,
        0,
        0,
        &[0x00, 0x03, 0, 0, 0, 0x64, 0x00, 0x04, 0, 0x10, 0, 0],
    );
    opening.extend_from_slice(&frame(SETTINGS, FLAG_ACK, 0, &[]));
    let credit = frame(WINDOW_UPDATE, 0, 0, &65_535u32.to_be_bytes());
    let response = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, STATUS_200);

    let (status, written) = with_client(
        vec![
            ReadEvent::Data(opening).after(Duration::from_millis(1)),
            ReadEvent::Data(credit).after(Duration::from_millis(50)),
            ReadEvent::Data(response).after(Duration::from_millis(100)),
            ReadEvent::Eof.after(Duration::from_millis(200)),
        ],
        |client| async move {
            let request = http::Request::post("http://example.test/upload")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, false).expect("a stream");
            stream
                .write(&vec![7u8; 100_000], true)
                .await
                .expect("written");
            let head = stream.response().await.expect("a response");
            head.status().as_u16()
        },
    );

    assert_eq!(status, 200);
    let sent: usize = frames(&written)
        .iter()
        .filter(|f| f.kind == DATA)
        .map(|f| f.payload.len())
        .sum();
    assert_eq!(sent, 100_000, "the whole body, past the first 65 535 bytes");
}
