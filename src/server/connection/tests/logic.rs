//! Sequences a conforming peer produces, which the connection has to serve.
//!
//! The suite beside this one is about peers that misbehave. These are the
//! other half: a defence that fires on an honest exchange is an outage, and
//! each test here is an honest exchange that one of them could mistake.

use std::time::Duration;

use runtime_core::deterministic_testing::{ReadEvent, Scripted};
use runtime_core::runtime::time::Sleep;

use super::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GET_BLOCK, GOAWAY, HEADERS, PING, PREFACE,
    RST_STREAM, SETTINGS, deliveries, frame, run_connection, run_connection_with,
};

const FLAG_PADDED: u8 = 0x8;

fn preface() -> Vec<u8> {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    bytes
}

fn status_of(head: &Frame) -> Option<String> {
    super::decode_block(&head.payload).get(":status").cloned()
}

/// A GET whose handler takes longer than `BODY_GRACE` to answer, on a
/// connection the peer keeps alive with a PING.
///
/// The request carried END_STREAM, so there is no body to be slow about: the
/// peer owes nothing, and the wait is the handler's.
#[test]
fn a_slow_handler_is_not_a_starved_body() {
    let mut open = preface();
    open.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));

    let second = Duration::from_secs(1);
    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        // Past `SWEEP_INTERVAL` and `BODY_GRACE`, while the handler sleeps.
        ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 6),
        // After the handler woke and wrote: the chunk its response leaves on.
        ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 9),
        ReadEvent::Eof.after(second * 10),
    ];

    let written = run_connection_with(
        inbound,
        |_, _| {},
        |stream: crate::server::Stream| async move {
            Sleep::during(Duration::from_secs(8)).await;
            stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
        },
    );

    assert!(
        !written.iter().any(|f| f.kind == RST_STREAM),
        "a request with no body cannot have a starved one: {written:?}"
    );
    let head = written
        .iter()
        .find(|f| f.kind == HEADERS)
        .expect("the slow handler's response went out");
    assert_eq!(status_of(head).as_deref(), Some("200"));
}

/// A small upload, complete, whose handler then thinks for a while. The body
/// is all there — END_STREAM came — so its rate has nothing left to say.
#[test]
fn a_finished_body_is_not_judged_on_its_rate() {
    let mut open = preface();
    open.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));
    open.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, b"tiny body"));

    let second = Duration::from_secs(1);
    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 6),
        ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 9),
        ReadEvent::Eof.after(second * 10),
    ];

    let written = run_connection_with(
        inbound,
        |_, _| {},
        |stream: crate::server::Stream| async move {
            while stream.readable().await {
                let taken = stream.peek(|bytes| bytes.len());
                stream.consume(taken);
            }
            Sleep::during(Duration::from_secs(8)).await;
            stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
        },
    );

    assert!(
        !written.iter().any(|f| f.kind == RST_STREAM),
        "the body was complete before anyone judged it: {written:?}"
    );
    assert!(written.iter().any(|f| f.kind == HEADERS));
}

/// A response the *handler* paces — an event stream — to a peer with all the
/// credit in the world. The peer is not holding anything: there is nothing to
/// take.
#[test]
fn a_response_paced_by_its_handler_is_not_a_starved_one() {
    let mut open = preface();
    open.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));

    let second = Duration::from_secs(1);
    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 7),
        ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 10),
        ReadEvent::Eof.after(second * 11),
    ];

    let written = run_connection_with(
        inbound,
        |_, _| {},
        |stream: crate::server::Stream| async move {
            stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
            stream.write_data(b"event: one\n\n").await;
            Sleep::during(Duration::from_secs(8)).await;
            stream.write_data_final(b"event: two\n\n").await;
        },
    );

    assert!(
        !written.iter().any(|f| f.kind == RST_STREAM),
        "the handler was the slow one, not the peer: {written:?}"
    );
    let body: Vec<u8> = written
        .iter()
        .filter(|f| f.kind == DATA)
        .flat_map(|f| f.payload.clone())
        .collect();
    assert_eq!(body, b"event: one\n\nevent: two\n\n");
}

/// §6.9.1: padding is debited from the stream window like the payload, and
/// like the payload it has to come back — the handler never sees it, so
/// nobody else will return it.
///
/// 300 frames of 1000 bytes under 255 of padding. Delivered 15 KB at a time
/// and consumed as it lands, so a server that accounts correctly never has
/// more than a fraction of the window outstanding.
#[test]
fn padding_is_credited_back_on_the_stream() {
    let mut bytes = preface();
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));

    let mut padded = vec![255u8];
    padded.extend_from_slice(&[b'x'; 1000]);
    padded.extend_from_slice(&[0u8; 255]);
    for _ in 0..300 {
        bytes.extend_from_slice(&frame(DATA, FLAG_PADDED, 1, &padded));
    }
    bytes.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, b""));

    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);
    let written = run_connection(inbound, |_, _| {});

    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "a peer inside its window was told it overran it: {:?}",
        written.iter().find(|f| f.kind == GOAWAY)
    );
    let body = written
        .iter()
        .find(|f| f.kind == DATA)
        .expect("the upload was answered");
    assert_eq!(body.payload, b"read 300000 bytes\n");
}

/// §6.5.2 / RFC 7541 §4.2: a peer that announces SETTINGS_HEADER_TABLE_SIZE 0
/// has no dynamic table, and a response that indexes into one cannot be
/// decoded by it.
#[test]
fn a_peer_with_no_hpack_table_is_not_sent_indexed_fields() {
    use crate::shared::hpack::Decoder;
    use bytes::BytesMut;

    let mut bytes = PREFACE.to_vec();
    // SETTINGS_HEADER_TABLE_SIZE (0x1) = 0.
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[0x00, 0x01, 0, 0, 0, 0]));
    for id in [1, 3] {
        bytes.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            id,
            GET_BLOCK,
        ));
    }

    let written = run_connection_with(
        vec![ReadEvent::Data(bytes).into(), ReadEvent::Eof.into()],
        |_, _| {},
        |stream: crate::server::Stream| async move {
            let mut fields = http::HeaderMap::new();
            fields.insert("x-request-tag", "the-same-value-twice".parse().unwrap());
            stream.write_headers_final(http::StatusCode::OK, &fields);
        },
    );

    // The peer's decoder: one for the connection, with the table it announced.
    let mut decoder = Decoder::new(0);
    let heads: Vec<&Frame> = written.iter().filter(|f| f.kind == HEADERS).collect();
    assert_eq!(heads.len(), 2);
    for head in heads {
        let mut buf = BytesMut::from(&head.payload[..]);
        let mut cursor = std::io::Cursor::new(&mut buf);
        let decoded = decoder.decode(&mut cursor, |_| {});
        assert!(
            decoded.is_ok(),
            "stream {}: a decoder with no table could not read {:02x?}: {decoded:?}",
            head.stream_id,
            head.payload
        );
    }
}

/// §8.2.1: a field HTTP refuses makes its request malformed, and nothing
/// more — the other streams share the HPACK table, not the fault. Refused
/// fields are still indexed, which is what the second request checks: it
/// names an entry that sits *behind* the refused one, and finds it only if
/// the refused one took its slot.
#[test]
fn a_refused_field_resets_its_stream_and_nothing_else() {
    let mut first = GET_BLOCK.to_vec();
    // `x-ok: 1`, then `x-bad: a\r\nb`, both literals with incremental
    // indexing: x-bad is entry 62, x-ok entry 63.
    first.extend_from_slice(&[0x40, 4, b'x', b'-', b'o', b'k', 1, b'1']);
    first.extend_from_slice(&[0x40, 5, b'x', b'-', b'b', b'a', b'd', 4, b'a', b'\r', b'\n', b'b']);
    let mut second = GET_BLOCK.to_vec();
    second.push(0x80 | 63);

    let mut bytes = preface();
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &first));
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 3, &second));

    let written = run_connection(vec![ReadEvent::Data(bytes), ReadEvent::Eof], |_, _| {});

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM && f.stream_id == 1)
        .unwrap_or_else(|| panic!("the malformed request was reset: {written:?}"));
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        crate::shared::codec::types::PROTOCOL_ERROR
    );
    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "one bad field is not the connection's fault: {:?}",
        written.iter().find(|f| f.kind == GOAWAY)
    );
    assert!(
        written.iter().any(|f| f.kind == HEADERS && f.stream_id == 3),
        "and the next request, indexing past it, was served: {written:?}"
    );
}

/// §5.4.2 / §5.1: a request whose header block is malformed is a *stream*
/// error, and the stream it was opening is closed by the reset — not idle. A
/// client that sent `HEADERS, DATA` back to back had the DATA on the wire
/// before our RST_STREAM could reach it, and the connection has to survive
/// that.
#[test]
fn a_body_in_flight_behind_a_malformed_request_does_not_end_the_connection() {
    let mut bytes = preface();
    // `:method GET` twice: decodes fine, and is malformed (§8.3).
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, &[0x82, 0x82, 0x86, 0x84]));
    bytes.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, b"already on the wire"));
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        3,
        GET_BLOCK,
    ));

    let written = run_connection(vec![ReadEvent::Data(bytes), ReadEvent::Eof], |_, _| {});

    assert!(
        written.iter().any(|f| f.kind == RST_STREAM && f.stream_id == 1),
        "the malformed request was reset: {written:?}"
    );
    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "its body in flight is a race, not a protocol error: {:?}",
        written.iter().find(|f| f.kind == GOAWAY)
    );
    assert!(
        written.iter().any(|f| f.kind == HEADERS && f.stream_id == 3),
        "and the next request was served: {written:?}"
    );
}

/// A handler that answers before the upload is over — a `401`, a `413` — and
/// returns. §8.1 lets the server follow a complete response with
/// RST_STREAM(NO_ERROR) to stop the body, and the stream's token does, on its
/// way out. Without it an honest peer is left parked on a stream window nobody
/// will ever reopen, holding one of `MAX_CONCURRENT_STREAMS` until
/// `body_is_starving` blames it.
#[test]
fn an_early_response_does_not_strand_the_upload() {
    let mut bytes = preface();
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));
    // Four frames of 15 KB: most of the 65 535 the stream window starts at.
    for _ in 0..4 {
        bytes.extend_from_slice(&frame(DATA, 0, 1, &[b'x'; 15_000]));
    }

    let mut inbound: Vec<Scripted> = deliveries(&bytes).into_iter().map(Into::into).collect();
    inbound.push(ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(Duration::from_secs(1)));
    inbound.push(ReadEvent::Eof.after(Duration::from_secs(2)));

    let written = run_connection_with(
        inbound,
        |_, _| {},
        |stream: crate::server::Stream| async move {
            stream.write_headers_final(http::StatusCode::UNAUTHORIZED, &http::HeaderMap::new());
        },
    );

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM && f.stream_id == 1)
        .unwrap_or_else(|| panic!("60 KB into a 64 KB window, and the peer was told nothing: {written:?}"));
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        crate::shared::codec::types::NO_ERROR,
        "the response was complete: nothing went wrong"
    );
    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "the body still in flight is a race, not a fault: {written:?}"
    );
}

/// §5.1: whoever sends RST_STREAM tolerates what the peer had in flight. A
/// handler that answers early has its stream reset on the way out, and
/// trailers the peer sent before it could have seen that land on an id that
/// is gone — which is a race, and used to cost every stream on the connection.
#[test]
fn trailers_in_flight_after_an_early_response_do_not_end_the_connection() {
    let mut first = preface();
    first.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));
    first.extend_from_slice(&frame(DATA, 0, 1, b"some of the body"));

    // `x: y`, as a literal without indexing.
    let mut later = frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &[0x00, 1, b'x', 1, b'y'],
    );
    later.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        3,
        GET_BLOCK,
    ));

    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(first).into(),
        ReadEvent::Data(later).after(Duration::from_millis(50)),
        ReadEvent::Eof.after(Duration::from_secs(1)),
    ];
    let written = run_connection_with(
        inbound,
        |_, _| {},
        |stream: crate::server::Stream| async move {
            stream.write_headers_final(http::StatusCode::UNAUTHORIZED, &http::HeaderMap::new());
        },
    );

    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "trailers that raced our reset are not a protocol error: {:?}",
        written.iter().find(|f| f.kind == GOAWAY)
    );
    assert!(
        written.iter().any(|f| f.kind == HEADERS && f.stream_id == 3),
        "and the next request was served: {written:?}"
    );
}

/// A gRPC call that ends on its HEADERS has no message, and is still a gRPC
/// call: the handler has to know, to answer with a `grpc-status` and not as
/// the HTTP request it would otherwise take it for.
#[cfg(feature = "grpc")]
#[test]
fn a_grpc_call_with_no_body_is_still_grpc() {
    // `:method POST`, `:scheme http`, `:path /`, then `content-type` as a
    // literal on the static table's name (index 31).
    let mut block = vec![0x83, 0x86, 0x84, 0x0f, 0x10, 21];
    block.extend_from_slice(b"application/grpc+json");

    let mut bytes = preface();
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &block,
    ));

    let written = run_connection_with(
        deliveries(&bytes).into_iter().map(Into::into).collect(),
        |_, _| {},
        |stream: crate::server::Stream| async move {
            assert!(stream.is_grpc());
            assert_eq!(stream.grpc_format(), Some(crate::grpc::GrpcFormat::Json));
            assert!(stream.message().await.is_none(), "half-closed, nothing sent");

            let mut fields = http::HeaderMap::new();
            fields.insert("grpc-status", http::HeaderValue::from_static("13"));
            stream.write_headers_final(http::StatusCode::OK, &fields);
        },
    );

    let head = written
        .iter()
        .find(|f| f.kind == HEADERS && f.stream_id == 1)
        .expect("answered");
    assert_eq!(
        super::decode_block(&head.payload)
            .get("grpc-status")
            .map(String::as_str),
        Some("13")
    );
}
