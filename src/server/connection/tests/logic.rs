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
            stream.respond(http::StatusCode::OK, &http::HeaderMap::new(), true);
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
            stream.respond(http::StatusCode::OK, &http::HeaderMap::new(), true);
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
            stream.respond(http::StatusCode::OK, &http::HeaderMap::new(), false);
            stream.write(b"event: one\n\n", false).await;
            Sleep::during(Duration::from_secs(8)).await;
            stream.write(b"event: two\n\n", true).await;
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
            stream.respond(http::StatusCode::OK, &fields, true);
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
/// RST_STREAM(NO_ERROR) to stop the body; short of that, the bytes still
/// arriving have to be discarded and their credit handed back. Doing neither
/// leaves an honest peer parked on a stream window nobody will ever reopen,
/// holding one of `MAX_CONCURRENT_STREAMS` until `body_is_starving` blames it.
#[test]
#[ignore = "known gap: nothing drains or resets a stream whose handler left before the body ended"]
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
            stream.respond(http::StatusCode::UNAUTHORIZED, &http::HeaderMap::new(), true);
        },
    );

    let stopped = written.iter().any(|f| f.kind == RST_STREAM && f.stream_id == 1);
    let reopened = written
        .iter()
        .any(|f| f.kind == super::WINDOW_UPDATE && f.stream_id == 1);
    assert!(
        stopped || reopened,
        "60 KB into a 64 KB window, and the peer was told nothing: {written:?}"
    );
}
