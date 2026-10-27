//! Sequences a conforming peer produces, which the connection has to serve:
//! a defence that fires on an honest exchange is an outage.

use std::time::Duration;

use runtime_core::deterministic_testing::{ReadEvent, Scripted};
use runtime_core::runtime::time::Sleep;

use super::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GET_BLOCK, GOAWAY, HEADERS, PING, PREFACE,
    RST_STREAM, SETTINGS, deliveries, frame, run_connection, run_connection_timed,
    run_connection_with, run_connection_writes,
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

/// The request carried END_STREAM, so there is no body to be slow about.
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

/// A response has to leave when it is written: a peer waiting for it sends
/// no next chunk to carry it.
#[test]
fn a_late_response_leaves_without_waiting_for_the_peer() {
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
        ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 3),
        ReadEvent::Eof.after(second * 4),
    ];

    let writes = run_connection_writes(
        inbound,
        |_, _| {},
        |stream: crate::server::Stream| async move {
            Sleep::during(Duration::from_secs(1)).await;
            stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
        },
    );

    let response = writes
        .iter()
        .position(|write| write.iter().any(|f| f.kind == HEADERS && f.stream_id == 1))
        .unwrap_or_else(|| panic!("the response went out: {writes:?}"));
    let ack = writes
        .iter()
        .position(|write| write.iter().any(|f| f.kind == PING && f.flags & 0x1 != 0))
        .unwrap_or_else(|| panic!("the PING was answered: {writes:?}"));
    assert!(
        response < ack,
        "the response waited for the peer's next chunk to leave: {writes:?}"
    );
}

/// A handler's output must not count as the peer being alive, or a deadline
/// restarted by it would never expire. Silence is measured from the peer's
/// last chunk.
#[test]
fn a_streaming_response_does_not_keep_a_silent_peer_alive() {
    let mut open = preface();
    open.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));

    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        ReadEvent::Eof.after(Duration::from_secs(1000)),
    ];

    let written = run_connection_with(
        inbound,
        |_, _| {},
        |stream: crate::server::Stream| async move {
            stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
            loop {
                stream.write_data(b"tick").await;
                Sleep::during(Duration::from_secs(2)).await;
            }
        },
    );

    let goaway = written
        .iter()
        .find(|f| f.kind == GOAWAY)
        .unwrap_or_else(|| panic!("the silent peer was let go: {written:?}"));
    assert_eq!(&goaway.payload[8..], b"keepalive PING unanswered");
    assert!(
        written.iter().any(|f| f.kind == PING && f.flags & 0x1 == 0),
        "it was asked first: {written:?}"
    );
    // One DATA every two seconds for `ACTIVE_TICKS` + `PING_TIMEOUT_TICKS`,
    // give or take a tick — not the five hundred the EOF would have allowed.
    let data = written.iter().filter(|f| f.kind == DATA).count() as u32;
    let expected = (super::super::ACTIVE_TICKS + super::super::PING_TIMEOUT_TICKS) * 5 / 2;
    assert!(
        (expected - 3..=expected + 3).contains(&data),
        "{data} DATA frames, expected about {expected}"
    );
}

/// The silence is the handler's time, not the peer's: it is asked with a
/// PING, and a peer that answers is served.
#[test]
fn a_handler_slower_than_the_active_deadline_is_waited_for() {
    let mut open = preface();
    open.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));

    let second = Duration::from_secs(1);
    let silence = second * 5 * super::super::ACTIVE_TICKS;
    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        // Any opaque will do: whatever the peer sends answers the question.
        ReadEvent::Data(frame(PING, 0x1, 0, &1u64.to_be_bytes())).after(silence + second * 7),
        ReadEvent::Eof.after(silence + second * 30),
    ];

    let written = run_connection_with(
        inbound,
        |_, _| {},
        |stream: crate::server::Stream| async move {
            Sleep::during(Duration::from_secs(40)).await;
            stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
        },
    );

    let probe = written
        .iter()
        .position(|f| f.kind == PING && f.flags & 0x1 == 0)
        .unwrap_or_else(|| panic!("the silent peer was asked: {written:?}"));
    let response = written
        .iter()
        .position(|f| f.kind == HEADERS && f.stream_id == 1)
        .unwrap_or_else(|| panic!("the slow handler's response went out: {written:?}"));
    assert!(
        probe < response,
        "asked while the handler worked: {written:?}"
    );
    assert_eq!(status_of(&written[response]).as_deref(), Some("200"));
    assert!(
        !written[..response].iter().any(|f| f.kind == GOAWAY),
        "and not closed on before it answered: {written:?}"
    );
}

/// A peer that opens a stream, sends no body, and answers every probe is
/// holding the stream: the sweep still resets it.
#[test]
fn answering_pings_does_not_hold_a_stream_without_its_body() {
    let mut open = preface();
    // No END_STREAM: a body is owed, and never sent.
    open.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));

    let second = Duration::from_secs(1);
    let silence = second * 5 * super::super::ACTIVE_TICKS;
    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        ReadEvent::Data(frame(PING, 0x1, 0, &1u64.to_be_bytes())).after(silence + second * 7),
        ReadEvent::Eof.after(silence + second * 30),
    ];

    let written = run_connection_timed(inbound, |_, _| {});

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM && f.stream_id == 1)
        .unwrap_or_else(|| panic!("the held stream was reset: {written:?}"));
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        crate::shared::codec::types::ENHANCE_YOUR_CALM
    );
}

/// §6.8: GOAWAY(NO_ERROR) is the peer opening nothing more, not giving up on
/// what it asked: the connection drains.
#[test]
fn a_peer_that_says_goodbye_still_gets_its_answer() {
    let mut open = preface();
    open.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));
    // Last stream id 0 — we opened none — and NO_ERROR.
    let goaway = frame(GOAWAY, 0, 0, &[0; 8]);

    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        ReadEvent::Data(goaway).after(Duration::from_millis(10)),
        // The connection has to end on its own, when its last stream does.
        ReadEvent::Eof.after(Duration::from_secs(1000)),
    ];
    let written = run_connection_with(inbound, |_, _| {}, slow_ok);

    let head = written
        .iter()
        .find(|f| f.kind == HEADERS && f.stream_id == 1)
        .unwrap_or_else(|| panic!("the request in flight was answered: {written:?}"));
    assert_eq!(status_of(head).as_deref(), Some("200"));
    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "the peer left in good order, and so do we: {written:?}"
    );
}

/// A half-closed peer sends no more, and can still read.
#[test]
fn a_peer_that_half_closes_still_gets_its_answer() {
    let mut open = preface();
    open.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));

    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        ReadEvent::Eof.after(Duration::from_millis(10)),
    ];
    let written = run_connection_with(inbound, |_, _| {}, slow_ok);

    let head = written
        .iter()
        .find(|f| f.kind == HEADERS && f.stream_id == 1)
        .unwrap_or_else(|| panic!("the request in flight was answered: {written:?}"));
    assert_eq!(status_of(head).as_deref(), Some("200"));
}

/// A body cut short by a half-close is reset rather than left to a handler
/// that would read the end of the input as the end of the body.
#[test]
fn a_half_close_resets_the_bodies_it_cut_short() {
    let mut open = preface();
    open.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));
    open.extend_from_slice(&frame(DATA, 0, 1, b"half of a bo"));
    open.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        3,
        GET_BLOCK,
    ));

    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        ReadEvent::Eof.after(Duration::from_millis(10)),
    ];
    let written = run_connection_with(inbound, |_, _| {}, slow_ok);

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM && f.stream_id == 1)
        .unwrap_or_else(|| panic!("the cut body's stream was reset: {written:?}"));
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        crate::shared::codec::types::CANCEL
    );
    assert!(
        !written
            .iter()
            .any(|f| f.kind == HEADERS && f.stream_id == 1),
        "and its handler did not answer a body it never got: {written:?}"
    );
    assert!(
        written
            .iter()
            .any(|f| f.kind == HEADERS && f.stream_id == 3),
        "the finished request beside it was answered: {written:?}"
    );
}

/// A half-closed peer cannot answer a PING, so the wait is bounded by
/// `HALF_CLOSED_TICKS` alone.
#[test]
fn a_half_closed_peer_is_not_waited_on_forever() {
    let mut open = preface();
    open.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));

    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        ReadEvent::Eof.after(Duration::from_millis(10)),
    ];
    let written = run_connection_with(
        inbound,
        |_, _| {},
        |stream: crate::server::Stream| async move {
            // Held, so the stream stays unanswered rather than dropped.
            let _held = stream;
            std::future::pending::<()>().await;
        },
    );

    let goaway = written
        .iter()
        .find(|f| f.kind == GOAWAY)
        .unwrap_or_else(|| panic!("the connection was closed, and said so: {written:?}"));
    assert_eq!(
        &goaway.payload[8..],
        b"peer half-closed, answers not finished"
    );
    assert!(
        !written.iter().any(|f| f.kind == PING && f.flags & 0x1 == 0),
        "and nobody asked a peer that cannot answer: {written:?}"
    );
}

/// After a half-close a response out of credit can never finish, so it is
/// reset as soon as its writer runs dry — before the EOF (stream 1) or after
/// it (stream 3). Stream 5, answered two seconds on, tells a reset on the
/// writer parking from one on the next tick.
#[test]
fn a_half_closed_peer_does_not_hold_responses_out_of_credit() {
    let mut open = preface();
    for id in [1, 3, 5] {
        open.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            id,
            GET_BLOCK,
        ));
    }

    let inbound: Vec<Scripted> = vec![
        ReadEvent::Data(open).into(),
        ReadEvent::Eof.after(Duration::from_millis(10)),
    ];
    let written = run_connection_with(
        inbound,
        |_, _| {},
        |stream: crate::server::Stream| async move {
            if u32::from(stream.id()) == 5 {
                Sleep::during(Duration::from_secs(2)).await;
                stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
                return;
            }
            // Past the 65 535 bytes of credit both windows start with.
            let body = vec![b'x'; 100_000];
            stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
            if u32::from(stream.id()) == 3 {
                Sleep::during(Duration::from_millis(100)).await;
            }
            stream.write_data_final(&body).await;
        },
    );

    for id in [1, 3] {
        let reset = written
            .iter()
            .find(|f| f.kind == RST_STREAM && f.stream_id == id)
            .unwrap_or_else(|| panic!("stream {id}, out of credit, was reset: {written:?}"));
        assert_eq!(
            u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
            crate::shared::codec::types::CANCEL
        );
    }
    let reset = written
        .iter()
        .position(|f| f.kind == RST_STREAM && f.stream_id == 3);
    let answer = written
        .iter()
        .position(|f| f.kind == HEADERS && f.stream_id == 5)
        .unwrap_or_else(|| panic!("the working handler was answered: {written:?}"));
    assert!(
        reset < Some(answer),
        "stream 3 was reset when it ran dry, not on a later turn: {written:?}"
    );
    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "and nothing was left to time out: {:?}",
        written.iter().find(|f| f.kind == GOAWAY)
    );
}

async fn slow_ok(stream: crate::server::Stream) {
    Sleep::during(Duration::from_millis(100)).await;
    stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
}

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
/// has to come back — the handler never sees it, so nobody else will.
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

/// §6.5.2 / RFC 7541 §4.2: a peer with SETTINGS_HEADER_TABLE_SIZE 0 cannot
/// decode a response that indexes into a dynamic table.
#[test]
fn a_peer_with_no_hpack_table_is_not_sent_indexed_fields() {
    use crate::shared::hpack::Decoder;
    use runtime::bytes::BytesMut;

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

/// §8.2.1: a refused field makes only its request malformed. Refused fields
/// are still indexed: the second request names an entry behind the refused
/// one, and finds it only if the refused one took its slot.
#[test]
fn a_refused_field_resets_its_stream_and_nothing_else() {
    let mut first = GET_BLOCK.to_vec();
    // `x-ok: 1`, then `x-bad: a\r\nb`, both literals with incremental
    // indexing: x-bad is entry 62, x-ok entry 63.
    first.extend_from_slice(&[0x40, 4, b'x', b'-', b'o', b'k', 1, b'1']);
    first.extend_from_slice(&[
        0x40, 5, b'x', b'-', b'b', b'a', b'd', 4, b'a', b'\r', b'\n', b'b',
    ]);
    let mut second = GET_BLOCK.to_vec();
    second.push(0x80 | 63);

    let mut bytes = preface();
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &first,
    ));
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        3,
        &second,
    ));

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
        written
            .iter()
            .any(|f| f.kind == HEADERS && f.stream_id == 3),
        "and the next request, indexing past it, was served: {written:?}"
    );
}

/// §5.1: whoever sends RST_STREAM ignores what the peer had in flight, also
/// for a request refused before it was ever opened.
#[test]
fn trailers_behind_a_malformed_request_do_not_end_the_connection() {
    let mut bytes = preface();
    // `:method GET` twice: decodes fine, and is malformed (§8.3).
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS,
        1,
        &[0x82, 0x82, 0x86, 0x84],
    ));
    bytes.extend_from_slice(&frame(DATA, 0, 1, b"already on the wire"));
    // `x: y`, as a literal without indexing.
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &[0x00, 1, b'x', 1, b'y'],
    ));
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        3,
        GET_BLOCK,
    ));

    let written = run_connection(vec![ReadEvent::Data(bytes), ReadEvent::Eof], |_, _| {});

    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "what was in flight behind the refusal is a race: {:?}",
        written.iter().find(|f| f.kind == GOAWAY)
    );
    assert_eq!(
        written
            .iter()
            .filter(|f| f.kind == RST_STREAM && f.stream_id == 1)
            .count(),
        1,
        "one reset, and the frames behind it ignored: {written:?}"
    );
    assert!(
        written
            .iter()
            .any(|f| f.kind == HEADERS && f.stream_id == 3),
        "and the next request was served: {written:?}"
    );
}

/// The same race behind the other refusal: the request one past
/// `MAX_CONCURRENT_STREAMS`, whose trailers were already sent.
#[test]
fn trailers_behind_a_refused_stream_do_not_end_the_connection() {
    let mut bytes = preface();
    let limit = super::super::MAX_CONCURRENT_STREAMS;
    // Every slot held: bodies still coming, so none of them finishes.
    for i in 0..limit {
        bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 2 * i + 1, GET_BLOCK));
    }
    let refused = 2 * limit + 1;
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, refused, GET_BLOCK));
    bytes.extend_from_slice(&frame(DATA, 0, refused, b"already on the wire"));
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        refused,
        &[0x00, 1, b'x', 1, b'y'],
    ));

    let written = run_connection(vec![ReadEvent::Data(bytes), ReadEvent::Eof], |_, _| {});

    let resets: Vec<_> = written
        .iter()
        .filter(|f| f.kind == RST_STREAM && f.stream_id == refused)
        .collect();
    assert_eq!(resets.len(), 1, "refused once: {written:?}");
    assert_eq!(
        u32::from_be_bytes(resets[0].payload[..4].try_into().unwrap()),
        crate::shared::codec::types::REFUSED_STREAM
    );
    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "and what followed it ignored: {:?}",
        written.iter().find(|f| f.kind == GOAWAY)
    );
}

/// §5.4.2 / §5.1: a malformed header block is a stream error, and the reset
/// closes the stream rather than leaving it idle, so DATA already in flight
/// must not end the connection.
#[test]
fn a_body_in_flight_behind_a_malformed_request_does_not_end_the_connection() {
    let mut bytes = preface();
    // `:method GET` twice: decodes fine, and is malformed (§8.3).
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS,
        1,
        &[0x82, 0x82, 0x86, 0x84],
    ));
    bytes.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, b"already on the wire"));
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        3,
        GET_BLOCK,
    ));

    let written = run_connection(vec![ReadEvent::Data(bytes), ReadEvent::Eof], |_, _| {});

    assert!(
        written
            .iter()
            .any(|f| f.kind == RST_STREAM && f.stream_id == 1),
        "the malformed request was reset: {written:?}"
    );
    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "its body in flight is a race, not a protocol error: {:?}",
        written.iter().find(|f| f.kind == GOAWAY)
    );
    assert!(
        written
            .iter()
            .any(|f| f.kind == HEADERS && f.stream_id == 3),
        "and the next request was served: {written:?}"
    );
}

/// §8.1: a complete early response is followed by RST_STREAM(NO_ERROR) to
/// stop the body; otherwise the peer is parked on a window nobody reopens,
/// holding one of `MAX_CONCURRENT_STREAMS`.
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
        .unwrap_or_else(|| {
            panic!("60 KB into a 64 KB window, and the peer was told nothing: {written:?}")
        });
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

/// §5.1: trailers in flight behind the reset of an early response are a
/// race, not a protocol error.
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
        written
            .iter()
            .any(|f| f.kind == HEADERS && f.stream_id == 3),
        "and the next request was served: {written:?}"
    );
}

/// A gRPC call that ends on its HEADERS is still gRPC: the handler has to
/// answer with a `grpc-status`.
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
            assert!(
                stream.message().await.is_none(),
                "half-closed, nothing sent"
            );

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

fn two_gets() -> Vec<ReadEvent> {
    let mut bytes = preface();
    for id in [1, 3] {
        bytes.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            id,
            GET_BLOCK,
        ));
    }
    vec![ReadEvent::Data(bytes), ReadEvent::Eof]
}

/// A panic unwinding out of the task would take the worker down, and every
/// connection on it.
#[test]
fn a_handler_that_panics_fails_its_stream_and_nothing_else() {
    let written = run_connection_with(
        two_gets().into_iter().map(Into::into).collect(),
        |_, _| {},
        |stream: crate::server::Stream| async move {
            if u32::from(stream.id()) == 1 {
                panic!("the application's bug");
            }
            stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
        },
    );

    let head = |id| {
        written
            .iter()
            .find(|f| f.kind == HEADERS && f.stream_id == id)
            .unwrap_or_else(|| panic!("stream {id} was answered: {written:?}"))
    };
    assert_eq!(status_of(head(1)).as_deref(), Some("500"));
    assert_eq!(head(1).flags & FLAG_END_STREAM, FLAG_END_STREAM);
    assert_eq!(status_of(head(3)).as_deref(), Some("200"));
    assert!(
        !written
            .iter()
            .any(|f| f.kind == GOAWAY || f.kind == RST_STREAM),
        "{written:?}"
    );
}

/// A `500` after a `200` is not a response; a reset is what says the body
/// is cut short.
#[test]
fn a_handler_that_panics_mid_response_resets_its_stream() {
    let written = run_connection_with(
        two_gets().into_iter().map(Into::into).collect(),
        |_, _| {},
        |stream: crate::server::Stream| async move {
            stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
            if u32::from(stream.id()) == 1 {
                stream.write_data(b"half of it").await;
                panic!("the application's bug");
            }
            stream.write_data_final(b"all of it").await;
        },
    );

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM && f.stream_id == 1)
        .unwrap_or_else(|| panic!("the cut body was reset: {written:?}"));
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        crate::shared::codec::types::INTERNAL_ERROR
    );
    assert!(
        written
            .iter()
            .any(|f| f.kind == DATA && f.stream_id == 3 && f.flags & FLAG_END_STREAM != 0),
        "the stream beside it finished: {written:?}"
    );
    assert!(!written.iter().any(|f| f.kind == GOAWAY), "{written:?}");
}
