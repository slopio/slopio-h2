//! A route reads its body the way it chooses, whatever the client sent: whole
//! with `body(limit)`, or as it comes with `readable`, with or without a
//! declared length.

use std::time::Duration;

use slopio::deterministic_testing::ReadEvent;
use slopio::http::{HeaderMap, StatusCode};

use super::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, HEADERS, PREFACE, SETTINGS, WINDOW_UPDATE,
    decode_block, deliveries, frame, run_connection_with,
};
use crate::server::Stream;

/// `POST /`, with `content-length` (static name 28) when `declared`.
fn post(declared: Option<usize>) -> Vec<u8> {
    let mut block = vec![0x83, 0x86, 0x84];
    if let Some(len) = declared {
        let len = len.to_string();
        block.extend_from_slice(&[0x0f, 0x0d, len.len() as u8]);
        block.extend_from_slice(len.as_bytes());
    }
    block
}

/// A request on stream 1, its body in `pieces`, the last ending the stream.
fn run<H, Fut>(declared: Option<usize>, pieces: &[&[u8]], handler: H) -> Vec<Frame>
where
    H: FnOnce(Stream) -> Fut + Clone + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    let flags = match pieces {
        [] => FLAG_END_HEADERS | FLAG_END_STREAM,
        _ => FLAG_END_HEADERS,
    };
    bytes.extend_from_slice(&frame(HEADERS, flags, 1, &post(declared)));
    for (i, piece) in pieces.iter().enumerate() {
        let end = if i + 1 == pieces.len() {
            FLAG_END_STREAM
        } else {
            0
        };
        bytes.extend_from_slice(&frame(DATA, end, 1, piece));
    }
    // In reads a buffer holds.
    let mut inbound: Vec<_> = deliveries(&bytes).into_iter().map(Into::into).collect();
    inbound.push(ReadEvent::Eof.after(Duration::from_millis(100)));
    run_connection_with(inbound, |_, _| {}, handler)
}

fn status(written: &[Frame]) -> String {
    let head = written
        .iter()
        .find(|f| f.kind == HEADERS)
        .expect("answered");
    decode_block(&head.payload)[":status"].clone()
}

fn body(written: &[Frame]) -> Vec<u8> {
    written
        .iter()
        .filter(|f| f.kind == DATA && f.stream_id == 1)
        .flat_map(|f| f.payload.clone())
        .collect()
}

/// Everything `body(limit)` gathered, echoed back; a `413` past the limit.
fn whole(
    limit: usize,
) -> impl FnOnce(Stream) -> std::pin::Pin<Box<dyn Future<Output = ()>>> + Clone {
    move |stream: Stream| {
        Box::pin(async move {
            match stream.body(limit).await {
                Ok(body) => {
                    stream.write_headers(StatusCode::OK, &HeaderMap::new());
                    stream.write_data_final(&body).await;
                }
                Err(_) => {
                    stream.write_headers(StatusCode::PAYLOAD_TOO_LARGE, &HeaderMap::new());
                    stream.write_data_final(b"").await;
                }
            }
        })
    }
}

/// Everything read as it came, echoed back.
async fn as_it_comes(stream: Stream) {
    let mut body = Vec::new();
    while stream.readable().await {
        let taken = stream.peek(|bytes| {
            body.extend_from_slice(bytes);
            bytes.len()
        });
        stream.consume(taken);
    }
    stream.write_headers(StatusCode::OK, &HeaderMap::new());
    stream.write_data_final(&body).await;
}

/// A small declared body is gathered whole before anything sees it; read as
/// it comes, it is one piece, and its credit, given back as it landed, is
/// not given back again.
#[test]
fn a_small_declared_body_can_be_read_as_it_comes() {
    let written = run(Some(9), &[b"hello", b" you"], as_it_comes);
    assert_eq!(status(&written), "200");
    assert_eq!(body(&written), b"hello you");

    let credited: u32 = written
        .iter()
        .filter(|f| f.kind == WINDOW_UPDATE && f.stream_id == 1)
        .map(|f| u32::from_be_bytes(f.payload[..4].try_into().unwrap()))
        .sum();
    assert!(credited <= 9, "{credited} bytes credited for a body of 9");
}

#[test]
fn body_gathers_a_body_that_declared_no_length() {
    let written = run(None, &[b"ab", b"cd", b"ef"], whole(100));
    assert_eq!(status(&written), "200");
    assert_eq!(body(&written), b"abcdef");
}

#[test]
fn body_gathers_a_small_declared_body() {
    let written = run(Some(6), &[b"abc", b"def"], whole(100));
    assert_eq!(body(&written), b"abcdef");
}

#[test]
fn body_gathers_a_large_declared_body() {
    let piece = vec![7u8; 10_000];
    let written = run(Some(20_000), &[&piece, &piece], whole(1 << 20));
    assert_eq!(body(&written).len(), 20_000);
}

#[test]
fn body_is_empty_when_there_is_none() {
    let written = run(None, &[], whole(10));
    assert_eq!(status(&written), "200");
    assert!(body(&written).is_empty());
}

/// Refused on its `content-length`, before a byte of it is read.
#[test]
fn body_refuses_a_declared_length_over_the_limit() {
    let written = run(Some(50), &[&[0; 50]], whole(10));
    assert_eq!(status(&written), "413");
}

#[test]
fn body_refuses_an_undeclared_body_past_the_limit() {
    let written = run(None, &[&[0; 6], &[0; 6], &[0; 6]], whole(10));
    assert_eq!(status(&written), "413");
}

/// A static body handed over goes out whole, in frames of at most the
/// default size, the last ending the stream.
#[test]
fn a_static_body_handed_over_is_sent_whole() {
    static ASSET: [u8; 40_000] = [7; 40_000];
    let written = run(None, &[], |stream: Stream| async move {
        stream.write_headers(StatusCode::OK, &HeaderMap::new());
        stream
            .write_owned_final(slopio::Bytes::from_static(&ASSET))
            .await;
    });
    assert_eq!(status(&written), "200");
    assert_eq!(body(&written), ASSET);

    let data: Vec<_> = written.iter().filter(|f| f.kind == DATA).collect();
    assert!(data.iter().all(|f| f.payload.len() <= 16_384));
    assert_eq!(
        data.last().unwrap().flags & FLAG_END_STREAM,
        FLAG_END_STREAM
    );
}
