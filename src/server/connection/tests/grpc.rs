//! A gRPC call through the whole connection: detected at its HEADERS, read as
//! length-prefixed messages, decoded, and answered with trailers.
//!
//! The pieces have their own tests in `src/grpc`. What is here is the seam —
//! that a `content-type` reaches the detector, that DATA payloads reach the
//! message reader, that taking a message credits the peer, and that a handler
//! can answer the way gRPC expects.

use std::time::Duration;

use prost::Message as _;
use runtime_core::deterministic_testing::{ReadEvent, Scripted};

use super::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GOAWAY, HEADERS, PREFACE, RST_STREAM, SETTINGS,
    WINDOW_UPDATE, decode_block, frame, run_connection_with,
};
use crate::server::Stream;

/// `grpc.health.v1.HealthCheckRequest`: what every Kubernetes gRPC probe
/// sends. An empty `service` means the whole server — and encodes to nothing.
#[derive(Clone, PartialEq, prost::Message)]
struct HealthCheckRequest {
    #[prost(string, tag = "1")]
    service: String,
}

/// Its answer. `status` is an enumeration, which is an `int32` on the wire.
#[derive(Clone, PartialEq, prost::Message)]
struct HealthCheckResponse {
    #[prost(int32, tag = "1")]
    status: i32,
}

const SERVING: i32 = 1;

/// One length-prefixed message, as the peer would put it on the wire — the
/// request side of what `grpc::frame_message` does for a response.
fn framed(message: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend_from_slice(&(message.len() as u32).to_be_bytes());
    out.extend_from_slice(message);
    out
}

/// `:method POST`, `:scheme http`, `:path /`, then `content-type` as a literal
/// on the static table's name (index 31).
fn grpc_block(content_type: &[u8]) -> Vec<u8> {
    let mut block = vec![0x83, 0x86, 0x84, 0x0f, 0x10, content_type.len() as u8];
    block.extend_from_slice(content_type);
    block
}

fn opening() -> Vec<u8> {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS,
        1,
        &grpc_block(b"application/grpc"),
    ));
    bytes
}

/// The call, then the peer going away — otherwise the connection sits idle
/// until the timeout GOAWAYs it, which is not what these are about.
fn scripted(bytes: &[u8]) -> Vec<Scripted> {
    vec![
        ReadEvent::Data(bytes.to_vec()).into(),
        ReadEvent::Eof.after(Duration::from_millis(100)),
    ]
}

fn on_stream_1(written: &[Frame]) -> Vec<&Frame> {
    written.iter().filter(|f| f.stream_id == 1).collect()
}

/// Answers the probe the way a gRPC handler does: a head, a message, and the
/// trailers that carry the outcome.
async fn health(stream: Stream) {
    assert!(stream.is_grpc());
    let request: HealthCheckRequest = match stream.message().await {
        Some(Ok(frame)) => frame.decode().expect("a request"),
        other => panic!("expected a message, got {other:?}"),
    };
    assert!(
        stream.message().await.is_none(),
        "unary: one message, then the half-close"
    );

    let mut fields = http::HeaderMap::new();
    fields.insert(
        "content-type",
        http::HeaderValue::from_static("application/grpc"),
    );
    stream.write_headers(http::StatusCode::OK, &fields);

    stream
        .write_message(&HealthCheckResponse {
            status: if request.service.is_empty() { SERVING } else { 0 },
        })
        .await;

    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
    stream.write_trailers(&trailers);
}

/// The shape of nearly every gRPC call: one message, then an empty DATA frame
/// whose only job is END_STREAM. The request here is the whole-server health
/// probe, which is a message of no bytes — five on the wire, and a value with
/// every field at its default when it comes out.
#[test]
fn a_unary_call_is_read_decoded_and_answered() {
    let request = HealthCheckRequest {
        service: String::new(),
    }
    .encode_to_vec();
    assert!(request.is_empty(), "all defaults: nothing to encode");

    let mut bytes = opening();
    bytes.extend_from_slice(&frame(DATA, 0, 1, &framed(&request)));
    bytes.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, &[]));

    let written = run_connection_with(scripted(&bytes), |_, _| {}, health);
    let ours = on_stream_1(&written);

    let kinds: Vec<u8> = ours.iter().map(|f| f.kind).collect();
    assert_eq!(
        kinds,
        [HEADERS, DATA, HEADERS],
        "head, message, trailers: {written:?}"
    );

    // Taking a message credits the peer for it — but not this one: its
    // END_STREAM came with it, and a peer that has finished sending has no
    // use for a window. A unary call is most calls, and this is the frame it
    // does not pay for.
    assert!(
        !written.iter().any(|f| f.kind == WINDOW_UPDATE && f.stream_id == 1),
        "nothing left to credit: {written:?}"
    );

    assert_eq!(
        decode_block(&ours[0].payload)
            .get("content-type")
            .map(String::as_str),
        Some("application/grpc")
    );

    let (prefix, message) = ours[1].payload.split_at(5);
    assert_eq!(prefix[0], 0, "not compressed");
    assert_eq!(
        u32::from_be_bytes(prefix[1..].try_into().unwrap()) as usize,
        message.len()
    );
    assert_eq!(
        HealthCheckResponse::decode(message).expect("a response"),
        HealthCheckResponse { status: SERVING }
    );

    let trailers = ours[2];
    assert_eq!(trailers.flags & FLAG_END_STREAM, FLAG_END_STREAM);
    let fields = decode_block(&trailers.payload);
    assert_eq!(fields.get("grpc-status").map(String::as_str), Some("0"));
    assert!(!fields.contains_key(":status"), "§8.1: no pseudo-header");

    assert!(
        !written
            .iter()
            .any(|f| f.kind == GOAWAY || f.kind == RST_STREAM),
        "nothing went wrong: {written:?}"
    );
}

/// The other half of that rule, and the one it exists for: a peer that has
/// not finished sending is credited for every message taken, at once and not
/// past a threshold. Hold that credit back and a large message behind a small
/// one never completes — so the handler never takes it, so the credit never
/// goes out.
#[test]
fn a_peer_still_sending_is_credited_for_each_message_it_takes() {
    let first = framed(
        &HealthCheckRequest {
            service: "a".repeat(30),
        }
        .encode_to_vec(),
    );
    let second = framed(
        &HealthCheckRequest {
            service: "b".repeat(30),
        }
        .encode_to_vec(),
    );

    let mut opening = opening();
    opening.extend_from_slice(&frame(DATA, 0, 1, &first));

    // The rest only after the handler has had the first: this is a call still
    // arriving, which is what makes its window worth reopening.
    let mut rest = frame(DATA, 0, 1, &second);
    rest.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, &[]));

    let written = run_connection_with(
        vec![
            ReadEvent::Data(opening).into(),
            ReadEvent::Data(rest).after(Duration::from_millis(50)),
            ReadEvent::Eof.after(Duration::from_secs(1)),
        ],
        |_, _| {},
        |stream: Stream| async move {
            let mut taken = Vec::new();
            while let Some(message) = stream.message().await {
                let request: HealthCheckRequest = message.expect("a request").decode().unwrap();
                taken.push(request.service);
            }
            assert_eq!(taken, ["a".repeat(30), "b".repeat(30)]);
            stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
        },
    );

    let credits: Vec<u32> = written
        .iter()
        .filter(|f| f.kind == WINDOW_UPDATE && f.stream_id == 1)
        .map(|f| u32::from_be_bytes(f.payload[..4].try_into().unwrap()))
        .collect();
    assert_eq!(
        credits,
        [first.len() as u32],
        "the first, whole: the second's END_STREAM came with it"
    );
}

/// Message boundaries are not DATA boundaries. Five calls at once, the same
/// message cut at a different place on each — inside the prefix, at its end,
/// inside the message — and every one of them decodes to the same request.
#[test]
fn messages_split_across_data_frames_arrive_whole() {
    let request = HealthCheckRequest {
        service: "a".repeat(40),
    };
    let body = framed(&request.encode_to_vec());

    let cuts = [1, 3, 5, 7, 25];
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    for (n, cut) in cuts.iter().enumerate() {
        let id = 1 + 2 * n as u32;
        bytes.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS,
            id,
            &grpc_block(b"application/grpc"),
        ));
        bytes.extend_from_slice(&frame(DATA, 0, id, &body[..*cut]));
        bytes.extend_from_slice(&frame(DATA, 0, id, &body[*cut..]));
        bytes.extend_from_slice(&frame(DATA, FLAG_END_STREAM, id, &[]));
    }

    let written = run_connection_with(
        scripted(&bytes),
        |_, _| {},
        |stream: Stream| async move {
            let taken: HealthCheckRequest = match stream.message().await {
                Some(Ok(frame)) => frame.decode().expect("a request"),
                other => panic!("stream {:?}: {other:?}", stream.id()),
            };
            // The one thing a cut in the wrong place would spoil.
            assert_eq!(taken.service, "a".repeat(40));
            assert!(stream.message().await.is_none());
            stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
        },
    );

    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "{written:?}"
    );
    for n in 0..cuts.len() {
        let id = 1 + 2 * n as u32;
        assert!(
            written
                .iter()
                .any(|f| f.kind == HEADERS && f.stream_id == id),
            "stream {id} was answered: {written:?}"
        );
    }
}
