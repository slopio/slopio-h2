use std::time::Duration;

use prost::Message as _;
use runtime_core::deterministic_testing::{ReadEvent, Scripted};

use super::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GOAWAY, HEADERS, PREFACE, RST_STREAM, SETTINGS,
    WINDOW_UPDATE, decode_block, frame, run_connection_with,
};
use crate::grpc::{GrpcCall, Status, service};
use crate::server::Stream;

/// `grpc.health.v1.HealthCheckRequest`. An empty `service` encodes to nothing.
#[derive(Clone, PartialEq, prost::Message)]
struct HealthCheckRequest {
    #[prost(string, tag = "1")]
    service: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct HealthCheckResponse {
    #[prost(int32, tag = "1")]
    status: i32,
}

const SERVING: i32 = 1;

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

/// Then the peer going away — otherwise the connection sits idle until the
/// timeout GOAWAYs it.
fn scripted(bytes: &[u8]) -> Vec<Scripted> {
    vec![
        ReadEvent::Data(bytes.to_vec()).into(),
        ReadEvent::Eof.after(Duration::from_millis(100)),
    ]
}

fn on_stream_1(written: &[Frame]) -> Vec<&Frame> {
    written.iter().filter(|f| f.stream_id == 1).collect()
}

/// The bytes of a message being assembled are consumed as they land, so the
/// credit goes back before the message is whole.
#[test]
fn a_message_larger_than_the_window_is_credited_as_it_fills() {
    const WINDOW: usize = crate::server::connection::STREAM_RECV_WINDOW as usize;
    let request = HealthCheckRequest {
        service: "a".repeat(2 * WINDOW + 1),
    }
    .encode_to_vec();
    let body = framed(&request);
    assert!(body.len() > 2 * WINDOW);

    // Each round is what fits in the peer's window at that point, one read
    // event per frame; the next comes after the credit for it has gone out.
    let mut events = vec![ReadEvent::Data(opening()).into()];
    let mut at = 0;
    let mut wait = Duration::ZERO;
    while at < body.len() {
        let end = (at + WINDOW).min(body.len());
        for piece in body[at..end].chunks(16_000) {
            events.push(ReadEvent::Data(frame(DATA, 0, 1, piece)).after(wait));
            wait = Duration::ZERO;
        }
        wait = Duration::from_millis(20);
        at = end;
    }
    events.push(ReadEvent::Data(frame(DATA, FLAG_END_STREAM, 1, &[])).after(wait));
    events.push(ReadEvent::Eof.after(Duration::from_secs(1)));

    let expected = request.clone();
    let written = run_connection_with(events, |_, _| {}, move |stream: Stream| {
        let expected = expected.clone();
        async move {
            let frame = stream.message().await.expect("a message").expect("well formed");
            let decoded: HealthCheckRequest = frame.decode().unwrap();
            assert_eq!(decoded.encode_to_vec(), expected);
            stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
        }
    });

    let credited: u32 = written
        .iter()
        .filter(|f| f.kind == WINDOW_UPDATE && f.stream_id == 1)
        .map(|f| u32::from_be_bytes(f.payload[..4].try_into().unwrap()))
        .sum();
    assert!(
        credited as usize >= body.len() - WINDOW,
        "credited {credited} of {}: the peer must have had window for all of it — {written:?}",
        body.len()
    );
    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "no flow control error: {written:?}"
    );
}

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

/// One message, then an empty DATA frame whose only job is END_STREAM. The
/// whole-server health probe is a message of no bytes — five on the wire.
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

    // Not credited: its END_STREAM came with it, and a peer that has finished
    // sending has no use for a window.
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

/// Named rather than closures: a closure's returned future does not carry the
/// higher-ranked lifetime `AsyncFn(&GrpcCall)` asks for.
async fn waits_forever(call: &GrpcCall) -> Status {
    assert_eq!(call.timeout(), Some(Duration::from_millis(100)));
    let _: Option<HealthCheckRequest> = call.message().await.expect("no body error");
    unreachable!("the deadline is what ends this call")
}

async fn answers_at_once(call: &GrpcCall) -> Status {
    let request: HealthCheckRequest = call.message().await.expect("no error").expect("a message");
    assert_eq!(request.service, "", "all defaults, and no bytes for them");
    call.write_message(&HealthCheckResponse { status: SERVING })
        .await;
    Status::ok()
}

async fn not_grpc(stream: Stream) {
    stream.write_headers_final(http::StatusCode::NOT_FOUND, &http::HeaderMap::new())
}

/// Reserved names included: gRPC's metadata is the service's to choose.
async fn echoes_its_metadata(call: &GrpcCall) -> Status {
    let mut head = http::HeaderMap::new();
    // Overrides the layer's only default.
    head.insert(
        "content-type",
        http::HeaderValue::from_static("application/grpc+json"),
    );
    head.insert(
        "x-grpc-test-echo-initial",
        http::HeaderValue::from_static("bonjour"),
    );
    call.set_headers(&head);

    let mut trailers = http::HeaderMap::new();
    trailers.insert(
        "x-grpc-test-echo-trailing-bin",
        http::HeaderValue::from_static("YWJjMTIz"),
    );
    // Written before the returned status, which wins: `finish` must not say
    // something other than what the handler returned.
    trailers.insert("grpc-status", http::HeaderValue::from_static("7"));
    call.set_trailers(&trailers);

    call.write_message(&HealthCheckResponse { status: SERVING })
        .await;
    Status::not_found("unknown service")
}

#[test]
fn a_handler_chooses_its_own_metadata_reserved_names_included() {
    let mut bytes = opening();
    bytes.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, &framed(&[])));

    let written = run_connection_with(scripted(&bytes), |_, _| {}, service(echoes_its_metadata, not_grpc));
    let ours = on_stream_1(&written);
    assert_eq!(
        ours.iter().map(|f| f.kind).collect::<Vec<_>>(),
        [HEADERS, DATA, HEADERS],
        "{written:?}"
    );

    let head = decode_block(&ours[0].payload);
    assert_eq!(
        head.get("content-type").map(String::as_str),
        Some("application/grpc+json"),
        "the handler's, not the layer's default"
    );
    assert_eq!(
        head.get("x-grpc-test-echo-initial").map(String::as_str),
        Some("bonjour")
    );

    let trailers = decode_block(&ours[2].payload);
    assert_eq!(
        trailers.get("x-grpc-test-echo-trailing-bin").map(String::as_str),
        Some("YWJjMTIz")
    );
    assert_eq!(
        trailers.get("grpc-status").map(String::as_str),
        Some("5"),
        "the returned Status, not the `7` the map asked for"
    );
    assert_eq!(
        trailers.get("grpc-message").map(String::as_str),
        Some("unknown service")
    );
}

/// A call that fails before it writes anything is one frame, so the head's
/// fields have to travel in it.
async fn fails_with_metadata(call: &GrpcCall) -> Status {
    let mut head = http::HeaderMap::new();
    head.insert("x-request-id", http::HeaderValue::from_static("abc123"));
    call.set_headers(&head);
    Status::unimplemented("no such method")
}

#[test]
fn a_trailers_only_response_carries_the_heads_fields_too() {
    let mut bytes = opening();
    bytes.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, &framed(&[])));

    let written = run_connection_with(scripted(&bytes), |_, _| {}, service(fails_with_metadata, not_grpc));
    let ours = on_stream_1(&written);
    assert_eq!(ours.iter().map(|f| f.kind).collect::<Vec<_>>(), [HEADERS]);
    assert_eq!(ours[0].flags & FLAG_END_STREAM, FLAG_END_STREAM);

    let fields = decode_block(&ours[0].payload);
    assert_eq!(fields.get("x-request-id").map(String::as_str), Some("abc123"));
    assert_eq!(fields.get("grpc-status").map(String::as_str), Some("12"));
    assert_eq!(
        fields.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
}

/// A call that outlives its `grpc-timeout` is cut off and answered, rather
/// than left running for a client that has given up. Nothing is sent on the
/// body, so the handler waits on a message that never comes.
#[test]
fn a_call_past_its_deadline_is_answered_deadline_exceeded() {
    let mut block = grpc_block(b"application/grpc");
    // `grpc-timeout: 100m`, a literal with a name of its own.
    block.extend_from_slice(&[0x00, 12]);
    block.extend_from_slice(b"grpc-timeout");
    block.push(4);
    block.extend_from_slice(b"100m");

    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, &block));

    let written = run_connection_with(
        vec![
            ReadEvent::Data(bytes).into(),
            ReadEvent::Eof.after(Duration::from_secs(5)),
        ],
        |_, _| {},
        service(waits_forever, not_grpc),
    );

    let ours = on_stream_1(&written);
    let kinds: Vec<u8> = ours.iter().map(|f| f.kind).collect();
    assert_eq!(
        kinds,
        [HEADERS, RST_STREAM],
        "Trailers-Only, and the body we will not read: {written:?}"
    );

    let head = ours[0];
    assert_eq!(head.flags & FLAG_END_STREAM, FLAG_END_STREAM);
    let fields = decode_block(&head.payload);
    assert_eq!(fields.get(":status").map(String::as_str), Some("200"));
    assert_eq!(fields.get("grpc-status").map(String::as_str), Some("4"));
    assert_eq!(
        fields.get("content-type").map(String::as_str),
        Some("application/grpc")
    );
}

/// The deadline is armed on every call, so it has to lose the race on the
/// ordinary ones.
#[test]
fn a_call_inside_its_deadline_keeps_its_own_status() {
    let mut block = grpc_block(b"application/grpc");
    block.extend_from_slice(&[0x00, 12]);
    block.extend_from_slice(b"grpc-timeout");
    block.push(3);
    block.extend_from_slice(b"30S");

    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, &block));
    bytes.extend_from_slice(&frame(DATA, FLAG_END_STREAM, 1, &framed(&[])));

    let written = run_connection_with(
        scripted(&bytes),
        |_, _| {},
        service(answers_at_once, not_grpc),
    );

    let ours = on_stream_1(&written);
    assert_eq!(
        ours.iter().map(|f| f.kind).collect::<Vec<_>>(),
        [HEADERS, DATA, HEADERS],
        "head, message, trailers: {written:?}"
    );
    assert_eq!(
        decode_block(&ours[2].payload)
            .get("grpc-status")
            .map(String::as_str),
        Some("0")
    );
}

/// Two whole messages in one frame, and the handler takes only the first:
/// the second still waits, so nothing held goes back yet.
#[test]
fn a_waiting_message_keeps_the_credit_held() {
    let mut both = framed(
        &HealthCheckRequest {
            service: "a".repeat(30),
        }
        .encode_to_vec(),
    );
    both.extend_from_slice(&framed(
        &HealthCheckRequest {
            service: "b".repeat(30),
        }
        .encode_to_vec(),
    ));
    let mut opening = opening();
    opening.extend_from_slice(&frame(DATA, 0, 1, &both));

    let written = run_connection_with(
        vec![
            ReadEvent::Data(opening).into(),
            ReadEvent::Eof.after(Duration::from_secs(1)),
        ],
        |_, _| {},
        |stream: Stream| async move {
            stream.message().await.expect("one").expect("a request");
            stream.write_headers_final(http::StatusCode::OK, &http::HeaderMap::new());
        },
    );

    assert!(
        !written
            .iter()
            .any(|f| f.kind == WINDOW_UPDATE && f.stream_id == 1),
        "the second still waits"
    );
}

/// A peer still sending is credited for every message taken, at once: hold
/// it back and a large message behind a small one never completes.
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

    // The rest only after the handler has had the first: a call still
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

/// Message boundaries are not DATA boundaries: the same message cut inside
/// the prefix, at its end, and inside the message decodes the same.
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
