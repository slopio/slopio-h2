//! Making gRPC calls, against a scripted server.
//!
//! The mirror of the server's gRPC tests: there, a scripted *client* sends
//! framed messages and the handler answers; here, a scripted *server* answers
//! and the call handle is what is under test. What that handle owes its
//! caller is a decoded message and a status — never a `200` with bytes in it
//! that the caller has to interpret.

use std::time::Duration;

use runtime_core::deterministic_testing::ReadEvent;

use super::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, HEADERS, STATUS_200, frame, literal, server_opening,
    settle, with_client,
};
use crate::grpc::{Code, GrpcClient};

/// `helloworld.HelloRequest`, near enough: one string field.
#[derive(Clone, PartialEq, prost::Message)]
struct HelloRequest {
    #[prost(string, tag = "1")]
    name: String,
}

/// Its answer.
#[derive(Clone, PartialEq, prost::Message)]
struct HelloReply {
    #[prost(string, tag = "1")]
    message: String,
}

const PATH: &str = "/helloworld.Greeter/SayHello";

/// One Length-Prefixed-Message as a server would put it on the wire.
fn framed<M: prost::Message>(message: &M) -> Vec<u8> {
    let body = message.encode_to_vec();
    let mut out = vec![0];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

/// A gRPC response head: `200` and the content-type that makes it gRPC.
fn grpc_head() -> Vec<u8> {
    let mut block = STATUS_200.to_vec();
    block.extend_from_slice(&literal("content-type", "application/grpc+proto"));
    frame(HEADERS, FLAG_END_HEADERS, 1, &block)
}

/// A trailer section carrying a status, as §4.1 puts it after the body.
fn status_trailers(code: &str, message: Option<&str>) -> Vec<u8> {
    let mut block = literal("grpc-status", code);
    if let Some(message) = message {
        block.extend_from_slice(&literal("grpc-message", message));
    }
    frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block)
}

/// The shape nearly every call has, and what the handle is for: a message in,
/// a message out, and a status that decides which of the two the caller sees.
#[test]
fn a_unary_call_sends_a_message_and_reads_one_back() {
    let reply = HelloReply {
        message: "hello, world".into(),
    };
    let mut response = grpc_head();
    response.extend_from_slice(&frame(DATA, 0, 1, &framed(&reply)));
    response.extend_from_slice(&status_trailers("0", None));

    let (outcome, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(20)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        |client| async move {
            let grpc = GrpcClient::new(client);
            let request = HelloRequest {
                name: "world".into(),
            };
            let outcome = grpc.unary::<_, HelloReply>(PATH, &request).await;
            settle().await;
            outcome
        },
    );

    let reply = outcome.expect("the call succeeded");
    assert_eq!(reply.message, "hello, world");

    // §4.1: what a gRPC request must look like on the wire.
    let head = super::frames(&written)
        .into_iter()
        .find(|f| f.kind == HEADERS && f.stream_id == 1)
        .expect("a request head went out");
    let fields = super::decode_block(&head.payload);
    assert_eq!(fields.get(":method").map(String::as_str), Some("POST"));
    assert_eq!(fields.get(":path").map(String::as_str), Some(PATH));
    assert_eq!(
        fields.get("content-type").map(String::as_str),
        Some("application/grpc+proto")
    );
    assert_eq!(fields.get("te").map(String::as_str), Some("trailers"));
    assert_eq!(
        head.flags & FLAG_END_STREAM,
        0,
        "the head never ends a gRPC request: the messages are the body"
    );

    // The request message, framed: flag 0, then its length.
    let data = super::frames(&written)
        .into_iter()
        .find(|f| f.kind == DATA && f.stream_id == 1)
        .expect("the message went out");
    assert_eq!(data.payload[0], 0, "§4.1's Compressed-Flag");
    let declared = u32::from_be_bytes(data.payload[1..5].try_into().unwrap()) as usize;
    assert_eq!(declared, data.payload.len() - 5, "the length is the length");
    assert_eq!(
        data.flags & FLAG_END_STREAM,
        FLAG_END_STREAM,
        "a unary request ends with its only message, not with an empty frame after it"
    );
}

/// §9.1's Trailers-Only: a status in the head, with no body behind it. What a
/// server sends for a method it does not have, which is the failure a caller
/// meets most often.
#[test]
fn a_trailers_only_response_is_the_whole_answer() {
    let mut block = STATUS_200.to_vec();
    block.extend_from_slice(&literal("content-type", "application/grpc+proto"));
    block.extend_from_slice(&literal("grpc-status", "12"));
    block.extend_from_slice(&literal("grpc-message", "unknown method"));
    let head = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block);

    let (outcome, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(head).after(Duration::from_millis(20)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        |client| async move {
            let grpc = GrpcClient::new(client);
            let outcome = grpc
                .unary::<_, HelloReply>(PATH, &HelloRequest::default())
                .await;
            settle().await;
            outcome
        },
    );

    let status = outcome.expect_err("a call that was never run is not a reply");
    assert_eq!(status.code, Code::Unimplemented);
    assert_eq!(status.message, "unknown method");
}

/// A call that ran and failed. The status is in the trailers, after a body
/// that may have carried nothing — and `grpc-message` is percent-encoded, so
/// what the caller reads is what the handler wrote.
#[test]
fn a_failed_call_carries_its_code_and_message_back() {
    let mut response = grpc_head();
    response.extend_from_slice(&status_trailers("5", Some("no such user: %41da")));

    let (outcome, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(20)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        |client| async move {
            let grpc = GrpcClient::new(client);
            let outcome = grpc
                .unary::<_, HelloReply>(PATH, &HelloRequest::default())
                .await;
            settle().await;
            outcome
        },
    );

    let status = outcome.expect_err("the call failed");
    assert_eq!(status.code, Code::NotFound);
    assert_eq!(
        status.message, "no such user: Ada",
        "§9.1's percent-encoding, undone"
    );
}

/// A server-streaming call: many messages, then the status. The handle hands
/// them over one at a time and `None` is the end — not an error, whatever the
/// status turns out to be.
#[test]
fn a_streaming_response_arrives_message_by_message() {
    let mut response = grpc_head();
    for message in ["one", "two", "three"] {
        let reply = HelloReply {
            message: message.into(),
        };
        response.extend_from_slice(&frame(DATA, 0, 1, &framed(&reply)));
    }
    response.extend_from_slice(&status_trailers("0", None));

    let (outcome, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(20)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        |client| async move {
            let grpc = GrpcClient::new(client);
            let call = grpc.call(PATH).expect("a call");
            call.write_message_final(&HelloRequest::default())
                .await
                .expect("the request went");

            let mut said = Vec::new();
            while let Some(reply) = call.message::<HelloReply>().await.expect("a message") {
                said.push(reply.message);
            }
            let status = call.status().await;
            settle().await;
            (said, status)
        },
    );

    assert_eq!(outcome.0, ["one", "two", "three"]);
    assert!(outcome.1.is_ok(), "and then the status: {:?}", outcome.1);
}

/// A response that ends without a status at all. Not something a conforming
/// server does — which is the point: the caller gets a status rather than an
/// `Ok` it would have to know not to trust.
#[test]
fn a_response_with_no_status_is_not_a_success() {
    let mut response = grpc_head();
    response.extend_from_slice(&frame(
        DATA,
        FLAG_END_STREAM,
        1,
        &framed(&HelloReply::default()),
    ));

    let (outcome, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(20)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        |client| async move {
            let grpc = GrpcClient::new(client);
            let outcome = grpc
                .unary::<_, HelloReply>(PATH, &HelloRequest::default())
                .await;
            settle().await;
            outcome
        },
    );

    let status = outcome.expect_err("a call that never ended cannot have succeeded");
    assert_eq!(status.code, Code::Internal);
}

/// §9.1: an intermediary answering instead of the server. There is no
/// `grpc-status` anywhere, and the HTTP status is all there is to go on.
#[test]
fn an_http_error_from_a_proxy_becomes_a_status() {
    // `503` is entry 63 of the static table, so it needs no literal.
    let head = frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &[0xc0 | 63]);

    let (outcome, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(head).after(Duration::from_millis(20)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        |client| async move {
            let grpc = GrpcClient::new(client);
            let outcome = grpc
                .unary::<_, HelloReply>(PATH, &HelloRequest::default())
                .await;
            settle().await;
            outcome
        },
    );

    let status = outcome.expect_err("503 is not a reply");
    assert_eq!(
        status.code,
        Code::Unavailable,
        "the code a caller retries on: {}",
        status.message
    );
}

/// A gRPC connection asks for the same handful of paths for its whole life,
/// so the second call to one should not spell it out again.
///
/// HPACK leaves `:path` out of its dynamic table by default — right for a
/// browser, whose paths are nearly all distinct, and wrong here. `GrpcClient`
/// turns that off, and this is where the difference is visible: on the wire.
#[test]
fn the_second_call_to_a_path_does_not_spell_it_out_again() {
    let reply = HelloReply {
        message: "hi".into(),
    };
    // The same exchange twice, on the two stream ids a client opens first.
    // Separately in time, and not as one chunk: the second stream does not
    // exist until the first call has been answered, and a response on a
    // stream this client never opened is a connection error (§5.1) — which
    // is the client being right and the script being wrong.
    let exchange = |id: u32| {
        let mut block = STATUS_200.to_vec();
        block.extend_from_slice(&literal("content-type", "application/grpc+proto"));
        let mut bytes = frame(HEADERS, FLAG_END_HEADERS, id, &block);
        bytes.extend_from_slice(&frame(DATA, 0, id, &framed(&reply)));
        bytes.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            id,
            &literal("grpc-status", "0"),
        ));
        bytes
    };

    let (_, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(exchange(1)).after(Duration::from_millis(20)),
            ReadEvent::Data(exchange(3)).after(Duration::from_millis(60)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        |client| async move {
            let grpc = GrpcClient::new(client);
            for _ in 0..2 {
                grpc.unary::<_, HelloReply>(PATH, &HelloRequest::default())
                    .await
                    .expect("both calls succeeded");
            }
            settle().await;
        },
    );

    let heads: Vec<super::Frame> = super::frames(&written)
        .into_iter()
        .filter(|f| f.kind == HEADERS && (f.stream_id == 1 || f.stream_id == 3))
        .collect();
    assert_eq!(heads.len(), 2, "two calls, two request heads");

    // The path is 28 characters; the first head carries it, Huffman-coded.
    assert!(
        heads[0].payload.len() > 20,
        "the first spells everything out: {} bytes",
        heads[0].payload.len()
    );
    assert!(
        heads[1].payload.len() <= 6,
        "the second is indices and nothing else: {} bytes, {:02x?}",
        heads[1].payload.len(),
        heads[1].payload
    );

    // And it still decodes to the same request, which is the point of doing
    // it this way rather than sending less and meaning less.
    let decoded = super::decode_block(&heads[0].payload);
    assert_eq!(decoded.get(":path").map(String::as_str), Some(PATH));
}
