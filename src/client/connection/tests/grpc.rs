use std::time::Duration;

use runtime_core::deterministic_testing::ReadEvent;

use super::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, HEADERS, STATUS_200, WINDOW_UPDATE, frame, literal,
    server_opening, settle, with_client,
};
use crate::client::{Connection, PlainText, pool};
use crate::grpc::{Code, GrpcClient};

const ORIGIN: &str = "http://example.test";

/// The scripted connection, behind the client API gRPC calls go through.
fn over(connection: Connection<PlainText>) -> GrpcClient<PlainText> {
    GrpcClient::new(pool::holding(connection, ORIGIN), ORIGIN).expect("a valid origin")
}

#[derive(Clone, PartialEq, prost::Message)]
struct HelloRequest {
    #[prost(string, tag = "1")]
    name: String,
}

#[derive(Clone, PartialEq, prost::Message)]
struct HelloReply {
    #[prost(string, tag = "1")]
    message: String,
}

const PATH: &str = "/helloworld.Greeter/SayHello";

fn framed<M: prost::Message>(message: &M) -> Vec<u8> {
    let body = message.encode_to_vec();
    let mut out = vec![0];
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

fn grpc_head() -> Vec<u8> {
    let mut block = STATUS_200.to_vec();
    block.extend_from_slice(&literal("content-type", "application/grpc+proto"));
    frame(HEADERS, FLAG_END_HEADERS, 1, &block)
}

fn status_trailers(code: &str, message: Option<&str>) -> Vec<u8> {
    let mut block = literal("grpc-status", code);
    if let Some(message) = message {
        block.extend_from_slice(&literal("grpc-message", message));
    }
    frame(HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1, &block)
}

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
            let grpc = over(client);
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

    // §4.1.
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

/// The message is gathered as its frames land, however they are cut, and
/// decoded whole.
#[test]
fn a_message_cut_across_frames_is_gathered_whole() {
    let reply = HelloReply {
        message: "hello, world".into(),
    };
    let message = framed(&reply);
    let (front, back) = message.split_at(3);

    let mut first = grpc_head();
    first.extend_from_slice(&frame(DATA, 0, 1, front));

    let (outcome, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(first).after(Duration::from_millis(20)),
            ReadEvent::Data(frame(DATA, 0, 1, back)).after(Duration::from_millis(30)),
            ReadEvent::Data(status_trailers("0", None)).after(Duration::from_millis(40)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        |client| async move {
            let grpc = over(client);
            grpc.unary::<_, HelloReply>(PATH, &HelloRequest::default())
                .await
        },
    );

    assert_eq!(outcome.expect("the call succeeded").message, "hello, world");
}

/// The DATA frames a unary call of a `size`-byte name goes out in, beside
/// the bytes they must add up to.
fn sent_for(size: usize) -> (Vec<super::Frame>, Vec<u8>) {
    let request = HelloRequest {
        name: "x".repeat(size),
    };
    let expected = framed(&request);
    let mut response = grpc_head();
    response.extend_from_slice(&frame(
        DATA,
        0,
        1,
        &framed(&HelloReply {
            message: "ok".into(),
        }),
    ));
    response.extend_from_slice(&status_trailers("0", None));

    let (outcome, written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(20)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        move |client| async move {
            let grpc = over(client);
            let outcome = grpc.unary::<_, HelloReply>(PATH, &request).await;
            settle().await;
            outcome
        },
    );
    outcome.expect("the call succeeded");

    let data = super::frames(&written)
        .into_iter()
        .filter(|f| f.kind == DATA && f.stream_id == 1)
        .collect();
    (data, expected)
}

fn assert_whole(data: &[super::Frame], expected: &[u8]) {
    let sent: Vec<u8> = data.iter().flat_map(|f| f.payload.clone()).collect();
    assert_eq!(sent, expected, "the message, prefix and all");
    let last = data.last().expect("a frame");
    assert_eq!(
        last.flags & FLAG_END_STREAM,
        FLAG_END_STREAM,
        "it ends the request"
    );
}

/// Encoded straight into the connection's output: one frame.
#[test]
fn a_message_that_fits_a_frame_goes_as_one() {
    let (data, expected) = sent_for(10);
    assert_whole(&data, &expected);
    assert_eq!(data.len(), 1);
}

/// Past `max_frame_size`: framed apart and cut, and arrives the same.
#[test]
fn a_message_past_a_frame_is_cut_and_arrives_whole() {
    let (data, expected) = sent_for(20_000);
    assert_whole(&data, &expected);
    assert!(data.len() > 1, "cut at max_frame_size: {}", data.len());
}

/// Two whole replies in one DATA frame, still unread: the bytes they hold
/// keep their credit until the call has taken them all. `taken` is how many
/// the call takes; whether a WINDOW_UPDATE for the stream went out after.
fn credit_after_taking(taken: usize) -> bool {
    let mut both = framed(&HelloReply {
        message: "first".into(),
    });
    both.extend_from_slice(&framed(&HelloReply {
        message: "second".into(),
    }));
    let mut response = grpc_head();
    response.extend_from_slice(&frame(DATA, 0, 1, &both));

    let ((), written) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(20)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        move |client| async move {
            let grpc = over(client);
            let call = grpc.call(PATH).await.expect("a call");
            call.write_message_final(&HelloRequest::default())
                .await
                .expect("sent");
            for _ in 0..taken {
                call.message::<HelloReply>()
                    .await
                    .expect("a reply")
                    .expect("one");
            }
            settle().await;
        },
    );

    super::frames(&written)
        .iter()
        .any(|f| f.kind == WINDOW_UPDATE && f.stream_id == 1)
}

/// Released on the first take, the queue could grow by one per take.
#[test]
fn a_waiting_message_keeps_the_credit_held() {
    assert!(!credit_after_taking(1), "one still waits");
}

#[test]
fn the_held_credit_goes_back_once_none_waits() {
    assert!(credit_after_taking(2));
}

/// Only a gRPC call's stream gathers messages: one sent as plain HTTP, as a
/// proxy relaying gRPC would, reads the same response as bytes.
#[test]
fn a_plain_request_reads_a_grpc_response_as_bytes() {
    let message = framed(&HelloReply {
        message: "relayed".into(),
    });
    let mut response = grpc_head();
    response.extend_from_slice(&frame(DATA, 0, 1, &message));
    response.extend_from_slice(&status_trailers("0", None));
    let expected = message.clone();

    let (body, _) = with_client(
        vec![
            ReadEvent::Data(server_opening()).after(Duration::from_millis(1)),
            ReadEvent::Data(response).after(Duration::from_millis(20)),
            ReadEvent::Eof.after(Duration::from_millis(500)),
        ],
        |client| async move {
            let request = http::Request::post("http://example.test/helloworld.Greeter/SayHello")
                .header("content-type", "application/grpc+proto")
                .body(())
                .unwrap();
            let stream = client.send_request(&request, true).expect("a stream");
            let mut body = Vec::new();
            while let Some(chunk) = stream.read().await.expect("a body") {
                body.extend_from_slice(&chunk);
            }
            body
        },
    );

    assert_eq!(body, expected, "the gRPC framing and all");
}

/// §9.1's Trailers-Only.
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
            let grpc = over(client);
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
            let grpc = over(client);
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
            let grpc = over(client);
            let call = grpc.call(PATH).await.expect("a call");
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
            let grpc = over(client);
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

/// §9.1.
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
            let grpc = over(client);
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

#[test]
fn the_second_call_to_a_path_does_not_spell_it_out_again() {
    let reply = HelloReply {
        message: "hi".into(),
    };
    // Sent separately in time: stream 3 does not exist until the first call
    // is answered, and a response on it earlier is a connection error (§5.1).
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
            let grpc = over(client);
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

    let decoded = super::decode_block(&heads[0].payload);
    assert_eq!(decoded.get(":path").map(String::as_str), Some(PATH));
}
