//! Routing as the handler's to do: by protocol, then by method and path,
//! each route's function spawned as its own task.

use std::time::Duration;

use http::{HeaderMap, Method, StatusCode};
use runtime_core::deterministic_testing::ReadEvent;

use super::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, HEADERS, PREFACE, SETTINGS, frame,
    run_connection_with,
};
use crate::server::{Handler, Incoming, Params, Router, Stream, StreamTask};

/// `:method` and `:path` as literals on the static table's names (2 and 4),
/// `:scheme http` indexed; with `content-type: application/grpc` (name 31)
/// for gRPC.
fn block(method: &str, path: &str, grpc: bool) -> Vec<u8> {
    let mut out = vec![0x02, method.len() as u8];
    out.extend_from_slice(method.as_bytes());
    out.push(0x86);
    out.extend_from_slice(&[0x04, path.len() as u8]);
    out.extend_from_slice(path.as_bytes());
    if grpc {
        out.extend_from_slice(&[0x0f, 0x10, 16]);
        out.extend_from_slice(b"application/grpc");
    }
    out
}

/// One request per stream, each without a body, then the peer going away.
fn run(requests: &[(&str, &str, bool)], handler: impl Handler) -> Vec<Frame> {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    for (i, (method, path, grpc)) in requests.iter().enumerate() {
        bytes.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1 + 2 * i as u32,
            &block(method, path, *grpc),
        ));
    }
    run_connection_with(
        vec![
            ReadEvent::Data(bytes).into(),
            ReadEvent::Eof.after(Duration::from_millis(100)),
        ],
        |_, _| {},
        handler,
    )
}

/// The heads' fields, `:status` among them, and the body, of one stream.
/// Every head is decoded, in order, by one decoder: the encoder indexes
/// fields as it goes, so a head can lean on one sent before it.
fn answer(
    written: &[Frame],
    stream_id: u32,
) -> (Vec<std::collections::HashMap<String, String>>, String) {
    use crate::shared::hpack::{Decoder, Header};

    let mut decoder = Decoder::new(4096);
    let mut heads = Vec::new();
    for f in written.iter().filter(|f| f.kind == HEADERS) {
        let mut buf = bytes::BytesMut::from(&f.payload[..]);
        let mut fields = std::collections::HashMap::new();
        decoder
            .decode(&mut std::io::Cursor::new(&mut buf), |header| {
                let (name, value) = match header {
                    Header::Field { name, value } => (
                        name.as_str().to_owned(),
                        String::from_utf8_lossy(value.as_bytes()).into_owned(),
                    ),
                    Header::Status(status) => (":status".to_owned(), status.as_str().to_owned()),
                    other => (format!("{other:?}"), String::new()),
                };
                fields.insert(name, value);
            })
            .expect("the heads decode, in order");
        if f.stream_id == stream_id {
            heads.push(fields);
        }
    }
    let body = written
        .iter()
        .filter(|f| f.kind == DATA && f.stream_id == stream_id)
        .flat_map(|f| f.payload.clone())
        .collect();
    (heads, String::from_utf8(body).unwrap())
}

async fn user(stream: Stream, params: Params) {
    let body = format!(
        "user {} via {}",
        params.get(&stream, 0).unwrap_or("?"),
        params.route()
    );
    stream.write_headers(StatusCode::OK, &HeaderMap::new());
    stream.write_data_final(body.as_bytes()).await;
}

async fn file(stream: Stream, params: Params) {
    let body = format!("file {}", params.get(&stream, 0).unwrap_or("?"));
    stream.write_headers(StatusCode::OK, &HeaderMap::new());
    stream.write_data_final(body.as_bytes()).await;
}

fn router() -> Router {
    Router::new()
        .route(Method::GET, "/users/{id}", user)
        .route(Method::DELETE, "/users/{id}", user)
        .route(Method::GET, "/files/{*path}", file)
}

#[test]
fn a_request_reaches_its_route_with_its_parameters() {
    let written = run(
        &[
            ("GET", "/users/42?verbose=1", false),
            ("GET", "/files/a/b.txt", false),
        ],
        router(),
    );

    let (heads, body) = answer(&written, 1);
    assert_eq!(heads[0][":status"], "200");
    assert_eq!(
        body, "user 42 via /users/{id}",
        "the query is not the route's"
    );
    assert_eq!(answer(&written, 3).1, "file a/b.txt");
}

#[test]
fn a_path_no_route_has_is_not_found() {
    let written = run(&[("GET", "/nowhere", false)], router());
    let (heads, body) = answer(&written, 1);
    assert_eq!(heads[0][":status"], "404");
    assert_eq!(body, "not found\n");
}

/// RFC 9110 §15.5.6: a 405 says what the path does answer.
#[test]
fn a_method_its_path_does_not_have_is_not_allowed() {
    let written = run(&[("POST", "/users/42", false)], router());
    let (heads, _) = answer(&written, 1);
    assert_eq!(heads[0][":status"], "405");
    assert_eq!(heads[0]["allow"], "GET, DELETE");
}

#[test]
#[should_panic(expected = "GET /users/{id} is routed twice")]
fn a_route_twice_is_refused_at_startup() {
    let _ = router().route(Method::GET, "/users/{id}", user);
}

/// A handler that panics choosing fails that stream, answered, and the
/// connection goes on to the next.
#[test]
fn a_handler_that_panics_choosing_fails_only_its_stream() {
    #[derive(Clone)]
    struct Choosy;

    impl Handler for Choosy {
        fn start(&self, incoming: Incoming) -> StreamTask {
            if incoming.path() == Some("/panic") {
                panic!("no route for that");
            }
            incoming.spawn(|stream: Stream| async move {
                stream.write_headers(StatusCode::OK, &HeaderMap::new());
                stream.write_data_final(b"fine").await;
            })
        }
    }

    let written = run(&[("GET", "/panic", false), ("GET", "/", false)], Choosy);
    let (heads, _) = answer(&written, 1);
    assert_eq!(heads[0][":status"], "500");
    let (heads, body) = answer(&written, 3);
    assert_eq!(
        (heads[0][":status"].as_str(), body.as_str()),
        ("200", "fine")
    );
}

#[cfg(feature = "grpc")]
mod grpc {
    use super::*;
    use crate::grpc::{GrpcCall, GrpcRouter, Status, service};

    async fn known(_: &GrpcCall) -> Status {
        Status::ok()
    }

    /// gRPC and HTTP on one connection, each to its own router: a method
    /// gRPC has, one it has not, which is UNIMPLEMENTED with a `200` (gRPC
    /// §9.1), and an HTTP route beside them.
    #[test]
    fn each_protocol_goes_to_its_own_router() {
        let grpc = GrpcRouter::new().route("/pkg.Service/Known", known);
        let written = run(
            &[
                ("POST", "/pkg.Service/Known", true),
                ("POST", "/pkg.Service/Unknown", true),
                ("GET", "/users/7", false),
            ],
            service(grpc, router()),
        );

        let (heads, _) = answer(&written, 1);
        assert_eq!(heads[0]["grpc-status"], "0");
        let (heads, _) = answer(&written, 3);
        assert_eq!(heads[0][":status"], "200");
        assert_eq!(heads[0]["grpc-status"], "12");
        assert_eq!(answer(&written, 5).1, "user 7 via /users/{id}");
    }
}
