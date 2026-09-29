//! Routing by method and path. `matchit` finds the route, which is only a
//! name, and a `match` calls it: nothing boxed and nothing allocated per
//! request, and each core builds its own table. gRPC paths are exact, so
//! they need no table at all.
//!
//!     cargo run --example router
//!     curl --http2-prior-knowledge http://localhost:8080/users/42
//!     curl --http2-prior-knowledge http://localhost:8080/files/a/b/c.txt
//!     curl --http2-prior-knowledge http://localhost:8080/echo -d hello
//!     curl --http2-prior-knowledge http://localhost:8080/echo -v       # 405
//!     curl --http2-prior-knowledge http://localhost:8080/nowhere -v    # 404
//!
//!     grpcurl -plaintext -import-path examples/grpc_server/proto -proto health.proto \
//!         -d '{"service": ""}' localhost:8080 grpc.health.v1.Health/Check
//!     grpcurl -plaintext -import-path examples/grpc_server/proto -proto echo.proto \
//!         -d '{"text": "a", "index": 1} {"text": "b", "index": 2}' \
//!         localhost:8080 popple.echo.v1.Echo/Chat

use std::collections::BTreeMap;
use std::rc::Rc;

use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use popple_h2::grpc::{GrpcCall, Status, service};
use popple_h2::server::{Server, ServerSettings, ServerTransport, Stream};
use runtime::main_thread_with;

runtime::define_buf_ring!(
    RouterRing,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 128,
    pool_size = 512
);

fn main() {
    println!("listening on http://localhost:8080 (HTTP/2 cleartext, prior knowledge)");
    if std::env::var_os("PER_CORE").is_some() {
        runtime::thread_per_core_with::<RouterRing, _>(|_| Box::pin(serve()));
    } else {
        main_thread_with::<RouterRing, _>(serve());
    }
}

async fn serve() {
    // Per core, inside the runtime: the table is `Rc`, never shared.
    let router = Router::new(ROUTES);
    let http = move |stream| router.clone().dispatch(stream);

    let settings = ServerSettings::new(([0, 0, 0, 0], 8080), ServerTransport::Plain);
    if let Err(e) = Server::new(settings)
        .run::<RouterRing, _>(service(grpc, http))
        .await
    {
        eprintln!("server error: {e}");
    }
}

// ---- Routes ----------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Route {
    Index,
    User,
    DeleteUser,
    File,
    Echo,
}

const ROUTES: &[(Method, &str, Route)] = &[
    (Method::GET, "/", Route::Index),
    (Method::GET, "/users/{id}", Route::User),
    (Method::DELETE, "/users/{id}", Route::DeleteUser),
    (Method::GET, "/files/{*path}", Route::File),
    (Method::POST, "/echo", Route::Echo),
];

impl Router {
    /// Every `Route` has to be answered here, so a route added to the enum
    /// and not to this is a compile error rather than a 404.
    async fn dispatch(self, stream: Stream) {
        let (route, params) = match self.resolve(&stream) {
            Ok(found) => found,
            Err(Miss::NotFound) => {
                return text(stream, StatusCode::NOT_FOUND, "not found\n").await;
            }
            Err(Miss::NotAllowed(allow)) => return method_not_allowed(stream, allow).await,
        };
        match route {
            Route::Index => index(stream).await,
            Route::User => user(stream, params).await,
            Route::DeleteUser => delete_user(stream, params).await,
            Route::File => file(stream, params).await,
            Route::Echo => echo(stream).await,
        }
    }
}

/// gRPC §9.1: a method this server does not have is UNIMPLEMENTED, with a
/// 200, rather than a 404.
async fn grpc(call: &GrpcCall) -> Status {
    match call.path() {
        Some("/grpc.health.v1.Health/Check") => check(call).await,
        Some("/popple.echo.v1.Echo/Chat") => chat(call).await,
        _ => Status::unimplemented("no such method"),
    }
}

// ---- HTTP handlers ---------------------------------------------------------

async fn index(stream: Stream) {
    text(
        stream,
        StatusCode::OK,
        "try /users/42, /files/a/b.txt, POST /echo\n",
    )
    .await
}

async fn user(stream: Stream, params: Params) {
    let body = format!("user {}\n", params.get(&stream, 0));
    text(stream, StatusCode::OK, &body).await
}

async fn delete_user(stream: Stream, params: Params) {
    let body = format!("deleted user {}\n", params.get(&stream, 0));
    text(stream, StatusCode::OK, &body).await
}

async fn file(stream: Stream, params: Params) {
    let body = format!("file {}\n", params.get(&stream, 0));
    text(stream, StatusCode::OK, &body).await
}

async fn echo(stream: Stream) {
    let body = read_body(&stream).await;
    stream.write_headers(StatusCode::OK, &HeaderMap::new());
    stream.write_data_final(&body).await;
}

// ---- gRPC handlers ---------------------------------------------------------

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

#[derive(Clone, PartialEq, prost::Message)]
struct EchoRequest {
    #[prost(string, tag = "1")]
    text: String,
    #[prost(int32, tag = "2")]
    index: i32,
}

#[derive(Clone, PartialEq, prost::Message)]
struct EchoResponse {
    #[prost(string, tag = "1")]
    text: String,
    #[prost(int32, tag = "2")]
    index: i32,
}

const SERVING: i32 = 1;

async fn check(call: &GrpcCall) -> Status {
    let request = match call.message::<HealthCheckRequest>().await {
        Ok(Some(request)) => request,
        Ok(None) => return Status::invalid_argument("no request message"),
        Err(status) => return status,
    };
    if !request.service.is_empty() {
        return Status::not_found("unknown service");
    }
    call.write_message(&HealthCheckResponse { status: SERVING })
        .await;
    Status::ok()
}

/// Both directions at once: each request is answered as it lands.
async fn chat(call: &GrpcCall) -> Status {
    loop {
        let request: EchoRequest = match call.message().await {
            Ok(Some(request)) => request,
            Ok(None) => return Status::ok(),
            Err(status) => return status,
        };
        call.write_message(&EchoResponse {
            text: request.text.to_uppercase(),
            index: request.index,
        })
        .await;
    }
}

// ---- The router ------------------------------------------------------------

const MAX_PARAMS: usize = 4;

/// Where each parameter sits in `:path`, in the order the route names them.
/// Ranges rather than the `&str`s themselves, which would borrow the stream
/// the handler takes by value.
#[derive(Clone, Copy, Default)]
struct Params {
    ranges: [(usize, usize); MAX_PARAMS],
    len: usize,
}

impl Params {
    fn get<'s>(&self, stream: &'s Stream, i: usize) -> &'s str {
        let (start, end) = self.ranges[..self.len][i];
        &stream.path().expect("routed on it")[start..end]
    }
}

/// Every method one path answers, and the `allow` a 405 on it sends.
struct Entry {
    methods: Vec<(Method, Route)>,
    allow: HeaderValue,
}

#[derive(Clone)]
struct Router(Rc<matchit::Router<Entry>>);

enum Miss {
    NotFound,
    NotAllowed(HeaderValue),
}

impl Router {
    /// Panics on a table that does not add up — a route twice, two that
    /// `matchit` finds in conflict, too many parameters: a bug in the table,
    /// found at startup rather than per request.
    fn new(routes: &[(Method, &str, Route)]) -> Self {
        // `matchit` takes each path once, so the methods are gathered first.
        let mut by_path: BTreeMap<&str, Vec<(Method, Route)>> = BTreeMap::new();
        for (method, path, route) in routes {
            assert!(
                path.matches('{').count() <= MAX_PARAMS,
                "{path}: more than {MAX_PARAMS} parameters"
            );
            let methods = by_path.entry(path).or_default();
            assert!(
                methods.iter().all(|(m, _)| m != method),
                "{method} {path} is routed twice"
            );
            methods.push((method.clone(), *route));
        }

        let mut table = matchit::Router::new();
        for (path, methods) in by_path {
            let allow = methods.iter().map(|(m, _)| m.as_str());
            let allow = HeaderValue::from_str(&allow.collect::<Vec<_>>().join(", "))
                .expect("method names are tokens");
            if let Err(e) = table.insert(path, Entry { methods, allow }) {
                panic!("route {path}: {e}");
            }
        }
        Router(Rc::new(table))
    }

    fn resolve(&self, stream: &Stream) -> Result<(Route, Params), Miss> {
        let full = stream.path().unwrap_or("/");
        // `:path` carries the query too; the route is only what precedes it.
        let path = full.split_once('?').map_or(full, |(path, _)| path);
        let found = self.0.at(path).map_err(|_| Miss::NotFound)?;

        let method = stream.method().unwrap_or(&Method::GET);
        let Some(&(_, route)) = found.value.methods.iter().find(|(m, _)| m == method) else {
            return Err(Miss::NotAllowed(found.value.allow.clone()));
        };

        let mut params = Params::default();
        for (_, value) in found.params.iter() {
            // `matchit` hands back slices of the path it was given.
            let start = value.as_ptr() as usize - full.as_ptr() as usize;
            params.ranges[params.len] = (start, start + value.len());
            params.len += 1;
        }
        Ok((route, params))
    }
}

/// §15.5.6 of RFC 9110: a 405 must say what the path does answer.
async fn method_not_allowed(stream: Stream, allow: HeaderValue) {
    let mut fields = HeaderMap::new();
    fields.insert(header::ALLOW, allow);
    fields.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    stream.write_headers(StatusCode::METHOD_NOT_ALLOWED, &fields);
    stream.write_data_final(b"method not allowed\n").await;
}

async fn text(stream: Stream, status: StatusCode, body: &str) {
    let mut fields = HeaderMap::new();
    fields.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    stream.write_headers(status, &fields);
    stream.write_data_final(body.as_bytes()).await;
}

async fn read_body(stream: &Stream) -> Vec<u8> {
    if stream.body_is_oneshot() {
        return stream
            .body(usize::MAX)
            .await
            .map_or_else(|_| Vec::new(), Vec::from);
    }
    let mut body = Vec::new();
    while stream.readable().await {
        let taken = stream.peek(|bytes| {
            body.extend_from_slice(bytes);
            bytes.len()
        });
        // Taking the bytes is what credits the peer for them (§6.9.1).
        stream.consume(taken);
    }
    body
}
