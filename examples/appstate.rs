//! A key-value store over HTTP/2: handlers sharing one `HashMap`.
//!
//! The server runs on one thread, so the map needs no lock: an `Rc` shares
//! it, a `RefCell` lets each handler borrow it in turn. Each route's closure
//! holds a clone of the `Rc`, cloned again for each request it answers.
//!
//!     cargo run --example appstate
//!     curl --http2-prior-knowledge http://localhost:8080/kv/greeting -X PUT -d hello   # 201
//!     curl --http2-prior-knowledge http://localhost:8080/kv/greeting                   # hello
//!     curl --http2-prior-knowledge http://localhost:8080/kv/greeting -X PUT -d bonjour # 204
//!     curl --http2-prior-knowledge http://localhost:8080/kv                            # the keys
//!     curl --http2-prior-knowledge http://localhost:8080/kv/greeting -X DELETE         # 204
//!     curl --http2-prior-knowledge http://localhost:8080/kv/greeting -v                # 404
//!
//! Under `thread_per_core` each core would run `serve` and build a map of its
//! own: a store shared by every core needs an `Arc` and a lock, or one core
//! owning it and the others asking it.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use slopio::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use slopio::main_thread_with;
use slopio_h2::server::{Params, Router, Server, ServerSettings, ServerTransport, Stream};

slopio::define_buf_ring!(
    AppStateRing,
    bgid = 1,
    buffer_size = 65536,
    ring_size = 128,
    pool_size = 512
);

/// Values are `Rc<[u8]>`: a `GET` takes one out of the map without copying
/// it, and writes it with the map no longer borrowed.
type Store = Rc<RefCell<HashMap<String, Rc<[u8]>>>>;

/// The largest value a `PUT` stores; past it, a `413`.
const VALUE_LIMIT: usize = 1 << 20;

fn main() {
    println!("listening on http://localhost:8080 (HTTP/2 cleartext, prior knowledge)");
    main_thread_with::<AppStateRing, _>(serve());
}

async fn serve() {
    let store = Store::default();
    let http = Router::new()
        .route(Method::GET, "/kv", with(&store, list))
        .route(Method::GET, "/kv/{key}", with(&store, get))
        .route(Method::PUT, "/kv/{key}", with(&store, put))
        .route(Method::DELETE, "/kv/{key}", with(&store, delete));

    let settings = ServerSettings::new(([0, 0, 0, 0], 8080), ServerTransport::Plain);
    if let Err(e) = Server::new(settings).run::<AppStateRing, _>(http).await {
        eprintln!("server error: {e}");
    }
}

/// A route that hands `answer` the store along with the stream.
fn with<F, Fut>(store: &Store, answer: F) -> impl FnOnce(Stream, Params) -> Fut + Clone + 'static
where
    F: FnOnce(Stream, Params, Store) -> Fut + Clone + 'static,
    Fut: Future<Output = ()> + 'static,
{
    let store = store.clone();
    move |stream, params| answer(stream, params, store)
}

async fn list(stream: Stream, _: Params, store: Store) {
    let mut keys: Vec<String> = store.borrow().keys().cloned().collect();
    keys.sort();
    let mut body = keys.join("\n");
    body.push('\n');
    text(stream, StatusCode::OK, &body).await
}

async fn get(stream: Stream, params: Params, store: Store) {
    let key = params.get(&stream, 0).unwrap_or("");
    // Cloned out, so the borrow ends before the write awaits.
    let value = store.borrow().get(key).cloned();
    match value {
        Some(value) => {
            stream.write_headers(StatusCode::OK, &HeaderMap::new());
            stream.write_data_final(&value).await;
        }
        None => text(stream, StatusCode::NOT_FOUND, "no such key\n").await,
    }
}

async fn put(stream: Stream, params: Params, store: Store) {
    let key = params.get(&stream, 0).unwrap_or("").to_owned();
    // The body is read before the map is borrowed: other requests run while
    // this one waits for its bytes.
    let Ok(value) = stream.body(VALUE_LIMIT).await else {
        return text(stream, StatusCode::PAYLOAD_TOO_LARGE, "too large\n").await;
    };
    let replaced = store.borrow_mut().insert(key, value.into()).is_some();
    let status = if replaced {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    };
    stream.write_headers_final(status, &HeaderMap::new());
}

async fn delete(stream: Stream, params: Params, store: Store) {
    let key = params.get(&stream, 0).unwrap_or("");
    if store.borrow_mut().remove(key).is_some() {
        stream.write_headers_final(StatusCode::NO_CONTENT, &HeaderMap::new());
    } else {
        text(stream, StatusCode::NOT_FOUND, "no such key\n").await
    }
}

async fn text(stream: Stream, status: StatusCode, body: &str) {
    let mut fields = HeaderMap::new();
    fields.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    stream.write_headers(status, &fields);
    stream.write_data_final(body.as_bytes()).await;
}
