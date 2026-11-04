//! Routing by method and path, to one async function per route, each spawned
//! as its own task:
//!
//! ```ignore
//! let router = Router::new()
//!     .route(Method::GET, "/users/{id}", user)
//!     .route(Method::GET, "/files/{*path}", file);
//!
//! async fn user(stream: Stream, params: Params) {
//!     let id = params.get(&stream, 0).unwrap_or("");
//!     // ...
//! }
//! ```
//!
//! Patterns are `matchit`'s: `{name}` is one segment, `{*name}` the rest of
//! the path. A path no route has is answered `404`; a method its path does
//! not have, `405` with the `allow` the path does answer (RFC 9110
//! §15.5.6). The query plays no part.

use std::rc::Rc;

use slopio::http::{HeaderMap, HeaderValue, Method, StatusCode, header};

use crate::server::{Handler, Incoming, Stream, StreamTask};

/// Parameters one route may name.
pub const MAX_PARAMS: usize = 4;

/// Spawns the task one route's function runs in.
type Route = Box<dyn Fn(Incoming, Params) -> StreamTask>;

/// Built once, then shared by the connections of a worker: cloning it
/// clones an `Rc`. Each worker builds its own.
#[derive(Clone)]
pub struct Router(Rc<Table>);

struct Table {
    /// Each pattern to its index in `paths`.
    patterns: matchit::Router<usize>,
    paths: Vec<Path>,
}

/// Every method one pattern answers.
struct Path {
    pattern: &'static str,
    methods: Vec<(Method, Route)>,
    /// What a `405` on it says.
    allow: HeaderValue,
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

impl Router {
    pub fn new() -> Self {
        Self(Rc::new(Table {
            patterns: matchit::Router::new(),
            paths: Vec::new(),
        }))
    }

    /// Panics on a table that does not add up — a method routed twice on a
    /// pattern, two patterns `matchit` finds in conflict, more than
    /// [`MAX_PARAMS`] parameters, a router already cloned: a bug in the
    /// table, found at startup rather than per request.
    pub fn route<F, Fut>(mut self, method: Method, pattern: &'static str, answer: F) -> Self
    where
        F: FnOnce(Stream, Params) -> Fut + Clone + 'static,
        Fut: Future<Output = ()> + 'static,
    {
        assert!(
            pattern.matches('{').count() <= MAX_PARAMS,
            "{pattern}: more than {MAX_PARAMS} parameters"
        );
        let table = Rc::get_mut(&mut self.0).expect("routes are added before the router is cloned");
        let route: Route = Box::new(move |incoming, params| {
            let answer = answer.clone();
            incoming.spawn(move |stream| answer(stream, params))
        });

        let at = match table.paths.iter().position(|p| p.pattern == pattern) {
            Some(at) => at,
            None => {
                if let Err(e) = table.patterns.insert(pattern, table.paths.len()) {
                    panic!("route {pattern}: {e}");
                }
                table.paths.push(Path {
                    pattern,
                    methods: Vec::new(),
                    allow: HeaderValue::from_static(""),
                });
                table.paths.len() - 1
            }
        };
        let path = &mut table.paths[at];
        assert!(
            path.methods.iter().all(|(m, _)| *m != method),
            "{method} {pattern} is routed twice"
        );
        path.methods.push((method, route));
        let allow = path.methods.iter().map(|(m, _)| m.as_str());
        path.allow = HeaderValue::from_str(&allow.collect::<Vec<_>>().join(", "))
            .expect("method names are tokens");
        self
    }
}

impl Handler for Router {
    fn start(&self, incoming: Incoming) -> StreamTask {
        let full = incoming.path().unwrap_or("/");
        // `:path` carries the query too; the route is only what precedes it.
        let path = full.split_once('?').map_or(full, |(path, _)| path);
        let Ok(found) = self.0.patterns.at(path) else {
            return incoming.spawn(not_found);
        };
        let entry = &self.0.paths[*found.value];

        let method = incoming.method().unwrap_or(&Method::GET);
        let Some((_, route)) = entry.methods.iter().find(|(m, _)| m == method) else {
            let allow = entry.allow.clone();
            return incoming.spawn(move |stream| method_not_allowed(stream, allow));
        };

        let mut params = Params {
            route: entry.pattern,
            ranges: [(0, 0); MAX_PARAMS],
            len: 0,
        };
        for (_, value) in found.params.iter() {
            // `matchit` hands back slices of the path it was given.
            let start = value.as_ptr() as usize - full.as_ptr() as usize;
            params.ranges[params.len] = (start, start + value.len());
            params.len += 1;
        }
        route(incoming, params)
    }
}

/// Where each parameter sits in `:path`, in the order the pattern names
/// them. Ranges rather than the `&str`s themselves, which would borrow the
/// stream the route's function takes by value.
#[derive(Clone, Copy, Debug)]
pub struct Params {
    route: &'static str,
    ranges: [(usize, usize); MAX_PARAMS],
    len: usize,
}

impl Params {
    /// The pattern that matched, `/users/{id}` rather than `/users/42`:
    /// OpenTelemetry's `http.route`.
    pub fn route(&self) -> &'static str {
        self.route
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The `i`th parameter, from the stream it was routed on.
    pub fn get<'s>(&self, stream: &'s Stream, i: usize) -> Option<&'s str> {
        let &(start, end) = self.ranges[..self.len].get(i)?;
        stream.path()?.get(start..end)
    }
}

async fn not_found(stream: Stream) {
    text(
        stream,
        StatusCode::NOT_FOUND,
        "not found\n",
        HeaderMap::new(),
    )
    .await;
}

async fn method_not_allowed(stream: Stream, allow: HeaderValue) {
    let mut fields = HeaderMap::new();
    fields.insert(header::ALLOW, allow);
    text(
        stream,
        StatusCode::METHOD_NOT_ALLOWED,
        "method not allowed\n",
        fields,
    )
    .await;
}

async fn text(stream: Stream, status: StatusCode, body: &str, mut fields: HeaderMap) {
    fields.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    stream.write_headers(status, &fields);
    stream.write_data_final(body.as_bytes()).await;
}
