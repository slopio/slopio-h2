//! Routing by method, to one async function per method, each spawned as its
//! own task:
//!
//! ```ignore
//! let grpc = GrpcRouter::new()
//!     .route("/grpc.health.v1.Health/Check", check)
//!     .route("/slopio.echo.v1.Echo/Chat", chat);
//! ```
//!
//! A gRPC path is the method's full name, matched whole: no patterns, no
//! query. One no route has is `UNIMPLEMENTED`, with a `200`, as gRPC §9.1 has
//! it, not a `404`.

use std::rc::Rc;

use fnv::FnvHashMap;

use super::call::{GrpcCall, GrpcHandler, answer};
use super::request::GrpcFormat;
use super::status::Status;
use crate::server::{Incoming, StreamTask};

/// Spawns the task one method's function runs in.
type Method = Box<dyn Fn(Incoming, GrpcFormat) -> StreamTask>;

/// Built once, then shared by the connections of a worker: cloning it
/// clones an `Rc`. Each worker builds its own.
#[derive(Clone)]
pub struct GrpcRouter(Rc<FnvHashMap<&'static str, Method>>);

impl Default for GrpcRouter {
    fn default() -> Self {
        Self::new()
    }
}

impl GrpcRouter {
    pub fn new() -> Self {
        Self(Rc::new(FnvHashMap::default()))
    }

    /// `path` is `/package.Service/Method`. Panics on one routed twice, or
    /// on a router already cloned: a bug in the table, found at startup.
    pub fn route<G>(mut self, path: &'static str, method: G) -> Self
    where
        G: AsyncFn(&GrpcCall) -> Status + Clone + 'static,
    {
        let table = Rc::get_mut(&mut self.0).expect("routes are added before the router is cloned");
        let method: Method = Box::new(move |incoming, format| {
            let method = method.clone();
            incoming.spawn(move |stream| answer(method, stream, format))
        });
        assert!(
            table.insert(path, method).is_none(),
            "{path} is routed twice"
        );
        self
    }
}

impl GrpcHandler for GrpcRouter {
    fn start(&self, incoming: Incoming, format: GrpcFormat) -> StreamTask {
        match incoming.path().and_then(|path| self.0.get(path)) {
            Some(method) => method(incoming, format),
            None => incoming.spawn(move |stream| answer(no_such_method, stream, format)),
        }
    }
}

async fn no_such_method(_: &GrpcCall) -> Status {
    Status::unimplemented("no such method")
}
