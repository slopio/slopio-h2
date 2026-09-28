//! A set of `Limits` that does not add up is refused before anything
//! listens: the port is still free afterwards.

use std::io;
use std::net::TcpListener;

use popple_h2::server::{Limits, Server, ServerSettings, ServerTransport, Stream};
use runtime::main_thread_with;

runtime::define_buf_ring!(ServerRing, bgid = 0, buffer_size = 16384, ring_size = 16);

async fn unreachable(_: Stream) {}

#[test]
fn run_refuses_limits_that_do_not_add_up() {
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let error = main_thread_with::<ServerRing, _>(async move {
        let mut settings = ServerSettings::new(([127, 0, 0, 1], port), ServerTransport::Plain);
        settings.limits = Limits {
            max_concurrent_streams: 0,
            ..Limits::default()
        };
        Server::new(settings)
            .run::<ServerRing, _>(unreachable)
            .await
    })
    .expect_err("refused");

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    TcpListener::bind(("127.0.0.1", port)).expect("nothing was bound");
}
