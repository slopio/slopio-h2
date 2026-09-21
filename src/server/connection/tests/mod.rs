//! The connection loop, run against a simulated ring.
//!
//! Nothing here opens a socket. `FakeRing` accepts the same SQEs the real
//! driver submits and answers them from a script, so the driver above it —
//! slabs, wakers, the multishot state machine, buffer recycling — and every
//! line of the connection loop run unmodified against a kernel the test
//! chooses. Inbound frames are declared up front with `on_multishot_read`;
//! what the peer would have received comes back from `handle.writes`.
//!
//! Declaring the world before the runtime starts is what makes these
//! reproducible: a test that drove the ring while the loop ran would depend
//! on when a task happened to be polled.
//!
//! They also run under Miri, which is where the `UnsafeCell` behind
//! `StreamMap` is actually checked — a task removing its own entry while the
//! connection is suspended is the aliasing this whole suite exercises by
//! accident:
//!
//! ```text
//! MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test --lib server::connection
//! ```
//!
//! Isolation has to come off because the timewheel samples the wall clock.
//! Two tests report leaks at exit — the ones that end with streams still
//! open: killing a task queues it for the scheduler to free, and `block_on`
//! returns without popping the queue. That predates `StreamMap` (198
//! allocations before it, 199 after, the one being the shared map a leaked
//! token's `Weak` keeps alive) and belongs to the runtime's shutdown.

mod cve;
mod dst;
mod logic;

use std::time::Duration;

use runtime_core::deterministic_testing::{
    FakeRing, FakeRingHandle, ReadEvent, Scripted, WriteEvent, simulated_socket,
};
use runtime_core::runtime::RuntimeInner;

use super::FLUSH_TIMEOUT;
use crate::server::connection::Connection;
use crate::shared::transport::PlainMessages;

// 16 KiB buffers, as the server uses. Four of them: the loop recycles each
// chunk as soon as it is decoded, so depth only has to cover what is in
// flight at once.
runtime_core::define_buf_ring!(TestRing, bgid = 2, buffer_size = 16384, ring_size = 4);

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The handler every test in this suite runs against: read the request body,
/// answer `200` and say how many bytes it was.
///
/// It lived in the library until the server took a handler. Keeping it here,
/// spelled out, is what lets a test assert on the bytes a response carries
/// without reaching into the connection to find out what it decided to send.
async fn echo(stream: crate::server::Stream) {
    let received = if stream.body_is_oneshot() {
        stream.body().await.map_or(0, |body| body.len())
    } else {
        let mut total = 0;
        while stream.readable().await {
            let taken = stream.peek(|bytes| bytes.len());
            stream.consume(taken);
            total += taken;
        }
        total
    };

    stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
    let body = format!("read {received} bytes\n");
    stream.write_data_final(body.as_bytes()).await;
}

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const SETTINGS: u8 = 0x4;
const PRIORITY: u8 = 0x2;
const CONTINUATION: u8 = 0x9;
const RST_STREAM: u8 = 0x3;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;

/// `:method GET` (index 2), `:scheme http` (6), `:path /` (4) — three static
/// table entries, so the block needs no literal encoding.
const GET_BLOCK: &[u8] = &[0x82, 0x86, 0x84];

pub(super) fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Frame {
    pub(super) kind: u8,
    pub(super) flags: u8,
    pub(super) stream_id: u32,
    pub(super) payload: Vec<u8>,
}

/// The fields of an encoded header block, by name. `:status` keeps its
/// colon, so a pseudo-header and a field of the same name stay distinct.
fn decode_block(payload: &[u8]) -> std::collections::HashMap<String, String> {
    use crate::shared::hpack::{Decoder, Header};
    use bytes::BytesMut;

    let mut buf = BytesMut::from(payload);
    let mut cursor = std::io::Cursor::new(&mut buf);
    let mut out = std::collections::HashMap::new();
    Decoder::new(4096)
        .decode(&mut cursor, |header| {
            let (name, value) = match header {
                Header::Field { name, value } => (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                ),
                Header::Status(status) => (":status".to_owned(), status.as_str().to_owned()),
                other => (format!("{other:?}"), String::new()),
            };
            out.insert(name, value);
        })
        .expect("the block we just encoded decodes");
    out
}

/// Every frame the peer would have received, in order. Takes the whole byte
/// stream rather than one write at a time: where a flush lands is the
/// connection's business, not the protocol's.
fn frames(bytes: &[u8]) -> Vec<Frame> {
    let mut out = Vec::new();
    let mut at = 0;
    while at + 9 <= bytes.len() {
        let len = u32::from_be_bytes([0, bytes[at], bytes[at + 1], bytes[at + 2]]) as usize;
        let end = at + 9 + len;
        assert!(end <= bytes.len(), "a frame ran past the bytes written");
        out.push(Frame {
            kind: bytes[at + 3],
            flags: bytes[at + 4],
            stream_id: u32::from_be_bytes([
                bytes[at + 5] & 0x7f,
                bytes[at + 6],
                bytes[at + 7],
                bytes[at + 8],
            ]),
            payload: bytes[at + 9..end].to_vec(),
        });
        at = end;
    }
    assert_eq!(at, bytes.len(), "trailing bytes that are not a frame");
    out
}

/// Runs one connection to completion over a scripted peer, and hands back
/// every frame it wrote.
pub(super) fn run_connection(
    inbound: Vec<ReadEvent>,
    script: impl FnOnce(&FakeRingHandle, i32),
) -> Vec<Frame> {
    run_connection_timed(inbound.into_iter().map(Into::into).collect(), script)
}

/// As [`run_connection`], with every delivery's arrival time declared.
///
/// `ReadEvent::after` holds a completion back from the moment the op is armed,
/// not from the delivery before it, so a peer that dribbles is written with
/// delays that grow — the timeline is ordered by due time, and equal delays
/// would land together. The clock is virtual, so a test may spend hours.
pub(super) fn run_connection_timed(
    inbound: Vec<Scripted>,
    script: impl FnOnce(&FakeRingHandle, i32),
) -> Vec<Frame> {
    run_connection_with(inbound, script, echo)
}

/// As [`run_connection_timed`], against a handler of the test's choosing —
/// for the tests that are about what the connection does *around* a handler
/// rather than about the bytes one produces.
pub(super) fn run_connection_with<H: crate::server::Handler>(
    inbound: Vec<Scripted>,
    script: impl FnOnce(&FakeRingHandle, i32),
    handler: H,
) -> Vec<Frame> {
    let (fake, handle) = FakeRing::builder().virtual_time().build();
    let socket = simulated_socket();
    let fd = socket.fd();

    handle.on_multishot_read(fd, inbound);
    script(&handle, fd);

    RuntimeInner::simulated(fake).block_on::<TestRing, _>(
        async move {
            // Spawned rather than awaited inline, which is how `Server` runs
            // it: the loop yields to let its stream tasks write, and a root
            // future that yields with an empty task list puts the runtime to
            // sleep with nothing armed to wake it.
            runtime_core::runtime::spawn(
                Connection::new(PlainMessages::<TestRing, false>::new(socket), handler).run(),
            )
            .await;
        },
        None,
        |run| run(),
    );

    frames(&handle.writes(fd).concat())
}

/// §5.1: a handler that returns without answering would leave the peer waiting
/// for a response nothing on this connection will ever send. The stream writes
/// a `500` on its way out rather than hanging it.
///
/// A handler that does nothing at all is the extreme case; the one that
/// matters in practice is the one that returns early on an error path and
/// forgets to say so.
#[test]
fn a_handler_that_answers_nothing_still_ends_the_stream() {
    let written = run_connection_with(
        deliveries(&a_get()).into_iter().map(Into::into).collect(),
        |_, _| {},
        |_stream: crate::server::Stream| async {},
    );

    let head = written
        .iter()
        .find(|f| f.kind == HEADERS)
        .expect("a response head went out");
    assert_eq!(head.stream_id, 1);
    assert_eq!(
        decode_block(&head.payload)
            .get(":status")
            .map(String::as_str),
        Some("500")
    );
    // §8.1: and it ends the message, so the peer stops waiting.
    assert_eq!(head.flags & FLAG_END_STREAM, FLAG_END_STREAM);
}

/// §8.1: a response that ends with a trailer section — head, body, and a last
/// HEADERS carrying END_STREAM and no pseudo-header. What a gRPC response is.
#[test]
fn a_response_can_end_with_trailers() {
    let written = run_connection_with(
        deliveries(&a_get()).into_iter().map(Into::into).collect(),
        |_, _| {},
        |stream: crate::server::Stream| async move {
            stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
            stream.write_data(b"a message").await;

            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
            stream.write_trailers(&trailers);
        },
    );

    let ours: Vec<&Frame> = written.iter().filter(|f| f.stream_id == 1).collect();
    let kinds: Vec<u8> = ours.iter().map(|f| f.kind).collect();
    assert_eq!(
        kinds,
        [HEADERS, DATA, HEADERS],
        "head, body, trailers — once"
    );

    let (head, body, trailers) = (ours[0], ours[1], ours[2]);
    assert_eq!(head.flags & FLAG_END_STREAM, 0);
    assert_eq!(body.payload, b"a message");
    assert_eq!(body.flags & FLAG_END_STREAM, 0, "the body does not end it");

    assert_eq!(
        trailers.flags & (FLAG_END_STREAM | FLAG_END_HEADERS),
        FLAG_END_STREAM | FLAG_END_HEADERS,
        "the trailers do"
    );
    let fields = decode_block(&trailers.payload);
    assert_eq!(fields.get("grpc-status").map(String::as_str), Some("0"));
    assert!(!fields.contains_key(":status"), "§8.1: no pseudo-header");
}

/// Trailers the peer has had no head for are a malformed response, so they
/// are not written — and a handler that did nothing else has answered nothing.
#[test]
fn trailers_without_a_head_are_not_a_response() {
    let written = run_connection_with(
        deliveries(&a_get()).into_iter().map(Into::into).collect(),
        |_, _| {},
        |stream: crate::server::Stream| async move {
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
            stream.write_trailers(&trailers);
        },
    );

    let ours: Vec<&Frame> = written.iter().filter(|f| f.stream_id == 1).collect();
    assert_eq!(ours.len(), 1);
    assert_eq!(
        decode_block(&ours[0].payload)
            .get(":status")
            .map(String::as_str),
        Some("500")
    );
}

/// The other way to leave a peer waiting: a head, some body, and a handler
/// that returns before its END_STREAM — between the last `write_data` and the
/// trailers, say. The stream is reset rather than finished on its behalf,
/// since ending it cleanly would pass a truncated response off as a whole one.
#[test]
fn a_response_left_unfinished_is_reset() {
    let written = run_connection_with(
        deliveries(&a_get()).into_iter().map(Into::into).collect(),
        |_, _| {},
        |stream: crate::server::Stream| async move {
            stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
            stream.write_data(b"half of it").await;
        },
    );

    let ours: Vec<&Frame> = written.iter().filter(|f| f.stream_id == 1).collect();
    let kinds: Vec<u8> = ours.iter().map(|f| f.kind).collect();
    assert_eq!(kinds, [HEADERS, DATA, RST_STREAM]);
    assert!(ours.iter().all(|f| f.flags & FLAG_END_STREAM == 0));
    assert_eq!(
        u32::from_be_bytes(ours[2].payload[..4].try_into().unwrap()),
        crate::shared::codec::types::INTERNAL_ERROR
    );
}

/// Cuts a byte stream into deliveries the ring's buffers can hold.
///
/// A delivery longer than a buffer is a short read, so the rest would be
/// lost rather than continued — how the payload divides is what the reader
/// sees, and the simulator says so rather than truncating in silence. Frame
/// boundaries are deliberately not respected: the decoder reassembles across
/// chunks, and a test that only ever fed it whole frames would never say so.
pub(super) fn deliveries(bytes: &[u8]) -> Vec<ReadEvent> {
    bytes
        .chunks(15_000)
        .map(|chunk| ReadEvent::Data(chunk.to_vec()))
        .collect()
}

/// `n` PING frames, delivered in ring-sized pieces.
pub(super) fn pings(n: u32) -> Vec<ReadEvent> {
    let mut bytes = Vec::new();
    for _ in 0..n {
        bytes.extend_from_slice(&frame(PING, 0, 0, b"flooding"));
    }
    deliveries(&bytes)
}

/// A client preface, its mandatory SETTINGS, and one GET.
pub(super) fn a_get() -> Vec<u8> {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));
    bytes
}

#[test]
fn a_request_is_answered_through_the_whole_loop() {
    let written = run_connection(
        vec![ReadEvent::Data(a_get()), ReadEvent::Eof],
        |_handle, _fd| {},
    );

    // §3.4: the server preface is a SETTINGS, and it is the first thing
    // written — before the ACK the client's own SETTINGS asks for.
    assert_eq!(written[0].kind, SETTINGS);
    assert_eq!(written[0].flags, 0);

    // §6.9.2: the connection window starts at 65535 and only a WINDOW_UPDATE
    // on stream 0 moves it up to CONNECTION_RECV_WINDOW.
    assert_eq!(written[1].kind, WINDOW_UPDATE);
    assert_eq!(written[1].stream_id, 0);
    assert_eq!(
        u32::from_be_bytes(written[1].payload[..4].try_into().unwrap()),
        super::CONNECTION_RECV_WINDOW - super::CONNECTION_INITIAL_WINDOW_SIZE
    );

    // §6.5.3: the ACK comes after the frames already queued, never before.
    assert_eq!(written[2].kind, SETTINGS);
    assert_eq!(written[2].flags, FLAG_ACK);

    assert_eq!(written[3].kind, HEADERS);
    assert_eq!(written[3].stream_id, 1);
    assert_eq!(written[3].flags & FLAG_END_HEADERS, FLAG_END_HEADERS);

    // Decoded rather than matched on the bytes, since HPACK is free to
    // Huffman a value. §8.3: the status is the only field a response must
    // carry, and the placeholder handler sets none of its own.
    let head = decode_block(&written[3].payload);
    assert_eq!(head.get(":status").map(String::as_str), Some("200"));
    assert_eq!(
        head.len(),
        1,
        "nothing is added to a response head: {head:?}"
    );

    assert_eq!(written[4].kind, DATA);
    assert_eq!(written[4].stream_id, 1);
    assert_eq!(written[4].flags & FLAG_END_STREAM, FLAG_END_STREAM);
    assert_eq!(written[4].payload, b"read 0 bytes\n");

    assert_eq!(written.len(), 5, "nothing else was written");
}

#[test]
fn a_control_frame_flood_ends_the_connection() {
    // Past CONTROL_FRAME_BURST with no request frame to clear the count.
    let mut inbound = vec![ReadEvent::Data(a_get())];
    inbound.extend(pings(super::protocol::CONTROL_FRAME_BURST + 1));
    inbound.push(ReadEvent::Eof);

    let written = run_connection(inbound, |_handle, _fd| {});

    let goaway = written
        .iter()
        .find(|f| f.kind == GOAWAY)
        .expect("the flood was answered with a GOAWAY");
    assert_eq!(
        u32::from_be_bytes(goaway.payload[4..8].try_into().unwrap()),
        crate::shared::codec::types::ENHANCE_YOUR_CALM
    );
    assert_eq!(&goaway.payload[8..], b"too many control frames");
}

#[test]
fn a_request_below_the_burst_is_served_normally() {
    // The same shape as the flood, an order of magnitude under the budget:
    // what separates them is the count alone.
    let mut inbound = vec![ReadEvent::Data(a_get())];
    inbound.extend(pings(1000));
    inbound.push(ReadEvent::Eof);

    let written = run_connection(inbound, |_handle, _fd| {});

    assert!(
        !written.iter().any(|f| f.kind == GOAWAY),
        "1000 pings is not a flood"
    );
    assert_eq!(
        written.iter().filter(|f| f.kind == PING).count(),
        1000,
        "every ping was answered"
    );
}

#[test]
fn a_response_survives_a_peer_that_takes_one_byte_at_a_time() {
    let written = run_connection(
        vec![ReadEvent::Data(a_get()), ReadEvent::Eof],
        |handle, fd| {
            // Every send accepts a single byte, so the gather write's
            // frontier has to walk the segment chain the whole way.
            for _ in 0..200 {
                handle.on_write(fd, WriteEvent::Short(1));
            }
        },
    );

    // The same frames in the same order: a short write costs submissions,
    // never bytes, and nothing was written twice or dropped at a segment
    // boundary.
    assert_eq!(written.len(), 5);
    assert_eq!(written[3].kind, HEADERS);
    assert_eq!(written[4].payload, b"read 0 bytes\n");
}

#[test]
fn a_broken_pipe_ends_the_connection_without_writing_more() {
    let written = run_connection(
        vec![ReadEvent::Data(a_get()), ReadEvent::Eof],
        |handle, fd| handle.on_write(fd, WriteEvent::Error(libc::EPIPE)),
    );

    // The failed send delivered nothing and the loop returned rather than
    // filling an output no one would ever send. What this pins is that the
    // send's buffers still came back through `restore_output` on the error
    // path — the borrow would have panicked otherwise.
    assert!(written.is_empty(), "the peer received nothing: {written:?}");
}

#[test]
fn a_receiver_that_never_takes_the_write_is_dropped_at_the_flush_timeout() {
    let written = run_connection(
        vec![ReadEvent::Data(a_get()), ReadEvent::Eof],
        // A send the peer never completes — the slow receiver, in the shape
        // that costs us most: the loop parks in `send` and stops popping its
        // inbound completions, each of which pins a ring buffer shared with
        // every other connection on the worker.
        |handle, fd| {
            handle.on_write(
                fd,
                WriteEvent::All.after(FLUSH_TIMEOUT + Duration::from_secs(60)),
            )
        },
    );

    // Nothing reached the peer: the ring records a write when it completes,
    // and this one was cancelled at the deadline instead. Virtual time, so the
    // five seconds cost the test nothing.
    //
    // What this pins is the release of the ring buffers, which is the reason
    // the timeout exists — the connection dying is only how it is done.
    assert!(
        written.is_empty(),
        "the send was cancelled, so the peer got nothing: {written:?}"
    );
}

#[test]
fn a_receiver_that_reads_within_the_timeout_is_served_normally() {
    let written = run_connection(
        vec![ReadEvent::Data(a_get()), ReadEvent::Eof],
        // Slow, but inside the deadline: a receiver that is actually reading
        // must not be cut off, or the timeout is a bug and not a defence.
        |handle, fd| handle.on_write(fd, WriteEvent::All.after(FLUSH_TIMEOUT / 2)),
    );

    assert_eq!(written.len(), 5, "served in full: {written:?}");
    assert_eq!(written[4].payload, b"read 0 bytes\n");
}

#[test]
fn a_ring_out_of_buffers_does_not_end_the_connection() {
    let written = run_connection(
        vec![ReadEvent::Data(a_get()), ReadEvent::Error(libc::ENOBUFS)],
        |_handle, _fd| {},
    );

    // The request in hand was answered before the ring ran dry.
    assert_eq!(written[3].kind, HEADERS);
    assert_eq!(written[4].payload, b"read 0 bytes\n");

    // And the dry ring did not end it. The ring is shared by every connection
    // on the worker, so an empty one says another connection is holding the
    // buffers, not that this peer is gone — the runtime classifies it
    // `ContinueLater` and the loop yields until one comes back.
    //
    // What closes this connection is the read deadline, two minutes later,
    // because the script has nothing after the error. A GOAWAY(NO_ERROR)
    // saying "idle too long" is the shape of an ordinary goodbye, where this
    // test used to assert a silent drop mid-stream.
    let goaway = written.last().expect("a connection that ends says so");
    assert_eq!(goaway.kind, GOAWAY);
    assert_eq!(
        u32::from_be_bytes(goaway.payload[4..8].try_into().unwrap()),
        0, // NO_ERROR
    );
    assert_eq!(&goaway.payload[8..], b"idle too long");
}
