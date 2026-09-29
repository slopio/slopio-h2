//! Run under Miri, which is where the `UnsafeCell` behind `StreamMap` is
//! actually checked:
//!
//! ```text
//! MIRIFLAGS=-Zmiri-disable-isolation cargo +nightly miri test --lib server::connection
//! ```
//!
//! Isolation has to come off because the timewheel samples the wall clock.
//! Tests that end with streams still open report leaks at exit: `block_on`
//! returns without freeing the tasks it killed.

mod cve;
mod dst;
#[cfg(feature = "grpc")]
mod grpc;
mod limits;
mod logic;
mod routing;

use std::time::Duration;

use runtime_core::deterministic_testing::{
    FakeRing, FakeRingHandle, ReadEvent, Scripted, WriteEvent, simulated_socket,
};
use runtime_core::runtime::RuntimeInner;

use super::FLUSH_TIMEOUT;
use crate::server::Limits;
use crate::server::connection::Connection;
use crate::shared::transport::PlainMessages;

// Four buffers: the loop recycles each chunk as soon as it is decoded.
runtime_core::define_buf_ring!(TestRing, bgid = 2, buffer_size = 16384, ring_size = 4);

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

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

/// `:status` keeps its colon, so a pseudo-header and a field of the same
/// name stay distinct.
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

pub(super) fn run_connection(
    inbound: Vec<ReadEvent>,
    script: impl FnOnce(&FakeRingHandle, i32),
) -> Vec<Frame> {
    run_connection_timed(inbound.into_iter().map(Into::into).collect(), script)
}

/// `ReadEvent::after` counts from the moment the op is armed, not from the
/// delivery before it, so a dribbling peer needs growing delays.
pub(super) fn run_connection_timed(
    inbound: Vec<Scripted>,
    script: impl FnOnce(&FakeRingHandle, i32),
) -> Vec<Frame> {
    run_connection_with(inbound, script, echo)
}

pub(super) fn run_connection_with<H: crate::server::Handler>(
    inbound: Vec<Scripted>,
    script: impl FnOnce(&FakeRingHandle, i32),
    handler: H,
) -> Vec<Frame> {
    frames(&run_writes(inbound, script, Limits::default(), handler).concat())
}

pub(super) fn run_connection_limited<H: crate::server::Handler>(
    inbound: Vec<Scripted>,
    limits: Limits,
    handler: H,
) -> Vec<Frame> {
    frames(&run_writes(inbound, |_, _| {}, limits, handler).concat())
}

/// Only for a peer that takes every write whole: a short write cuts a frame
/// in two, and neither half parses on its own.
pub(super) fn run_connection_writes<H: crate::server::Handler>(
    inbound: Vec<Scripted>,
    script: impl FnOnce(&FakeRingHandle, i32),
    handler: H,
) -> Vec<Vec<Frame>> {
    run_writes(inbound, script, Limits::default(), handler)
        .iter()
        .map(|write| frames(write))
        .collect()
}

fn run_writes<H: crate::server::Handler>(
    inbound: Vec<Scripted>,
    script: impl FnOnce(&FakeRingHandle, i32),
    limits: Limits,
    handler: H,
) -> Vec<Vec<u8>> {
    let (fake, handle) = FakeRing::builder().virtual_time().build();
    let socket = simulated_socket();
    let fd = socket.fd();

    handle.on_multishot_read(fd, inbound);
    script(&handle, fd);

    RuntimeInner::simulated(fake).block_on::<TestRing, _>(
        async move {
            // Spawned, as `Server` does: a root future that yields with an empty task
            // list puts the runtime to sleep with nothing armed to wake it.
            runtime_core::runtime::spawn(
                Connection::new(
                    PlainMessages::<TestRing, false>::new(socket),
                    None,
                    limits,
                    handler,
                )
                .run(),
            )
            .await;
        },
        None,
        |run| run(),
    );

    handle.writes(fd)
}

/// §5.1: a handler that returns without answering gets a `500` written on
/// its way out, rather than leaving the peer waiting.
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
    // §8.1: and it ends the message.
    assert_eq!(head.flags & FLAG_END_STREAM, FLAG_END_STREAM);
}

/// §8.1: head, body, and a last HEADERS carrying END_STREAM and no
/// pseudo-header.
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

/// Trailers without a head are a malformed response, so they are not
/// written.
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

/// Reset rather than finished on the handler's behalf: ending it cleanly
/// would pass a truncated response off as a whole one.
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

/// A delivery longer than a buffer is a short read. Frame boundaries are
/// deliberately not respected: the decoder reassembles across chunks.
pub(super) fn deliveries(bytes: &[u8]) -> Vec<ReadEvent> {
    bytes
        .chunks(15_000)
        .map(|chunk| ReadEvent::Data(chunk.to_vec()))
        .collect()
}

pub(super) fn pings(n: u32) -> Vec<ReadEvent> {
    let mut bytes = Vec::new();
    for _ in 0..n {
        bytes.extend_from_slice(&frame(PING, 0, 0, b"flooding"));
    }
    deliveries(&bytes)
}

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

    // §3.4: the server preface is a SETTINGS, and it is written first.
    assert_eq!(written[0].kind, SETTINGS);
    assert_eq!(written[0].flags, 0);

    // §6.9.2: only a WINDOW_UPDATE on stream 0 moves the connection window
    // past 65535.
    assert_eq!(written[1].kind, WINDOW_UPDATE);
    assert_eq!(written[1].stream_id, 0);
    assert_eq!(
        u32::from_be_bytes(written[1].payload[..4].try_into().unwrap()),
        super::CONNECTION_RECV_WINDOW - super::CONNECTION_INITIAL_WINDOW_SIZE
    );

    // §6.5.3: the ACK comes after the frames already queued.
    assert_eq!(written[2].kind, SETTINGS);
    assert_eq!(written[2].flags, FLAG_ACK);

    assert_eq!(written[3].kind, HEADERS);
    assert_eq!(written[3].stream_id, 1);
    assert_eq!(written[3].flags & FLAG_END_HEADERS, FLAG_END_HEADERS);

    // §8.3: the status is the only field a response must carry.
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
            // Every send accepts a single byte, so the gather write's frontier has
            // to walk the segment chain the whole way.
            for _ in 0..200 {
                handle.on_write(fd, WriteEvent::Short(1));
            }
        },
    );

    // A short write costs submissions, never bytes.
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

    // The send's buffers must still come back through `restore_output` on
    // the error path — the borrow would have panicked otherwise.
    assert!(written.is_empty(), "the peer received nothing: {written:?}");
}

#[test]
fn a_receiver_that_never_takes_the_write_is_dropped_at_the_flush_timeout() {
    let written = run_connection(
        vec![ReadEvent::Data(a_get()), ReadEvent::Eof],
        // A send never completed: the loop parks in `send` and stops popping
        // completions, each pinning a ring buffer shared with the whole worker.
        |handle, fd| {
            handle.on_write(
                fd,
                WriteEvent::All.after(FLUSH_TIMEOUT + Duration::from_secs(60)),
            )
        },
    );

    // The ring records a write when it completes; this one was cancelled.
    // What this pins is the release of the ring buffers, which is why the
    // timeout exists.
    assert!(
        written.is_empty(),
        "the send was cancelled, so the peer got nothing: {written:?}"
    );
}

#[test]
fn a_receiver_that_reads_within_the_timeout_is_served_normally() {
    let written = run_connection(
        vec![ReadEvent::Data(a_get()), ReadEvent::Eof],
        // A receiver that is actually reading must not be cut off.
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

    assert_eq!(written[3].kind, HEADERS);
    assert_eq!(written[4].payload, b"read 0 bytes\n");

    // The ring is shared by every connection on the worker, so an empty one
    // does not mean this peer is gone. What closes it is the read deadline.
    let goaway = written.last().expect("a connection that ends says so");
    assert_eq!(goaway.kind, GOAWAY);
    assert_eq!(
        u32::from_be_bytes(goaway.payload[4..8].try_into().unwrap()),
        0, // NO_ERROR
    );
    assert_eq!(&goaway.payload[8..], b"idle too long");
}

/// A peer that credits everything, so the download never waits: the
/// SETTINGS and the connection WINDOW_UPDATE that open both windows to
/// 2^31-1, then a GET.
fn a_get_with_all_the_credit() -> Vec<u8> {
    let mut bytes = PREFACE.to_vec();
    let mut settings = vec![0x00, 0x04]; // INITIAL_WINDOW_SIZE
    settings.extend_from_slice(&0x7fff_ffffu32.to_be_bytes());
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &settings));
    bytes.extend_from_slice(&frame(
        WINDOW_UPDATE,
        0,
        0,
        &(0x7fff_ffff - 65_535u32).to_be_bytes(),
    ));
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));
    bytes
}

/// 4 MiB, in writes that never wait for credit.
async fn a_download(stream: crate::server::Stream) {
    stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
    let chunk = vec![7u8; 16_384];
    for _ in 0..256 {
        stream.write_data(&chunk).await;
    }
    stream.write_data_final(b"").await;
}

/// The loop reads while a download with credit keeps the output full: the
/// peer's PING, already waiting, is answered before the download ends.
#[test]
fn a_download_with_credit_does_not_stop_the_loop_reading() {
    let written = run_connection_with(
        vec![
            ReadEvent::Data(a_get_with_all_the_credit()).into(),
            ReadEvent::Data(frame(PING, 0, 0, b"are you?")).into(),
            ReadEvent::Eof.after(Duration::from_secs(1)),
        ],
        |_, _| {},
        a_download,
    );

    let answer = written
        .iter()
        .position(|f| f.kind == PING && f.flags & FLAG_ACK != 0)
        .expect("the PING is answered");
    let last_data = written
        .iter()
        .rposition(|f| f.kind == DATA && f.stream_id == 1)
        .expect("the download went out");
    assert_eq!(written[last_data].flags & FLAG_END_STREAM, FLAG_END_STREAM);
    assert!(answer < last_data, "the PING waited for the whole download");
}

/// A connection error ends the streams with it: nothing follows the
/// GOAWAY, however much credit a writer still had.
#[test]
fn nothing_is_written_after_the_goaway() {
    let written = run_connection_with(
        vec![
            ReadEvent::Data(a_get_with_all_the_credit()).into(),
            // §6.7: a PING of 7 bytes is a connection FRAME_SIZE_ERROR.
            ReadEvent::Data(frame(PING, 0, 0, b"short!!")).into(),
            ReadEvent::Eof.after(Duration::from_secs(1)),
        ],
        |_, _| {},
        a_download,
    );

    let last = written.last().expect("the connection says why it ends");
    assert_eq!(last.kind, GOAWAY, "the GOAWAY is the last frame");
    let data = written.iter().filter(|f| f.kind == DATA).count();
    assert!(data < 256, "the download was cut: {data} DATA frames");
}

/// A response larger than the connection window: the writer parks on the
/// spent window, in its stream's slot, and goes on when stream 0 is credited.
#[test]
fn a_writer_parked_on_the_connection_window_goes_on_when_it_is_credited() {
    let mut first = PREFACE.to_vec();
    // The stream window out of the way, so the connection's is what runs out.
    let mut settings = vec![0x00, 0x04]; // INITIAL_WINDOW_SIZE
    settings.extend_from_slice(&(1u32 << 20).to_be_bytes());
    first.extend_from_slice(&frame(SETTINGS, 0, 0, &settings));
    first.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));
    let credit = frame(WINDOW_UPDATE, 0, 0, &65_535u32.to_be_bytes());

    let written = run_connection_with(
        vec![
            ReadEvent::Data(first).into(),
            ReadEvent::Data(credit).after(Duration::from_secs(1)),
            ReadEvent::Eof.after(Duration::from_secs(1)),
        ],
        |_, _| {},
        |stream: crate::server::Stream| async move {
            stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
            stream.write_data_final(&vec![7u8; 100_000]).await;
        },
    );

    let data: Vec<&Frame> = written.iter().filter(|f| f.kind == DATA).collect();
    let sent: usize = data.iter().map(|f| f.payload.len()).sum();
    assert_eq!(sent, 100_000, "the whole body, past the first 65 535 bytes");
    let last = data.last().expect("the body went out");
    assert_eq!(last.flags & FLAG_END_STREAM, FLAG_END_STREAM);
}
