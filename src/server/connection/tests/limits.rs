//! `Limits` other than the defaults, which every other test runs on: what the
//! preface announces and what the connection enforces have to be the same
//! numbers.

use runtime_core::deterministic_testing::ReadEvent;

use super::{
    FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GET_BLOCK, HEADERS, PREFACE, RST_STREAM, SETTINGS,
    echo, frame, run_connection_limited,
};
use crate::server::Limits;
use crate::shared::codec::types::REFUSED_STREAM;

const MAX_CONCURRENT_STREAMS: u16 = 0x3;
const INITIAL_WINDOW_SIZE: u16 = 0x4;
const MAX_HEADER_LIST_SIZE: u16 = 0x6;

fn opened(streams: &[(u32, u8, &[u8])]) -> Vec<super::Scripted> {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    for &(id, flags, block) in streams {
        bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS | flags, id, block));
    }
    vec![ReadEvent::Data(bytes).into(), ReadEvent::Eof.into()]
}

/// §6.5.1: six octets a setting, identifier then value.
fn announced(written: &[Frame], id: u16) -> Option<u32> {
    let preface = written.iter().find(|f| f.kind == SETTINGS && f.flags == 0)?;
    preface.payload.chunks_exact(6).find_map(|entry| {
        (u16::from_be_bytes([entry[0], entry[1]]) == id)
            .then(|| u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]))
    })
}

fn refused(written: &[Frame], id: u32) -> bool {
    written.iter().any(|f| {
        f.kind == RST_STREAM
            && f.stream_id == id
            && u32::from_be_bytes(f.payload[..4].try_into().unwrap()) == REFUSED_STREAM
    })
}

#[test]
fn the_preface_announces_the_limits_it_was_given() {
    let limits = Limits {
        max_concurrent_streams: 7,
        stream_window: 100_000,
        max_header_list_size: 4096,
        ..Limits::default()
    };
    let written = run_connection_limited(opened(&[]), limits, echo);

    assert_eq!(announced(&written, MAX_CONCURRENT_STREAMS), Some(7));
    assert_eq!(announced(&written, INITIAL_WINDOW_SIZE), Some(100_000));
    assert_eq!(announced(&written, MAX_HEADER_LIST_SIZE), Some(4096));
}

/// Bodies still to come, so neither of the first two finishes and frees its
/// slot before the third arrives.
#[test]
fn a_stream_past_max_concurrent_streams_is_refused() {
    let limits = Limits {
        max_concurrent_streams: 2,
        ..Limits::default()
    };
    let written = run_connection_limited(
        opened(&[(1, 0, GET_BLOCK), (3, 0, GET_BLOCK), (5, 0, GET_BLOCK)]),
        limits,
        echo,
    );

    assert!(refused(&written, 5), "the third was refused: {written:?}");
    assert!(
        !refused(&written, 1) && !refused(&written, 3),
        "the two admitted were not: {written:?}"
    );
}

#[test]
fn a_header_list_past_max_header_list_size_is_refused() {
    // `x-big: <100 bytes>` as a literal without indexing: 5 + 100 + 32 octets
    // decoded, past a limit of 128 that GET_BLOCK alone is well under.
    let mut big = GET_BLOCK.to_vec();
    big.extend_from_slice(&[0x00, 5]);
    big.extend_from_slice(b"x-big");
    big.push(100);
    big.extend_from_slice(&[b'a'; 100]);

    let limits = Limits {
        max_header_list_size: 128,
        ..Limits::default()
    };
    let written = run_connection_limited(
        opened(&[(1, FLAG_END_STREAM, &big), (3, FLAG_END_STREAM, GET_BLOCK)]),
        limits,
        echo,
    );

    assert!(refused(&written, 1), "the large one was refused: {written:?}");
    assert!(
        written.iter().any(|f| f.kind == HEADERS && f.stream_id == 3),
        "the small one was served: {written:?}"
    );
}

/// A peer that sent its preface and then nothing for a minute, and whether
/// it was closed as idle. One run a test: the ring is per thread.
fn closed_as_idle(limits: Limits) -> bool {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    let inbound = vec![
        ReadEvent::Data(bytes).into(),
        ReadEvent::Eof.after(std::time::Duration::from_secs(60)),
    ];
    run_connection_limited(inbound, limits, echo)
        .iter()
        .find(|f| f.kind == super::GOAWAY)
        .is_some_and(|f| &f.payload[8..] == b"idle too long")
}

#[test]
fn a_silent_connection_is_closed_at_its_idle_timeout() {
    assert!(closed_as_idle(Limits {
        idle_timeout: std::time::Duration::from_secs(20),
        ..Limits::default()
    }));
}

/// The control: two minutes outlast the minute of silence.
#[test]
fn the_default_idle_timeout_outlasts_a_minute() {
    assert!(!closed_as_idle(Limits::default()));
}
