//! Deterministic simulation: the same connection, with the bytes cut and
//! timed differently every run.
//!
//! Delays are drawn here, kept monotonic, rather than by `after_between`: the
//! simulator orders its timeline by due time, and a transport that reorders
//! bytes is not TCP.
//!
//! A failing seed is a reproduction: `scenario(seed)` is a pure function of it.

use std::time::Duration;

use runtime_core::deterministic_testing::{ReadEvent, Scripted};

use super::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GET_BLOCK, GOAWAY, HEADERS, PREFACE, SETTINGS,
    frame, run_connection_timed,
};

/// `DST_SEEDS` lowers it for Miri, where any seed exercises the aliasing in
/// `StreamMap`.
fn seeds() -> u64 {
    std::env::var("DST_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(512)
}

/// splitmix64.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// In `1..=max`.
    fn upto(&mut self, max: u64) -> u64 {
        1 + self.next() % max
    }
}

fn scenario(seed: u64) -> (Vec<Scripted>, usize) {
    let mut rng = Rng(seed);

    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));

    let requests = rng.upto(8) as usize;
    let mut id = 1u32;
    for _ in 0..requests {
        bytes.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            id,
            GET_BLOCK,
        ));
        id += 2;
    }

    // Cut at arbitrary offsets, one byte included. Frame boundaries are
    // deliberately not respected, so reassembly is tested.
    let mut deliveries = Vec::new();
    let mut at = 0;
    let mut due = 0u64;
    while at < bytes.len() {
        let end = (at + rng.upto(48) as usize).min(bytes.len());
        // Monotonic: the spacing varies, the order cannot.
        due += rng.upto(4);
        deliveries.push(ReadEvent::Data(bytes[at..end].to_vec()).after(Duration::from_millis(due)));
        at = end;
    }
    // Well inside `PARTIAL_TIMEOUT`, so this explores reassembly rather than
    // the deadlines.
    deliveries.push(ReadEvent::Eof.after(Duration::from_millis(due + 10)));

    (deliveries, requests)
}

#[test]
fn every_split_and_spacing_is_served_in_full() {
    for seed in 0..seeds() {
        // A thread per seed: the buffer ring is a thread-local that may be
        // installed once.
        let outcome = std::thread::spawn(move || check(seed)).join();
        assert!(outcome.is_ok(), "seed {seed} panicked; see above");
    }
}

/// A hang trips the simulator's own "ops parked with nothing to complete
/// them", and output that is not a clean sequence of frames trips the
/// assertions in `frames`.
fn check(seed: u64) {
    let (deliveries, requests) = scenario(seed);
    let written = run_connection_timed(deliveries, |_, _| {});

    assert_eq!(
        goaway_count(&written),
        0,
        "seed {seed}: a legal stream was answered with a GOAWAY: {written:?}"
    );

    let responses = written.iter().filter(|f| f.kind == HEADERS).count();
    assert_eq!(
        responses, requests,
        "seed {seed}: {requests} requests, {responses} responses"
    );

    // The body follows its headers on the same stream, whatever the split.
    for response in written.iter().filter(|f| f.kind == DATA) {
        assert!(
            response.payload.ends_with(b"bytes\n"),
            "seed {seed}: truncated body {:?}",
            response.payload
        );
    }
}

fn goaway_count(written: &[Frame]) -> usize {
    written.iter().filter(|f| f.kind == GOAWAY).count()
}
