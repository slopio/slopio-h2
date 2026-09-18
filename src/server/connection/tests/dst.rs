//! Deterministic simulation: the same connection, over and over, with the
//! bytes cut and timed differently every run.
//!
//! The suite beside this one asks whether a *particular* sequence is handled.
//! This asks whether handling survives the thing a network actually varies —
//! where the chunk boundaries fall and how far apart they arrive. A frame
//! decoder that reassembles correctly for the splits a hand-written test
//! happens to pick can still be wrong at the offset nobody chose, and the
//! decoder is called on every byte of every connection.
//!
//! The randomness is the test's own rather than the simulator's `after_between`,
//! and that is not a preference. The simulator orders its timeline by due time,
//! so two deliveries drawing out-of-order delays would swap — and a transport
//! that reorders bytes is not TCP. Delays here are drawn but kept monotonic, so
//! only the *spacing* varies and the stream stays a stream.
//!
//! A failing seed is a reproduction: `scenario(seed)` is a pure function of it.

use std::time::Duration;

use runtime_core::deterministic_testing::{ReadEvent, Scripted};

use super::{
    DATA, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GET_BLOCK, GOAWAY, HEADERS, PREFACE, SETTINGS,
    frame, run_connection_timed,
};

/// How many seeds one run of the test explores.
///
/// Each is a whole connection through the simulated ring, so the cost is real
/// but small — the clock is virtual, and nothing sleeps.
const SEEDS: u64 = 512;

/// splitmix64: a few lines, no dependency, and the same sequence everywhere.
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

/// One connection's worth of deliveries, and how many requests are in them.
///
/// A pure function of the seed, so a failure prints a number that reproduces
/// it exactly.
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

    // Cut at arbitrary offsets — one byte at a time is a legal TCP segment and
    // the decoder has to survive it. Frame boundaries are deliberately not
    // respected: a decoder only ever fed whole frames is a decoder whose
    // reassembly is untested.
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
    // re-testing the deadlines.
    deliveries.push(ReadEvent::Eof.after(Duration::from_millis(due + 10)));

    (deliveries, requests)
}

/// Every seed: the connection ends, what it wrote parses, and every request
/// got its response.
#[test]
fn every_split_and_spacing_is_served_in_full() {
    for seed in 0..SEEDS {
        // A thread per seed, because the buffer ring is a thread-local that
        // may be installed once: every `#[test]` gets a fresh thread for free,
        // and a loop inside one does not.
        let outcome = std::thread::spawn(move || check(seed)).join();
        assert!(outcome.is_ok(), "seed {seed} panicked; see above");
    }
}

/// One seed, end to end.
///
/// Three invariants, and the first two are checked for free. A connection that
/// hangs trips the simulator's own "ops parked with nothing to complete them",
/// and output that is not a clean sequence of frames trips the assertions in
/// `frames`. Only the third is spelled out here.
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
