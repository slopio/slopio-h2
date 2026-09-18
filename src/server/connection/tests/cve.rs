//! The published HTTP/2 denial-of-service attacks, run against the loop.
//!
//! One test per CVE, each named for it, so what is covered and what is not
//! is a list a reader can check rather than a claim. Every one of these is a
//! peer that speaks the protocol correctly and costs us far more than it
//! costs itself — none of them is a malformed frame, which is why the frame
//! decoder catches none of them and every defence here is a budget.
//!
//! The ones that pass assert the budget that stops them. The one that does
//! not asserts what happens today, and says what would stop it.

use runtime_core::deterministic_testing::ReadEvent;

use super::{
    FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GET_BLOCK, GOAWAY, HEADERS, PREFACE, PRIORITY,
    RST_STREAM, SETTINGS, deliveries, frame, pings, run_connection,
};
use crate::shared::codec::types::ENHANCE_YOUR_CALM;

/// The GOAWAY a connection was closed with, if it was.
fn goaway(written: &[Frame]) -> Option<(u32, String)> {
    written.iter().find(|f| f.kind == GOAWAY).map(|f| {
        (
            u32::from_be_bytes(f.payload[4..8].try_into().unwrap()),
            String::from_utf8_lossy(&f.payload[8..]).into_owned(),
        )
    })
}

/// A client preface and its SETTINGS, with no request behind it.
fn preface() -> Vec<u8> {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    bytes
}

/// CVE-2019-9512 — a flood of PINGs, each of which we must answer.
#[test]
fn ping_flood() {
    let mut inbound = deliveries(&preface());
    inbound.extend(pings(super::super::protocol::CONTROL_FRAME_BURST + 1));
    inbound.push(ReadEvent::Eof);

    let (code, reason) =
        goaway(&run_connection(inbound, |_, _| {})).expect("the flood was answered with a GOAWAY");
    assert_eq!(code, ENHANCE_YOUR_CALM);
    assert_eq!(reason, "too many control frames");
}

/// CVE-2019-9515 — a flood of SETTINGS, each of which forces an ACK.
#[test]
fn settings_flood() {
    let mut bytes = preface();
    for _ in 0..super::super::protocol::CONTROL_FRAME_BURST + 1 {
        bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let written = run_connection(inbound, |_, _| {});
    let (code, reason) = goaway(&written).expect("the flood was answered with a GOAWAY");
    assert_eq!(code, ENHANCE_YOUR_CALM);
    assert_eq!(reason, "too many control frames");

    // The point of the attack is the answer it forces. Whatever it got, it
    // stopped at the budget rather than running as long as the peer liked.
    let acks = written
        .iter()
        .filter(|f| f.kind == SETTINGS && f.flags & 0x1 != 0)
        .count();
    assert!(
        acks <= super::super::protocol::CONTROL_FRAME_BURST as usize + 2000,
        "{acks} ACKs for a budget of {}",
        super::super::protocol::CONTROL_FRAME_BURST
    );
}

/// CVE-2019-9513 — a flood of PRIORITY frames. We implement no priority
/// scheme, so there is no tree to rebuild; what remains is the decode, and
/// the control budget is what bounds it.
#[test]
fn priority_flood() {
    let mut bytes = preface();
    // §6.3: exclusive bit + dependency id, then weight.
    for _ in 0..super::super::protocol::CONTROL_FRAME_BURST + 1 {
        bytes.extend_from_slice(&frame(PRIORITY, 0, 1, &[0, 0, 0, 0, 15]));
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let (code, _) =
        goaway(&run_connection(inbound, |_, _| {})).expect("the flood was answered with a GOAWAY");
    assert_eq!(code, ENHANCE_YOUR_CALM);
}

/// CVE-2019-9514 — open a stream, reset it, repeat. Every reset is a stream
/// error we count, and past `FAULT_LIMIT` the connection goes.
#[test]
fn reset_flood() {
    let mut bytes = preface();
    let mut id = 1u32;
    for _ in 0..super::super::protocol::FAULT_LIMIT + 1 {
        bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, id, GET_BLOCK));
        bytes.extend_from_slice(&frame(RST_STREAM, 0, id, &0x8u32.to_be_bytes()));
        id += 2;
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let (code, reason) =
        goaway(&run_connection(inbound, |_, _| {})).expect("the flood was answered with a GOAWAY");
    assert_eq!(code, ENHANCE_YOUR_CALM);
    assert_eq!(reason, "too many stream resets");
}

/// CVE-2023-44487, Rapid Reset — the same open-and-cancel, whose point is
/// that a cancelled stream stops counting against `MAX_CONCURRENT_STREAMS`,
/// so the limit that looks like the defence never fires. `FAULT_LIMIT` is
/// what actually stops it, and it stops it long before the 100 concurrent
/// streams the peer never got to hold.
#[test]
fn rapid_reset() {
    let mut bytes = preface();
    let mut id = 1u32;
    // Ten times the concurrency limit, which on its own would refuse
    // nothing: each stream is gone before the next arrives.
    for _ in 0..super::super::MAX_CONCURRENT_STREAMS * 10 {
        bytes.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            id,
            GET_BLOCK,
        ));
        bytes.extend_from_slice(&frame(RST_STREAM, 0, id, &0x8u32.to_be_bytes()));
        id += 2;
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let written = run_connection(inbound, |_, _| {});
    let (code, reason) = goaway(&written).expect("rapid reset was answered with a GOAWAY");
    assert_eq!(code, ENHANCE_YOUR_CALM);
    assert_eq!(reason, "too many stream resets");

    // Nothing was refused *before* the GOAWAY. A REFUSED_STREAM after it is
    // §6.8 — every id above the one the GOAWAY named is refused from then on
    // — where one before it would have been the concurrency limit catching
    // the attack, which is precisely what this attack evades.
    let closed_at = written.iter().position(|f| f.kind == GOAWAY).unwrap();
    let refused_early = written[..closed_at].iter().any(|f| {
        f.kind == RST_STREAM && u32::from_be_bytes(f.payload[..4].try_into().unwrap()) == 0x7
    });
    assert!(
        !refused_early,
        "the concurrency limit fired, so this is not the attack it claims to be"
    );
}

/// CVE-2019-9518 — a flood of empty frames on an open stream.
///
/// This one is **not** defended against, and the test says what happens
/// rather than what should. An empty DATA frame costs the peer nothing: §6.9
/// accounts zero bytes against both windows, so no credit is spent and no
/// WINDOW_UPDATE is ever owed. It costs us a decode, a dispatch, and a
/// wake of the handler task, which finds nothing to read and parks again.
///
/// Worse, it *clears* the control-frame budget. `count_control_frame` reads
/// DATA as progress on a request, which a zero-length DATA frame is not — so
/// a peer that interleaves empty DATA frames escapes the budget that stops
/// every other flood here.
///
/// The fix is one line in `count_control_frame`: progress is a request frame
/// that carries something, so a DATA frame of length zero belongs in the
/// budget rather than clearing it.
#[test]
fn empty_frames_flood_is_not_yet_bounded() {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    // A stream left open: no END_STREAM, so DATA may keep arriving.
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));
    for _ in 0..super::super::protocol::CONTROL_FRAME_BURST * 2 {
        bytes.extend_from_slice(&frame(0x0, 0, 1, &[]));
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let written = run_connection(inbound, |_, _| {});

    assert!(
        goaway(&written).is_none(),
        "this is the gap: twice the control budget in empty DATA frames, and \
         the connection is still open because each one reset the count",
    );
}
