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
    CONTINUATION, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GET_BLOCK, GOAWAY, HEADERS, PING,
    PREFACE, PRIORITY, RST_STREAM, SETTINGS, WINDOW_UPDATE, deliveries, frame, pings,
    run_connection,
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
    for _ in 0..super::super::protocol::ODD_FRAME_BURST + 1 {
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
/// An empty DATA frame costs the peer nothing: §6.9 accounts zero bytes
/// against both windows, so no credit is spent and no WINDOW_UPDATE is ever
/// owed. It costs us a decode, a dispatch and a wake of the handler task,
/// which finds nothing to read and parks again. Flow control cannot see it,
/// so the control budget is what has to.
#[test]
fn empty_data_flood() {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    // A stream left open: no END_STREAM, so DATA may keep arriving.
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));
    for _ in 0..super::super::protocol::ODD_FRAME_BURST + 1 {
        bytes.extend_from_slice(&frame(0x0, 0, 1, &[]));
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let (code, reason) =
        goaway(&run_connection(inbound, |_, _| {})).expect("the flood was answered with a GOAWAY");
    assert_eq!(code, ENHANCE_YOUR_CALM);
    assert_eq!(reason, "too many pointless frames");
}

/// CVE-2024-27316 — the CONTINUATION flood, with empty fragments.
///
/// `MAX_HEADER_BLOCK_SIZE` already bounds this attack in its usual form: a
/// header block that keeps growing without END_HEADERS is cut off at twice
/// the decoded limit. But that cap counts *bytes*, and a zero-length
/// fragment adds none — so an endless stream of empty CONTINUATIONs never
/// reaches it, while costing a decode and a dispatch each.
///
/// A fragment that carries nothing is not progress, so the control budget
/// is what catches this form — the byte cap catches the other.
#[test]
fn continuation_flood_with_empty_fragments() {
    let mut bytes = preface();
    // A header block deliberately left open: no END_HEADERS, ever.
    bytes.extend_from_slice(&frame(HEADERS, 0, 1, GET_BLOCK));
    for _ in 0..super::super::protocol::ODD_FRAME_BURST + 1 {
        bytes.extend_from_slice(&frame(CONTINUATION, 0, 1, &[]));
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let (code, reason) =
        goaway(&run_connection(inbound, |_, _| {})).expect("the flood was answered with a GOAWAY");
    assert_eq!(code, ENHANCE_YOUR_CALM);
    assert_eq!(reason, "too many pointless frames");
}

/// Not a CVE: the cost of the budget, stated as a test.
///
/// A download is the one legitimate exchange where the peer sends nothing
/// but control frames — it receives DATA and answers WINDOW_UPDATE, over and
/// over, and nothing it sends ever counts as progress. A client that leaves
/// its stream window at the §6.9.2 default of 65535 and credits it back half
/// a window at a time therefore spends one budget unit per 32 KiB received,
/// and trips `CONTROL_FRAME_BURST` somewhere past 300 MB.
///
/// The clients that matter avoid it by announcing a large window instead of
/// a chatty one — curl and nghttp2 both do — so this is a bound on the
/// conservative client, not a common case. It is recorded here because the
/// budget cannot tell it apart from a flood, and a reader deserves the
/// number rather than the reassurance.
#[test]
fn a_download_that_only_ever_sends_window_updates_trips_the_budget() {
    let mut bytes = preface();
    for _ in 0..super::super::protocol::CONTROL_FRAME_BURST + 1 {
        bytes.extend_from_slice(&frame(WINDOW_UPDATE, 0, 0, &32_768u32.to_be_bytes()));
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let (code, _) = goaway(&run_connection(inbound, |_, _| {}))
        .expect("the budget cannot tell a chatty download from a flood");
    assert_eq!(code, ENHANCE_YOUR_CALM);
}

/// The cost the strict budget must not have: a client still speaking the
/// RFC 7540 priority scheme sends a PRIORITY frame with every request, and
/// Firefox did exactly that for years. Ten times `ODD_FRAME_BURST` of them
/// is fine, because each request clears the count — which is the whole
/// reason the budget is a burst rather than a lifetime total.
///
/// Delivered in batches under `MAX_CONCURRENT_STREAMS`, because a
/// conforming client respects the limit we advertised (§5.1.2) and because
/// the map only drains between chunks: the tasks that answer a request run
/// when the loop yields, which is once per inbound chunk.
#[test]
fn a_priority_frame_per_request_is_not_a_flood() {
    let mut inbound = deliveries(&preface());
    let mut id = 1u32;
    for _ in 0..20 {
        let mut batch = Vec::new();
        for _ in 0..50 {
            batch.extend_from_slice(&frame(PRIORITY, 0, id, &[0, 0, 0, 0, 15]));
            batch.extend_from_slice(&frame(
                HEADERS,
                FLAG_END_HEADERS | FLAG_END_STREAM,
                id,
                GET_BLOCK,
            ));
            id += 2;
        }
        inbound.push(ReadEvent::Data(batch));
    }
    inbound.push(ReadEvent::Eof);

    let written = run_connection(inbound, |_, _| {});
    assert!(
        goaway(&written).is_none(),
        "a priority frame that comes with a request is not a pointless one",
    );
    assert_eq!(
        written.iter().filter(|f| f.kind == HEADERS).count(),
        1000,
        "every request was answered"
    );
}

/// §5.1.2 — a peer that fills the stream map and keeps asking.
///
/// A HEADERS frame refused for want of a slot still carries a header block,
/// so `FrameWorth` reads it as progress and it clears both budgets. Left
/// uncounted, that is a peer holding every defence at zero for as long as it
/// likes while paying an HPACK decode and a RST_STREAM of ours per attempt.
/// §5.1.2 makes exceeding the advertised limit a stream error, so the fault
/// budget is what counts it.
#[test]
fn a_peer_that_keeps_asking_past_the_stream_limit_is_closed() {
    let mut bytes = preface();
    let mut id = 1u32;
    // Fill the map: no END_STREAM, so every one of these stays open.
    for _ in 0..super::super::MAX_CONCURRENT_STREAMS {
        bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, id, GET_BLOCK));
        id += 2;
    }
    // Every one of these can only be refused, and pings between them no
    // longer buy the peer a reset of the count.
    for _ in 0..super::super::protocol::FAULT_LIMIT + 1 {
        bytes.extend_from_slice(&frame(PING, 0, 0, b"reset_me"));
        bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, id, GET_BLOCK));
        id += 2;
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let written = run_connection(inbound, |_, _| {});
    let (code, reason) = goaway(&written).expect("the peer was closed on");
    assert_eq!(code, ENHANCE_YOUR_CALM);
    assert_eq!(reason, "too many refused streams");
}
