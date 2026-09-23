//! The published HTTP/2 denial-of-service attacks, run against the loop.
//! Budgets stop the floods, size caps stop the bombs, deadlines stop the
//! slowloris group. Deadline tests come in pairs: the attack, and the honest
//! peer that looks like it.

use std::time::Duration;

use runtime_core::deterministic_testing::{ReadEvent, Scripted};

use super::{
    CONTINUATION, DATA, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GET_BLOCK, GOAWAY, HEADERS, PING,
    PREFACE, PRIORITY, RST_STREAM, SETTINGS, WINDOW_UPDATE, deliveries, frame, pings,
    run_connection, run_connection_timed,
};
use crate::shared::codec::types::{
    ENHANCE_YOUR_CALM, NO_ERROR, PROTOCOL_ERROR, REFUSED_STREAM, STREAM_CLOSED,
};

fn goaway(written: &[Frame]) -> Option<(u32, String)> {
    written.iter().find(|f| f.kind == GOAWAY).map(|f| {
        (
            u32::from_be_bytes(f.payload[4..8].try_into().unwrap()),
            String::from_utf8_lossy(&f.payload[8..]).into_owned(),
        )
    })
}

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

    // The point of the attack is the ACKs it forces: they stop at the budget.
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

/// CVE-2019-9513 — a flood of PRIORITY frames.
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

/// CVE-2019-9514 — open a stream, reset it, repeat.
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

/// CVE-2023-44487, Rapid Reset — open-and-cancel, so no stream ever counts
/// against `MAX_CONCURRENT_STREAMS` for long. `FAULT_LIMIT` is what stops it.
#[test]
fn rapid_reset() {
    let mut bytes = preface();
    let mut id = 1u32;
    // Each stream is gone before the next arrives, so the concurrency limit
    // alone would refuse nothing.
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

    // Nothing refused before the GOAWAY (after it is §6.8): that would be the
    // concurrency limit catching it, which is what this attack evades.
    let closed_at = written.iter().position(|f| f.kind == GOAWAY).unwrap();
    let refused_early = written[..closed_at].iter().any(|f| {
        f.kind == RST_STREAM && u32::from_be_bytes(f.payload[..4].try_into().unwrap()) == 0x7
    });
    assert!(
        !refused_early,
        "the concurrency limit fired, so this is not the attack it claims to be"
    );
}

/// CVE-2019-9518 — a flood of empty DATA frames on an open stream. They spend
/// no credit (§6.9), so flow control cannot see them.
#[test]
fn empty_data_flood() {
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
    // No END_STREAM, so DATA may keep arriving.
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
/// `MAX_HEADER_BLOCK_SIZE` counts bytes and an empty fragment adds none, so
/// the budget is what catches this form.
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

/// Not a CVE: the known cost of the budget. A download credits back half a
/// §6.9.2 default window at a time and trips `CONTROL_FRAME_BURST` past
/// ~300 MB; the budget cannot tell it from a flood.
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

/// The strict budget must not trip on an RFC 7540 client sending a PRIORITY
/// with every request: each request clears the count.
///
/// Batched under `MAX_CONCURRENT_STREAMS` (§5.1.2): the map only drains
/// between chunks.
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

/// §5.1.2 — a peer that fills the stream map and keeps asking. A refused
/// HEADERS still reads as progress and clears both burst budgets, so the
/// fault budget has to count it.
#[test]
fn a_peer_that_keeps_asking_past_the_stream_limit_is_closed() {
    let mut bytes = preface();
    let mut id = 1u32;
    // Fill the map: no END_STREAM, so every one of these stays open.
    for _ in 0..super::super::MAX_CONCURRENT_STREAMS {
        bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, id, GET_BLOCK));
        id += 2;
    }
    // Pings between them no longer buy the peer a reset of the count.
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

/// CVE-2019-9516, the 0-length headers leak — fields with empty names and
/// values. A malformed request (§8.1.1): a stream error, not a connection one.
#[test]
fn zero_length_headers_leak() {
    let mut block = GET_BLOCK.to_vec();
    // Literal without indexing, new name: name length 0, value length 0.
    for _ in 0..600 {
        block.extend_from_slice(&[0x00, 0x00, 0x00]);
    }

    let mut bytes = preface();
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &block,
    ));

    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);
    let written = run_connection(inbound, |_, _| {});

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM && f.stream_id == 1)
        .unwrap_or_else(|| panic!("the malformed request was reset: {written:?}"));
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        PROTOCOL_ERROR
    );
    assert!(
        !written.iter().any(|f| f.kind == HEADERS),
        "and never reached the handler: {written:?}"
    );
    assert_eq!(goaway(&written), None);
}

/// The other half of CVE-2019-9516: many tiny legal fields. §6.5.2 charges
/// each `1 + 0 + 32`, an eightfold amplification — the reason for the 32 in
/// `decoded_header_size`. A stream error: the HPACK tables still agree.
#[test]
fn a_header_list_of_tiny_fields_is_refused_by_the_size_cap() {
    let mut block = GET_BLOCK.to_vec();
    // Literal without indexing, new name: name "a", value empty.
    for _ in 0..600 {
        block.extend_from_slice(&[0x00, 0x01, b'a', 0x00]);
    }

    let mut bytes = preface();
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &block,
    ));

    // EOF, unlike the tests that end in a GOAWAY: the connection survives a
    // refused stream, so without it the loop waits on a read that never comes.
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);
    let written = run_connection(inbound, |_, _| {});

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM)
        .expect("the over-sized list was refused");
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        REFUSED_STREAM
    );
    assert_eq!(goaway(&written), None, "the connection survives it");
}

/// Each refusal cost a full decode while `FrameWorth` calls the block
/// progress, so `FAULT_LIMIT` has to count it.
#[test]
fn a_flood_of_over_sized_header_lists_ends_the_connection() {
    let mut block = GET_BLOCK.to_vec();
    for _ in 0..600 {
        block.extend_from_slice(&[0x00, 0x01, b'a', 0x00]);
    }

    let mut bytes = preface();
    for i in 0..=super::super::protocol::FAULT_LIMIT {
        bytes.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            1 + 2 * i,
            &block,
        ));
    }

    let written = run_connection(deliveries(&bytes), |_, _| {});

    let (code, reason) = goaway(&written).expect("refusing for ever is not a defence");
    assert_eq!(code, ENHANCE_YOUR_CALM);
    assert_eq!(reason, "too many over-sized header lists");
}

/// An HPACK bomb: one large value in the dynamic table, then one-byte
/// references to it. Caught by the decoded size, not `MAX_HEADER_BLOCK_SIZE`.
///
/// 4000 bytes, not 4096: §4.4 empties the table instead of adding an entry
/// larger than it, so index 62 would not exist.
#[test]
fn an_hpack_bomb_is_refused_by_the_decoded_size() {
    let mut block = GET_BLOCK.to_vec();

    // Literal with incremental indexing, new name "a", 4000-byte value. The
    // length is a 7-bit-prefix varint: 127, then 3873 as 0xA1 0x1E.
    block.extend_from_slice(&[0x40, 0x01, b'a', 0x7F, 0xA1, 0x1E]);
    block.extend(std::iter::repeat_n(b'x', 4000));

    // Five references to index 62, the entry just added: one byte each, and
    // each costs 1 + 4000 + 32 against the list size.
    for _ in 0..5 {
        block.push(0xBE);
    }

    let mut bytes = preface();
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        &block,
    ));

    // EOF, unlike the tests that end in a GOAWAY: the connection survives a
    // refused stream, so without it the loop waits on a read that never comes.
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);
    let written = run_connection(inbound, |_, _| {});

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM)
        .expect("the bomb was refused by the size cap, not by a decode failure");
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        REFUSED_STREAM
    );
    assert_eq!(
        goaway(&written),
        None,
        "the block decoded, so the tables agree and the connection survives"
    );
}

/// CVE-2025-8671, MadeYouReset — the reset flood with the resets sent by us:
/// DATA after END_STREAM (§5.1) makes us reset, so our own resets must count.
#[test]
fn made_you_reset() {
    let mut bytes = preface();
    for i in 0..super::super::protocol::FAULT_LIMIT + 1 {
        let id = 2 * i + 1;
        bytes.extend_from_slice(&frame(
            HEADERS,
            FLAG_END_HEADERS | FLAG_END_STREAM,
            id,
            GET_BLOCK,
        ));
        // DATA after the peer's own END_STREAM.
        bytes.extend_from_slice(&frame(DATA, 0, id, b"x"));
    }

    let written = run_connection(deliveries(&bytes), |_, _| {});

    let (code, _) = goaway(&written).expect("a peer that keeps making us reset is closed");
    assert_eq!(code, ENHANCE_YOUR_CALM);
}

/// MadeYouReset with triggers the frame decoder finds: a WINDOW_UPDATE of
/// zero (§6.9), a PRIORITY of the wrong size (§6.3) or depending on itself
/// (§5.3.1).
///
/// One test per trigger: a test thread runs one connection.
fn made_you_reset_by_the_decoder(kind: u8, trigger: impl Fn(u32) -> Vec<u8>) {
    let mut bytes = preface();
    for i in 0..super::super::protocol::FAULT_LIMIT + 1 {
        let id = 2 * i + 1;
        bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, id, GET_BLOCK));
        bytes.extend_from_slice(&frame(kind, 0, id, &trigger(id)));
    }

    let written = run_connection(deliveries(&bytes), |_, _| {});

    let (code, _) = goaway(&written).expect("a peer that keeps making us reset is closed");
    assert_eq!(code, ENHANCE_YOUR_CALM);
}

#[test]
fn made_you_reset_with_a_zero_window_update() {
    made_you_reset_by_the_decoder(WINDOW_UPDATE, |_| vec![0; 4]);
}

#[test]
fn made_you_reset_with_a_short_priority() {
    made_you_reset_by_the_decoder(PRIORITY, |_| vec![0; 4]);
}

#[test]
fn made_you_reset_with_a_self_dependent_priority() {
    made_you_reset_by_the_decoder(PRIORITY, |id| {
        let mut payload = id.to_be_bytes().to_vec();
        payload.push(15);
        payload
    });
}

/// DATA on a stream the peer closed is a stream error (§5.1), answered once:
/// answering every frame made us a reflector, one RST_STREAM out per byte in.
#[test]
fn data_on_a_stream_the_peer_closed_is_answered_once() {
    let mut bytes = preface();
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));
    bytes.extend_from_slice(&frame(RST_STREAM, 0, 1, &0x8u32.to_be_bytes()));
    for _ in 0..5_000 {
        bytes.extend_from_slice(&frame(DATA, 0, 1, b"x"));
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let written = run_connection(inbound, |_, _| {});

    let resets: Vec<_> = written
        .iter()
        .filter(|f| f.kind == RST_STREAM && f.stream_id == 1)
        .collect();
    assert_eq!(resets.len(), 1, "one answer, not one per frame");
    assert_eq!(
        u32::from_be_bytes(resets[0].payload[..4].try_into().unwrap()),
        STREAM_CLOSED
    );
}

/// DATA on a gone stream is not progress, or one byte every few thousand
/// PINGs keeps the PING flood (CVE-2019-9512) alive.
#[test]
fn data_on_a_dead_stream_does_not_refresh_the_control_budget() {
    let mut bytes = preface();
    // A stream we reset, so the DATA behind it is ignored rather than counted.
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));
    bytes.extend_from_slice(&frame(WINDOW_UPDATE, 0, 1, &[0, 0, 0, 0]));
    let burst = super::super::protocol::CONTROL_FRAME_BURST;
    for _ in 0..3 {
        for _ in 0..burst / 2 {
            bytes.extend_from_slice(&frame(PING, 0, 0, b"flooding"));
        }
        bytes.extend_from_slice(&frame(DATA, 0, 1, b"x"));
    }
    let mut inbound = deliveries(&bytes);
    inbound.push(ReadEvent::Eof);

    let written = run_connection(inbound, |_, _| {});

    let (code, reason) = goaway(&written).expect("the flood was answered with a GOAWAY");
    assert_eq!(code, ENHANCE_YOUR_CALM);
    assert_eq!(reason, "too many control frames");
    assert_eq!(
        written
            .iter()
            .filter(|f| f.kind == RST_STREAM && f.stream_id == 1)
            .count(),
        1,
        "the body behind our reset is ignored, not answered"
    );
}

// ---------------------------------------------------------------------------
// Slowloris: the attacks that cost time rather than frames.
//
// Budgets never see a peer that sends almost nothing; deadlines do.
// ---------------------------------------------------------------------------

/// Slowloris — a preface dribbled a byte at a time, faster than an
/// inactivity timer would notice. `PARTIAL_TIMEOUT` runs from when the
/// half-sent state began, so more of the same does not refill it.
///
/// §3.4: an unfinished preface is answered with silence, not a GOAWAY.
#[test]
fn slowloris_a_dribbled_preface_is_cut_off() {
    let gap = Duration::from_secs(5);
    let inbound: Vec<Scripted> = PREFACE
        .iter()
        .enumerate()
        .map(|(i, byte)| ReadEvent::Data(vec![*byte]).after(gap * (i as u32 + 1)))
        .collect();

    let written = run_connection_timed(inbound, |_, _| {});

    assert!(
        written.is_empty(),
        "dropped mid-preface, in silence: {written:?}"
    );
}

#[test]
fn an_idle_connection_is_closed_when_the_keepalive_runs_out() {
    let written = run_connection_timed(
        vec![
            ReadEvent::Data(preface()).into(),
            ReadEvent::Eof.after(Duration::from_secs(24 * 60 * 60)),
        ],
        |_, _| {},
    );

    let (code, _) = goaway(&written).expect("an idle connection is closed, and told so");
    assert_eq!(code, NO_ERROR);
}

/// A HEADERS that never ends: §6.10 forbids any frame in between, so it
/// blocks every other stream on the connection.
#[test]
fn an_unfinished_header_block_is_cut_off() {
    let mut bytes = preface();
    // No END_HEADERS, and no CONTINUATION will ever come.
    bytes.extend_from_slice(&frame(HEADERS, 0, 1, GET_BLOCK));

    let written = run_connection_timed(
        vec![
            ReadEvent::Data(bytes).into(),
            ReadEvent::Eof.after(Duration::from_secs(24 * 60 * 60)),
        ],
        |_, _| {},
    );

    let (code, _) = goaway(&written).expect("a block that never ends is not waited on for ever");
    assert_eq!(code, NO_ERROR);
}

/// A request body dribbled a byte at a time. The connection is never idle,
/// so only the stream's rate, not a deadline, can catch it.
#[test]
fn a_dribbled_request_body_is_reset() {
    let mut open = preface();
    // No END_STREAM: a body is coming.
    open.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));

    let second = Duration::from_secs(1);
    let mut inbound: Vec<Scripted> = vec![ReadEvent::Data(open).into()];
    // One byte a second, well under `MIN_BODY_RATE`, for long enough to pass
    // `BODY_GRACE` and be judged.
    for i in 1..30u32 {
        inbound.push(ReadEvent::Data(frame(DATA, 0, 1, b"x")).after(second * i));
    }
    inbound.push(ReadEvent::Eof.after(second * 30));

    let written = run_connection_timed(inbound, |_, _| {});

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM)
        .expect("a starved body is reset");
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        ENHANCE_YOUR_CALM
    );
}

/// A defence that cannot tell a slow upload from a held stream is an outage.
/// 4 KiB a second against a 256 B/s floor.
#[test]
fn a_slow_but_honest_request_body_is_served() {
    let mut open = preface();
    open.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, GET_BLOCK));

    let second = Duration::from_secs(1);
    let mut inbound: Vec<Scripted> = vec![ReadEvent::Data(open).into()];
    let chunk = vec![b'x'; 4096];
    for i in 1..12u32 {
        inbound.push(ReadEvent::Data(frame(DATA, 0, 1, &chunk)).after(second * i));
    }
    inbound.push(ReadEvent::Data(frame(DATA, FLAG_END_STREAM, 1, b"")).after(second * 12));

    let written = run_connection_timed(inbound, |_, _| {});

    assert!(
        !written.iter().any(|f| f.kind == RST_STREAM),
        "an honest upload is not reset: {written:?}"
    );
    assert!(
        written.iter().any(|f| f.kind == HEADERS),
        "and it gets its response: {written:?}"
    );
}

/// SETTINGS advertising `initial_window_size`, so a response of any size
/// stalls after that many bytes.
fn preface_with_window(initial: u32) -> Vec<u8> {
    let mut payload = vec![0x00, 0x04]; // SETTINGS_INITIAL_WINDOW_SIZE
    payload.extend_from_slice(&initial.to_be_bytes());
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &payload));
    bytes
}

/// CVE-2019-9511, Data Dribble — ask for a response, then refuse to take it.
/// No DATA arrives, the writer parks on zero credit and nothing is queued to
/// time out; only the sweep sees it.
#[test]
fn data_dribble_a_response_the_peer_will_not_take() {
    let mut bytes = preface_with_window(1);
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));

    let second = Duration::from_secs(1);
    let written = run_connection_timed(
        vec![
            ReadEvent::Data(bytes).into(),
            // Keepalive, and what drives the sweep.
            ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 6),
            ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 12),
            ReadEvent::Eof.after(second * 18),
        ],
        |_, _| {},
    );

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM)
        .expect("a response the peer will not take is not held open for it");
    assert_eq!(reset.stream_id, 1);
    assert_eq!(
        u32::from_be_bytes(reset.payload[..4].try_into().unwrap()),
        ENHANCE_YOUR_CALM
    );
}

/// A send-rate floor that cannot tell a small receive buffer from a held
/// stream is an outage.
#[test]
fn a_small_window_that_keeps_crediting_is_served() {
    let mut bytes = preface_with_window(1);
    bytes.extend_from_slice(&frame(
        HEADERS,
        FLAG_END_HEADERS | FLAG_END_STREAM,
        1,
        GET_BLOCK,
    ));

    let second = Duration::from_secs(1);
    let written = run_connection_timed(
        vec![
            ReadEvent::Data(bytes).into(),
            // Enough credit for the rest of the body, well inside the grace.
            ReadEvent::Data(frame(WINDOW_UPDATE, 0, 1, &100u32.to_be_bytes())).after(second),
            ReadEvent::Eof.after(second * 12),
        ],
        |_, _| {},
    );

    assert!(
        !written.iter().any(|f| f.kind == RST_STREAM),
        "a peer that credits is served: {written:?}"
    );
    assert!(
        written
            .iter()
            .any(|f| f.kind == DATA && f.payload.ends_with(b"bytes\n")),
        "and gets its whole body: {written:?}"
    );
}

/// A request body that never starts: the DATA-driven check never runs. One
/// HEADERS holds a stream slot, its window and a `content-length`-sized
/// buffer.
#[test]
fn a_request_body_that_never_arrives_is_reclaimed() {
    // `content-length` with no END_STREAM: a body is promised and never sent.
    let mut block = GET_BLOCK.to_vec();
    // Literal without indexing, new name "content-length", value "16384".
    block.push(0x00);
    block.push(14);
    block.extend_from_slice(b"content-length");
    block.push(5);
    block.extend_from_slice(b"16384");

    let mut bytes = preface();
    bytes.extend_from_slice(&frame(HEADERS, FLAG_END_HEADERS, 1, &block));

    let second = Duration::from_secs(1);
    let written = run_connection_timed(
        vec![
            ReadEvent::Data(bytes).into(),
            ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 6),
            ReadEvent::Data(frame(PING, 0, 0, b"keepaliv")).after(second * 12),
            ReadEvent::Eof.after(second * 18),
        ],
        |_, _| {},
    );

    let reset = written
        .iter()
        .find(|f| f.kind == RST_STREAM)
        .expect("a promised body that never arrives does not hold its slot");
    assert_eq!(reset.stream_id, 1);
}

/// §6.5.2 lets a peer ask for any `u32`; obeyed, our encoder's table would
/// grow without bound. §4.2 lets an encoder use less than it is offered.
#[test]
fn a_peer_cannot_name_an_unbounded_hpack_table() {
    use crate::shared::codec::types::Setting;
    use crate::shared::connection::settings::{MAX_ENCODER_TABLE_SIZE, Settings};

    let mut settings = Settings::default();
    // §6.5.2: any u32 is legal to ask for, so this must not be an error.
    assert!(settings.apply(Setting::HeaderTableSize(u32::MAX)).is_ok());
    assert_eq!(settings.header_table_size, MAX_ENCODER_TABLE_SIZE);

    // The clamp is a ceiling rather than a constant.
    assert!(settings.apply(Setting::HeaderTableSize(512)).is_ok());
    assert_eq!(settings.header_table_size, 512);
}
