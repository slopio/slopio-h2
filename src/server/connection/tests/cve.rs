//! The published HTTP/2 denial-of-service attacks, run against the loop.
//!
//! One test per CVE, each named for it, so what is covered and what is not
//! is a list a reader can check rather than a claim. Every one of these is a
//! peer that speaks the protocol correctly and costs us far more than it
//! costs itself — none of them is a malformed frame, which is why the frame
//! decoder catches none of them and most defences here are budgets.
//!
//! Three kinds of defence appear here, and which one catches an attack is the
//! interesting part. A *budget* counts frames and is cleared by progress,
//! which is what stops the floods. A *size cap* counts what a header block
//! expands to rather than the bytes it arrived in, which is what stops the
//! bombs. A *deadline* measures time, and is the only thing that sees the
//! slowloris group at the bottom — those peers send almost nothing, so no
//! budget ever increments and no cap is ever approached.
//!
//! The deadline tests come in pairs on purpose: the attack, and the honest
//! peer that looks like it. A defence that cannot tell a slow upload from a
//! held stream is not a defence, so `a_slow_but_honest_request_body_is_served`
//! is as load-bearing as the attack beside it.

use std::time::Duration;

use runtime_core::deterministic_testing::{ReadEvent, Scripted};

use super::{
    CONTINUATION, DATA, FLAG_END_HEADERS, FLAG_END_STREAM, Frame, GET_BLOCK, GOAWAY, HEADERS, PING,
    PREFACE, PRIORITY, RST_STREAM, SETTINGS, WINDOW_UPDATE, deliveries, frame, pings,
    run_connection, run_connection_timed,
};
use crate::shared::codec::types::{
    COMPRESSION_ERROR, ENHANCE_YOUR_CALM, NO_ERROR, REFUSED_STREAM,
};

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

/// CVE-2019-9516, the 0-length headers leak — a header block whose fields have
/// empty names and empty values, three bytes each to send.
///
/// It never reaches a size cap: §8.2.1 has no empty field names, so `Header`
/// refuses the first one and the block fails to decode. §4.3 makes an HPACK
/// failure a *connection* error, which is the right answer — the dynamic table
/// is shared by every stream, so a block that did not decode leaves the peer
/// and us with different tables and nothing after it can be trusted.
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

    let written = run_connection(deliveries(&bytes), |_, _| {});

    let (code, _) = goaway(&written).expect("an undecodable block closes the connection");
    assert_eq!(code, COMPRESSION_ERROR);
}

/// The other half of CVE-2019-9516: fields that are legal, tiny, and many.
///
/// A one-byte name and an empty value is four bytes on the wire, and §6.5.2
/// charges it `1 + 0 + 32`. 600 of them are 2400 bytes in and 19 800 against
/// `DECODE_MAX_HEADER_LIST_SIZE` — an eightfold amplification, and the reason
/// the 32 in `decoded_header_size` is not a rounding detail. Without it this
/// block would count 600 bytes and there would be no cap to reach.
///
/// Refused as a stream error, not a connection one: the block decoded, so the
/// HPACK tables agree and only this request is unusable.
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

/// An HPACK bomb: one large value entered into the dynamic table, then named
/// again by one-byte references.
///
/// The block is ~4 KiB and the list it expands to is ~24 KiB, so
/// `MAX_HEADER_BLOCK_SIZE`, which bounds what arrives, never sees a problem.
/// What stops it is that the decoder counts what the block *decodes to*
/// against `DECODE_MAX_HEADER_LIST_SIZE` rather than the bytes it read.
///
/// The value is 4000 bytes and not 4096 on purpose: an entry costs its name,
/// its value and 32, and §4.4 says one larger than the table's maximum empties
/// the table instead of being added. At 4096 the entry would never exist,
/// index 62 would be undefined, and this would test a decode failure rather
/// than the cap.
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

/// CVE-2025-8671, MadeYouReset — the reset flood with the resets sent by *us*.
///
/// Rapid Reset is bounded by counting the peer's RST_STREAMs, so the variant
/// stops sending them: each stream is opened, ended, and then given a DATA
/// frame it may not have (§5.1), which is a stream error *we* answer with a
/// reset. The stream slot frees either way, so `MAX_CONCURRENT_STREAMS` is
/// never approached — and the budget that catches it has to be one that counts
/// our own resets too, which is what `fail_stream` calling `count_fault` is
/// for.
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
        // DATA after the peer's own END_STREAM: the fault we are made to find.
        bytes.extend_from_slice(&frame(DATA, 0, id, b"x"));
    }

    let written = run_connection(deliveries(&bytes), |_, _| {});

    let (code, _) = goaway(&written).expect("a peer that keeps making us reset is closed");
    assert_eq!(code, ENHANCE_YOUR_CALM);
}

// ---------------------------------------------------------------------------
// Slowloris: the attacks that cost time rather than frames.
//
// The budgets above all count frames and are cleared by progress, so none of
// them sees a peer whose whole method is to send almost nothing. These are the
// deadlines instead, and each names the state it is measuring.
// ---------------------------------------------------------------------------

/// Slowloris proper — a preface dribbled a byte at a time, *faster* than the
/// deadline it is trying to outlast.
///
/// Five seconds between bytes against a ten-second budget, which is the whole
/// point: an inactivity timer resets on every byte and would never fire here,
/// so this peer would hold the connection for the two minutes its preface
/// takes and then start on a header block. `PARTIAL_TIMEOUT` is spent from the
/// moment the half-sent state began and sending more of the same does not
/// refill it.
///
/// Nothing is written back: §3.4 answers an unfinished preface with silence,
/// not a GOAWAY, so the absence of frames *is* the connection being dropped —
/// a peer that got its preface in would have had our SETTINGS.
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

/// The same peer once its preface is in, holding a connection open having
/// asked for nothing.
///
/// Closed after `IDLE_TICKS` with NO_ERROR: an idle connection is not
/// misbehaving, it is finished, and a client that reconnects on NO_ERROR is
/// doing the right thing. This is the keepalive policy — HTTP/2 has no header
/// for it and the RFC sets no deadline, so it is ours to pick.
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

/// A HEADERS that never ends — worse than idle, because §6.10 forbids any
/// frame between a HEADERS and its CONTINUATION, so this blocks every *other*
/// stream on the connection and not just its own.
///
/// Caught by the same budget as the dribbled preface, and for the same reason:
/// `header_pending()` is the predicate, and it was written for this long
/// before anything called it.
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

/// A request body arriving a byte at a time: the upload side of the same idea,
/// and the one the connection deadlines cannot see, since the peer is sending
/// constantly and the connection is never idle.
///
/// What catches it is the stream's own rate — bytes over age — which is why it
/// has to be a rate and not a deadline: this peer is indistinguishable from a
/// large upload by any measure that only asks how long the stream has been
/// open.
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

/// The same shape at an honest rate, which must be served: a defence that
/// cannot tell a slow upload from a held stream is not a defence, it is an
/// outage. 4 KiB a second against a 256 B/s floor.
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

/// A client preface whose SETTINGS advertise `initial_window_size`, so a
/// response of any size stalls after that many bytes.
fn preface_with_window(initial: u32) -> Vec<u8> {
    let mut payload = vec![0x00, 0x04]; // SETTINGS_INITIAL_WINDOW_SIZE
    payload.extend_from_slice(&initial.to_be_bytes());
    let mut bytes = PREFACE.to_vec();
    bytes.extend_from_slice(&frame(SETTINGS, 0, 0, &payload));
    bytes
}

/// CVE-2019-9511, Data Dribble — ask for a response, then refuse to take it.
///
/// The download half of the slowloris family, and the one the other defences
/// are blind to. Nothing arrives to count, so the body rate never fires; the
/// writer parks inside `write_data` with no credit, so the send-side check is
/// never reached either; and with the peer's window at zero nothing is ever
/// queued, so `FLUSH_TIMEOUT` has no send to time out. A PING every few
/// seconds keeps the read deadline from expiring and costs one unit of a
/// budget of ten thousand.
///
/// What ends it is the sweep, which runs on the peer's chunks but not on the
/// peer's cooperation.
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
            // Keepalive, and what drives the sweep: legal, cheap, and useless.
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

/// The same tiny window, taken properly: a peer with little buffer that keeps
/// crediting is a peer being served, not an attack.
///
/// The pair matters more than the attack beside it. A send-rate floor that
/// cannot tell a small receive buffer from a held stream is an outage.
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

/// A request body that never starts — the inbound case the DATA-driven check
/// cannot see, since it is only reached by a DATA frame arriving.
///
/// Costs the peer one HEADERS and buys a stream slot, its receive window, and
/// a buffer sized by the `content-length` it declared, for as long as it keeps
/// the connection awake.
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
