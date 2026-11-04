//! The server under a world drawn from a seed.
//!
//! No scenario here is written by hand. Each seed draws how many clients
//! connect and when, and what each asks: after the preface and the SETTINGS
//! exchange, a few rounds of GETs and POSTs, each round waiting for every
//! answer before the next. A round's requests go out in sends of any grouping,
//! their bodies' DATA interleaved and sometimes held back, so a stream may be
//! open with its body still to come. The clients are [`Dialogue`] peers: they
//! read the server's frames however its writes were split, and check each
//! answer's body, on its stream, before going on. What a client sends reaches
//! the server in pieces of any size, a single byte included.
//!
//! Each seed also draws how hostile the world is, one axis at a time: clients
//! that reset in the middle of a send, vanish, or make a send of the server's
//! fail; sends taken only in part or drained slowly; a kernel that interrupts
//! or ends the multishot read on its own.
//!
//! What must hold whatever the seed: a healthy client is answered in full and
//! never sent a GOAWAY or a reset; no client is answered wrong; every
//! connection ends, a vanished client's on one of the server's deadlines;
//! nothing is left open, owed or in flight.

use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::rc::Rc;
use std::time::Duration;

use slopio::deterministic_testing::{
    AcceptEvent, Check, Dialogue, DialogueReport, FakeRingHandle, Fault, FdKind, Scripted, mint,
};
use slopio::io_driver::operations::sockets::multi_accept::MultiAccept;
use slopio::runtime::{RuntimeInner, spawn};
use slopio::streams::StreamExt;

use super::{GET_BLOCK, PREFACE, echo};
use crate::dst::{
    DATA, FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM, GOAWAY, HEADERS, PING, Profile, RST_STREAM,
    Rng, SETTINGS, Slot, WINDOW_UPDATE, assert_explored, error_code, explore, frame, frame_at,
    frames, judge, kind, leftovers, profile, ring, spread,
};
use crate::server::Limits;
use crate::server::connection::Connection;
use crate::shared::transport::PlainMessages;

// Small buffers, so a frame spans many completions; a pool past the ring, so
// the reserve is in play.
slopio::define_buf_ring!(
    DstRing,
    bgid = 0,
    buffer_size = 512,
    ring_size = 16,
    pool_size = 64
);

/// `:method POST` (index 3), `:scheme http`, `:path /`.
const POST_BLOCK: &[u8] = &[0x83, 0x86, 0x84];

const SEEDS: u64 = 512;

/// Inclusive ranges.
const CLIENTS: (usize, usize) = (1, 4);
const ROUNDS: (usize, usize) = (1, 4);
const REQUESTS: (usize, usize) = (1, 4);
const BODY: (usize, usize) = (0, 20_000);
/// §4.2: SETTINGS_MAX_FRAME_SIZE's initial value.
const DATA_FRAME: (usize, usize) = (1, 16_384);

/// What the echo handler answers a request whose body was `len` bytes.
fn answer(len: usize) -> Vec<u8> {
    format!("read {len} bytes\n").into_bytes()
}

/// One request's frames, HEADERS first, its body split into DATA frames.
fn request(rng: &mut Rng, id: u32, body: Option<usize>) -> VecDeque<Vec<u8>> {
    let Some(len) = body else {
        let flags = FLAG_END_HEADERS | FLAG_END_STREAM;
        return VecDeque::from([frame(HEADERS, flags, id, GET_BLOCK)]);
    };
    let mut frames = VecDeque::from([frame(HEADERS, FLAG_END_HEADERS, id, POST_BLOCK)]);
    let bytes = vec![b'x'; len];
    let mut at = 0;
    loop {
        let end = (at + rng.upto(DATA_FRAME)).min(len);
        let flags = if end == len { FLAG_END_STREAM } else { 0 };
        frames.push_back(frame(DATA, flags, id, &bytes[at..end]));
        at = end;
        if at == len {
            return frames;
        }
    }
}

/// Before the first request: anything but the server's SETTINGS, which it
/// must send first (§3.4), is wrong.
fn server_settings(got: &[u8]) -> Check {
    let mut at = 0;
    while let Some((frame, len)) = frame_at(&got[at..]) {
        at += len;
        match frame.kind {
            SETTINGS if frame.flags & FLAG_ACK == 0 => return Check::Pass(at),
            WINDOW_UPDATE if frame.stream_id == 0 => {}
            other => return Check::Fail(format!("frame type {other} before the SETTINGS")),
        }
    }
    Check::More
}

/// Every stream in `want` answered with its body, in whatever order and
/// however interleaved, among frames that need no answer.
fn answers(want: Vec<(u32, Vec<u8>)>) -> impl FnMut(&[u8]) -> Check {
    move |got| {
        let mut bodies: Vec<Option<Vec<u8>>> = vec![None; want.len()];
        let mut left = want.len();
        let mut at = 0;
        while let Some((frame, len)) = frame_at(&got[at..]) {
            at += len;
            match frame.kind {
                SETTINGS | PING | WINDOW_UPDATE => continue,
                HEADERS | DATA => {}
                GOAWAY => return Check::Fail(format!("GOAWAY {}", error_code(frame.payload, 4))),
                RST_STREAM => {
                    let code = error_code(frame.payload, 0);
                    return Check::Fail(format!("stream {} reset, {code}", frame.stream_id));
                }
                other => return Check::Fail(format!("frame type {other}")),
            }
            let Some(i) = want.iter().position(|(id, _)| *id == frame.stream_id) else {
                return Check::Fail(format!("a frame on stream {}", frame.stream_id));
            };
            match (&mut bodies[i], frame.kind) {
                (None, HEADERS) => bodies[i] = Some(Vec::new()),
                (Some(body), DATA) => body.extend_from_slice(frame.payload),
                (_, kind) => {
                    return Check::Fail(format!(
                        "frame type {kind} out of place on stream {}",
                        want[i].0
                    ));
                }
            }
            if frame.ends_stream() {
                if bodies[i].as_deref() != Some(&want[i].1[..]) {
                    let got = String::from_utf8_lossy(bodies[i].as_deref().unwrap_or_default());
                    return Check::Fail(format!("stream {} answered {got:?}", want[i].0));
                }
                left -= 1;
                if left == 0 {
                    return Check::Pass(at);
                }
            }
        }
        Check::More
    }
}

/// One client: its descriptor, and the report its dialogue fills in.
struct Client {
    fd: i32,
    report: Rc<RefCell<DialogueReport>>,
}

/// A round's requests, interleaved but each stream opened in order (§5.1.1),
/// grouped into sends of the seed's choosing.
fn round(
    rng: &mut Rng,
    mut requests: Vec<VecDeque<Vec<u8>>>,
    mut dialogue: Dialogue,
) -> (Dialogue, usize) {
    let mut sends = 0;
    let mut opened = 0;
    let mut pending = Vec::new();
    loop {
        // A request can go on once its HEADERS have, or if it is next to open.
        let ready: Vec<usize> = (0..requests.len())
            .filter(|&i| !requests[i].is_empty() && i <= opened)
            .collect();
        let Some(&i) = ready.get(rng.upto((0, ready.len().max(1) - 1))) else {
            break;
        };
        if i == opened {
            opened += 1;
        }
        pending.extend(requests[i].pop_front().expect("a frame"));
        if rng.one_in(2) {
            dialogue = dialogue.send(std::mem::take(&mut pending));
            sends += 1;
            if rng.one_in(4) {
                dialogue = dialogue.wait(rng.millis(0, 20));
            }
        }
    }
    if !pending.is_empty() {
        dialogue = dialogue.send(pending);
        sends += 1;
    }
    (dialogue, sends)
}

/// One client's dialogue, under `profile`: the preface, the SETTINGS
/// exchange, a few rounds of requests each awaiting its answers, and FIN.
pub(super) fn dialogue(rng: &mut Rng, profile: &Profile) -> Dialogue {
    let mut opening = PREFACE.to_vec();
    opening.extend(frame(SETTINGS, 0, 0, &[]));
    let mut dialogue = Dialogue::new()
        .send(opening)
        .expect("the server's SETTINGS", server_settings)
        .send(frame(SETTINGS, FLAG_ACK, 0, &[]));
    let (mut sends, mut steps, mut rounds) = (2, 3, 0);

    let mut id = 1;
    for _ in 0..rng.upto(ROUNDS) {
        let mut requests = Vec::new();
        let mut want = Vec::new();
        for _ in 0..rng.upto(REQUESTS) {
            let body = rng.one_in(2).then(|| rng.upto(BODY));
            requests.push(request(rng, id, body));
            want.push((id, answer(body.unwrap_or(0))));
            id += 2;
        }
        let sent;
        (dialogue, sent) = round(rng, requests, dialogue);
        dialogue = dialogue.expect(
            format!("the answers to {} request(s)", want.len()),
            answers(want),
        );
        sends += sent;
        steps += 2 * sent + 1;
        rounds += 1;
        if rng.one_in(2) {
            dialogue = dialogue.wait(rng.millis(0, 5));
        }
    }
    let mut dialogue = dialogue
        .close()
        .faults(spread(profile.faults, sends, steps, rounds + 1))
        .short_writes(profile.short_writes);
    if let Some(max) = profile.write_latency {
        dialogue = dialogue.write_latency(Duration::ZERO, max);
    }
    dialogue
}

/// Draw the clients and their dialogues, and attach them. The accept script
/// needs the listener, which only exists once the run has started, so it is
/// handed back to be declared then.
fn draw(rng: &mut Rng, profile: Profile, handle: &FakeRingHandle) -> (Vec<Client>, Vec<Scripted>) {
    let mut clients = Vec::new();
    let mut arrivals = Vec::new();
    for _ in 0..rng.upto(CLIENTS) {
        let (peer, report) = dialogue(rng, &profile).build();
        let fd = mint(FdKind::Socket);
        handle.attach(fd, peer);
        arrivals.push(AcceptEvent::On(fd).after_between(Duration::ZERO, rng.millis(0, 20)));
        clients.push(Client { fd, report });
    }
    (clients, arrivals)
}

/// What one run produced, for the tallies and the replay check.
#[derive(Debug, PartialEq, Eq)]
struct Report {
    faults: Vec<Option<Fault>>,
    /// Steps each client played, of how many.
    progress: Vec<(usize, usize)>,
    /// Bytes each client sent and was sent.
    bytes: Vec<(usize, usize)>,
    elapsed: Duration,
}

/// Serve the clients `seed` draws, a connection each, as `Server` does.
fn run(seed: u64, journal: Option<&Slot>) -> Result<Report, String> {
    let mut rng = Rng(seed);
    let profile = profile(&mut rng);
    let (fake, handle) = ring(seed, &profile, journal);
    let (clients, arrivals) = draw(&mut rng, profile, &handle);
    let count = clients.len();

    let script = handle.clone();
    let ended = RuntimeInner::simulated(fake).block_on::<DstRing, _>(
        async move {
            let mut listener = MultiAccept::new(0).expect("bind");
            // Declared before the first poll of the accept, so it is part of
            // the scenario and not a race with it.
            let arrivals = arrivals.into_iter().map(|arrival| vec![arrival]);
            script.on_multishot_accept(listener.socket().fd(), arrivals);

            let mut connections = Vec::with_capacity(count);
            while connections.len() < count {
                match listener.next().await {
                    Some(Ok(socket)) => {
                        let fd = socket.fd();
                        let transport = PlainMessages::<DstRing, false>::new(socket);
                        let connection = Connection::new(transport, None, Limits::default(), echo);
                        connections.push(spawn(async move {
                            connection.run().await;
                            fd
                        }));
                    }
                    Some(Err(_)) => continue,
                    None => break,
                }
            }
            drop(listener);

            let mut ended = Vec::with_capacity(count);
            for connection in connections {
                ended.push(connection.await);
            }
            ended
        },
        None,
        |run| run(),
    );

    check(&handle, &clients, &ended)?;
    Ok(Report {
        faults: clients.iter().map(|c| c.report.borrow().fault).collect(),
        progress: clients
            .iter()
            .map(|c| (c.report.borrow().done, c.report.borrow().total))
            .collect(),
        bytes: clients
            .iter()
            .map(|c| {
                (
                    handle.reads(c.fd).concat().len(),
                    handle.writes(c.fd).concat().len(),
                )
            })
            .collect(),
        elapsed: handle.clock().expect("virtual time").elapsed(),
    })
}

/// What must hold whatever the seed drew.
fn check(handle: &FakeRingHandle, clients: &[Client], ended: &[i32]) -> Result<(), String> {
    let mut failures = String::new();

    for client in clients {
        let fd = client.fd;
        let report = client.report.borrow();
        if !ended.contains(&fd) {
            let _ = writeln!(failures, "fd {fd}: never served");
        }
        // A wrong answer is a wrong answer, fault or not.
        if let Some(failure) = &report.failure {
            let _ = writeln!(failures, "fd {fd}: {failure}");
        }
        if report.fault.is_some() {
            continue;
        }
        if report.done != report.total {
            let _ = writeln!(
                failures,
                "fd {fd}: healthy, yet played {} of {} steps",
                report.done, report.total
            );
        }
        // Whole frames, with nothing after the answers that a healthy client
        // should not get.
        let written = handle.writes(fd).concat();
        let (frames, covered) = frames(&written);
        if covered != written.len() {
            let _ = writeln!(failures, "fd {fd}: a frame cut short at byte {covered}");
        }
        for frame in frames
            .iter()
            .filter(|f| matches!(f.kind, GOAWAY | RST_STREAM))
        {
            let _ = writeln!(
                failures,
                "fd {fd}: healthy, yet sent frame type {} on stream {}, {}",
                frame.kind,
                frame.stream_id,
                error_code(frame.payload, if frame.kind == GOAWAY { 4 } else { 0 }),
            );
        }
    }
    leftovers(handle, &mut failures);

    match failures.is_empty() {
        true => Ok(()),
        false => Err(failures),
    }
}

#[test]
fn every_client_is_answered_right_or_let_go_cleanly() {
    let (mut runs, mut clients) = (0, 0);
    let mut faults: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut longest = Duration::ZERO;
    explore("server_dst", SEEDS, run, |_, report: Report| {
        runs += 1;
        clients += report.faults.len();
        for fault in &report.faults {
            *faults.entry(kind(*fault)).or_default() += 1;
        }
        longest = longest.max(report.elapsed);
    });
    eprintln!("{runs} seed(s), {clients} clients: {faults:?}; longest run {longest:?} simulated");
    assert_explored(
        &faults,
        &["healthy", "cut in send", "send error", "vanished"],
    );
}

#[test]
fn a_seed_replays_the_same_run() {
    for seed in crate::dst::seeds(SEEDS).take(8) {
        assert_eq!(judge(seed, run), judge(seed, run), "seed {seed}");
    }
}
