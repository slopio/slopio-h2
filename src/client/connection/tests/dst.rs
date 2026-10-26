//! The client under a server drawn from a seed.
//!
//! No scenario here is written by hand. Each seed draws what the application
//! asks: after the handshake, a few rounds of GETs and POSTs, each round
//! opened all at once and read back before the next. The server is a
//! [`Dialogue`] peer: it reads the client's frames however its writes were
//! split, checks each request on its stream, and only then answers, the
//! answers' frames interleaved and grouped into sends of the seed's choosing.
//! What it sends reaches the client in pieces of any size, a single byte
//! included. At the end the application closes, and the server expects the
//! client's GOAWAY.
//!
//! Each seed also draws how hostile the server is, one axis at a time: one
//! that resets in the middle of a send, vanishes, or makes a send of the
//! client's fail; sends taken only in part or drained slowly; a kernel that
//! interrupts or ends the multishot read on its own.
//!
//! What must hold whatever the seed: against a healthy server every request
//! is answered with its own body and the connection ends cleanly; no request
//! is ever handed a body that is not its own, fault or not; the client's
//! frames are never wrong; the connection's loop always ends, against a
//! vanished server on its keepalive; nothing is left open, owed or in flight.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;
use std::time::Duration;

use runtime_core::deterministic_testing::{
    Check, Dialogue, DialogueReport, FakeRingHandle, Fault, simulated_socket,
};
use runtime_core::runtime::RuntimeInner;
use runtime_core::runtime::time::timeout;

use super::Driver;
use crate::client::{CONNECT_TIMEOUT, Connection, PlainText};
use crate::dst::{
    DATA, FLAG_ACK, FLAG_END_HEADERS, FLAG_END_STREAM, GOAWAY, HEADERS, PING, Profile, RST_STREAM,
    Rng, SETTINGS, Slot, WINDOW_UPDATE, assert_explored, error_code, explore, frame, frame_at,
    judge, kind, leftovers, profile, ring, spread,
};
use crate::shared::codec::frames::CLIENT_PREFACE;
use crate::shared::transport::PlainMessages;

// Small buffers, so a frame spans many completions; a pool past the ring, so
// the reserve is in play.
runtime_core::define_buf_ring!(
    DstRing,
    bgid = 0,
    buffer_size = 512,
    ring_size = 16,
    pool_size = 64
);

const SEEDS: u64 = 512;

/// Inclusive ranges.
const ROUNDS: (usize, usize) = (1, 4);
const REQUESTS: (usize, usize) = (1, 4);
const BODY: (usize, usize) = (0, 20_000);
/// §4.2: SETTINGS_MAX_FRAME_SIZE's initial value.
const DATA_FRAME: (usize, usize) = (1, 16_384);

/// How long the application waits on anything. Far past every deadline of
/// the client's own, so it is the client that gives up, never this.
const PATIENCE: Duration = Duration::from_secs(600);

/// Static table entry 8.
const STATUS_200: &[u8] = &[0x88];

/// What the application asks, and what the server answers it.
#[derive(Clone)]
struct Ask {
    /// `None` for a GET.
    body: Option<usize>,
    answer: Vec<u8>,
}

/// Bytes that say which stream they belong to, and where in it, so an answer
/// handed to the wrong request cannot pass.
fn marked(id: u32, len: usize) -> Vec<u8> {
    (0..len)
        .map(|offset| Rng((u64::from(id) << 32) | offset as u64).next() as u8)
        .collect()
}

/// The server's half of the handshake: its SETTINGS, room on the connection
/// for every body this run sends, and the ACK of the client's SETTINGS.
fn server_opening() -> Vec<u8> {
    // SETTINGS_MAX_CONCURRENT_STREAMS = 100.
    let mut bytes = frame(SETTINGS, 0, 0, &[0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);
    bytes.extend(frame(WINDOW_UPDATE, 0, 0, &(1u32 << 30).to_be_bytes()));
    bytes.extend(frame(SETTINGS, FLAG_ACK, 0, &[]));
    bytes
}

/// §3.4: the preface, then SETTINGS.
fn client_opening(got: &[u8]) -> Check {
    let n = got.len().min(CLIENT_PREFACE.len());
    if got[..n] != CLIENT_PREFACE[..n] {
        return Check::Fail("not the client preface".into());
    }
    if n < CLIENT_PREFACE.len() {
        return Check::More;
    }
    match frame_at(&got[n..]) {
        None => Check::More,
        Some((frame, len)) if frame.kind == SETTINGS && frame.flags & FLAG_ACK == 0 => {
            Check::Pass(n + len)
        }
        Some((frame, _)) => Check::Fail(format!("frame type {} after the preface", frame.kind)),
    }
}

/// A frame no step waits for, which needs no answer from this server.
fn aside(kind: u8) -> bool {
    matches!(kind, SETTINGS | WINDOW_UPDATE | PING)
}

/// Every stream in `want` opened (§5.1.1: in order) and ended, a GET's on its
/// HEADERS, a POST's after a body of the length asked.
fn requests(want: Vec<(u32, Option<usize>)>) -> impl FnMut(&[u8]) -> Check {
    move |got| {
        let mut bodies: Vec<Option<usize>> = vec![None; want.len()];
        let mut opened = 0;
        let mut left = want.len();
        let mut at = 0;
        while let Some((frame, len)) = frame_at(&got[at..]) {
            at += len;
            match frame.kind {
                kind if aside(kind) => continue,
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
            let (id, body) = want[i];
            match (&mut bodies[i], frame.kind) {
                (None, HEADERS) if i == opened => {
                    opened += 1;
                    bodies[i] = Some(0);
                }
                (None, HEADERS) => return Check::Fail(format!("stream {id} opened out of order")),
                (Some(len), DATA) => *len += frame.payload.len(),
                (_, kind) => {
                    return Check::Fail(format!("frame type {kind} out of place on stream {id}"));
                }
            }
            if frame.ends_stream() {
                let sent = bodies[i].filter(|_| frame.kind == DATA);
                if sent != body {
                    return Check::Fail(format!(
                        "stream {id} ended with {sent:?} bytes of body, not {body:?}"
                    ));
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

/// The client's farewell (§6.8), once the application has closed.
fn farewell(got: &[u8]) -> Check {
    let mut at = 0;
    while let Some((frame, len)) = frame_at(&got[at..]) {
        at += len;
        match frame.kind {
            kind if aside(kind) => {}
            GOAWAY if error_code(frame.payload, 4) == "NO_ERROR" => return Check::Pass(at),
            GOAWAY => return Check::Fail(format!("GOAWAY {}", error_code(frame.payload, 4))),
            other => return Check::Fail(format!("frame type {other} instead of a GOAWAY")),
        }
    }
    Check::More
}

/// The client acknowledging the server's SETTINGS, the last of the
/// handshake.
fn settings_ack(got: &[u8]) -> Check {
    let mut at = 0;
    while let Some((frame, len)) = frame_at(&got[at..]) {
        at += len;
        match frame.kind {
            SETTINGS if frame.flags & FLAG_ACK != 0 => return Check::Pass(at),
            WINDOW_UPDATE => {}
            other => return Check::Fail(format!("frame type {other} before the SETTINGS ACK")),
        }
    }
    Check::More
}

/// One answer's frames: HEADERS, then its body in DATA frames.
fn answer(rng: &mut Rng, id: u32, body: &[u8]) -> VecDeque<Vec<u8>> {
    if body.is_empty() {
        let flags = FLAG_END_HEADERS | FLAG_END_STREAM;
        return VecDeque::from([frame(HEADERS, flags, id, STATUS_200)]);
    }
    let mut frames = VecDeque::from([frame(HEADERS, FLAG_END_HEADERS, id, STATUS_200)]);
    let mut at = 0;
    while at < body.len() {
        let end = (at + rng.upto(DATA_FRAME)).min(body.len());
        let flags = if end == body.len() {
            FLAG_END_STREAM
        } else {
            0
        };
        frames.push_back(frame(DATA, flags, id, &body[at..end]));
        at = end;
    }
    frames
}

/// A round's answers, in any order and interleaved, grouped into sends of the
/// seed's choosing.
fn answers(
    rng: &mut Rng,
    mut answers: Vec<VecDeque<Vec<u8>>>,
    mut dialogue: Dialogue,
) -> (Dialogue, usize) {
    let mut sends = 0;
    let mut pending = Vec::new();
    loop {
        let ready: Vec<usize> = (0..answers.len())
            .filter(|&i| !answers[i].is_empty())
            .collect();
        if ready.is_empty() {
            break;
        }
        let i = ready[rng.upto((0, ready.len() - 1))];
        pending.extend(answers[i].pop_front().expect("a frame"));
        if rng.one_in(2) {
            dialogue = dialogue.send(std::mem::take(&mut pending));
            sends += 1;
            // Not after the last: see `draw`.
            let more = answers.iter().any(|frames| !frames.is_empty());
            if more && rng.one_in(4) {
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

/// The application's rounds, and the server that answers them.
fn draw(rng: &mut Rng, profile: Profile) -> (Vec<Vec<Ask>>, Dialogue) {
    let mut dialogue = Dialogue::new()
        .expect("the client's preface and SETTINGS", client_opening)
        .send(server_opening());
    let (mut sends, mut steps) = (1, 2);

    let mut rounds = Vec::new();
    let mut id = 1;
    for round in 0..rng.upto(ROUNDS) {
        // Between rounds only: once the client has closed, nothing the server
        // still had to play can happen.
        if round > 0 && rng.one_in(2) {
            dialogue = dialogue.wait(rng.millis(0, 5));
            steps += 1;
        }
        let mut asks = Vec::new();
        let mut want = Vec::new();
        let mut frames = Vec::new();
        for _ in 0..rng.upto(REQUESTS) {
            let body = rng.one_in(2).then(|| rng.upto(BODY));
            let answer_body = marked(id, rng.upto(BODY));
            frames.push(answer(rng, id, &answer_body));
            want.push((id, body));
            asks.push(Ask {
                body,
                answer: answer_body,
            });
            id += 2;
        }
        dialogue = dialogue.expect(format!("{} request(s)", want.len()), requests(want));
        let sent;
        (dialogue, sent) = answers(rng, frames, dialogue);
        sends += sent;
        steps += 2 * sent + 1;
        rounds.push(asks);
    }
    let mut dialogue = dialogue
        .expect("the client's GOAWAY", farewell)
        .close()
        .faults(spread(profile.faults, sends, steps + 2, rounds.len() + 2))
        .short_writes(profile.short_writes);
    if let Some(max) = profile.write_latency {
        dialogue = dialogue.write_latency(Duration::ZERO, max);
    }
    (rounds, dialogue)
}

/// What became of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Answered {
        status: u16,
        body: Vec<u8>,
    },
    /// Refused, failed or abandoned: the connection was gone.
    Failed,
}

/// What became of the application's run.
#[derive(Debug, PartialEq, Eq)]
struct Played {
    handshake: bool,
    outcomes: Vec<Vec<Outcome>>,
    /// What the connection's loop returned, if it ended.
    ended: Option<Result<(), String>>,
}

async fn ask(conn: &Connection<PlainText>, ask: &Ask) -> Result<crate::client::Stream, ()> {
    let request = match ask.body {
        None => http::Request::get("http://example.test/"),
        Some(_) => http::Request::post("http://example.test/"),
    };
    let request = request.body(()).expect("a request");
    let stream = conn
        .send_request(&request, ask.body.is_none())
        .map_err(drop)?;
    if let Some(len) = ask.body {
        stream.write(&vec![b'x'; len], true).await.map_err(drop)?;
    }
    Ok(stream)
}

async fn read(stream: &crate::client::Stream) -> std::io::Result<Outcome> {
    let head = stream.response().await?;
    let mut body = Vec::new();
    while let Some(chunk) = stream.read().await? {
        body.extend_from_slice(&chunk);
    }
    Ok(Outcome::Answered {
        status: head.status().as_u16(),
        body,
    })
}

/// The application: each round opened at once and read back, then close.
async fn app(
    conn: Connection<PlainText>,
    rounds: Vec<Vec<Ask>>,
) -> (Vec<Vec<Outcome>>, Option<Result<(), String>>) {
    let mut outcomes = Vec::new();
    for round in rounds {
        let mut streams = Vec::new();
        for request in &round {
            streams.push(ask(&conn, request).await);
        }
        let mut answered = Vec::new();
        for stream in streams {
            let outcome = match stream {
                Ok(stream) => match timeout(PATIENCE, read(&stream)).await {
                    Ok(Ok(outcome)) => outcome,
                    Ok(Err(_)) | Err(()) => Outcome::Failed,
                },
                Err(()) => Outcome::Failed,
            };
            answered.push(outcome);
        }
        outcomes.push(answered);
    }
    conn.close();
    let ended = timeout(PATIENCE, conn.closed())
        .await
        .ok()
        .map(|r| r.map_err(|e| e.to_string()));
    (outcomes, ended)
}

/// What one run produced, for the tallies and the replay check.
#[derive(Debug, PartialEq, Eq)]
struct Report {
    fault: Option<Fault>,
    played: Played,
    /// Steps the server played, of how many.
    progress: (usize, usize),
    elapsed: Duration,
}

/// One connection, to the server `seed` draws.
fn run(seed: u64, journal: Option<&Slot>) -> Result<Report, String> {
    let mut rng = Rng(seed);
    let profile = profile(&mut rng);
    let (fake, handle) = ring(seed, &profile, journal);
    let (rounds, server) = draw(&mut rng, profile);
    let (server, report) = server.build();

    let socket = simulated_socket();
    let fd = socket.fd();
    handle.attach(fd, server);

    let wanted = rounds.clone();
    let played = RuntimeInner::simulated(fake).block_on::<DstRing, _>(
        async move {
            runtime_core::runtime::spawn(async move {
                let transport = PlainMessages::<DstRing, false>::new(socket);
                // As `connect` does.
                match timeout(CONNECT_TIMEOUT, Driver::handshake(transport)).await {
                    Ok(Ok(driver)) => {
                        let (outcomes, ended) = app(driver.spawn(), rounds).await;
                        Played {
                            handshake: true,
                            outcomes,
                            ended,
                        }
                    }
                    Ok(Err(_)) | Err(()) => Played {
                        handshake: false,
                        outcomes: Vec::new(),
                        ended: Some(Err("no handshake".into())),
                    },
                }
            })
            .await
        },
        None,
        |run| run(),
    );

    let report = report.borrow().clone();
    check(&handle, fd, &report, &wanted, &played)?;
    Ok(Report {
        fault: report.fault,
        played,
        progress: (report.done, report.total),
        elapsed: handle.clock().expect("virtual time").elapsed(),
    })
}

/// What must hold whatever the seed drew.
fn check(
    handle: &FakeRingHandle,
    fd: i32,
    report: &DialogueReport,
    wanted: &[Vec<Ask>],
    played: &Played,
) -> Result<(), String> {
    let mut failures = String::new();

    // A wrong frame is a wrong frame, fault or not.
    if let Some(failure) = &report.failure {
        let _ = writeln!(failures, "fd {fd}: {failure}");
    }
    for (round, (asks, outcomes)) in wanted.iter().zip(&played.outcomes).enumerate() {
        for (i, (ask, outcome)) in asks.iter().zip(outcomes).enumerate() {
            let healthy = report.fault.is_none();
            match outcome {
                Outcome::Answered { status: 200, body } if *body == ask.answer => {}
                Outcome::Failed if !healthy => {}
                Outcome::Failed => {
                    let _ = writeln!(failures, "fd {fd}: round {round}, request {i} failed");
                }
                Outcome::Answered { status, body } => {
                    let _ = writeln!(
                        failures,
                        "fd {fd}: round {round}, request {i} answered {status} with {} bytes, \
                         not 200 with {}",
                        body.len(),
                        ask.answer.len(),
                    );
                }
            }
        }
    }
    match (&played.ended, report.fault) {
        (None, _) => {
            let _ = writeln!(failures, "fd {fd}: the connection's loop never ended");
        }
        (Some(Err(error)), None) => {
            let _ = writeln!(
                failures,
                "fd {fd}: healthy, yet the loop ended with {error}"
            );
        }
        (Some(_), _) => {}
    }
    if report.fault.is_none() && report.done != report.total {
        let _ = writeln!(
            failures,
            "fd {fd}: healthy, yet the server played {} of {} steps",
            report.done, report.total
        );
    }
    leftovers(handle, &mut failures);

    match failures.is_empty() {
        true => Ok(()),
        false => Err(failures),
    }
}

#[test]
fn every_request_is_answered_right_or_failed_cleanly() {
    let (mut runs, mut requests, mut answered) = (0, 0, 0);
    let mut faults: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut longest = Duration::ZERO;
    explore("client_dst", SEEDS, run, |_, report: Report| {
        runs += 1;
        *faults.entry(kind(report.fault)).or_default() += 1;
        for outcome in report.played.outcomes.iter().flatten() {
            requests += 1;
            answered += usize::from(matches!(outcome, Outcome::Answered { .. }));
        }
        longest = longest.max(report.elapsed);
    });
    eprintln!(
        "{runs} seed(s), {requests} requests, {answered} answered: {faults:?}; \
         longest run {longest:?} simulated"
    );
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

/// Seed 62's world, written down: a server that stops reading in the middle
/// of a request body. The send that fills its buffer must not hold the loop
/// for ever; past `FLUSH_TIMEOUT` the connection is given up on.
#[test]
fn a_server_that_stops_reading_does_not_hold_the_connection() {
    let (fake, handle) = runtime_core::deterministic_testing::FakeRing::builder()
        .virtual_time()
        .build();
    let (server, report) = Dialogue::new()
        .expect("the client's preface and SETTINGS", client_opening)
        .send(server_opening())
        // Once the handshake is over: a vanished peer delivers nothing, not
        // even what it sent before.
        .expect("the client's SETTINGS ACK", settings_ack)
        .vanish()
        .build();
    let socket = simulated_socket();
    let fd = socket.fd();
    handle.attach(fd, server);

    let (answered, ended, took) = RuntimeInner::simulated(fake).block_on::<DstRing, _>(
        async move {
            runtime_core::runtime::spawn(async move {
                let transport = PlainMessages::<DstRing, false>::new(socket);
                let conn = Driver::handshake(transport)
                    .await
                    .expect("a handshake")
                    .spawn();
                let started = runtime_core::runtime::now();
                // Past any room the vanished server leaves, inside its window.
                let asked = Ask {
                    body: Some(60_000),
                    answer: Vec::new(),
                };
                let answered = match ask(&conn, &asked).await {
                    Ok(stream) => timeout(PATIENCE, read(&stream))
                        .await
                        .ok()
                        .map(|r| r.is_ok()),
                    Err(()) => Some(false),
                };
                let ended = timeout(PATIENCE, conn.closed()).await.ok();
                let took = runtime_core::runtime::now()
                    .duration_since(started)
                    .unwrap_or_default();
                (answered, ended.map(|r| r.is_ok()), took)
            })
            .await
        },
        None,
        |run| run(),
    );

    assert_eq!(report.borrow().fault, Some(Fault::Vanished));
    assert_eq!(answered, Some(false), "the request fails rather than hangs");
    assert_eq!(ended, Some(false), "the loop ends, on an error");
    assert!(
        took < crate::client::FLUSH_TIMEOUT * 2,
        "given up on within a flush's deadline, not {took:?}"
    );
    let mut failures = String::new();
    leftovers(&handle, &mut failures);
    assert!(failures.is_empty(), "{failures}");
}
