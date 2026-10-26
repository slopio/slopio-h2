//! The client against a server that speaks HTTP/2 back: it credits what it
//! reads, answers PINGs, changes its settings, and goes away.
//!
//! Each seed draws, one axis at a time:
//!
//! - **pressure**: the server's initial window small and its credit late and
//!   in batches, its connection window left at 64 KiB, bodies of hundreds of
//!   KiB, the initial window changed with uploads in flight (§6.9.2), and
//!   answers past the client's own stream window to an application that
//!   reads slowly;
//! - **cancellation**: the application dropping a stream before its body, or
//!   partway through reading its answer;
//! - **GOAWAY**: the server going away after a drawn request, answering only
//!   up to the last stream it took, then closing.
//!
//! What must hold whatever the seed: no DATA past a window and no frame the
//! server cannot parse; nothing on a stream after the client reset it; every
//! request answered with its own body, unless it was cancelled, or past the
//! GOAWAY (then failed, never answered); the connection's loop ends; nothing
//! is left open, owed or in flight.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;
use std::rc::Rc;
use std::time::Duration;

use runtime_core::deterministic_testing::{
    Actor, ActorCx, FakeRingHandle, ReadReply, WriteReply, simulated_socket,
};
use runtime_core::runtime::RuntimeInner;
use runtime_core::runtime::time::timeout;

use super::Driver;
use crate::client::{CONNECT_TIMEOUT, Connection, PlainText, Stream};
use crate::dst::peer::{CREDIT, Credit, INITIAL_WINDOW_SIZE, In, MAX_CONCURRENT_STREAMS, Wire};
use crate::dst::{Rng, Slot, explore, judge, leftovers, profile, ring};
use crate::shared::transport::PlainMessages;

runtime_core::define_buf_ring!(
    PeerRing,
    bgid = 0,
    buffer_size = 1024,
    ring_size = 32,
    pool_size = 128
);

const SEEDS: u64 = 128;

/// Static table entry 8.
const STATUS_200: &[u8] = &[0x88];

/// §7.
const NO_ERROR: u32 = 0x0;

/// How long the application waits on anything: far past the client's own
/// deadlines, so that it is the client that gives up, never this.
const PATIENCE: Duration = Duration::from_secs(600);

/// Bytes that say which stream they belong to and where in it, so an answer
/// handed to the wrong request cannot pass.
fn marked(id: u32, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| ((i as u64 * 31 + u64::from(id) * 17) % 251) as u8)
        .collect()
}

/// Where the application drops a stream.
#[derive(Debug, Clone, Copy)]
enum Cancel {
    /// Before sending its body or reading anything.
    Opened,
    /// Once this much of its answer has been read.
    Reading(usize),
}

#[derive(Debug, Clone, Copy)]
struct Ask {
    /// `None` for a GET.
    body: Option<usize>,
    answer: usize,
    cancel: Option<Cancel>,
    /// Read with a pause after each piece.
    slow: bool,
}

/// What became of one request, as the application saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// Its own body, in full.
    Answered,
    /// Status or body not what was sent.
    Wrong(String),
    Cancelled,
    /// Refused, failed or abandoned.
    Failed,
}

#[derive(Debug, Default)]
struct Report {
    /// The GOAWAY the server sent: its last stream.
    goaway: Option<u32>,
    /// Streams the client reset.
    reset: BTreeSet<u32>,
    failure: Option<String>,
}

/// A server that answers each request once it has all of it, as the plan
/// says, and goes away when told to.
struct Server {
    wire: Wire,
    /// What each stream asked for, in the order the application opens them.
    asks: HashMap<u32, Ask>,
    /// Body bytes received, by stream.
    received: HashMap<u32, usize>,
    /// After this many requests have opened, GOAWAY.
    goaway_after: Option<usize>,
    opened: usize,
    highest: u32,
    /// Streams up to the GOAWAY's last still owed an answer.
    owed: BTreeSet<u32>,
    change: Option<(usize, u32)>,
    total: usize,
    report: Rc<RefCell<Report>>,
}

impl Server {
    fn going_away(&self) -> Option<u32> {
        self.report.borrow().goaway
    }

    fn respond(&mut self, id: u32, cx: &mut ActorCx) {
        if self.going_away().is_some_and(|last| id > last) {
            return;
        }
        let Some(ask) = self.asks.get(&id).copied() else {
            self.wire.fail(format!("stream {id} was never asked"));
            return;
        };
        let received = self.received.get(&id).copied().unwrap_or(0);
        if Some(received) != ask.body.or(Some(0)) {
            let why = format!(
                "stream {id} sent {received} bytes of body, not {:?}",
                ask.body
            );
            self.wire.fail(why);
            return;
        }
        self.wire.headers(id, STATUS_200, ask.answer == 0);
        if ask.answer > 0 {
            self.wire.body(id, marked(id, ask.answer), true, cx);
        }
        self.owed.remove(&id);
    }

    /// Once every stream it took is answered and sent, a server going away
    /// closes.
    fn maybe_close(&mut self) {
        let sent = self.owed.is_empty() && self.owed_unsent() == 0;
        if self.going_away().is_some() && sent {
            self.wire.closed = true;
        }
    }

    fn owed_unsent(&self) -> usize {
        let last = self.going_away().unwrap_or(0);
        (1..=last).step_by(2).map(|id| self.wire.unsent(id)).sum()
    }

    fn handle(&mut self, events: Vec<In>, cx: &mut ActorCx) {
        for event in events {
            if !matches!(event, In::Data { .. }) {
                cx.note(|| format!("{event:?}"));
            }
            match event {
                In::Headers {
                    id,
                    end,
                    method,
                    path,
                    ..
                } => {
                    let Some(ask) = self.asks.get(&id).copied() else {
                        self.wire
                            .fail(format!("stream {id} opened, which was never asked"));
                        continue;
                    };
                    let want = if ask.body.is_some() { "POST" } else { "GET" };
                    if method.as_deref() != Some(want) || path.as_deref() != Some("/") {
                        let why = format!("stream {id}: {method:?} {path:?}, not {want} /");
                        self.wire.fail(why);
                        continue;
                    }
                    self.opened += 1;
                    self.highest = self.highest.max(id);
                    if self.going_away().is_none() {
                        self.owed.insert(id);
                    }
                    if self.goaway_after.is_some_and(|after| self.opened >= after)
                        && self.going_away().is_none()
                    {
                        self.wire.goaway(self.highest, NO_ERROR);
                        self.report.borrow_mut().goaway = Some(self.highest);
                    }
                    if end {
                        self.respond(id, cx);
                    }
                }
                In::Data { id, payload, end } => {
                    if self.report.borrow().reset.contains(&id) {
                        self.wire
                            .fail(format!("DATA on stream {id} after the client reset it"));
                        continue;
                    }
                    self.total += payload.len();
                    *self.received.entry(id).or_default() += payload.len();
                    if let Some((at, initial)) = self.change
                        && self.total >= at
                    {
                        self.change = None;
                        self.wire.settings(&[(INITIAL_WINDOW_SIZE, initial)]);
                    }
                    if end {
                        self.respond(id, cx);
                    }
                }
                In::Reset { id, .. } => {
                    self.report.borrow_mut().reset.insert(id);
                    self.owed.remove(&id);
                }
                // The client's farewell.
                In::GoAway { .. } => self.wire.closed = true,
            }
        }
        self.maybe_close();
    }

    fn settle(&mut self) {
        if let Some(failure) = &self.wire.failure {
            self.report
                .borrow_mut()
                .failure
                .get_or_insert(failure.clone());
        }
    }
}

impl Actor for Server {
    fn on_open(&mut self, cx: &mut ActorCx) {
        cx.note(|| {
            format!(
                "plan: recv {:?}, credit {:?}, change {:?}, goaway after {:?}",
                self.wire.recv, self.wire.credit, self.change, self.goaway_after
            )
        });
    }

    fn read(&mut self, max: usize, cx: &mut ActorCx) -> ReadReply {
        self.wire.read(max, cx)
    }

    fn write(&mut self, bytes: &[u8], cx: &mut ActorCx) -> WriteReply {
        let reply = self.wire.accept(bytes, cx);
        let events = self.wire.take(cx);
        self.handle(events, cx);
        self.settle();
        reply
    }

    fn on_timer(&mut self, tag: u64, cx: &mut ActorCx) {
        if tag == CREDIT {
            self.wire.on_credit(cx);
        }
        self.maybe_close();
        self.settle();
    }
}

/// One request, as the application makes it.
async fn ask(conn: Rc<Connection<PlainText>>, ask: Ask, id: u32) -> Outcome {
    let request = match ask.body {
        None => http::Request::get("http://example.test/"),
        Some(_) => http::Request::post("http://example.test/"),
    };
    let request = request.body(()).expect("a request");
    let Ok(stream) = conn.send_request(&request, ask.body.is_none()) else {
        return Outcome::Failed;
    };
    if matches!(ask.cancel, Some(Cancel::Opened)) {
        return Outcome::Cancelled;
    }
    if let Some(len) = ask.body
        && stream.write(&vec![b'x'; len], true).await.is_err()
    {
        return Outcome::Failed;
    }
    match timeout(PATIENCE, read(&stream, ask, id)).await {
        Ok(Ok(outcome)) => outcome,
        Ok(Err(_)) | Err(()) => Outcome::Failed,
    }
}

async fn read(stream: &Stream, ask: Ask, id: u32) -> std::io::Result<Outcome> {
    let head = stream.response().await?;
    if head.status() != http::StatusCode::OK {
        return Ok(Outcome::Wrong(format!("status {}", head.status())));
    }
    let mut body = Vec::new();
    while let Some(chunk) = stream.read().await? {
        body.extend_from_slice(&chunk);
        if let Some(Cancel::Reading(at)) = ask.cancel
            && body.len() >= at
            && body.len() < ask.answer
        {
            return Ok(Outcome::Cancelled);
        }
        if ask.slow {
            let _ = timeout(Duration::from_millis(2), std::future::pending::<()>()).await;
        }
    }
    Ok(match body == marked(id, ask.answer) {
        true => Outcome::Answered,
        false => Outcome::Wrong(format!("{} bytes, not the {} sent", body.len(), ask.answer)),
    })
}

/// Each round's requests opened at once, then read back; then close.
async fn app(
    conn: Connection<PlainText>,
    rounds: Vec<Vec<(u32, Ask)>>,
) -> (Vec<Outcome>, Option<Result<(), String>>) {
    let conn = Rc::new(conn);
    let mut outcomes = Vec::new();
    for round in rounds {
        let tasks: Vec<_> = round
            .into_iter()
            .map(|(id, a)| runtime_core::runtime::spawn(ask(conn.clone(), a, id)))
            .collect();
        for task in tasks {
            outcomes.push(task.await);
        }
    }
    conn.close();
    let ended = timeout(PATIENCE, conn.closed())
        .await
        .ok()
        .map(|r| r.map_err(|e| e.to_string()));
    (outcomes, ended)
}

#[derive(Debug, PartialEq, Eq)]
struct Summary {
    outcomes: Vec<Outcome>,
    goaway: Option<u32>,
    ended: Option<Result<(), String>>,
    elapsed: Duration,
}

fn run(seed: u64, journal: Option<&Slot>) -> Result<Summary, String> {
    let mut rng = Rng(seed);
    let profile = profile(&mut rng);
    let (fake, handle) = ring(seed, &profile, journal);
    let pressure = rng.one_in(2);
    let cancels = rng.one_in(2);
    let goaway = rng.one_in(2);

    let (body, answer) = match pressure {
        true => (131_072, 262_144),
        false => (20_000, 20_000),
    };
    let mut rounds = Vec::new();
    let mut asks = HashMap::new();
    let mut id = 1;
    for _ in 0..rng.upto((1, 3)) {
        let mut round = Vec::new();
        for _ in 0..rng.upto((1, 4)) {
            // Past the client's 1 MiB stream window, now and then.
            let answer = match pressure && rng.one_in(8) {
                true => rng.upto((1 << 20, 3 << 19)),
                false => rng.upto((0, answer)),
            };
            let a = Ask {
                body: rng.one_in(2).then(|| rng.upto((1, body))),
                answer,
                cancel: (cancels && rng.one_in(4)).then(|| match rng.one_in(3) {
                    true => Cancel::Opened,
                    false => Cancel::Reading(rng.upto((0, answer))),
                }),
                slow: pressure && rng.one_in(4),
            };
            asks.insert(id, a);
            round.push((id, a));
            id += 2;
        }
        rounds.push(round);
    }
    let total = asks.len();

    let initial = match pressure {
        true => rng.between(1024, 65_535) as u32,
        false => 1 << 20,
    };
    let credit = match pressure {
        true => Credit {
            delay: (0, 20),
            batch: rng.between(1, u64::from(initial / 2)) as u32,
        },
        false => Credit {
            delay: (0, 0),
            batch: 1,
        },
    };
    let short_writes = if rng.one_in(3) { 0.3 } else { 0.0 };
    let mut wire = Wire::new(true, credit).hostile(short_writes, profile.write_latency);
    wire.settings(&[
        (MAX_CONCURRENT_STREAMS, 100),
        (INITIAL_WINDOW_SIZE, initial),
    ]);
    if !pressure || rng.one_in(2) {
        wire.widen(1 << 30);
    }
    let report = Rc::new(RefCell::new(Report::default()));
    let server = Server {
        wire,
        asks,
        received: HashMap::new(),
        goaway_after: goaway.then(|| rng.upto((1, total))),
        opened: 0,
        highest: 0,
        owed: BTreeSet::new(),
        change: (pressure && rng.one_in(2))
            .then(|| (rng.upto((0, 200_000)), rng.between(1024, 1 << 20) as u32)),
        total: 0,
        report: report.clone(),
    };

    let socket = simulated_socket();
    let fd = socket.fd();
    handle.attach(fd, server);

    let plan = rounds.clone();
    let (outcomes, ended) = RuntimeInner::simulated(fake).block_on::<PeerRing, _>(
        async move {
            runtime_core::runtime::spawn(async move {
                let transport = PlainMessages::<PeerRing, false>::new(socket);
                match timeout(CONNECT_TIMEOUT, Driver::handshake(transport)).await {
                    Ok(Ok(driver)) => app(driver.spawn(), rounds).await,
                    Ok(Err(e)) => (Vec::new(), Some(Err(e.to_string()))),
                    Err(()) => (Vec::new(), Some(Err("no handshake".into()))),
                }
            })
            .await
        },
        None,
        |run| run(),
    );

    let plan: Vec<(u32, Ask)> = plan.into_iter().flatten().collect();
    check(&handle, fd, &report.borrow(), &plan, &outcomes, &ended)?;
    let goaway = report.borrow().goaway;
    Ok(Summary {
        outcomes,
        goaway,
        ended,
        elapsed: handle.clock().expect("virtual time").elapsed(),
    })
}

fn check(
    handle: &FakeRingHandle,
    fd: i32,
    report: &Report,
    plan: &[(u32, Ask)],
    outcomes: &[Outcome],
    ended: &Option<Result<(), String>>,
) -> Result<(), String> {
    let mut failures = String::new();
    if let Some(failure) = &report.failure {
        let _ = writeln!(failures, "fd {fd}: {failure}");
    }
    if outcomes.len() != plan.len() {
        let _ = writeln!(
            failures,
            "fd {fd}: {} of {} requests played",
            outcomes.len(),
            plan.len()
        );
    }
    for ((id, ask), outcome) in plan.iter().zip(outcomes) {
        let past = report.goaway.is_some_and(|last| *id > last);
        let fits = match outcome {
            Outcome::Answered => !past,
            Outcome::Cancelled => ask.cancel.is_some(),
            Outcome::Failed => report.goaway.is_some(),
            Outcome::Wrong(_) => false,
        };
        if !fits {
            let _ = writeln!(failures, "fd {fd}: stream {id} {outcome:?}, asked {ask:?}");
        }
    }
    match (ended, report.goaway) {
        (None, _) => {
            let _ = writeln!(failures, "fd {fd}: the connection's loop never ended");
        }
        (Some(Err(error)), None) => {
            let _ = writeln!(failures, "fd {fd}: the loop ended with {error}");
        }
        _ => {}
    }
    leftovers(handle, &mut failures);
    match failures.is_empty() {
        true => Ok(()),
        false => Err(failures),
    }
}

#[test]
fn every_request_is_answered_cancelled_or_refused_as_it_should() {
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    let mut runs = 0;
    explore("client_dst_peer", SEEDS, run, |_, summary: Summary| {
        runs += 1;
        for outcome in &summary.outcomes {
            let name = format!("{outcome:?}");
            *tally
                .entry(name.split('(').next().unwrap_or_default().to_owned())
                .or_default() += 1;
        }
        *tally.entry("goaway".into()).or_default() += usize::from(summary.goaway.is_some());
    });
    eprintln!("{runs} seed(s): {tally:?}");
    if crate::dst::seeds(SEEDS) == (0..SEEDS) && !cfg!(miri) {
        for kind in ["Answered", "Cancelled", "Failed", "goaway"] {
            assert!(
                tally.contains_key(kind),
                "no request ever {kind}: {tally:?}"
            );
        }
    }
}

#[test]
fn a_seed_replays_the_same_run() {
    for seed in crate::dst::seeds(SEEDS).take(8) {
        assert_eq!(judge(seed, run), judge(seed, run), "seed {seed}");
    }
}
