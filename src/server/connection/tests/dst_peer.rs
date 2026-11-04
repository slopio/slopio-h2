//! The server against clients that speak HTTP/2 back: they credit what they
//! read, answer PINGs, cancel streams, and react to a GOAWAY.
//!
//! Each seed draws, one axis at a time:
//!
//! - **pressure**: small initial windows, credit given late and in batches,
//!   a connection window left at its 64 KiB, bodies and answers of hundreds
//!   of KiB, and the initial window changed while streams are open, below
//!   zero included (§6.9.2);
//! - **cancellation**: streams reset with CANCEL during their head, their
//!   body, or their answer;
//! - **metering**: a client crediting one answer a byte at a time, which the
//!   server must reset rather than serve for ever;
//! - **shutdown**: the server stopped at a drawn moment, as `Server` does,
//!   with clients in the middle of their rounds.
//!
//! What must hold whatever the seed: no DATA past a window, no frame a client
//! cannot parse; every stream answered in full with its own body, unless it
//! was cancelled, metered (then reset), or past the GOAWAY's last stream
//! (then never processed); every handler ends; every connection ends; nothing
//! is left open, owed or in flight.

use slopio::http;
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::fmt::Write as _;
use std::pin::pin;
use std::rc::Rc;
use std::time::Duration;

use slopio::deterministic_testing::{
    AcceptEvent, Actor, ActorCx, FakeRingHandle, FdKind, ReadReply, Scripted, WriteReply, mint,
};
use slopio::io_driver::operations::sockets::multi_accept::MultiAccept;
use slopio::runtime::time::{Sleep, timeout};
use slopio::runtime::{RuntimeInner, spawn};
use slopio::streams::StreamExt;

use crate::dst::peer::{
    CANCEL, CREDIT, Credit, INITIAL_WINDOW_SIZE, In, PREFACE as CLIENT_PREFACE, Wire, block,
};
use crate::dst::{Rng, Slot, error_code, explore, frames, judge, leftovers, profile, ring};
use crate::server::connection::Connection;
use crate::server::limits::DRAIN_GRACE;
use crate::server::shutdown::Shutdown;
use crate::server::{Limits, Stream, serve_plain};
use crate::shared::transport::PlainMessages;

slopio::define_buf_ring!(
    PeerRing,
    bgid = 0,
    buffer_size = 1024,
    ring_size = 32,
    pool_size = 128
);

const SEEDS: u64 = 128;

/// `:method GET` and `:method POST`, then `:scheme http`; the path follows.
const GET: &[u8] = &[0x82, 0x86];
const POST: &[u8] = &[0x83, 0x86];

/// §7.
const NO_ERROR: u32 = 0x0;

/// The peer's own timer, for the pause between rounds.
const ROUND: u64 = 1;

/// What the handler answers a request for `n` bytes whose body was
/// `received`: the count on a line, then `n` bytes that say where they sit.
fn answer(n: usize, received: usize) -> Vec<u8> {
    let mut out = format!("{received}\n").into_bytes();
    out.extend((0..n).map(|i| ((i * 7 + n) % 251) as u8));
    out
}

/// Each handler that started, and whether it ended, by its request's tag.
type Handlers = Rc<RefCell<HashMap<String, bool>>>;

/// Marks its handler ended when dropped, however it went.
struct Ending(Handlers, String);

impl Drop for Ending {
    fn drop(&mut self) {
        self.0
            .borrow_mut()
            .insert(std::mem::take(&mut self.1), true);
    }
}

/// Reads the whole body, then answers as [`answer`] says, a frame's worth at
/// a time.
async fn serve(stream: Stream, handlers: Handlers) {
    let path = stream.path().unwrap_or_default().to_owned();
    handlers.borrow_mut().insert(path.clone(), false);
    let _ending = Ending(handlers, path.clone());

    let n: usize = path
        .split('/')
        .nth(1)
        .and_then(|n| n.parse().ok())
        .unwrap_or(0);
    let received = if stream.body_is_oneshot() {
        stream.body(usize::MAX).await.map_or(0, |body| body.len())
    } else {
        let mut total = 0;
        while stream.readable().await {
            let taken = stream.peek(|bytes| bytes.len());
            stream.consume(taken);
            total += taken;
        }
        total
    };
    stream.write_headers(http::StatusCode::OK, &http::HeaderMap::new());
    let body = answer(n, received);
    let (body, last) = body.split_at(body.len().saturating_sub(16_384));
    for chunk in body.chunks(16_384) {
        stream.write_data(chunk).await;
    }
    stream.write_data_final(last).await;
}

/// Where a stream is cancelled.
#[derive(Debug, Clone, Copy)]
enum Cancel {
    /// Right after its HEADERS.
    Head,
    /// Once this much of its body has gone.
    Body(usize),
    /// Once this much of its answer has come.
    Answer(usize),
}

#[derive(Debug, Clone, Copy)]
struct Ask {
    /// How long an answer to ask for.
    n: usize,
    body: usize,
    cancel: Option<Cancel>,
    /// Credited a byte at a time.
    metered: bool,
}

/// What became of one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Open,
    Answered,
    Cancelled,
    /// Past the GOAWAY's last stream.
    Refused,
    /// Reset by the server, with this code.
    Reset(u32),
}

#[derive(Debug, Default)]
struct Report {
    /// By stream id: what was asked, and what became of it.
    streams: BTreeMap<u32, (Ask, Outcome)>,
    goaway: Option<(u32, u32)>,
    failure: Option<String>,
    /// Every round played, and the connection closed.
    finished: bool,
    /// Anything at all came from the server.
    heard: bool,
    /// The server closed the connection.
    closed: bool,
    /// The connection was accepted at all.
    opened: bool,
}

/// A client that plays rounds of requests, each round once the last is
/// answered, and speaks the rest of HTTP/2 as it goes.
struct Client {
    wire: Wire,
    tag: usize,
    rounds: VecDeque<(Vec<Ask>, Duration)>,
    next_id: u32,
    /// The current round's streams still open, and what has come back on each.
    live: BTreeMap<u32, (Ask, Option<Vec<u8>>)>,
    /// After this many bytes of answers, the initial window becomes this.
    change: Option<(usize, u32)>,
    received: usize,
    goaway: Option<u32>,
    /// A round is being opened: a stream cancelled as it opens must not end
    /// the round before the rest of it is open.
    opening: bool,
    report: Rc<RefCell<Report>>,
}

impl Client {
    fn outcome(&self, id: u32, outcome: Outcome) {
        if let Some(entry) = self.report.borrow_mut().streams.get_mut(&id) {
            entry.1 = outcome;
        }
    }

    fn fail(&mut self, why: String) {
        self.wire.fail(why);
    }

    fn start_round(&mut self, cx: &mut ActorCx) {
        let round = match self.goaway {
            None => self.rounds.pop_front(),
            // §6.8: nothing new once the server is going away.
            Some(_) => None,
        };
        let Some((asks, _)) = round else {
            self.wire.closed = true;
            self.report.borrow_mut().finished = true;
            return;
        };
        self.opening = true;
        for ask in asks {
            let id = self.next_id;
            self.next_id += 2;
            let path = format!("/{}/{}-{id}", ask.n, self.tag);
            let head = if ask.body == 0 { GET } else { POST };
            self.wire
                .headers(id, &block(head, Some(&path)), ask.body == 0);
            if ask.metered {
                self.wire.metered.insert(id);
            }
            self.report
                .borrow_mut()
                .streams
                .insert(id, (ask, Outcome::Open));
            self.live.insert(id, (ask, None));
            if ask.body > 0 {
                self.wire.body(id, vec![b'x'; ask.body], true, cx);
            }
            if matches!(ask.cancel, Some(Cancel::Head)) {
                self.cancel(id, cx);
            }
        }
        self.opening = false;
        self.round_over(cx);
    }

    fn cancel(&mut self, id: u32, cx: &mut ActorCx) {
        self.wire.reset(id, CANCEL);
        self.live.remove(&id);
        self.outcome(id, Outcome::Cancelled);
        self.round_over(cx);
    }

    /// Cancel the streams whose body has gone far enough.
    fn cancel_sent(&mut self, cx: &mut ActorCx) {
        let due: Vec<u32> = self
            .live
            .iter()
            .filter(|(id, (ask, _))| match ask.cancel {
                Some(Cancel::Body(at)) => ask.body - self.wire.unsent(**id) >= at,
                _ => false,
            })
            .map(|(id, _)| *id)
            .collect();
        for id in due {
            self.cancel(id, cx);
        }
    }

    /// Once the round's last stream is done, the next round, after its pause.
    fn round_over(&mut self, cx: &mut ActorCx) {
        if self.opening || !self.live.is_empty() || self.wire.closed {
            return;
        }
        match self.rounds.front() {
            Some((_, pause)) if self.goaway.is_none() && !pause.is_zero() => {
                cx.timer(*pause, ROUND);
            }
            _ => self.start_round(cx),
        }
    }

    fn handle(&mut self, events: Vec<In>, cx: &mut ActorCx) {
        for event in events {
            if !matches!(event, In::Data { .. }) {
                cx.note(|| format!("{event:?}"));
            }
            match event {
                In::Headers {
                    id, end, status, ..
                } => {
                    let Some((ask, got)) = self.live.get_mut(&id) else {
                        self.stray(id, "HEADERS");
                        continue;
                    };
                    if status != Some(200) || got.is_some() {
                        let why = format!("stream {id}: a head with status {status:?}");
                        self.fail(why);
                        continue;
                    }
                    *got = Some(Vec::new());
                    if end {
                        let ask = *ask;
                        self.complete(id, ask, Vec::new(), cx);
                    }
                }
                In::Data { id, payload, end } => {
                    self.received += payload.len();
                    if let Some((at, initial)) = self.change
                        && self.received >= at
                    {
                        self.change = None;
                        self.wire.settings(&[(INITIAL_WINDOW_SIZE, initial)]);
                    }
                    let Some((ask, got)) = self.live.get_mut(&id) else {
                        self.stray(id, "DATA");
                        continue;
                    };
                    let ask = *ask;
                    let Some(body) = got else {
                        self.fail(format!("stream {id}: DATA before its head"));
                        continue;
                    };
                    body.extend_from_slice(&payload);
                    if end {
                        let body = std::mem::take(body);
                        self.complete(id, ask, body, cx);
                    } else if let Some(Cancel::Answer(at)) = ask.cancel
                        && body.len() >= at
                    {
                        self.cancel(id, cx);
                    }
                }
                In::Reset { id, code } => {
                    if self.live.remove(&id).is_some() {
                        self.outcome(id, Outcome::Reset(code));
                        self.round_over(cx);
                    }
                }
                In::GoAway { last, code } => {
                    self.goaway = Some(last);
                    self.report.borrow_mut().goaway = Some((last, code));
                    let refused: Vec<u32> =
                        self.live.range(last + 1..).map(|(id, _)| *id).collect();
                    for id in refused {
                        self.live.remove(&id);
                        self.wire.reset(id, CANCEL);
                        self.outcome(id, Outcome::Refused);
                    }
                    self.round_over(cx);
                }
            }
        }
    }

    /// A frame on a stream no longer live: fine on one we cancelled, which
    /// the server may not have read yet; wrong anywhere else.
    fn stray(&mut self, id: u32, kind: &str) {
        let outcome = self
            .report
            .borrow()
            .streams
            .get(&id)
            .map(|(_, o)| o.clone());
        match outcome {
            Some(Outcome::Cancelled) | Some(Outcome::Reset(_)) => {}
            other => self.fail(format!("stream {id}: {kind} when it was {other:?}")),
        }
    }

    fn complete(&mut self, id: u32, ask: Ask, body: Vec<u8>, cx: &mut ActorCx) {
        self.live.remove(&id);
        if body != answer(ask.n, ask.body) {
            let why = format!(
                "stream {id}: {} bytes of answer, not the {} asked",
                body.len(),
                answer(ask.n, ask.body).len()
            );
            self.fail(why);
            return;
        }
        self.outcome(id, Outcome::Answered);
        self.round_over(cx);
    }

    fn settle(&mut self, cx: &mut ActorCx) {
        self.cancel_sent(cx);
        if let Some(failure) = &self.wire.failure {
            self.report
                .borrow_mut()
                .failure
                .get_or_insert(failure.clone());
        }
    }
}

impl Actor for Client {
    fn on_open(&mut self, cx: &mut ActorCx) {
        cx.note(|| {
            format!(
                "plan: recv {:?}, credit {:?}, change {:?}, rounds {:?}",
                self.wire.recv, self.wire.credit, self.change, self.rounds
            )
        });
        self.report.borrow_mut().opened = true;
        self.start_round(cx);
        self.settle(cx);
    }

    fn read(&mut self, max: usize, cx: &mut ActorCx) -> ReadReply {
        self.wire.read(max, cx)
    }

    fn write(&mut self, bytes: &[u8], cx: &mut ActorCx) -> WriteReply {
        self.report.borrow_mut().heard = true;
        let reply = self.wire.accept(bytes, cx);
        let events = self.wire.take(cx);
        self.handle(events, cx);
        self.settle(cx);
        reply
    }

    fn on_closed(&mut self, _: &mut ActorCx) {
        self.report.borrow_mut().closed = true;
    }

    fn on_timer(&mut self, tag: u64, cx: &mut ActorCx) {
        match tag {
            CREDIT => self.wire.on_credit(cx),
            _ => self.start_round(cx),
        }
        self.settle(cx);
    }
}

/// How one client is drawn.
fn client(
    rng: &mut Rng,
    tag: usize,
    pressure: bool,
    cancels: bool,
    metered: bool,
) -> (Client, Rc<RefCell<Report>>) {
    let short_writes = if rng.one_in(3) { 0.3 } else { 0.0 };
    let latency = rng.one_in(3).then(|| rng.millis(1, 5));
    let initial = match (metered, pressure) {
        (true, _) => 4096,
        (false, true) => rng.between(1024, 65_535) as u32,
        (false, false) => 1 << 20,
    };
    let credit = match (metered, pressure) {
        (true, _) => Credit {
            delay: (100, 100),
            batch: 1,
        },
        (false, true) => Credit {
            delay: (0, 20),
            batch: rng.between(1, u64::from(initial / 2)) as u32,
        },
        (false, false) => Credit {
            delay: (0, 0),
            batch: 1,
        },
    };
    let (body, n) = match pressure {
        true => (131_072, 262_144),
        false => (20_000, 20_000),
    };

    let mut rounds = VecDeque::new();
    for _ in 0..rng.upto((1, 3)) {
        let asks: Vec<Ask> = (0..rng.upto((1, 4)))
            .map(|_| {
                let body = if rng.one_in(2) {
                    rng.upto((1, body))
                } else {
                    0
                };
                let cancel = (cancels && rng.one_in(4)).then(|| match rng.between(0, 2) {
                    0 => Cancel::Head,
                    1 => Cancel::Body(rng.upto((0, body))),
                    _ => Cancel::Answer(rng.upto((0, n))),
                });
                Ask {
                    n: rng.upto((0, n)),
                    body,
                    cancel,
                    metered: false,
                }
            })
            .collect();
        rounds.push_back((asks, rng.millis(0, 30)));
    }
    if metered && let Some((asks, _)) = rounds.front_mut() {
        asks.push(Ask {
            n: 65_536,
            body: 0,
            cancel: None,
            metered: true,
        });
    }

    let mut wire = Wire::new(false, credit).hostile(short_writes, latency);
    wire.raw(CLIENT_PREFACE);
    wire.settings(&[(INITIAL_WINDOW_SIZE, initial)]);
    // Under pressure, half the clients leave the connection window at its
    // 64 KiB, so it is the connection's credit that runs out.
    if !pressure || rng.one_in(2) {
        wire.widen(1 << 30);
    }
    // Not on a metered client: a raised window would let its answer through.
    let change = (pressure && !metered && rng.one_in(2))
        .then(|| (rng.upto((0, 200_000)), rng.between(1024, 1 << 20) as u32));

    let report = Rc::new(RefCell::new(Report::default()));
    let peer = Client {
        wire,
        tag,
        rounds,
        next_id: 1,
        live: BTreeMap::new(),
        change,
        received: 0,
        goaway: None,
        opening: false,
        report: report.clone(),
    };
    (peer, report)
}

/// One seed's draw, kept for the checks.
struct World {
    reports: Vec<(i32, Rc<RefCell<Report>>)>,
    stop: Option<Duration>,
    handlers: Handlers,
}

#[derive(Debug, PartialEq, Eq)]
struct Summary {
    outcomes: Vec<Vec<Outcome>>,
    goaways: usize,
    drained: Option<Duration>,
    elapsed: Duration,
}

fn run(seed: u64, journal: Option<&Slot>) -> Result<Summary, String> {
    let mut rng = Rng(seed);
    let profile = profile(&mut rng);
    let (fake, handle) = ring(seed, &profile, journal);
    let pressure = rng.one_in(2);
    let cancels = rng.one_in(2);
    let metering = rng.one_in(4);
    let shutdown = rng.one_in(2);

    let mut reports = Vec::new();
    let mut arrivals: Vec<Scripted> = Vec::new();
    let mut last_arrival = Duration::ZERO;
    for tag in 0..rng.upto((1, 4)) {
        let (peer, report) = client(&mut rng, tag, pressure, cancels, metering && tag == 0);
        let fd = mint(FdKind::Socket);
        handle.attach(fd, peer);
        // Each arrival counts from the one before it.
        let gap = rng.millis(0, 10);
        last_arrival += gap;
        arrivals.push(AcceptEvent::On(fd).after(gap));
        reports.push((fd, report));
    }
    // Past the last arrival by more than the timewheel's 10 ms tick, which
    // a sleep may end early by.
    let stop = shutdown.then(|| last_arrival + rng.millis(20, 120));
    let handlers: Handlers = Rc::default();
    let world = World {
        reports,
        stop,
        handlers: handlers.clone(),
    };
    let count = world.reports.len();

    let script = handle.clone();
    let drained = RuntimeInner::simulated(fake).block_on::<PeerRing, _>(
        async move {
            let listener = MultiAccept::new(0).expect("bind");
            let arrivals = arrivals.into_iter().map(|arrival| vec![arrival]);
            script.on_multishot_accept(listener.socket().fd(), arrivals);
            let handler = move |stream: Stream| serve(stream, handlers.clone());
            let limits = Limits::default();
            match stop {
                // As `Server::run_until` does.
                Some(at) => {
                    let shutdown = Rc::new(Shutdown::default());
                    let stop = pin!(Sleep::during(at));
                    let _ = serve_plain::<PeerRing, false, _, _>(
                        listener, limits, handler, &shutdown, stop,
                    )
                    .await;
                    let stopped = slopio::runtime::now();
                    shutdown.begin(limits.drain_timeout);
                    let _ = timeout(limits.drain_timeout + DRAIN_GRACE, shutdown.emptied()).await;
                    Some(
                        slopio::runtime::now()
                            .duration_since(stopped)
                            .unwrap_or_default(),
                    )
                }
                None => {
                    serve_all(listener, count, limits, handler).await;
                    None
                }
            }
        },
        None,
        |run| run(),
    );

    check(&handle, &world, drained)?;
    Ok(Summary {
        outcomes: world
            .reports
            .iter()
            .map(|(_, r)| {
                r.borrow()
                    .streams
                    .values()
                    .map(|(_, o)| o.clone())
                    .collect()
            })
            .collect(),
        goaways: world
            .reports
            .iter()
            .filter(|(_, r)| r.borrow().goaway.is_some())
            .count(),
        drained,
        elapsed: handle.clock().expect("virtual time").elapsed(),
    })
}

/// Accept `count` connections and serve each to its end.
async fn serve_all<H: crate::server::Handler>(
    mut listener: MultiAccept,
    count: usize,
    limits: Limits,
    handler: H,
) {
    let mut connections = Vec::with_capacity(count);
    while connections.len() < count {
        match listener.next().await {
            Some(Ok(socket)) => {
                let transport = PlainMessages::<PeerRing, false>::new(socket);
                let connection = Connection::new(transport, None, limits, handler.clone());
                connections.push(spawn(connection.run()));
            }
            Some(Err(_)) => continue,
            None => break,
        }
    }
    drop(listener);
    for connection in connections {
        connection.await;
    }
}

fn check(handle: &FakeRingHandle, world: &World, drained: Option<Duration>) -> Result<(), String> {
    let mut failures = String::new();
    for (tag, (fd, report)) in world.reports.iter().enumerate() {
        let report = report.borrow();
        if let Some(failure) = &report.failure {
            let _ = writeln!(failures, "fd {fd}: {failure}");
        }
        // Accepted as the server stopped and closed unread, as one still in
        // the listener's backlog would be, or never accepted: nothing of it
        // may have run.
        if world.stop.is_some() && (!report.opened || report.closed && !report.heard) {
            let prefix = format!("-{tag}-");
            let ran = world.handlers.borrow().keys().any(|path| {
                path.rsplit('/')
                    .next()
                    .is_some_and(|t| format!("-{t}").starts_with(&prefix))
            });
            if ran {
                let _ = writeln!(failures, "fd {fd}: turned away, yet a handler of its ran");
            }
            continue;
        }
        let last = report.goaway.map(|(last, _)| last);
        if let Some((_, code)) = report.goaway
            && code != NO_ERROR
        {
            let _ = writeln!(failures, "fd {fd}: GOAWAY with error {code:#x}");
        }
        if report.goaway.is_some() && world.stop.is_none() {
            let _ = writeln!(failures, "fd {fd}: a GOAWAY from a server not stopping");
        }
        if !report.finished && report.goaway.is_none() {
            let _ = writeln!(failures, "fd {fd}: never played to its end");
        }
        for (id, (ask, outcome)) in &report.streams {
            let fits = match outcome {
                Outcome::Answered => !ask.metered,
                Outcome::Cancelled => ask.cancel.is_some(),
                Outcome::Refused => last.is_some_and(|last| *id > last),
                // Metered past the floor; or cut at the drain's deadline.
                Outcome::Reset(_) => ask.metered || world.stop.is_some(),
                Outcome::Open => false,
            };
            if !fits {
                let _ = writeln!(failures, "fd {fd}: stream {id} {outcome:?}, asked {ask:?}");
                let _ = writeln!(
                    failures,
                    "  the server's last frames: {}",
                    tail(handle, *fd)
                );
            }
        }
    }
    // Past the last stream it took, the server must not have started anything.
    let handlers = world.handlers.borrow();
    for (path, ended) in handlers.iter() {
        if !ended {
            let _ = writeln!(failures, "handler for {path} never ended");
        }
        let tagged = path.rsplit('/').next().and_then(|t| t.split_once('-'));
        if let Some((tag, id)) = tagged
            && let (Ok(tag), Ok(id)) = (tag.parse::<usize>(), id.parse::<u32>())
            && let Some((_, report)) = world.reports.get(tag)
            && let Some((last, _)) = report.borrow().goaway
            && id > last
        {
            let _ = writeln!(failures, "handler for {path} ran past the GOAWAY's {last}");
        }
    }
    if let Some(drained) = drained {
        let limit = Limits::default().drain_timeout + DRAIN_GRACE;
        if drained > limit {
            let _ = writeln!(failures, "the drain took {drained:?}, past {limit:?}");
        }
    }
    leftovers(handle, &mut failures);
    match failures.is_empty() {
        true => Ok(()),
        false => Err(failures),
    }
}

/// The last frames the server wrote on `fd`, DATA left out.
fn tail(handle: &FakeRingHandle, fd: i32) -> String {
    let written = handle.writes(fd).concat();
    let (frames, _) = frames(&written);
    let named: Vec<String> = frames
        .iter()
        .filter(|f| f.kind != crate::dst::DATA)
        .map(|f| match f.kind {
            crate::dst::GOAWAY => format!(
                "GOAWAY({}, {})",
                u32::from_be_bytes(f.payload[..4].try_into().unwrap_or_default()),
                error_code(f.payload, 4)
            ),
            crate::dst::RST_STREAM => {
                format!("RST_STREAM({}, {})", f.stream_id, error_code(f.payload, 0))
            }
            kind => format!("{kind}/{:#x}@{}", f.flags, f.stream_id),
        })
        .collect();
    named[named.len().saturating_sub(12)..].join(" ")
}

#[test]
fn every_stream_is_answered_cancelled_reset_or_refused_as_it_should() {
    let mut tally: BTreeMap<String, usize> = BTreeMap::new();
    let mut runs = 0;
    explore("server_dst_peer", SEEDS, run, |_, summary: Summary| {
        runs += 1;
        for outcome in summary.outcomes.iter().flatten() {
            let name = format!("{outcome:?}");
            *tally
                .entry(name.split('(').next().unwrap_or_default().to_owned())
                .or_default() += 1;
        }
        *tally.entry("goaway".into()).or_default() += summary.goaways;
    });
    eprintln!("{runs} seed(s): {tally:?}");
    if crate::dst::seeds(SEEDS) == (0..SEEDS) && !cfg!(miri) {
        for kind in ["Answered", "Cancelled", "Refused", "Reset", "goaway"] {
            assert!(tally.contains_key(kind), "no stream ever {kind}: {tally:?}");
        }
    }
}

#[test]
fn a_seed_replays_the_same_run() {
    for seed in crate::dst::seeds(SEEDS).take(8) {
        assert_eq!(judge(seed, run), judge(seed, run), "seed {seed}");
    }
}
