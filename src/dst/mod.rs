//! What the deterministic simulations share: drawing a world from a seed, how
//! hostile it is, and a failing seed replayed with the ring's journal on.
//!
//! Each run is on a thread of its own: the buffer ring, the simulated
//! descriptors and the runtime are thread-locals, and a run that panicked
//! leaves them in no state for the next.
//!
//! `DST_SEED=<n>` replays one seed, and `DST_SEEDS=<n>` runs the first `n`
//! (`DST_SEEDS=<a>..<b>` those from `a` to `b`).
//! A failing seed is replayed by itself with the journal on: the whole journal
//! goes to a file, and its end about the connections at fault into the
//! failure. `DST_TRACE=1` keeps the journal of a passing seed too.

pub(crate) mod peer;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::time::Duration;

use slopio::deterministic_testing::{
    FakeRing, FakeRingHandle, Fault, Faults, KernelFaults, open_fds,
};

/// Where a run leaves its ring's handle, to be read even if the run panics.
pub(crate) type Slot = RefCell<Option<FakeRingHandle>>;

/// A simulation: one seed's run, keeping a journal when given a slot.
pub(crate) type Run<R> = fn(u64, Option<&Slot>) -> Result<R, String>;

/// SplitMix64, for drawing the workload. The simulator and each peer draw the
/// world below it from the same seed, on streams of their own.
pub(crate) struct Rng(pub(crate) u64);

impl Rng {
    pub(crate) fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `lo..=hi`.
    pub(crate) fn between(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.next() % (hi - lo + 1)
    }

    /// [`between`](Self::between), for counts and lengths.
    pub(crate) fn upto(&mut self, (lo, hi): (usize, usize)) -> usize {
        self.between(lo as u64, hi as u64) as usize
    }

    /// True one time in `n`.
    pub(crate) fn one_in(&mut self, n: u64) -> bool {
        self.next().is_multiple_of(n)
    }

    pub(crate) fn millis(&mut self, lo: u64, hi: u64) -> Duration {
        Duration::from_millis(self.between(lo, hi))
    }

    /// `odds` on half the seeds, none on the others: one axis of hostility.
    fn axis(&mut self, odds: f64) -> f64 {
        if self.one_in(2) { odds } else { 0.0 }
    }
}

/// How hostile one run is, drawn one axis at a time, so that some runs are
/// calm and others hostile along one axis rather than every run a little of
/// all.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Profile {
    /// Each the chance a peer meets that fault over its whole dialogue: see
    /// [`spread`].
    pub(crate) faults: Faults,
    /// The longest the program waits to learn a send went through.
    pub(crate) write_latency: Option<Duration>,
    /// Odds that a send of the program's is only partly taken.
    pub(crate) short_writes: f64,
    pub(crate) kernel: KernelFaults,
}

pub(crate) fn profile(rng: &mut Rng) -> Profile {
    Profile {
        faults: Faults {
            send_error: rng.axis(0.15),
            cut_in_send: rng.axis(0.15),
            vanish: rng.axis(0.1),
        },
        write_latency: rng.one_in(2).then(|| rng.millis(1, 5)),
        short_writes: rng.axis(0.3),
        kernel: KernelFaults {
            interrupted: rng.axis(0.05),
            ended: rng.axis(0.1),
        },
    }
}

/// Turn odds over a whole dialogue into odds per occasion, so a long dialogue
/// is no likelier to be struck than a short one, only later. A cut can strike
/// each of the peer's sends, a vanishing each step, a failed send each of the
/// program's sends, of which `program_sends` is a guess.
pub(crate) fn spread(faults: Faults, sends: usize, steps: usize, program_sends: usize) -> Faults {
    Faults {
        send_error: faults.send_error / program_sends.max(1) as f64,
        cut_in_send: faults.cut_in_send / sends.max(1) as f64,
        vanish: faults.vanish / steps.max(1) as f64,
    }
}

/// A ring on virtual time, under `profile`'s kernel, keeping a journal and
/// leaving its handle in `journal` if given one.
pub(crate) fn ring(
    seed: u64,
    profile: &Profile,
    journal: Option<&Slot>,
) -> (FakeRing, FakeRingHandle) {
    let builder = FakeRing::builder()
        .seed(seed)
        .virtual_time()
        .kernel_faults(profile.kernel);
    let builder = match journal {
        Some(_) => builder.journal(),
        None => builder,
    };
    let (fake, handle) = builder.build();
    if let Some(slot) = journal {
        *slot.borrow_mut() = Some(handle.clone());
    }
    (fake, handle)
}

/// What a finished run must not leave behind, whatever its seed.
pub(crate) fn leftovers(handle: &FakeRingHandle, failures: &mut String) {
    let open = open_fds();
    if !open.is_empty() {
        let _ = writeln!(failures, "still open: {open:?}");
    }
    let remaining = handle.scenario_remaining();
    if remaining != 0 {
        let _ = writeln!(failures, "{remaining} scripted completion(s) never claimed");
    }
    let inflight = handle.inflight().len();
    if inflight != 0 {
        let _ = writeln!(failures, "{inflight} op(s) still in flight");
    }
}

/// A fault as the tallies name it.
pub(crate) fn kind(fault: Option<Fault>) -> &'static str {
    match fault {
        None => "healthy",
        Some(Fault::Reset) => "reset",
        Some(Fault::CutInSend { .. }) => "cut in send",
        Some(Fault::SendError(_)) => "send error",
        Some(Fault::Vanished) => "vanished",
    }
}

/// Seeds that explore nothing would pass all the same, so a full run says
/// which of `kinds` it never met.
pub(crate) fn assert_explored(tally: &BTreeMap<&'static str, usize>, kinds: &[&str]) {
    if !full_run() {
        return;
    }
    for kind in kinds {
        assert!(tally.contains_key(kind), "no peer was {kind}: {tally:?}");
    }
}

/// Every seed, or only those `DST_SEED` or `DST_SEEDS` (`n`, or `a..b`) ask
/// for.
pub(crate) fn seeds(default: u64) -> std::ops::Range<u64> {
    if let Ok(seed) = std::env::var("DST_SEED") {
        let seed = seed.parse().expect("DST_SEED is a number");
        return seed..seed + 1;
    }
    let Ok(asked) = std::env::var("DST_SEEDS") else {
        return 0..if cfg!(miri) { 4 } else { default };
    };
    let number = |n: &str| n.parse().expect("DST_SEEDS is `n` or `a..b`");
    match asked.split_once("..") {
        Some((from, to)) => number(from)..number(to),
        None => 0..number(&asked),
    }
}

fn full_run() -> bool {
    !cfg!(miri) && std::env::var_os("DST_SEED").is_none() && std::env::var_os("DST_SEEDS").is_none()
}

/// Run every seed, panicking on the first that fails with its journal, and
/// hand each report to `tally`.
pub(crate) fn explore<R: Send + 'static>(
    name: &str,
    default: u64,
    run: Run<R>,
    mut tally: impl FnMut(u64, R),
) {
    for seed in seeds(default) {
        let report = judge(seed, run)
            .unwrap_or_else(|failure| panic!("{}", explain(name, seed, run, &failure)));
        trace_if_asked(name, seed, run);
        tally(seed, report);
    }
}

/// `run` for `seed` on a thread of its own, a panic in it reported as that
/// seed's failure.
pub(crate) fn judge<R: Send + 'static>(seed: u64, run: Run<R>) -> Result<R, String> {
    std::thread::spawn(move || run(seed, None))
        .join()
        .unwrap_or_else(|panic| {
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("a panic with no message");
            Err(message.to_string())
        })
}

/// Replay `seed` with the journal on. The whole journal as text, and its last
/// events about `fds` (about anything, if `fds` is empty).
fn trace<R: 'static>(seed: u64, run: Run<R>, fds: Vec<i32>) -> (String, String) {
    std::thread::spawn(move || {
        let slot = RefCell::new(None);
        // The replay fails as the run did; what matters is what it saw.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(seed, Some(&slot))));
        let handle = slot.into_inner().expect("the replay built its ring");
        let all = handle.journal_text(&[], None).unwrap_or_default();
        let tail = handle.journal_text(&fds, Some(60)).unwrap_or_default();
        (all, tail)
    })
    .join()
    .expect("the tracing thread")
}

/// Write `journal` where `cargo` keeps test scratch files; where it went.
fn keep(name: &str, seed: u64, journal: &str) -> String {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/tmp");
    let path = dir.join(format!("{name}-seed-{seed}.journal"));
    match std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&path, journal)) {
        Ok(()) => path.display().to_string(),
        Err(error) => format!("not written ({error})"),
    }
}

/// A failure, with the journal of its seed replayed: kept whole in a file,
/// and its end about the connections the failure names shown here.
fn explain<R: 'static>(name: &str, seed: u64, run: Run<R>, failure: &str) -> String {
    let fds = fds_in(failure);
    let (all, tail) = trace(seed, run, fds.clone());
    let kept = keep(name, seed, &all);
    let about = match fds.is_empty() {
        true => "the run".to_string(),
        false => format!("fd {fds:?}"),
    };
    format!(
        "seed {seed}:\n{failure}\nreplay with DST_SEED={seed}; whole journal: {kept}\n\
         last events of {about}:\n{tail}"
    )
}

fn trace_if_asked<R: 'static>(name: &str, seed: u64, run: Run<R>) {
    if std::env::var_os("DST_TRACE").is_some() {
        let (all, _) = trace(seed, run, Vec::new());
        eprintln!("seed {seed}: journal in {}", keep(name, seed, &all));
    }
}

/// The descriptors a failure names, as `fd <n>`.
fn fds_in(text: &str) -> Vec<i32> {
    let mut fds: Vec<i32> = text
        .match_indices("fd ")
        .filter_map(|(at, _)| {
            let digits: String = text[at + 3..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().ok()
        })
        .collect();
    fds.sort_unstable();
    fds.dedup();
    fds
}

pub(crate) const DATA: u8 = 0x0;
pub(crate) const HEADERS: u8 = 0x1;
pub(crate) const RST_STREAM: u8 = 0x3;
pub(crate) const SETTINGS: u8 = 0x4;
pub(crate) const PING: u8 = 0x6;
pub(crate) const GOAWAY: u8 = 0x7;
pub(crate) const WINDOW_UPDATE: u8 = 0x8;

pub(crate) const FLAG_END_STREAM: u8 = 0x1;
pub(crate) const FLAG_ACK: u8 = 0x1;
pub(crate) const FLAG_END_HEADERS: u8 = 0x4;

pub(crate) fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

pub(crate) struct Frame<'a> {
    pub(crate) kind: u8,
    pub(crate) flags: u8,
    pub(crate) stream_id: u32,
    pub(crate) payload: &'a [u8],
}

impl Frame<'_> {
    pub(crate) fn ends_stream(&self) -> bool {
        matches!(self.kind, HEADERS | DATA) && self.flags & FLAG_END_STREAM != 0
    }
}

/// The frame `bytes` start with and its length on the wire, once all of it
/// has arrived.
pub(crate) fn frame_at(bytes: &[u8]) -> Option<(Frame<'_>, usize)> {
    let head = bytes.get(..9)?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    let payload = bytes.get(9..9 + len)?;
    let frame = Frame {
        kind: head[3],
        flags: head[4],
        stream_id: u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]),
        payload,
    };
    Some((frame, 9 + len))
}

/// Every whole frame in `bytes`, and how many bytes they cover.
pub(crate) fn frames(bytes: &[u8]) -> (Vec<Frame<'_>>, usize) {
    let mut out = Vec::new();
    let mut at = 0;
    while let Some((frame, len)) = frame_at(&bytes[at..]) {
        out.push(frame);
        at += len;
    }
    (out, at)
}

/// An error code, as RFC 9113 §7 names it.
pub(crate) fn error_code(payload: &[u8], at: usize) -> String {
    let code = payload
        .get(at..at + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    let name = match code {
        Some(0x0) => "NO_ERROR",
        Some(0x1) => "PROTOCOL_ERROR",
        Some(0x2) => "INTERNAL_ERROR",
        Some(0x3) => "FLOW_CONTROL_ERROR",
        Some(0x4) => "SETTINGS_TIMEOUT",
        Some(0x5) => "STREAM_CLOSED",
        Some(0x6) => "FRAME_SIZE_ERROR",
        Some(0x7) => "REFUSED_STREAM",
        Some(0x8) => "CANCEL",
        Some(0x9) => "COMPRESSION_ERROR",
        Some(0xb) => "ENHANCE_YOUR_CALM",
        Some(other) => return format!("error {other:#x}"),
        None => return "a short frame".to_string(),
    };
    name.to_string()
}
