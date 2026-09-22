//! Whether the peer is still there, and what to do when it stops saying so.
//!
//! §6.7 is the whole mechanism: a PING must be echoed, and a connection whose
//! echo never comes is one where the socket is open and the other end is not.
//! That failure is the one TCP hides — a peer that crashed, a NAT that dropped
//! the flow, a cable pulled — and without a probe it surfaces as a request
//! that hangs until the kernel gives up on retransmissions, minutes later.
//!
//! What is counted here is *silence*, not time. Any frame proves the peer is
//! alive, so a busy connection never probes: the answer a PING would fetch has
//! already arrived in the form of a response.
//!
//! Silence is measured on the clock, from the peer's last chunk, and not
//! counted in [`DEADLINE_TICK`]s. A tick is only a tick when nothing else
//! happens for a whole one, and our own writes are something: a count of
//! ticks stopped counting while the application kept sending — so a client
//! writing a request every few seconds to a peer that had gone never asked
//! it, and was left to TCP after all.
//!
//! [`DEADLINE_TICK`]: crate::shared::connection::DEADLINE_TICK

use std::time::SystemTime;

use crate::client::{ACTIVE_PING_TICKS, IDLE_PING_TICKS, PING_TIMEOUT_TICKS};
use crate::shared::connection::DEADLINE_TICK;

/// What the peer's silence asks the loop to do.
pub(super) enum Due {
    /// Nothing yet: the peer's silence is still within its budget.
    Nothing,
    /// Send this PING, and expect it back (§6.7).
    Ping([u8; 8]),
    /// The last probe went unanswered for its whole budget. The connection is
    /// not one requests can be made on, whatever the socket says.
    Unanswered,
}

pub(super) struct Keepalive {
    /// When the peer last sent anything. Any chunk moves it.
    last_heard: SystemTime,
    /// When the outstanding probe went out, if one is outstanding. Only ever
    /// one: a second probe tells us nothing the first has not already asked,
    /// and a peer that answers neither is diagnosed just as well by one.
    probe_sent: Option<SystemTime>,
    /// The opaque of the outstanding probe. §6.7 requires it back byte for
    /// byte, which is what makes an ACK *ours* rather than an answer to
    /// somebody else's question.
    ///
    /// A counter rather than a nonce: the peer is not an adversary here, and
    /// what this has to survive is a stale ACK from a probe we have already
    /// given up on, which a value that never repeats settles.
    probes_sent: u64,
}

impl Keepalive {
    /// A connection that has just heard from its peer — the handshake is
    /// what establishes it.
    pub(super) fn new(now: SystemTime) -> Self {
        Self {
            last_heard: now,
            probe_sent: None,
            probes_sent: 0,
        }
    }

    /// The peer said something. Whatever it was, it came from an end that is
    /// alive and a path that still carries — which is everything a PING was
    /// going to establish, so the outstanding probe is dropped along with the
    /// silence.
    pub(super) fn heard(&mut self, now: SystemTime) {
        self.last_heard = now;
        self.probe_sent = None;
    }

    /// §6.7: an ACK came back. Ours only if it carries the opaque we sent —
    /// a peer is free to send PINGs of its own, and their ACKs are its
    /// business.
    ///
    /// Mostly redundant beside [`heard`](Self::heard), which any frame
    /// including this one reaches first. It is here because "the probe was
    /// answered" and "something arrived" are different facts, and a future
    /// that measures round-trip time will want the one this checks.
    pub(super) fn acknowledged(&mut self, opaque: [u8; 8]) {
        if self.probe_sent.is_some() && opaque == self.probes_sent.to_be_bytes() {
            self.probe_sent = None;
        }
    }

    /// What the silence up to `now` calls for. Asked on every turn of the
    /// loop, whatever woke it: the answer depends on the clock and on what
    /// the peer last sent, not on how many turns there were.
    ///
    /// `in_flight` is whether any stream is open, which is what picks the
    /// budget: a connection with a request on it is one whose peer is expected
    /// to be doing something, and the strict timeouts are the ones that apply
    /// to it.
    ///
    /// Clocks that step backwards floor at zero, so an adjustment cannot end
    /// a connection.
    pub(super) fn due(&mut self, now: SystemTime, in_flight: bool) -> Due {
        let since = |then: SystemTime| now.duration_since(then).unwrap_or_default();

        if let Some(sent) = self.probe_sent {
            return match since(sent) >= DEADLINE_TICK * PING_TIMEOUT_TICKS {
                true => Due::Unanswered,
                false => Due::Nothing,
            };
        }

        let budget = match in_flight {
            true => ACTIVE_PING_TICKS,
            false => IDLE_PING_TICKS,
        };
        if since(self.last_heard) < DEADLINE_TICK * budget {
            return Due::Nothing;
        }

        self.probes_sent += 1;
        self.probe_sent = Some(now);
        Due::Ping(self.probes_sent.to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// An arbitrary start, so the arithmetic below reads as offsets from it.
    fn start() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000)
    }

    fn ticks(n: u32) -> Duration {
        DEADLINE_TICK * n
    }

    #[test]
    fn silence_under_the_budget_is_left_alone() {
        let mut keepalive = Keepalive::new(start());
        let just_under = start() + ticks(ACTIVE_PING_TICKS) - Duration::from_millis(1);
        assert!(matches!(keepalive.due(just_under, true), Due::Nothing));
    }

    /// A probe goes out at the budget, and only one: the turns that follow
    /// wait for the answer rather than asking again.
    #[test]
    fn one_probe_goes_out_and_then_the_wait_begins() {
        let mut keepalive = Keepalive::new(start());
        let asked = start() + ticks(ACTIVE_PING_TICKS);
        assert!(matches!(keepalive.due(asked, true), Due::Ping(_)));

        let just_under = asked + ticks(PING_TIMEOUT_TICKS) - Duration::from_millis(1);
        assert!(matches!(keepalive.due(just_under, true), Due::Nothing));
        assert!(matches!(
            keepalive.due(asked + ticks(PING_TIMEOUT_TICKS), true),
            Due::Unanswered
        ));
    }

    /// How often the loop asks has nothing to do with it. A loop woken over
    /// and over by our own writes asks many times a tick, and the silence it
    /// measures is the same silence: this is the case a count of ticks got
    /// wrong, since those wakes kept a whole tick from ever passing.
    #[test]
    fn asking_often_does_not_reset_the_silence() {
        let mut keepalive = Keepalive::new(start());
        let mut now = start();
        let mut probed = false;
        // A turn every second, for as long as the budget and then some.
        for _ in 0..=ACTIVE_PING_TICKS * 5 {
            now += Duration::from_secs(1);
            probed |= matches!(keepalive.due(now, true), Due::Ping(_));
        }
        assert!(probed, "the peer's silence was asked about");
    }

    /// An idle connection is probed on the longer budget, which is what keeps
    /// a client holding connections for reuse from looking like a flood.
    #[test]
    fn an_idle_connection_waits_longer() {
        let mut keepalive = Keepalive::new(start());
        assert!(matches!(
            keepalive.due(start() + ticks(ACTIVE_PING_TICKS), false),
            Due::Nothing
        ));
        assert!(matches!(
            keepalive.due(start() + ticks(IDLE_PING_TICKS), false),
            Due::Ping(_)
        ));
    }

    /// Anything from the peer settles the question a probe was asking. The
    /// silence that follows may well earn a probe of its own — what it must
    /// not do is inherit the abandoned one's remaining budget.
    #[test]
    fn a_frame_from_the_peer_cancels_the_probe() {
        let mut keepalive = Keepalive::new(start());
        let asked = start() + ticks(ACTIVE_PING_TICKS);
        assert!(matches!(keepalive.due(asked, true), Due::Ping(_)));

        keepalive.heard(asked + Duration::from_secs(1));
        assert!(!matches!(
            keepalive.due(asked + ticks(PING_TIMEOUT_TICKS), true),
            Due::Unanswered
        ));
    }

    /// §6.7: the opaque is what makes an ACK an answer to *our* probe.
    #[test]
    fn an_ack_that_is_not_ours_answers_nothing() {
        let asked = start() + ticks(ACTIVE_PING_TICKS);
        let gave_up = asked + ticks(PING_TIMEOUT_TICKS);

        let mut keepalive = Keepalive::new(start());
        let Due::Ping(opaque) = keepalive.due(asked, true) else {
            panic!("a probe went out");
        };
        keepalive.acknowledged(*b"someones");
        assert!(matches!(keepalive.due(gave_up, true), Due::Unanswered));

        // And the one we did send is the one that counts: the probe is
        // answered, so the turns that follow can ask again but cannot give up.
        let mut keepalive = Keepalive::new(start());
        assert!(matches!(keepalive.due(asked, true), Due::Ping(_)));
        keepalive.acknowledged(opaque);
        assert!(!matches!(keepalive.due(gave_up, true), Due::Unanswered));
    }
}
