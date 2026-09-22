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
//! already arrived in the form of a response. Silence is counted in
//! [`DEADLINE_TICK`]s rather than measured, because the loop already wakes on
//! that tick and the runtime keeps a store for exactly that duration.
//!
//! [`DEADLINE_TICK`]: crate::shared::connection::DEADLINE_TICK

use crate::client::{ACTIVE_PING_TICKS, IDLE_PING_TICKS, PING_TIMEOUT_TICKS};

/// What a tick of silence asks the loop to do.
pub(super) enum Due {
    /// Nothing yet: the peer's silence is still within its budget.
    Nothing,
    /// Send this PING, and expect it back (§6.7).
    Ping([u8; 8]),
    /// The last probe went unanswered for its whole budget. The connection is
    /// not one requests can be made on, whatever the socket says.
    Unanswered,
}

#[derive(Default)]
pub(super) struct Keepalive {
    /// Ticks in a row with nothing from the peer. Any chunk resets it, so this
    /// counts silence and not time.
    silent_ticks: u32,
    /// Ticks the outstanding probe has waited, if one is outstanding. Only ever
    /// one: a second probe tells us nothing the first has not already asked,
    /// and a peer that answers neither is diagnosed just as well by one.
    waited_ticks: Option<u32>,
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
    /// The peer said something. Whatever it was, it came from an end that is
    /// alive and a path that still carries — which is everything a PING was
    /// going to establish, so the outstanding probe is dropped along with the
    /// silence.
    pub(super) fn heard(&mut self) {
        self.silent_ticks = 0;
        self.waited_ticks = None;
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
        if self.waited_ticks.is_some() && opaque == self.probes_sent.to_be_bytes() {
            self.waited_ticks = None;
        }
    }

    /// One [`DEADLINE_TICK`](crate::shared::connection::DEADLINE_TICK) passed
    /// with nothing from the peer.
    ///
    /// `in_flight` is whether any stream is open, which is what picks the
    /// budget: a connection with a request on it is one whose peer is expected
    /// to be doing something, and the strict timeouts are the ones that apply
    /// to it.
    pub(super) fn tick(&mut self, in_flight: bool) -> Due {
        self.silent_ticks += 1;

        if let Some(waited) = &mut self.waited_ticks {
            *waited += 1;
            if *waited >= PING_TIMEOUT_TICKS {
                return Due::Unanswered;
            }
            return Due::Nothing;
        }

        let budget = match in_flight {
            true => ACTIVE_PING_TICKS,
            false => IDLE_PING_TICKS,
        };
        if self.silent_ticks < budget {
            return Due::Nothing;
        }

        self.probes_sent += 1;
        self.waited_ticks = Some(0);
        Due::Ping(self.probes_sent.to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_under_the_budget_is_left_alone() {
        let mut keepalive = Keepalive::default();
        for _ in 0..ACTIVE_PING_TICKS - 1 {
            assert!(matches!(keepalive.tick(true), Due::Nothing));
        }
    }

    /// A probe goes out at the budget, and only one: the ticks that follow
    /// wait for the answer rather than asking again.
    #[test]
    fn one_probe_goes_out_and_then_the_wait_begins() {
        let mut keepalive = Keepalive::default();
        for _ in 0..ACTIVE_PING_TICKS - 1 {
            assert!(matches!(keepalive.tick(true), Due::Nothing));
        }
        assert!(matches!(keepalive.tick(true), Due::Ping(_)));
        for _ in 0..PING_TIMEOUT_TICKS - 1 {
            assert!(matches!(keepalive.tick(true), Due::Nothing));
        }
        assert!(matches!(keepalive.tick(true), Due::Unanswered));
    }

    /// An idle connection is probed on the longer budget, which is what keeps
    /// a client holding connections for reuse from looking like a flood.
    #[test]
    fn an_idle_connection_waits_longer() {
        let mut keepalive = Keepalive::default();
        for _ in 0..IDLE_PING_TICKS - 1 {
            assert!(matches!(keepalive.tick(false), Due::Nothing));
        }
        assert!(matches!(keepalive.tick(false), Due::Ping(_)));
    }

    /// Anything from the peer settles the question a probe was asking. The
    /// silence that follows may well earn a probe of its own — what it must
    /// not do is inherit the abandoned one's remaining budget.
    #[test]
    fn a_frame_from_the_peer_cancels_the_probe() {
        let mut keepalive = Keepalive::default();
        for _ in 0..ACTIVE_PING_TICKS {
            keepalive.tick(true);
        }
        keepalive.heard();
        for _ in 0..PING_TIMEOUT_TICKS {
            assert!(!matches!(keepalive.tick(true), Due::Unanswered));
        }
    }

    /// §6.7: the opaque is what makes an ACK an answer to *our* probe.
    #[test]
    fn an_ack_that_is_not_ours_answers_nothing() {
        let mut keepalive = Keepalive::default();
        for _ in 0..ACTIVE_PING_TICKS - 1 {
            keepalive.tick(true);
        }
        let Due::Ping(opaque) = keepalive.tick(true) else {
            panic!("a probe went out");
        };

        keepalive.acknowledged(*b"someones");
        for _ in 0..PING_TIMEOUT_TICKS - 1 {
            assert!(matches!(keepalive.tick(true), Due::Nothing));
        }
        assert!(matches!(keepalive.tick(true), Due::Unanswered));

        // And the one we did send is the one that counts: the probe is
        // answered, so the ticks that follow can ask again but cannot give up.
        let mut keepalive = Keepalive::default();
        for _ in 0..ACTIVE_PING_TICKS - 1 {
            keepalive.tick(true);
        }
        assert!(matches!(keepalive.tick(true), Due::Ping(_)));
        keepalive.acknowledged(opaque);
        for _ in 0..PING_TIMEOUT_TICKS {
            assert!(!matches!(keepalive.tick(true), Due::Unanswered));
        }
    }
}
