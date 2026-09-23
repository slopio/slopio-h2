//! §6.7 keepalive: detects a peer whose socket is open but whose other end is
//! gone, which TCP alone takes minutes to report.
//!
//! Silence is measured on the clock from the peer's last chunk, not counted in
//! [`DEADLINE_TICK`]s: our own writes keep a whole tick from passing, so a
//! tick count never probes a peer the application keeps writing to.
//!
//! [`DEADLINE_TICK`]: crate::shared::connection::DEADLINE_TICK

use std::time::SystemTime;

use crate::client::{ACTIVE_PING_TICKS, IDLE_PING_TICKS, PING_TIMEOUT_TICKS};
use crate::shared::connection::DEADLINE_TICK;

pub(super) enum Due {
    Nothing,
    /// §6.7.
    Ping([u8; 8]),
    /// The last probe went unanswered for its whole budget.
    Unanswered,
}

pub(super) struct Keepalive {
    last_heard: SystemTime,
    /// At most one probe is outstanding.
    probe_sent: Option<SystemTime>,
    /// The opaque of the outstanding probe (§6.7: echoed byte for byte). A
    /// never-repeating counter, so a stale ACK from an abandoned probe cannot
    /// match.
    probes_sent: u64,
}

impl Keepalive {
    pub(super) fn new(now: SystemTime) -> Self {
        Self {
            last_heard: now,
            probe_sent: None,
            probes_sent: 0,
        }
    }

    /// Any frame proves the peer alive, so the outstanding probe is dropped too.
    pub(super) fn heard(&mut self, now: SystemTime) {
        self.last_heard = now;
        self.probe_sent = None;
    }

    /// §6.7: an ACK is ours only if it carries the opaque we sent.
    pub(super) fn acknowledged(&mut self, opaque: [u8; 8]) {
        if self.probe_sent.is_some() && opaque == self.probes_sent.to_be_bytes() {
            self.probe_sent = None;
        }
    }

    /// Must depend only on the clock and the peer's last frame, not on how
    /// many turns of the loop asked. Clocks that step backwards floor at zero,
    /// so an adjustment cannot end a connection.
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

    /// Regression: a loop woken many times a tick by our own writes must still
    /// see the peer's silence.
    #[test]
    fn asking_often_does_not_reset_the_silence() {
        let mut keepalive = Keepalive::new(start());
        let mut now = start();
        let mut probed = false;
        for _ in 0..=ACTIVE_PING_TICKS * 5 {
            now += Duration::from_secs(1);
            probed |= matches!(keepalive.due(now, true), Due::Ping(_));
        }
        assert!(probed, "the peer's silence was asked about");
    }

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

    /// The silence that follows must not inherit the abandoned probe's budget.
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

        let mut keepalive = Keepalive::new(start());
        assert!(matches!(keepalive.due(asked, true), Due::Ping(_)));
        keepalive.acknowledged(opaque);
        assert!(!matches!(keepalive.due(gave_up, true), Due::Unanswered));
    }
}
