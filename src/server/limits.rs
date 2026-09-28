use std::io;
use std::time::Duration;

use crate::server::connection::{
    CONNECTION_RECV_WINDOW, DEADLINE_TICK, FLUSH_TIMEOUT, IDLE_TICKS, MAX_CONCURRENT_STREAMS,
    STREAM_RECV_WINDOW,
};
use crate::shared::codec::frames::DECODE_MAX_HEADER_LIST_SIZE;
use crate::shared::connection::MAX_SLEEP;

/// How far past `drain_timeout` a stopping server still waits: a connection
/// cut at its deadline flushes its last GOAWAY, and a flush may take up to
/// `FLUSH_TIMEOUT`, twice if the cut came during one.
pub(super) const DRAIN_GRACE: Duration = Duration::from_secs(2 * FLUSH_TIMEOUT.as_secs());

/// What one connection may hold, and for how long. The defaults are what the
/// test suite and the benchmarks run on; [`Server::run`](super::Server::run)
/// refuses a set that does not add up before it listens.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// §6.5.2 SETTINGS_MAX_CONCURRENT_STREAMS. A stream past it is refused
    /// with REFUSED_STREAM, which a client may retry.
    pub max_concurrent_streams: u32,
    /// §6.9.2 SETTINGS_INITIAL_WINDOW_SIZE: what a peer may send on one
    /// stream before its handler takes any of it, so what a stalled handler
    /// can be made to hold. At least 65 535, §6.9.2's default, and at most
    /// 2^31-1 (§6.9.1).
    pub stream_window: u32,
    /// §6.5.2 SETTINGS_MAX_HEADER_LIST_SIZE, decoded (RFC 7541 §4.1). A
    /// request past it is refused on its stream. A header block is also
    /// capped at twice this compressed, which is what stops a CONTINUATION
    /// flood (CVE-2024-27316).
    pub max_header_list_size: u32,
    /// How long a connection with no stream open may send nothing. Checked
    /// every 5 s, so up to that late, and never less than that.
    pub idle_timeout: Duration,
    /// How long a peer has to finish the TLS handshake. No connection
    /// deadline applies before it, so a peer that connects and sends nothing
    /// would otherwise hold a task, a socket and a handshake buffer. At most
    /// an hour, the longest timer the runtime has.
    #[cfg(feature = "tls")]
    pub tls_handshake_timeout: Duration,
    /// How long a stopping server gives the streams in flight to finish,
    /// once every connection has been sent its GOAWAY. What is still open
    /// then is cut. Zero sends the GOAWAY and cuts at once.
    ///
    /// Under `thread_per_core`, SIGTERM or SIGINT stops the server, and the
    /// runtime ends the process 30 s after the signal whatever is still
    /// running: past about 20 s, that is the deadline, not this.
    pub drain_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_concurrent_streams: MAX_CONCURRENT_STREAMS,
            stream_window: STREAM_RECV_WINDOW,
            max_header_list_size: DECODE_MAX_HEADER_LIST_SIZE as u32,
            idle_timeout: DEADLINE_TICK * IDLE_TICKS,
            #[cfg(feature = "tls")]
            tls_handshake_timeout: Duration::from_secs(10),
            // With `DRAIN_GRACE`, inside the runtime's 30 s after a signal.
            drain_timeout: Duration::from_secs(20),
        }
    }
}

impl Limits {
    pub(super) fn validate(&self) -> io::Result<()> {
        let invalid = |why: &str| Err(io::Error::new(io::ErrorKind::InvalidInput, why));
        if self.max_concurrent_streams == 0 {
            return invalid("max_concurrent_streams: a connection must admit a stream");
        }
        if !(65_535..=i32::MAX as u32).contains(&self.stream_window) {
            return invalid("stream_window: between 65 535 and 2^31-1 (§6.9.1, §6.9.2)");
        }
        // The peer's spendable connection credit is the window less what is
        // consumed and not yet announced, which sits below half of it: every
        // stream's full window has to fit in the other half, or the
        // connection window is what a stream ends up waiting on.
        let every_window = self.max_concurrent_streams as u64 * self.stream_window as u64;
        if every_window > (CONNECTION_RECV_WINDOW - CONNECTION_RECV_WINDOW / 2) as u64 {
            return invalid("max_concurrent_streams × stream_window: at most 2^30");
        }
        if self.max_header_list_size == 0 {
            return invalid("max_header_list_size: a request needs its pseudo-headers");
        }
        if self.idle_timeout < DEADLINE_TICK {
            return invalid("idle_timeout: at least 5 s, the deadlines' tick");
        }
        #[cfg(feature = "tls")]
        if self.tls_handshake_timeout.is_zero() || self.tls_handshake_timeout > MAX_SLEEP {
            return invalid("tls_handshake_timeout: more than zero, at most an hour");
        }
        if self.drain_timeout + DRAIN_GRACE > MAX_SLEEP {
            return invalid("drain_timeout: at most an hour less 10 s");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_defaults_add_up() {
        Limits::default().validate().unwrap();
    }

    #[test]
    fn a_set_that_does_not_add_up_is_refused() {
        let refused = |limits: Limits| limits.validate().is_err();
        let base = Limits::default();
        assert!(refused(Limits {
            max_concurrent_streams: 0,
            ..base
        }));
        assert!(refused(Limits {
            stream_window: 65_534,
            ..base
        }));
        assert!(refused(Limits {
            stream_window: 1 << 31,
            ..base
        }));
        assert!(refused(Limits {
            max_concurrent_streams: 2048,
            stream_window: 1 << 20,
            ..base
        }));
        assert!(refused(Limits {
            max_header_list_size: 0,
            ..base
        }));
        assert!(refused(Limits {
            idle_timeout: Duration::from_secs(4),
            ..base
        }));
        #[cfg(feature = "tls")]
        {
            assert!(refused(Limits {
                tls_handshake_timeout: Duration::ZERO,
                ..base
            }));
            assert!(refused(Limits {
                tls_handshake_timeout: MAX_SLEEP + Duration::from_secs(1),
                ..base
            }));
            assert!(!refused(Limits {
                tls_handshake_timeout: MAX_SLEEP,
                ..base
            }));
        }
        assert!(!refused(Limits {
            drain_timeout: Duration::ZERO,
            ..base
        }));
        assert!(!refused(Limits {
            drain_timeout: MAX_SLEEP - DRAIN_GRACE,
            ..base
        }));
        assert!(refused(Limits {
            drain_timeout: MAX_SLEEP,
            ..base
        }));
        assert!(!refused(Limits {
            max_concurrent_streams: 1024,
            stream_window: 1 << 20,
            ..base
        }));
    }
}
