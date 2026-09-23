use std::cell::Cell;

use crate::shared::connection::settings::Settings;

/// §6.9.2.
pub const LOCAL_INITIAL_WINDOW_SIZE: u32 = 65_535;

pub struct StreamWindow {
    to_send: Cell<i32>,
    to_recv: Cell<i32>,
    pending_release: Cell<u32>,
    /// Half the window, so the peer never runs out of credit waiting for us.
    release_threshold: u32,
}

impl StreamWindow {
    /// A negative window (from a shrinking SETTINGS) is no credit at all.
    pub fn available_send(&self) -> u32 {
        self.to_send.get().max(0) as u32
    }

    /// §6.9.2: may go below zero; past 2^31-1 is a connection error.
    pub fn adjust_send(&self, delta: i32) -> Result<(), ()> {
        let adjusted = self.to_send.get().checked_add(delta).ok_or(())?;
        self.to_send.set(adjusted);
        Ok(())
    }

    /// §6.9.1: going past 2^31-1 (`i32::MAX`) is an error. The window may be
    /// negative.
    pub fn credit_send(&self, increment: u32) -> Result<(), ()> {
        let credited = self
            .to_send
            .get()
            .checked_add_unsigned(increment)
            .ok_or(())?;
        self.to_send.set(credited);
        Ok(())
    }

    /// §6.9.1. On `Err` the frame must not go out, and nothing is debited.
    pub fn debit_send(&self, len: u32) -> Result<(), ()> {
        let debited = self
            .to_send
            .get()
            .checked_sub_unsigned(len)
            .filter(|remaining| *remaining >= 0)
            .ok_or(())?;
        self.to_send.set(debited);
        Ok(())
    }

    /// `Some` is already credited here, so the caller *must* write the
    /// WINDOW_UPDATE it is handed: the ledger must never say more than the wire.
    #[must_use]
    pub fn release_recv(&self, len: u32) -> Option<u32> {
        let pending = self.pending_release.get() + len;
        if pending < self.release_threshold {
            self.pending_release.set(pending);
            return None;
        }
        self.pending_release.set(0);
        self.to_recv.set(self.to_recv.get() + pending as i32);
        Some(pending)
    }

    /// As [`release_recv`](Self::release_recv), with nothing held back.
    #[cfg(feature = "grpc")]
    #[must_use]
    pub fn release_recv_now(&self, len: u32) -> Option<u32> {
        let pending = self.pending_release.replace(0) + len;
        if pending == 0 {
            return None;
        }
        self.to_recv.set(self.to_recv.get() + pending as i32);
        Some(pending)
    }

    /// §6.9.1: debits the *padded* length. §6.9.2's tolerance for an overrun
    /// after shrinking is not needed: ours only ever grows, announced before
    /// any stream opens, so an overrun here is always real.
    pub fn recv(&self, padded_len: u32) -> Result<(), ()> {
        let debited = self
            .to_recv
            .get()
            .checked_sub_unsigned(padded_len)
            .filter(|remaining| *remaining >= 0)
            .ok_or(())?;
        self.to_recv.set(debited);
        Ok(())
    }
}

impl StreamWindow {
    /// `recv` must be what this side announced as its own
    /// SETTINGS_INITIAL_WINDOW_SIZE: the ledger has to match the wire.
    pub fn new(peer: &Settings, recv: u32) -> Self {
        Self {
            to_send: Cell::new(peer.initial_window_size as i32),
            to_recv: Cell::new(recv as i32),
            pending_release: Cell::new(0),
            release_threshold: recv / 2,
        }
    }
}

impl From<&Settings> for StreamWindow {
    fn from(peer: &Settings) -> Self {
        Self::new(peer, LOCAL_INITIAL_WINDOW_SIZE)
    }
}
