use std::cell::Cell;

use crate::shared::connection::settings::Settings;

pub const LOCAL_INITIAL_WINDOW_SIZE: u32 = 65_535;

/// Credit a handler has consumed before a WINDOW_UPDATE goes out for it.
/// Half the window: rare enough not to answer every DATA frame with a frame
/// of our own, early enough that the peer never runs out of credit waiting
/// for us.
const RELEASE_THRESHOLD: u32 = LOCAL_INITIAL_WINDOW_SIZE / 2;

pub struct StreamWindow {
    to_send: Cell<i32>,
    to_recv: Cell<i32>,
    /// Consumed by the handler and owed back to the peer, not yet announced.
    pending_release: Cell<u32>,
}

impl StreamWindow {
    /// What a DATA frame may still spend on this stream. A negative window
    /// — a shrinking SETTINGS may have put it there — is no credit at all.
    pub fn available_send(&self) -> u32 {
        self.to_send.get().max(0) as u32
    }

    /// §6.9.2: the peer's SETTINGS_INITIAL_WINDOW_SIZE changed by `delta`,
    /// and every live stream's send window moves with it — below zero if
    /// need be, which only means waiting for WINDOW_UPDATE. Going past
    /// 2^31-1 is a connection error.
    pub fn adjust_send(&self, delta: i32) -> Result<(), ()> {
        let adjusted = self.to_send.get().checked_add(delta).ok_or(())?;
        self.to_send.set(adjusted);
        Ok(())
    }

    /// §6.9.1: going past 2^31-1 is an error, and `i32::MAX` is exactly that
    /// bound. The window can be negative — a shrinking SETTINGS may have put
    /// it there.
    pub fn credit_send(&self, increment: u32) -> Result<(), ()> {
        let credited = self
            .to_send
            .get()
            .checked_add_unsigned(increment)
            .ok_or(())?;
        self.to_send.set(credited);
        Ok(())
    }

    /// §6.9.1: a DATA frame we send debits this window by its payload length.
    /// `Err` is the peer's credit running short: the frame must not go out,
    /// and nothing is debited.
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

    /// Credit owed back to the peer for body bytes the handler has taken.
    /// Accumulated rather than announced one DATA frame at a time; `Some` is
    /// the amount that has piled up and is worth a frame.
    ///
    /// The window is credited here, in the same breath, so the caller *must*
    /// write the WINDOW_UPDATE it is handed: the ledger would otherwise say
    /// more than the wire, which is the one thing §6.9 cannot forgive.
    #[must_use]
    pub fn release_recv(&self, len: u32) -> Option<u32> {
        let pending = self.pending_release.get() + len;
        if pending < RELEASE_THRESHOLD {
            self.pending_release.set(pending);
            return None;
        }
        self.pending_release.set(0);
        self.to_recv.set(self.to_recv.get() + pending as i32);
        Some(pending)
    }

    /// As [`release_recv`](Self::release_recv), with nothing held back: `len`
    /// and whatever was pending, however little. For a receiver that holds
    /// whole messages and cannot take the next until its sender has the
    /// credit to finish sending it.
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

    /// §6.9.1: a DATA frame debits the receive window by its *padded* length,
    /// pad-length byte and padding included. Dropping below zero means the
    /// peer sent past the credit we gave it.
    ///
    /// §6.9.2 carves out one exception we do not need: a receiver that has
    /// just shrunk its window must tolerate an overrun in flight. We never
    /// send SETTINGS_INITIAL_WINDOW_SIZE, so an overrun here is always real.
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

impl From<&Settings> for StreamWindow {
    /// `to_send` is credited by the peer's SETTINGS_INITIAL_WINDOW_SIZE,
    /// `to_recv` by ours.
    fn from(peer: &Settings) -> Self {
        Self {
            to_send: Cell::new(peer.initial_window_size as i32),
            to_recv: Cell::new(LOCAL_INITIAL_WINDOW_SIZE as i32),
            pending_release: Cell::new(0),
        }
    }
}
