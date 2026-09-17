use std::cell::Cell;

use crate::server::connection::settings::Settings;

pub const LOCAL_INITIAL_WINDOW_SIZE: u32 = 65_535;

pub struct StreamWindow {
    to_send: Cell<i32>,
    to_recv: Cell<i32>,
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
        }
    }
}
