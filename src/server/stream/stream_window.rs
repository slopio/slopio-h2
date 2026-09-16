use std::cell::Cell;

use crate::server::connection::Settings;

/// Notre SETTINGS_INITIAL_WINDOW_SIZE. Annonce dans le preface et jamais
/// modifie, donc une constante suffit — seuls les settings du pair bougent.
pub const LOCAL_INITIAL_WINDOW_SIZE: u32 = 65_535;

pub struct StreamWindow {
    //what we can send to the peer
    to_send: Cell<i32>,
    //what the peer can send to this stream
    to_recv: Cell<i32>,
}

impl StreamWindow {}

impl From<&Settings> for StreamWindow {
    /// `to_send` est credite par le SETTINGS_INITIAL_WINDOW_SIZE du pair,
    /// `to_recv` par le notre — d'ou la constante pour le second cote.
    fn from(peer: &Settings) -> Self {
        Self {
            to_send: Cell::new(peer.initial_window_size as i32),
            to_recv: Cell::new(LOCAL_INITIAL_WINDOW_SIZE as i32),
        }
    }
}
