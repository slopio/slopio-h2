use std::task::Waker;

use crate::{
    server::{
        connection::settings::Settings,
        stream::{input_data::InputData, stream_window::StreamWindow},
    },
    shared::codec::frames::headers::Headers,
};

mod input_data;
mod stream_window;

pub struct Stream {
    header: Box<Headers>,
    state: StreamState,
    input: Option<InputData>,
    window: StreamWindow,
    waker: Option<Waker>,
}

impl Stream {
    /// `settings` are the peer's: they credit the send window.
    pub fn create(settings: &Settings, header: Box<Headers>) -> Self {
        // END_STREAM already on the request: the stream is born
        // half-closed(remote).
        let state = if header.is_end_stream() {
            StreamState::InputClosed
        } else {
            StreamState::Normal
        };

        Self {
            window: StreamWindow::from(settings),
            header,
            state,
            input: None,
            waker: None,
        }
    }

    pub fn credit_send(&self, increment: u32) -> Result<(), ()> {
        self.window.credit_send(increment)
    }
}

pub enum StreamState {
    Normal,
    InputClosed,
}
