use std::task::Waker;

use crate::{
    server::{
        connection::Settings,
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
    /// `settings` sont ceux du pair : ils creditent la fenetre d'emission.
    /// Le `Handle` de la tache ne vit pas ici — la connexion le garde a cote
    /// du `Rc<Stream>` dans sa map, ce qui casse le cycle construction/spawn.
    pub fn create(settings: &Settings, header: Box<Headers>) -> Self {
        // END_STREAM des la requete : le pair a fini d'emettre, le stream
        // nait half-closed(remote).
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
}

pub enum StreamState {
    Normal,
    InputClosed,
}
