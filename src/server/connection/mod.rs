use std::rc::Rc;

use crate::server::{STREAM_ID, connection::shared_with_streams::SharedConnection, stream::Stream};
use crate::shared::codec::{
    frames::{FrameHandler, FrameKind, SettingsIter, headers::Headers, stream_id::StreamId},
    types::{
        DecodeError, ErrorScope, PROTOCOL_ERROR, REFUSED_STREAM, STREAM_CLOSED, StreamViolation,
    },
};
use runtime::{Handle, spawn};
use rustc_hash::FxHashMap;

mod shared_with_streams;

/// Notre SETTINGS_MAX_CONCURRENT_STREAMS, annonce dans le preface. Au-dela,
/// un HEADERS ouvrant un stream est refuse par RST_STREAM REFUSED_STREAM.
pub const MAX_CONCURRENT_STREAMS: u32 = 64;

pub struct Connection {
    input: (),
    writer: (),
    peer_settings: Settings,
    shared: Rc<SharedConnection>,
    window: ConnectionWindow,
    streams: Streams,
}

pub struct ConnectionWindow {}

struct Streams {
    last_client_stream_id: STREAM_ID,
    /// Le `Handle` vit a cote du `Rc`, pas dedans : construire le `Stream`
    /// demande le handle, spawner la tache demande le `Rc<Stream>`.
    streams: FxHashMap<STREAM_ID, (Rc<Stream>, Handle<()>)>,
}

impl Streams {
    fn new_stream(&mut self) {}
}

impl Connection {
    fn new() -> Self {
        unimplemented!()
    }

    async fn flush() {}

    /// GOAWAY + la connexion cesse de traiter.
    fn fail_connection(&mut self, error_code: u32, reason: &'static str) {
        unimplemented!()
    }

    /// RST_STREAM, scope decide par `stream_error_scope`.
    fn fail_stream(&mut self, stream_id: StreamId, violation: StreamViolation) {
        unimplemented!()
    }

    /// RST_STREAM sec, sans passer par le budget de violations.
    fn reset_stream(&mut self, stream_id: StreamId, error_code: u32) {
        unimplemented!()
    }

    /// Trailers §8.1 : doivent porter END_STREAM et aucun pseudo-header.
    fn on_trailers(&mut self, stream: Rc<Stream>, headers: Box<Headers>) {
        unimplemented!()
    }

    /// §5.1.2 : reste-t-il de la place sous notre MAX_CONCURRENT_STREAMS ?
    /// La map ne contient que les streams vivants, donc sa taille est le
    /// compte courant.
    fn admits(&self) -> bool {
        self.streams.streams.len() < MAX_CONCURRENT_STREAMS as usize
    }
}

/// §8.1.2.1/.3/.6 : `:method` et `:scheme` obligatoires, `:path` non vide,
/// pas de `:status` (pseudo-header de reponse).
fn is_malformed_request(headers: &Headers) -> bool {
    let p = headers.pseudo();
    p.status.is_some()
        || p.method.is_none()
        || p.scheme.is_none()
        || !p.path.as_deref().is_some_and(|path| !path.is_empty())
}

/// La tache applicative du stream.
async fn handle_stream(shared: Rc<SharedConnection>, stream: Rc<Stream>, id: StreamId) {
    unimplemented!()
}

impl FrameHandler for Connection {
    // --- methodes sans impl par defaut ---

    /// `payload` emprunte le buffer du decodeur : valide seulement pendant
    /// l'appel. `padded_len` est ce qui compte pour le controle de flux
    /// (pad-length + corps + padding, §6.9.1).
    fn on_data(
        &mut self,
        stream_id: StreamId,
        payload: &[u8],
        padded_len: usize,
        end_stream: bool,
    ) {
        unimplemented!()
    }

    /// Un bloc complet : HEADERS + toutes ses CONTINUATION, deja decode HPACK.
    ///
    /// Deux roles : ouvrir un stream, ou porter les trailers d'un stream
    /// vivant. L'aiguillage se fait sur la presence de l'id dans la map.
    fn on_headers(&mut self, headers: Box<Headers>) {
        let id = headers.stream_id();
        let raw: STREAM_ID = id.into();

        // --- ce qui ne regarde que la frame ---

        // §5.3.1 : un stream ne peut pas dependre de lui-meme.
        if let Some(dep) = headers.stream_dep()
            && dep.dependency_id == id
        {
            return self.fail_stream(id, StreamViolation::HeadersSelfDependency);
        }

        // §5.1.1 : les ids client sont impairs, les pairs sont reserves au
        // serveur. Un HEADERS entrant sur un id pair tue la connexion.
        if !id.is_client_initiated() {
            return self.fail_connection(PROTOCOL_ERROR, "HEADERS with server-initiated stream id");
        }

        // Liste tronquee au decodage : l'etat HPACK reste synchrone, mais le
        // contenu est incomplet et ne doit pas atteindre le handler.
        if headers.is_over_size() {
            self.streams.last_client_stream_id = raw.max(self.streams.last_client_stream_id);
            return self.reset_stream(id, REFUSED_STREAM);
        }

        // --- aiguillage : trailers, ou creation ---

        if let Some((stream, _)) = self.streams.streams.get(&raw) {
            let stream = Rc::clone(stream);
            return self.on_trailers(stream, headers);
        }

        // Absent de la map mais deja consomme : le stream a vecu et est parti.
        // C'est `last_client_stream_id` qui distingue ce cas de « id jamais
        // utilise », la map ne contenant que les streams vivants.
        if raw <= self.streams.last_client_stream_id {
            return self.fail_connection(STREAM_CLOSED, "HEADERS on closed stream");
        }

        // --- ce qui regarde la requete ---

        // L'id est consomme des qu'on le refuse : dans les deux branches
        // ci-dessous il avance, mais aucun stream n'est ouvert.
        if is_malformed_request(&headers) {
            self.streams.last_client_stream_id = raw;
            return self.fail_stream(id, StreamViolation::MalformedRequest);
        }

        if !self.admits() {
            self.streams.last_client_stream_id = raw;
            return self.reset_stream(id, REFUSED_STREAM);
        }

        // --- creation ---

        self.streams.last_client_stream_id = raw;

        // L'entree reste dans la map meme si END_STREAM est pose : le stream
        // est half-closed(remote), pas parti — il faut encore encaisser ses
        // WINDOW_UPDATE et rejeter les DATA egarees.
        let stream = Rc::new(Stream::create(&self.peer_settings, headers));
        let handle = spawn(handle_stream(
            Rc::clone(&self.shared),
            Rc::clone(&stream),
            id,
        ));
        self.streams.streams.insert(raw, (stream, handle));
    }

    fn on_settings(&mut self, ack: bool, settings: SettingsIter<'_>) {
        unimplemented!()
    }

    /// `stream_id` a zero vise la fenetre de connexion, pas un stream.
    fn on_window_update(&mut self, stream_id: StreamId, increment: u32) {
        unimplemented!()
    }

    fn on_rst_stream(&mut self, stream_id: StreamId, error_code: u32) {
        unimplemented!()
    }

    fn on_ping(&mut self, ack: bool, opaque: [u8; 8]) {
        unimplemented!()
    }

    fn on_goaway(&mut self, last_stream_id: StreamId, error_code: u32, debug_data: &[u8]) {
        unimplemented!()
    }

    /// Apres un `DecodeError::Connection` le decodeur cesse d'emettre : c'est
    /// a nous de retenir que la connexion est morte.
    fn on_error(&mut self, err: DecodeError) {
        unimplemented!()
    }

    // --- methodes avec impl par defaut : supprimables ---

    /// Defaut : `ErrorScope::Stream`. C'est le hook RST_STREAM vs GOAWAY.
    fn stream_error_scope(&self, violation: StreamViolation) -> ErrorScope {
        unimplemented!()
    }

    /// Defaut : no-op. Appele avant validation, pour la comptabilite qui ne
    /// depend que du type de frame.
    fn on_frame(&mut self, kind: FrameKind, stream_id: StreamId, length: u32, flags: u8) {
        unimplemented!()
    }

    /// Defaut : no-op. Le preface serveur (SETTINGS) doit etre mis en file ici,
    /// avant que le decodeur ne dispatche la moindre frame suivante.
    fn on_preface(&mut self) {
        unimplemented!()
    }
}

pub struct Settings {
    /// 0x01 — taille max de la table dynamique HPACK. Defaut 4096.
    pub header_table_size: u32,
    /// 0x02 — server push. Defaut true, mais un serveur annonce false.
    pub enable_push: bool,
    /// 0x03 — `None` = illimite (defaut). `Some(0)` interdit tout nouveau stream.
    pub max_concurrent_streams: Option<u32>,
    /// 0x04 — fenetre initiale de chaque stream. Defaut 65535, max 2^31-1.
    pub initial_window_size: u32,
    /// 0x05 — taille max d'un payload de frame. Defaut 16384, dans [2^14, 2^24-1].
    pub max_frame_size: u32,
    /// 0x06 — `None` = illimite (defaut). Indicatif, non contraignant.
    pub max_header_list_size: Option<u32>,
    /// 0x08 — RFC 8441, extended CONNECT (WebSocket sur h2). Defaut false.
    pub enable_connect_protocol: bool,
    /// 0x09 — RFC 9218, abandon des priorites RFC 7540. Defaut false.
    pub no_rfc7540_priorities: bool,
}
