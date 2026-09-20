//! Everything a client connection holds that is not the transport.
//!
//! The connection loop owns the socket and the decoder and is a task of its
//! own; the application holds [`Client`] and [`Stream`] handles. All three
//! reach the same state through an `Rc`, which is why every field below is
//! behind a cell: opening a stream, writing a body and decoding a frame all
//! mutate it, and they run in different tasks.
//!
//! [`Client`]: crate::client::Client

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use http::HeaderName;

use crate::client::stream::{Failure, Stream, StreamState};
use crate::shared::codec::frames::{encode::encode_rst_stream, stream_id::StreamId};
use crate::shared::connection::stream_map::StreamMap;
use crate::shared::connection::{STREAM_ID, SharedConnection, settings::Settings};
use crate::shared::hpack::{BytesStr, Header};

/// §5.1.1: the first stream a client may open.
const FIRST_CLIENT_STREAM: STREAM_ID = 1;

/// §5.1.1: ids are 31 bits, and one past the last usable odd one is where a
/// client has to stop and open a new connection.
const MAX_STREAM_ID: STREAM_ID = (1 << 31) - 1;

/// Why no stream could be opened, and what the caller should do about it.
///
/// Two answers rather than one error, because they call for opposite things:
/// one is a wait on this connection, the other is another connection. Neither
/// is a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// §5.1.2: the peer's `max_concurrent_streams` is reached. Finish a
    /// stream and ask again — opening one anyway earns a REFUSED_STREAM, and
    /// a refusal we could have predicted is worse than a wait.
    AtLimit,
    /// The connection cannot carry another request, ever: it is closing, or
    /// §5.1.1's 31-bit ids are spent. Open another one; there is no
    /// recycling, because the peer remembers every id it has seen.
    Closed,
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AtLimit => f.write_str("the peer's concurrent stream limit is reached"),
            Self::Closed => f.write_str("the connection can carry no more requests"),
        }
    }
}

impl std::error::Error for Unavailable {}

/// The connection's live streams. No task per stream, unlike the server's:
/// the application's own task drives a client stream through its handle, so
/// there is no handle to store beside the state.
pub(crate) type LiveStreams = StreamMap<StreamState, ()>;

pub(crate) struct ClientShared {
    /// The send chain, the encoder and the connection window — the half of a
    /// connection that is the same at both ends.
    pub(crate) core: SharedConnection,
    pub(crate) streams: LiveStreams,
    /// §5.1.1: the id the next request will use. Odd, and only ever forward —
    /// a client that reused one would be reopening a stream the peer
    /// considers closed.
    next_stream_id: Cell<STREAM_ID>,
    /// What the server told us it will accept. Read whenever a stream is
    /// opened, replaced whenever a SETTINGS frame arrives.
    peer_settings: RefCell<Settings>,
    /// Set once this connection can take no more streams: a GOAWAY arrived,
    /// the loop is sending one, or the transport is gone.
    closing: Cell<bool>,
}

impl ClientShared {
    /// `recv_window` is the connection receive window this client will
    /// announce once the handshake is done.
    pub(crate) fn new(recv_window: u32) -> Self {
        // §6.5.2 defaults, until the peer's SETTINGS says otherwise — and the
        // encoder and frame size we start from are those same defaults.
        let peer_settings = Settings::default();
        Self {
            core: SharedConnection::new(
                peer_settings.header_table_size,
                peer_settings.max_frame_size,
                recv_window,
            ),
            streams: LiveStreams::new(),
            next_stream_id: Cell::new(FIRST_CLIENT_STREAM),
            peer_settings: RefCell::new(peer_settings),
            closing: Cell::new(false),
        }
    }

    /// What the peer said it will accept, as of the last SETTINGS frame.
    ///
    /// A copy: the borrow must not escape, and a caller that held one across
    /// an `await` would be holding it while the loop applied the next
    /// SETTINGS.
    pub(crate) fn peer_settings(&self) -> Settings {
        self.peer_settings.borrow().clone()
    }

    /// Takes the peer's new settings, and with them the frame size every
    /// writer is bounded by.
    pub(crate) fn set_peer_settings(&self, settings: Settings) {
        self.core.set_max_frame_size(settings.max_frame_size);
        self.core.set_header_table_size(settings.header_table_size);
        *self.peer_settings.borrow_mut() = settings;
    }

    /// §5.1: whether `id` names a stream this client never opened — which,
    /// on a client connection, is every id the peer could invent. An id it
    /// *did* open and has since retired is not idle, and a frame arriving
    /// late on one of those is tolerated rather than fatal.
    pub(crate) fn is_idle(&self, id: STREAM_ID) -> bool {
        id >= self.next_stream_id.get()
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.closing.get()
    }

    /// No more streams may be opened. The live ones are left alone: a GOAWAY
    /// does not cancel what the peer already took up (§6.8), and the
    /// connection stays useful until they finish.
    pub(crate) fn stop_opening(&self) {
        self.closing.set(true);
    }

    /// Opens a stream and puts `request`'s head on it.
    ///
    /// `end_stream` says the request has no body, which §8.1 lets end the
    /// message at its head. The response is not waited for: a client that
    /// blocked on one per request would have multiplexing it could not use.
    ///
    /// The frame is written, not sent — the connection loop is what flushes
    /// it, and `write_frame` is what tells the loop there is something to
    /// flush.
    pub(crate) fn send_request(
        self: &Rc<Self>,
        request: &http::Request<()>,
        end_stream: bool,
    ) -> Result<Stream, Unavailable> {
        if self.closing.get() {
            return Err(Unavailable::Closed);
        }

        let settings = self.peer_settings();
        // §5.1.2: the peer's limit is the peer's to set and ours to respect.
        // The map holds exactly the live streams, so its length is the count.
        let allowed = settings.max_concurrent_streams.unwrap_or(u32::MAX);
        if self.streams.len() as u64 >= allowed as u64 {
            return Err(Unavailable::AtLimit);
        }

        let raw = self.next_stream_id.get();
        if raw > MAX_STREAM_ID {
            return Err(Unavailable::Closed);
        }
        // Odd to odd. The peer is the only one who opens the even ones, and
        // it has told us it will not (§8.2, and we asked for no push).
        self.next_stream_id.set(raw.saturating_add(2));
        let id = StreamId::from(raw);

        let state = Rc::new(StreamState::new(id, &settings, end_stream));
        self.streams.insert(raw, Rc::clone(&state), ());

        self.core
            .write_headers(id, request_headers(request), end_stream);

        Ok(Stream::new(id, state, Rc::clone(self)))
    }

    /// Takes a stream out once both its halves are done (§5.1), handing back
    /// whatever connection credit it still held.
    ///
    /// Called by whichever half closes last, which is why it checks rather
    /// than assumes: the peer's END_STREAM reports through the connection
    /// loop, ours through the handle that wrote it, and either may be second.
    pub(crate) fn retire_if_closed(&self, id: STREAM_ID) {
        if !self.streams.get(id).is_some_and(|state| state.is_closed()) {
            return;
        }
        self.remove_stream(id);
    }

    /// Ours: the stream is cancelled, the peer is told (§6.4), and anything
    /// waiting on it is failed. A stream already retired is simply gone, and
    /// no frame goes out for it — §5.1 has nothing left to reset.
    pub(crate) fn reset_stream(&self, id: StreamId, error_code: u32) {
        let Some(state) = self.remove_stream(id.into()) else {
            return;
        };
        self.core
            .write_frame(|out| encode_rst_stream(out, id, error_code));
        state.fail(Failure::Gone("stream cancelled"));
    }

    /// Theirs: §6.4, and nothing is written back — the stream just goes.
    pub(crate) fn peer_reset(&self, id: StreamId, error_code: u32) {
        if let Some(state) = self.remove_stream(id.into()) {
            state.fail(Failure::Reset(error_code));
        }
    }

    /// The connection is over. Every live stream is failed with the same
    /// reason, so nothing is left waiting on frames that will never come.
    ///
    /// The handles outlive this: a `Stream` whose state has been failed still
    /// yields whatever body arrived before the end, and then the error.
    pub(crate) fn shut_down(&self, reason: &'static str) {
        self.closing.set(true);
        for (state, ()) in self.streams.take_all() {
            state.fail(Failure::Gone(reason));
        }
    }

    /// §6.8: a GOAWAY says nothing above `last_stream_id` was processed, so
    /// those requests are safe to retry — elsewhere, since this connection is
    /// done taking them. Everything at or below it is still being answered.
    pub(crate) fn fail_unprocessed(&self, last_stream_id: STREAM_ID) {
        // Collected first: removing walks into the map, and doing that inside
        // `try_for_each` would re-enter the borrow it is contracted not to.
        let mut abandoned = Vec::new();
        let _ = self.streams.try_for_each(|state| {
            if STREAM_ID::from(state.id()) > last_stream_id {
                abandoned.push(state.id());
            }
            Ok::<(), ()>(())
        });

        for id in abandoned {
            if let Some(state) = self.remove_stream(id.into()) {
                state.fail(Failure::Gone(
                    "the peer went away without processing this request",
                ));
            }
        }
    }

    /// §6.9.2: shifts every live stream's send window. The first overflow
    /// stops the walk — the connection is over, the rest does not matter.
    pub(crate) fn adjust_send_windows(&self, delta: i32) -> Result<(), ()> {
        self.streams.try_for_each(|state| state.adjust_send(delta))
    }

    /// Out of the map, with its credit handed back. The state itself lives on
    /// for as long as a handle holds it.
    fn remove_stream(&self, id: STREAM_ID) -> Option<Rc<StreamState>> {
        let (state, ()) = self.streams.remove(id)?;
        // Body bytes the application never read still hold connection credit.
        self.core.release_stream_credit(state.take_unreleased());
        Some(state)
    }
}

/// A request's field section in wire order.
///
/// §8.3: every request pseudo-header comes before every ordinary field, and
/// `:authority` is where a request carries what HTTP/1.1 put in `Host` —
/// §8.3.1 prefers it and a server may reject a request that has neither.
fn request_headers(
    request: &http::Request<()>,
) -> impl Iterator<Item = Header<Option<HeaderName>>> + '_ {
    let uri = request.uri();
    let pseudo = [
        Header::Method(request.method().clone()),
        Header::Scheme(BytesStr::from(uri.scheme_str().unwrap_or("http"))),
        Header::Path(BytesStr::from(
            uri.path_and_query().map_or("/", |p| p.as_str()),
        )),
    ];
    let authority = uri
        .authority()
        .map(|a| Header::Authority(BytesStr::from(a.as_str())));
    let fields = request.headers().iter().map(|(name, value)| Header::Field {
        name: Some(name.clone()),
        value: value.clone(),
    });

    pseudo.into_iter().chain(authority).map(reify).chain(fields)
}

/// The encoder takes header names as `Option`, which is how it says "the same
/// name as the one before" for a run of fields. A pseudo-header never repeats,
/// so they all carry their own.
fn reify(header: Header) -> Header<Option<HeaderName>> {
    match header {
        Header::Field { name, value } => Header::Field {
            name: Some(name),
            value,
        },
        Header::Authority(v) => Header::Authority(v),
        Header::Method(v) => Header::Method(v),
        Header::Scheme(v) => Header::Scheme(v),
        Header::Path(v) => Header::Path(v),
        Header::Protocol(v) => Header::Protocol(v),
        Header::Status(v) => Header::Status(v),
    }
}
