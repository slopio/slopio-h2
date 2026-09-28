use std::cell::{Cell, RefCell};
use std::rc::Rc;

use http::HeaderName;
use http::uri::Scheme;

use crate::client::stream::{Failure, Stream, StreamState};
use crate::shared::codec::frames::{encode::encode_rst_stream, stream_id::StreamId};
use crate::shared::codec::types::StreamViolation;
use crate::shared::connection::stream_map::StreamMap;
use crate::shared::connection::{STREAM_ID, SharedConnection, settings::Settings};
use crate::shared::hpack::{BytesStr, Header};

/// §5.1.1: the first stream a client may open.
const FIRST_CLIENT_STREAM: STREAM_ID = 1;

/// §5.1.1: ids are 31 bits.
const MAX_STREAM_ID: STREAM_ID = (1 << 31) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unavailable {
    /// §5.1.2: the peer's `max_concurrent_streams` is reached.
    AtLimit,
    /// Closing, or §5.1.1's ids are spent; ids are never recycled.
    Closed,
}

impl Unavailable {
    pub fn reason(self) -> &'static str {
        match self {
            Self::AtLimit => "the peer's concurrent stream limit is reached",
            Self::Closed => "the connection can carry no more requests",
        }
    }
}

impl std::fmt::Display for Unavailable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for Unavailable {}

pub(crate) type LiveStreams = StreamMap<StreamState, ()>;

pub(crate) struct ClientShared {
    pub(crate) core: SharedConnection,
    pub(crate) streams: LiveStreams,
    /// §5.1.1: odd, and only ever forward; reusing one would reopen a stream
    /// the peer considers closed.
    next_stream_id: Cell<STREAM_ID>,
    peer_settings: RefCell<Settings>,
    /// Set once this connection can take no more streams.
    closing: Cell<bool>,
    /// `https` over TLS, `http` otherwise: what the transport carries, not
    /// what a request asks for.
    scheme: Scheme,
}

impl ClientShared {
    pub(crate) fn new(recv_window: u32, scheme: Scheme) -> Self {
        // §6.5.2 defaults until the peer's SETTINGS arrives.
        let peer_settings = Settings::default();
        Self {
            core: SharedConnection::new(
                peer_settings.header_table_size,
                peer_settings.max_frame_size,
                recv_window,
                None,
            ),
            streams: LiveStreams::new(),
            next_stream_id: Cell::new(FIRST_CLIENT_STREAM),
            peer_settings: RefCell::new(peer_settings),
            closing: Cell::new(false),
            scheme,
        }
    }

    pub(crate) fn scheme(&self) -> &Scheme {
        &self.scheme
    }

    /// A copy: the borrow must not escape across an `await`, where the loop
    /// may apply the next SETTINGS.
    pub(crate) fn peer_settings(&self) -> Settings {
        self.peer_settings.borrow().clone()
    }

    pub(crate) fn set_peer_settings(&self, settings: Settings) {
        self.core.set_max_frame_size(settings.max_frame_size);
        self.core.set_header_table_size(settings.header_table_size);
        *self.peer_settings.borrow_mut() = settings;
    }

    /// §5.1: an id this client never opened. A retired id of ours is not
    /// idle, so late frames on it are tolerated. Even ids are always idle,
    /// however low, since we refused push.
    pub(crate) fn is_idle(&self, id: STREAM_ID) -> bool {
        id.is_multiple_of(2) || id >= self.next_stream_id.get()
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.closing.get()
    }

    #[cfg(test)]
    pub(crate) fn skip_to_stream_id(&self, id: STREAM_ID) {
        self.next_stream_id.set(id);
    }

    /// Live streams are left alone (§6.8).
    pub(crate) fn stop_opening(&self) {
        self.closing.set(true);
    }

    /// `grpc`: the stream is a gRPC call, whose response a `Call` reads
    /// message by message; any other is read as bytes, whatever it carries.
    pub(crate) fn send_request(
        self: &Rc<Self>,
        request: &http::Request<()>,
        end_stream: bool,
        grpc: bool,
    ) -> Result<Stream, Unavailable> {
        if self.closing.get() {
            return Err(Unavailable::Closed);
        }

        let settings = self.peer_settings();
        // §5.1.2. The map holds exactly the live streams.
        let allowed = settings.max_concurrent_streams.unwrap_or(u32::MAX);
        if self.streams.len() as u64 >= allowed as u64 {
            return Err(Unavailable::AtLimit);
        }

        let raw = self.next_stream_id.get();
        if raw > MAX_STREAM_ID {
            return Err(Unavailable::Closed);
        }
        self.next_stream_id.set(raw.saturating_add(2));
        // §5.1.1: the last id is spent, so `closing` must say so up front.
        if raw.saturating_add(2) > MAX_STREAM_ID {
            self.stop_opening();
        }
        let id = StreamId::from(raw);

        let head = request.method() == http::Method::HEAD;
        let state = Rc::new(StreamState::new(id, &settings, end_stream, head, grpc));
        self.streams.insert(raw, Rc::clone(&state), ());

        self.core
            .write_headers(id, request_headers(request, &self.scheme), end_stream);

        Ok(Stream::new(id, state, Rc::clone(self)))
    }

    /// §5.1. Called by whichever half closes last, and either may be second,
    /// so it checks rather than assumes.
    pub(crate) fn retire_if_closed(&self, id: STREAM_ID) {
        if !self.streams.get(id).is_some_and(|state| state.is_closed()) {
            return;
        }
        self.remove_stream(id);
    }

    /// §6.4. No frame goes out for a stream already retired (§5.1).
    pub(crate) fn reset_stream(&self, id: StreamId, error_code: u32) {
        let Some(state) = self.remove_stream(id.into()) else {
            return;
        };
        self.core
            .write_frame(|out| encode_rst_stream(out, id, error_code));
        state.fail(Failure::Gone("stream cancelled"));
    }

    /// §5.4.2.
    pub(crate) fn reject_stream(&self, id: StreamId, violation: StreamViolation) {
        let Some(state) = self.remove_stream(id.into()) else {
            return;
        };
        self.core
            .write_frame(|out| encode_rst_stream(out, id, violation.code()));
        state.fail(Failure::Gone(violation.message()));
    }

    /// §6.4: nothing is written back.
    pub(crate) fn peer_reset(&self, id: StreamId, error_code: u32) {
        if let Some(state) = self.remove_stream(id.into()) {
            state.fail(Failure::Reset(error_code));
        }
    }

    /// A failed `Stream` still yields the body that arrived before the end,
    /// and then the error.
    pub(crate) fn shut_down(&self, reason: &'static str) {
        self.closing.set(true);
        for (state, ()) in self.streams.take_all() {
            state.fail(Failure::Gone(reason));
        }
    }

    /// §6.8: streams above `last_stream_id` were not processed.
    pub(crate) fn fail_unprocessed(&self, last_stream_id: STREAM_ID) {
        // Collected first: removing inside `try_for_each` would re-enter the
        // borrow it is contracted not to.
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

    /// Connection credit after the window was spent. Only walked when a
    /// writer can have been waiting, so a stream gone holds nothing to wake.
    pub(crate) fn wake_senders(&self) {
        let _ = self.streams.try_for_each(|state| {
            state.wake_sender();
            Ok::<(), ()>(())
        });
    }

    /// §6.9.2. The first overflow stops the walk; the connection is over.
    pub(crate) fn adjust_send_windows(&self, delta: i32) -> Result<(), ()> {
        self.streams.try_for_each(|state| state.adjust_send(delta))
    }

    fn remove_stream(&self, id: STREAM_ID) -> Option<Rc<StreamState>> {
        let (state, ()) = self.streams.remove(id)?;
        // Body bytes the application never read still hold connection credit.
        self.core.release_stream_credit(state.take_unreleased());
        Some(state)
    }
}

/// §8.3: every pseudo-header must come before every ordinary field. A URI
/// with no scheme (a bare path, as gRPC's) takes the connection's.
fn request_headers<'r>(
    request: &'r http::Request<()>,
    scheme: &Scheme,
) -> impl Iterator<Item = Header<Option<HeaderName>>> + use<'r> {
    let uri = request.uri();
    let pseudo = [
        Header::Method(request.method().clone()),
        Header::Scheme(BytesStr::from(uri.scheme_str().unwrap_or(scheme.as_str()))),
        Header::Path(BytesStr::from(
            uri.path_and_query().map_or("/", |p| p.as_str()),
        )),
    ];
    let authority = uri
        .authority()
        .map(|a| Header::Authority(BytesStr::from(a.as_str())));
    let fields = request
        .headers()
        .iter()
        .filter(|(name, value)| !is_connection_specific(name, value))
        .map(|(name, value)| Header::Field {
            name: Some(name.clone()),
            value: value.clone(),
        });

    pseudo.into_iter().chain(authority).map(reify).chain(fields)
}

/// §8.2.2: connection-specific fields an HTTP/2 message MUST NOT carry. `TE`
/// may stay only as `trailers`.
fn is_connection_specific(name: &HeaderName, value: &http::HeaderValue) -> bool {
    use http::header;
    matches!(
        *name,
        header::CONNECTION | header::TRANSFER_ENCODING | header::UPGRADE
    ) || name == "keep-alive"
        || name == "proxy-connection"
        || (*name == header::TE && value != "trailers")
}

/// `None` means "same name as the previous field" to the encoder, so every
/// name here must be `Some`.
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
