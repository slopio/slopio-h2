//! What a server connection shares with the tasks running its streams.
//!
//! The send chain, the encoder and the connection window are not here: they
//! were never server-specific and now live in
//! [`shared::connection`](crate::shared::connection). What is left is the part
//! that is — the map of live streams and the task tokens that retire them, and
//! the two writers whose shape is a *response*.

use std::rc::Rc;

use http::{HeaderMap, StatusCode};

use crate::server::stream::Stream;
use crate::shared::connection::STREAM_ID;
use crate::shared::connection::SharedConnection;
use crate::shared::connection::stream_map::StreamMap;
use crate::shared::{
    codec::frames::{encode::encode_window_update, stream_id::StreamId},
    hpack::Header,
};
use runtime::Handle;
use std::rc::Weak;

/// The connection's live streams. Each entry owns its stream and the handle
/// of the task running it.
pub type LiveStreams = StreamMap<Stream, Handle<()>>;

/// Takes a stream out once both its halves are done (§5.1), handing back
/// whatever connection credit it still held.
///
/// Called by whichever half closes last, which is why it checks rather than
/// assumes: the task reports through its [`StreamToken`], the peer's
/// END_STREAM reports through the connection, and either may be second.
pub fn retire_if_closed(map: &LiveStreams, shared: &SharedConnection, id: STREAM_ID) {
    if !map.get(id).is_some_and(|stream| stream.is_closed()) {
        return;
    }
    let Some((stream, _handle)) = map.remove(id) else {
        return;
    };
    // Body bytes no handler consumed still hold credit. `_handle` drops
    // here, outside the map, which for a task retiring itself is that task
    // detaching its own handle — sound because the scheduler holds a
    // reference to the task for the whole poll its destructor runs in.
    shared.release_stream_credit(stream.take_unreleased());
}

/// What a stream task holds for as long as it runs, and what cleans up when
/// it stops — however it stops. Returning normally, being reset by the peer,
/// going down with its connection: all of them drop this.
///
/// The connection used to ask instead, walking every live stream once per
/// turn of its loop to see which had finished. A task knows when it is done
/// and nothing else does, so it is the task that says so.
pub struct StreamToken {
    id: StreamId,
    stream: Rc<Stream>,
    shared: Rc<SharedConnection>,
    /// `Weak` because the map owns this token, by way of the handle of the
    /// task that holds it: an `Rc` back would be a cycle neither ever leaves.
    map: Weak<LiveStreams>,
}

impl StreamToken {
    pub fn new(
        id: StreamId,
        stream: Rc<Stream>,
        shared: Rc<SharedConnection>,
        map: Weak<LiveStreams>,
    ) -> Self {
        Self {
            id,
            stream,
            shared,
            map,
        }
    }

    pub fn id(&self) -> StreamId {
        self.id
    }

    pub fn stream(&self) -> &Rc<Stream> {
        &self.stream
    }

    pub fn shared(&self) -> &Rc<SharedConnection> {
        &self.shared
    }
}

impl Drop for StreamToken {
    /// Our half of the stream is over (§5.1): the task wrote whatever it was
    /// going to. Whatever body bytes it never consumed still hold connection
    /// credit, and they go back here — `take_unreleased` zeroes as it reads,
    /// so the removal that follows can safely ask again for whatever arrived
    /// in between.
    ///
    /// Then it takes itself out of the map, if the peer is done too. Safe to
    /// do from here because a task only ever runs — and so only ever drops —
    /// while the connection is suspended at an `await`, holding no reference
    /// into the map; `StreamMap` is where that argument lives in full.
    fn drop(&mut self) {
        self.stream.end_output();
        if let Some(map) = self.map.upgrade() {
            retire_if_closed(&map, &self.shared, self.id.into());
        }
    }
}

/// The two writers that are a *server*'s: a response head, and the credit a
/// handler's reads hand back.
///
/// An inherent impl on a type from another module, which Rust allows within a
/// crate, so that a handler still writes `shared.write_headers(...)` rather
/// than reaching for a free function with the connection as its first
/// argument. Nothing here touches a private field — both go through the
/// shared writers.
impl SharedConnection {
    /// Writes a response head. §8.3: the response pseudo-header comes before
    /// every ordinary field.
    ///
    /// Nothing is added here. RFC 9110 §6.6.1 does want a `Date` on every
    /// 2xx, 3xx and 4xx from an origin server with a clock, and
    /// `shared::date::now` is the cheap way to produce one — but it costs
    /// about a tenth of the request rate, and whether to pay that is the
    /// handler's call, not the frame writer's. A gateway would relay the
    /// origin's `Date` rather than stamp its own anyway.
    pub fn write_response(
        &self,
        stream_id: StreamId,
        status: StatusCode,
        fields: &HeaderMap,
        end_stream: bool,
    ) {
        let headers =
            std::iter::once(Header::Status(status)).chain(fields.iter().map(|(name, value)| {
                Header::Field {
                    name: Some(name.clone()),
                    value: value.clone(),
                }
            }));
        self.write_headers(stream_id, headers, end_stream);
    }

    /// Takes `n` body bytes off the stream on the handler's behalf and gives
    /// the peer back the credit they were holding — on the stream and on the
    /// connection both, §6.9.1 having debited both when they arrived.
    ///
    /// Here rather than on `Stream` because it has to write frames, and the
    /// stream half cannot. Nothing goes out until a worthwhile amount has
    /// piled up at either level, so a handler taking a few bytes at a time
    /// does not answer every DATA frame with a WINDOW_UPDATE of its own.
    pub fn consume(&self, stream_id: StreamId, stream: &Stream, n: usize) {
        let taken = stream.consume(n);
        if taken == 0 {
            return;
        }
        if let Some(increment) = stream.release_recv(taken) {
            self.write_frame(|out| encode_window_update(out, stream_id, increment));
        }
        self.release_stream_credit(taken);
    }
}
