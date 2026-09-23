use std::rc::Rc;

use http::{HeaderMap, StatusCode};

use crate::server::stream::StreamState;
use crate::shared::connection::STREAM_ID;
use crate::shared::connection::SharedConnection;
use crate::shared::connection::stream_map::StreamMap;
use crate::shared::{
    codec::frames::{
        encode::{encode_rst_stream, encode_window_update},
        stream_id::StreamId,
    },
    codec::types::{INTERNAL_ERROR, NO_ERROR},
    hpack::Header,
};
use runtime::Handle;
use std::rc::Weak;

pub type LiveStreams = StreamMap<StreamState, Handle<()>>;

/// Called by whichever half closes last (§5.1), which is why it checks rather
/// than assumes: the task and the peer's END_STREAM may each be second.
pub fn retire_if_closed(map: &LiveStreams, shared: &SharedConnection, id: STREAM_ID) {
    if !map.get(id).is_some_and(|stream| stream.is_closed()) {
        return;
    }
    let Some((stream, _handle)) = map.remove(id) else {
        return;
    };
    stream.note_retired();
    // A reset stream is removed where the RST_STREAM is handled and never
    // arrives here, so this is the one place that knows a stream finished
    // cleanly, which is what the fault budget spends itself against.
    shared.note_completed();
    // `_handle` drops here, outside the map; for a task retiring itself that
    // is sound because the scheduler holds a reference to the task for the
    // whole poll its destructor runs in.
    shared.release_stream_credit(stream.take_unreleased());
}

/// Cleans up when a stream task stops, however it stops: returning, being
/// reset, or going down with its connection all drop this.
pub struct StreamToken {
    id: StreamId,
    stream: Rc<StreamState>,
    shared: Rc<SharedConnection>,
    /// `Weak` because the map owns this token via the task's handle: an `Rc`
    /// back would be a cycle.
    map: Weak<LiveStreams>,
}

impl StreamToken {
    pub fn new(
        id: StreamId,
        stream: Rc<StreamState>,
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

    pub fn stream(&self) -> &Rc<StreamState> {
        &self.stream
    }

    pub fn shared(&self) -> &Rc<SharedConnection> {
        &self.shared
    }
}

impl Drop for StreamToken {
    /// `take_unreleased` zeroes as it reads, so the removal can safely ask
    /// again for credit that arrived in between.
    ///
    /// Taking itself out of the map is safe from here because a task only
    /// ever runs, and so drops, while the connection is suspended at an
    /// `await` holding no reference into the map; see `StreamMap`.
    fn drop(&mut self) {
        // A handler that returned without answering gets a `500`, since
        // nothing else will ever speak for that stream. Only for a stream
        // not yet retired: a HEADERS frame on a stream that no longer exists
        // is noise the peer has to account for.
        if !self.stream.has_responded() && !self.stream.is_retired() {
            self.shared.write_response(
                self.id,
                StatusCode::INTERNAL_SERVER_ERROR,
                &HeaderMap::new(),
                true,
            );
        } else if !self.stream.output_ended() && !self.stream.is_retired() {
            // A response started but not ended must be reset, not finished:
            // an empty DATA with END_STREAM would pass a truncated body off as
            // a whole one.
            self.shared
                .write_frame(|out| encode_rst_stream(out, self.id, INTERNAL_ERROR));
            if !self.stream.input_ended() {
                self.shared.note_reset(self.id.into());
            }
            self.stream.abandon_input();
        }

        // §8.1: a complete response to a request still arriving is followed
        // by RST_STREAM(NO_ERROR) rather than taking a body nobody will read.
        if !self.stream.input_ended() && !self.stream.is_retired() {
            self.shared
                .write_frame(|out| encode_rst_stream(out, self.id, NO_ERROR));
            self.shared.note_reset(self.id.into());
            self.stream.abandon_input();
        }

        self.stream.end_output();
        if let Some(map) = self.map.upgrade() {
            retire_if_closed(&map, &self.shared, self.id.into());
        }
    }
}

impl SharedConnection {
    /// §8.3: the response pseudo-header comes before every ordinary field.
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

    #[cfg(feature = "grpc")]
    pub fn release_held(&self, stream_id: StreamId, stream: &StreamState) {
        let (held, increment) = stream.release_held();
        if let Some(increment) = increment {
            self.write_frame(|out| encode_window_update(out, stream_id, increment));
        }
        if held > 0 {
            self.release_stream_credit(held);
        }
    }

    /// Credits both the stream and the connection, §6.9.1 having debited both.
    pub fn consume(&self, stream_id: StreamId, stream: &StreamState, n: usize) {
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
