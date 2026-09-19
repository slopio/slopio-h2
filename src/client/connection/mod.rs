//! One client connection: the handshake, and the loop that will carry
//! requests over it.

use std::io;

use runtime_streams::StreamExt;

use crate::shared::codec::frames::{
    CLIENT_PREFACE, DECODE_MAX_HEADER_LIST_SIZE, FrameDecoder,
    encode::{encode_header_block, encode_settings},
    stream_id::StreamId,
};
use crate::shared::codec::types::Setting;
use crate::shared::hpack::{BytesStr, Header};
use crate::shared::connection::settings::Settings;
use crate::shared::transport::{RecvError, Transport};

mod protocol;
#[cfg(test)]
mod tests;

use protocol::Protocol;

pub struct Connection<T: Transport> {
    transport: T,
    decoder: FrameDecoder,
    protocol: Protocol,
}

impl<T: Transport> Connection<T> {
    /// Opens the connection: preface out, the peer's SETTINGS in, both
    /// acknowledged.
    ///
    /// §3.4 makes the preface a magic string immediately followed by a
    /// SETTINGS frame, and both go out together — a server that has read the
    /// string and is waiting for the frame is a server holding a connection
    /// open for a round trip that need not happen.
    pub async fn handshake(transport: T) -> io::Result<Self> {
        let mut conn = Self {
            transport,
            // The inbound stream carries no preface — a server sends frames
            // from its first byte — so the decoder starts past that check.
            decoder: FrameDecoder::client(),
            protocol: Protocol::new(),
        };

        conn.protocol.write_frame(|out| {
            out.extend_from_slice(CLIENT_PREFACE);
            encode_settings(
                out,
                &[
                    // We accept no pushed streams (§8.2), so say so before the
                    // peer can promise one.
                    Setting::EnablePush(0),
                    // The decoder drops fields past this; telling the peer
                    // lets it stay under rather than find out by refusal.
                    Setting::MaxHeaderListSize(DECODE_MAX_HEADER_LIST_SIZE as u32),
                ],
            );
        });
        conn.flush().await?;

        while !conn.protocol.handshake.is_complete() {
            match conn.recv().await {
                // The peer closed without finishing the handshake.
                None => return Err(handshake_failed(&conn, "peer closed during the handshake")),
                Some(Err(RecvError::Fatal(e))) => return Err(e),
                // The ring was empty, not the connection: come back for it.
                Some(Err(RecvError::Later)) => {
                    runtime::yield_now().await;
                    continue;
                }
                Some(Ok(())) => {}
            }
            // Whatever the frames produced — a SETTINGS ack, a PING answer, a
            // GOAWAY — leaves now.
            conn.flush().await?;
            if conn.protocol.is_closing() {
                return Err(handshake_failed(&conn, "peer refused the connection"));
            }
        }

        Ok(conn)
    }

    /// What the peer said it will accept. Fixed for the connection's life
    /// except by a later SETTINGS, which nothing reads yet.
    pub fn peer_settings(&self) -> &Settings {
        &self.protocol.peer_settings
    }

    /// Opens a stream and puts `request`'s head on it, returning the id it
    /// went out on.
    ///
    /// `end_stream` says there is no body, which is the only shape there is
    /// until a body writer exists. The response is not waited for here: a
    /// client that blocked on one per request would have multiplexing it could
    /// not use, and §8.1 lets the request end the moment its head is written.
    ///
    /// `None` when no stream can be opened — the peer's
    /// `max_concurrent_streams` is reached, or §5.1.1's 31-bit ids are spent.
    /// Neither is an error: the first is a wait and the second is a new
    /// connection.
    pub async fn send_request(
        &mut self,
        request: &http::Request<()>,
        end_stream: bool,
    ) -> io::Result<Option<StreamId>> {
        let Some(stream_id) = self.protocol.open_stream() else {
            return Ok(None);
        };

        // §8.3: every request pseudo-header comes before every ordinary field,
        // and `:authority` is where a request carries what HTTP/1.1 put in
        // `Host` — §8.3.1 prefers it and a server may reject a request that
        // has neither.
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
        let headers = pseudo.into_iter().chain(authority).map(reify).chain(fields);

        let mut block = Vec::new();
        self.protocol.encoder.encode(headers, &mut block);

        // The peer's limit, floored: §6.5.2 puts it at 2^14 or more, but it
        // came off the wire and a zero would panic the split.
        let limit = (self.protocol.peer_settings.max_frame_size as usize).max(1);
        self.protocol
            .write_frame(|out| encode_header_block(out, stream_id, &block, limit, end_stream));
        self.flush().await?;

        Ok(Some(stream_id))
    }

    /// Takes one chunk off the transport and dispatches every frame in it.
    async fn recv(&mut self) -> Option<Result<(), RecvError>> {
        let chunk = match self.transport.next().await? {
            Ok(chunk) => chunk,
            Err(e) => return Some(Err(e)),
        };
        self.decoder.decode_with(chunk.as_ref(), &mut self.protocol);
        Some(Ok(()))
    }

    /// Sends everything written since the last flush, as one gather write.
    async fn flush(&mut self) -> io::Result<()> {
        if self.protocol.output.is_empty() {
            return Ok(());
        }
        let bufs = self.protocol.output.take();
        let (result, bufs) = self.transport.send(bufs, false).await;
        self.protocol.output.restore(bufs);
        result
    }
}

/// The peer's own reason where there is one, so a failed handshake says what
/// the server objected to rather than only that it objected.
fn handshake_failed<T: Transport>(conn: &Connection<T>, fallback: &'static str) -> io::Error {
    io::Error::other(conn.protocol.failure.unwrap_or(fallback))
}

/// The encoder takes header names as `Option`, which is how it says "the same
/// name as the one before" for a run of fields. A pseudo-header never repeats,
/// so they all carry their own.
fn reify(header: Header) -> Header<Option<http::HeaderName>> {
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
