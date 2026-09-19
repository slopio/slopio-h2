//! One client connection: the handshake, and the loop that will carry
//! requests over it.

use std::io;

use runtime_streams::StreamExt;

use crate::shared::codec::frames::{
    CLIENT_PREFACE, DECODE_MAX_HEADER_LIST_SIZE, FrameDecoder, encode::encode_settings,
};
use crate::shared::codec::types::Setting;
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
        if self.protocol.output.borrow().is_empty() {
            return Ok(());
        }
        let bufs = self.protocol.output.borrow_mut().take();
        let (result, bufs) = self.transport.send(bufs, false).await;
        self.protocol.output.borrow_mut().restore(bufs);
        result
    }
}

/// The peer's own reason where there is one, so a failed handshake says what
/// the server objected to rather than only that it objected.
fn handshake_failed<T: Transport>(conn: &Connection<T>, fallback: &'static str) -> io::Error {
    io::Error::other(conn.protocol.failure.unwrap_or(fallback))
}
