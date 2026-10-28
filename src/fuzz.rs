//! Entry points for `fuzz/`, built under `cargo fuzz` (`--cfg fuzzing`) and
//! for the tests: the decoders are crate-private. Each takes whatever bytes
//! the fuzzer makes and panics only on a broken invariant, never on bad input.

use std::io::Cursor;

use crate::shared::codec::frames::headers::Headers;
use crate::shared::codec::frames::stream_id::StreamId;
use crate::shared::codec::frames::{
    CLIENT_PREFACE, FrameDecoder, FrameHandler, FrameKind, SettingsIter,
};
use crate::shared::codec::types::DecodeError;
use crate::shared::hpack::{Decoder, DecoderError, Encoder, Header};

/// One connection's header blocks. The first byte picks the table size the
/// peer may use; then each block follows its length, two bytes big-endian,
/// staged as the frame decoder stages a HEADERS payload.
///
/// A block that decodes must encode and decode back to the same fields on a
/// second pair of tables, and the table's bookkeeping must hold after every
/// block. A malformed field ends only its block, as a stream error does; any
/// other error ends the connection.
pub fn hpack_decode(data: &[u8]) {
    let Some((&size, mut rest)) = data.split_first() else {
        return;
    };
    let max = match size % 4 {
        0 => 0,
        1 => 256,
        2 => 4096,
        _ => size as usize * 64,
    };
    let mut decoder = Decoder::new(max);
    let mut encoder = Encoder::default();
    let mut mirror = Decoder::default();

    while let [hi, lo, tail @ ..] = rest {
        let len = (u16::from_be_bytes([*hi, *lo]) as usize).min(tail.len());
        let (block, next) = tail.split_at(len);
        rest = next;

        let mut buf = decoder.stage(block);
        let mut fields = Vec::new();
        let res = decoder.decode(&mut Cursor::new(&mut buf), |h| fields.push(h));
        decoder.assert_consistent();
        match res {
            Ok(()) => {}
            Err(DecoderError::InvalidField) => continue,
            Err(_) => return,
        }

        let mut wire = Vec::new();
        encoder.encode(fields.iter().cloned().map(named), &mut wire);
        let mut buf = mirror.stage(&wire);
        let mut back = Vec::new();
        mirror
            .decode(&mut Cursor::new(&mut buf), |h| back.push(h))
            .expect("what was decoded encodes and decodes back");
        assert_eq!(back, fields);
    }
}

fn named(header: Header) -> Header<Option<http::HeaderName>> {
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

/// What a peer sends, cut into reads. The first byte's low bit picks the side
/// decoding it (the server, which expects the preface first, or the client);
/// its next bit, on the server, sends the preface ahead of the input. Then
/// each read follows its length on one byte.
///
/// The decoder reports nothing after a connection error.
pub fn frames(data: &[u8]) {
    let Some((&flags, mut rest)) = data.split_first() else {
        return;
    };
    let server = flags & 1 == 0;
    let mut decoder = match server {
        true => FrameDecoder::new(),
        false => FrameDecoder::client(),
    };
    let mut sink = Sink { closed: false };
    if server && flags & 2 == 0 {
        decoder.decode_with(CLIENT_PREFACE, &mut sink);
    }
    while let [len, tail @ ..] = rest {
        let (read, next) = tail.split_at((*len as usize).min(tail.len()));
        rest = next;
        decoder.decode_with(read, &mut sink);
    }
}

struct Sink {
    closed: bool,
}

impl Sink {
    fn event(&self) {
        assert!(!self.closed, "an event after a connection error");
    }
}

impl FrameHandler for Sink {
    fn on_data(&mut self, _: StreamId, payload: &[u8], padded_len: usize, _: bool) {
        self.event();
        assert!(
            payload.len() <= padded_len,
            "more payload than the frame carried"
        );
    }
    fn on_frame(&mut self, _: FrameKind, _: StreamId, _: u32, _: u8) {
        self.event();
    }
    fn on_preface(&mut self) {
        self.event();
    }
    fn on_headers(&mut self, headers: Box<Headers>) {
        self.event();
        // Reached the way a stream reads its head.
        let _ = headers.pseudo();
        for (name, value) in headers.fields() {
            let _ = (name.as_str(), value.as_bytes());
        }
    }
    fn on_settings(&mut self, _: bool, settings: SettingsIter<'_>) {
        self.event();
        settings.for_each(drop);
    }
    fn on_window_update(&mut self, _: StreamId, _: u32) {
        self.event();
    }
    fn on_rst_stream(&mut self, _: StreamId, _: u32) {
        self.event();
    }
    fn on_ping(&mut self, _: bool, _: [u8; 8]) {
        self.event();
    }
    fn on_goaway(&mut self, _: StreamId, _: u32, _: &[u8]) {
        self.event();
    }
    fn on_error(&mut self, err: DecodeError) {
        self.event();
        if let DecodeError::Connection { .. } = err {
            self.closed = true;
        }
    }
}

/// What `cargo fuzz` kept under `fuzz/corpus/`, through the same targets: run
/// under Miri, the fuzzer's strangest inputs go through the `unsafe` it cannot
/// see into, mimalloc hiding the heap from ASan. `FUZZ_REPLAY_EVERY=<n>`
/// takes one input in `n`, Miri being slow.
#[cfg(test)]
#[test]
#[ignore = "needs a corpus: cargo +nightly fuzz run"]
fn replays_the_fuzz_corpus() {
    let every: usize =
        std::env::var("FUZZ_REPLAY_EVERY").map_or(1, |n| n.parse().expect("a number"));
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    let targets = [
        ("hpack_decode", hpack_decode as fn(&[u8])),
        ("frames", frames),
    ];
    for (target, run) in targets {
        let mut inputs: Vec<_> = std::fs::read_dir(corpus.join(target))
            .unwrap_or_else(|e| panic!("{target}: {e}"))
            .map(|entry| entry.unwrap().path())
            .collect();
        inputs.sort();
        for path in inputs.iter().step_by(every) {
            let data = std::fs::read(path).unwrap();
            if std::panic::catch_unwind(|| run(&data)).is_err() {
                panic!("{target}: {} fails", path.display());
            }
        }
        eprintln!("{target}: {} inputs replayed", inputs.len().div_ceil(every));
    }
}
