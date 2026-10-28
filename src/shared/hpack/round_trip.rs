//! Header lists drawn from a seed, encoded and decoded back block after block
//! on one pair of tables: what comes out must be what went in. Adapted from
//! hyperium/h2's `hpack/test/fuzz.rs` (MIT), on the simulator's seeds:
//! `DST_SEED=<n>` replays one, `DST_SEEDS=<n>` or `<a>..<b>` runs more.
//!
//! Headers are picked from a pool with a skew, so that many repeat and the
//! dynamic table is hit, filled and evicted; some blocks resize it first. A
//! block is now and then decoded in two parts, cut at a drawn byte, which
//! must give the same fields as decoding it whole.

use super::{BytesStr, Decoder, DecoderError, Encoder, Header};
use crate::dst::{Rng, seeds};

use http::header::{self, HeaderName, HeaderValue};
use http::{Method, StatusCode};
use runtime::bytes::BytesMut;

use std::io::Cursor;

/// Both the decoder's limit and the encoder's largest resize.
const MAX_TABLE: usize = 4096;

#[test]
fn encoded_blocks_decode_back() {
    for seed in seeds(256) {
        if let Err(failure) = std::panic::catch_unwind(|| run(seed)) {
            let msg = failure
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| failure.downcast_ref::<&str>().copied())
                .unwrap_or("panicked");
            panic!("seed {seed}: {msg}\nreplay with DST_SEED={seed}");
        }
    }
}

struct Block {
    resizes: Vec<usize>,
    headers: Vec<Header<Option<HeaderName>>>,
}

fn run(seed: u64) {
    let mut rng = Rng(seed);
    let mut encoder = Encoder::default();
    let mut decoder = Decoder::new(MAX_TABLE);

    for block in blocks(&mut rng) {
        let expect = named(&block.headers);

        for &size in &block.resizes {
            encoder.update_max_size(size);
        }
        let mut wire = Vec::new();
        encoder.encode(block.headers, &mut wire);

        let mut got = Vec::new();
        let mut buf = BytesMut::new();
        if rng.one_in(4) && wire.len() > 1 {
            let cut = rng.upto((1, wire.len() - 1));
            buf.extend_from_slice(&wire[..cut]);
            match decoder.decode(&mut Cursor::new(&mut buf), |h| got.push(h)) {
                Ok(()) | Err(DecoderError::NeedMore(_)) => {}
                Err(e) => panic!("cut at {cut} of {}: {e:?}", wire.len()),
            }
            buf.extend_from_slice(&wire[cut..]);
        } else {
            buf.extend_from_slice(&wire);
        }
        decoder
            .decode(&mut Cursor::new(&mut buf), |h| got.push(h))
            .expect("a whole block decodes");

        assert!(buf.is_empty(), "{} bytes left over", buf.len());
        assert_eq!(got, expect);
        decoder.assert_consistent();
    }
}

/// The list as it decodes: a field without a name has the one before it.
fn named(headers: &[Header<Option<HeaderName>>]) -> Vec<Header> {
    let mut previous = None;
    headers
        .iter()
        .map(|header| match header.clone().reify() {
            Ok(header) => {
                previous = match &header {
                    Header::Field { name, .. } => Some(name.clone()),
                    _ => None,
                };
                header
            }
            Err(value) => Header::Field {
                name: previous.clone().expect("a name before it"),
                value,
            },
        })
        .collect()
}

fn blocks(rng: &mut Rng) -> Vec<Block> {
    let pool: Vec<_> = (0..2000).map(|_| header(rng)).collect();
    // The higher, the more often the first few of the pool come back.
    let skew = rng.between(1, 4) as i32;
    let total = rng.upto((40, 500));

    let mut blocks = Vec::new();
    let mut added = 0;
    while added < total {
        let resizes = match rng.between(0, 19) {
            0 => {
                let high = rng.upto((128, MAX_TABLE));
                vec![rng.upto((0, high)), high]
            }
            1..=3 => vec![rng.upto((128, MAX_TABLE))],
            _ => vec![],
        };

        let mut headers = Vec::new();
        // A field without a name only follows a field.
        let mut after_field = false;
        for _ in 0..rng.upto((1, total - added)) {
            let x = (rng.next() as f64 / u64::MAX as f64).powi(skew);
            let picked = &pool[((x * pool.len() as f64) as usize).min(pool.len() - 1)];
            match picked {
                Header::Field { name: None, .. } if !after_field => continue,
                Header::Field { .. } => after_field = true,
                _ => after_field = false,
            }
            headers.push(picked.clone());
            added += 1;
        }
        blocks.push(Block { resizes, headers });
    }
    blocks
}

fn header(rng: &mut Rng) -> Header<Option<HeaderName>> {
    if !rng.one_in(10) {
        let name = (!rng.one_in(10)).then(|| header_name(rng));
        let mut value = HeaderValue::from_bytes(text(rng, 0, 70).as_bytes()).unwrap();
        if rng.one_in(30) {
            value.set_sensitive(true);
        }
        return Header::Field { name, value };
    }
    match rng.between(0, 4) {
        0 => Header::Authority(BytesStr::from(&text(rng, 4, 20))),
        1 => Header::Method(match rng.between(0, 5) {
            0 => Method::GET,
            1 => Method::POST,
            2 => Method::PUT,
            3 => Method::PATCH,
            4 => Method::DELETE,
            _ => {
                let token: String = (0..rng.upto((3, 6)))
                    .map(|_| (b'A' + rng.between(0, 25) as u8) as char)
                    .collect();
                Method::from_bytes(token.as_bytes()).unwrap()
            }
        }),
        2 => Header::Scheme(BytesStr::from(["http", "https"][rng.upto((0, 1))])),
        3 => Header::Path(BytesStr::from(&match rng.between(0, 99) {
            0 => "/".to_string(),
            1 => "/index.html".to_string(),
            _ => text(rng, 2, 20),
        })),
        _ => Header::Status(StatusCode::from_u16(rng.between(100, 599) as u16).unwrap()),
    }
}

fn header_name(rng: &mut Rng) -> HeaderName {
    if rng.one_in(2) {
        return STANDARD[rng.upto((0, STANDARD.len() - 1))].clone();
    }
    HeaderName::from_bytes(text(rng, 1, 25).as_bytes()).unwrap()
}

/// Letters of both cases and dashes: a valid name once lowercased, and a
/// value that Huffman coding sometimes shortens.
fn text(rng: &mut Rng, min: usize, max: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVabcdefghilpqrstuvwxyz----";
    (0..rng.upto((min, max)))
        .map(|_| CHARS[rng.upto((0, CHARS.len() - 1))] as char)
        .collect()
}

const STANDARD: &[HeaderName] = &[
    header::ACCEPT,
    header::ACCEPT_CHARSET,
    header::ACCEPT_ENCODING,
    header::ACCEPT_LANGUAGE,
    header::ACCEPT_RANGES,
    header::ACCESS_CONTROL_ALLOW_ORIGIN,
    header::AGE,
    header::ALLOW,
    header::AUTHORIZATION,
    header::CACHE_CONTROL,
    header::CONNECTION,
    header::CONTENT_DISPOSITION,
    header::CONTENT_ENCODING,
    header::CONTENT_LENGTH,
    header::CONTENT_TYPE,
    header::COOKIE,
    header::DATE,
    header::ETAG,
    header::EXPIRES,
    header::HOST,
    header::IF_MODIFIED_SINCE,
    header::IF_NONE_MATCH,
    header::LAST_MODIFIED,
    header::LOCATION,
    header::REFERER,
    header::SERVER,
    header::SET_COOKIE,
    header::STRICT_TRANSPORT_SECURITY,
    header::TE,
    header::TRANSFER_ENCODING,
    header::USER_AGENT,
    header::VARY,
    header::VIA,
    header::WWW_AUTHENTICATE,
];
