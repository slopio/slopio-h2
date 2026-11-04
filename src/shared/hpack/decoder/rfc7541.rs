//! RFC 7541 Appendix C: blocks another encoder wrote, Huffman-coded or not,
//! with the header lists and dynamic tables they must decode to. The round
//! trip in `round_trip.rs` cannot catch a mistake the encoder and decoder
//! share; these can.

use super::*;
use crate::shared::hpack::Encoder;

use slopio::http::header::{HeaderName, HeaderValue};

struct Example {
    section: &'static str,
    title: &'static str,
    wire: &'static [u8],
    headers: &'static [(&'static str, &'static str)],
    /// Newest first, as §2.3.3 numbers them: name and §4.1 size.
    table: &'static [(&'static str, usize)],
    table_size: usize,
}

include!("rfc7541_examples.rs");

/// Each C.2 example starts from an empty table. C.3 to C.6 are three blocks
/// each on one connection; the responses (C.5, C.6) use a 256-byte table.
fn connections() -> Vec<(usize, Vec<&'static Example>)> {
    let mut connections: Vec<(usize, Vec<&Example>)> = Vec::new();
    for example in EXAMPLES {
        let group = &example.section[..3];
        let same = connections
            .last()
            .is_some_and(|(_, prev)| group != "C.2" && prev[0].section.starts_with(group));
        if same {
            connections.last_mut().unwrap().1.push(example);
        } else {
            let size = if matches!(group, "C.5" | "C.6") {
                256
            } else {
                4096
            };
            connections.push((size, vec![example]));
        }
    }
    connections
}

fn text(header: &Header) -> (String, String) {
    let name = String::from_utf8(header.name().as_slice().to_vec()).unwrap();
    let value = String::from_utf8(header.value_slice().to_vec()).unwrap();
    (name, value)
}

fn expected(example: &Example) -> Vec<(String, String)> {
    let owned = |(n, v): &(&str, &str)| (n.to_string(), v.to_string());
    example.headers.iter().map(owned).collect()
}

#[test]
fn decodes_the_rfc_examples() {
    assert_eq!(EXAMPLES.len(), 16);
    for (size, examples) in connections() {
        let mut decoder = Decoder::new(size);
        for example in examples {
            let at = format!("{} {}", example.section, example.title);
            let mut buf = BytesMut::from(example.wire);
            let mut got = Vec::new();
            decoder
                .decode(&mut Cursor::new(&mut buf), |h| got.push(text(&h)))
                .unwrap_or_else(|e| panic!("{at}: {e:?}"));
            assert_eq!(got, expected(example), "{at}");

            let table: Vec<_> = decoder
                .table
                .entries
                .iter()
                .map(|entry| match entry {
                    Entry::Field(h) => (text(h).0, entry.len()),
                    Entry::Invalid { .. } => panic!("{at}: a refused entry"),
                })
                .collect();
            let want: Vec<_> = example
                .table
                .iter()
                .map(|&(n, s)| (n.to_string(), s))
                .collect();
            assert_eq!(table, want, "{at}: dynamic table");
            assert_eq!(decoder.table.size(), example.table_size, "{at}: table size");
        }
    }
}

/// Our encoder makes its own choices (Huffman, what to index), so its bytes
/// differ from the RFC's; on the same connections, they must decode back.
#[test]
fn encodes_the_rfc_header_lists_back() {
    for (size, examples) in connections() {
        let mut encoder = Encoder::new(size, 0);
        let mut decoder = Decoder::new(size);
        for example in examples {
            let at = format!("{} {}", example.section, example.title);
            let headers = example.headers.iter().map(|&(name, value)| {
                match Header::new(
                    &Bytes::from_static(name.as_bytes()),
                    &Bytes::from_static(value.as_bytes()),
                )
                .unwrap_or_else(|e| panic!("{at}: {name}: {e:?}"))
                {
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
            });
            let mut wire = Vec::new();
            encoder.encode(
                headers.collect::<Vec<Header<Option<HeaderName>>>>(),
                &mut wire,
            );

            let mut buf = BytesMut::from(&wire[..]);
            let mut got = Vec::new();
            decoder
                .decode(&mut Cursor::new(&mut buf), |h| got.push(text(&h)))
                .unwrap_or_else(|e| panic!("{at}: {e:?}"));
            assert_eq!(got, expected(example), "{at}");
        }
    }
}

/// C.1: 10 and 1337 on a 5-bit prefix, 42 on a whole octet.
#[test]
fn decodes_the_rfc_integers() {
    for (bytes, prefix, value) in [
        (&[0x0a][..], 5, 10),
        (&[0x1f, 0x9a, 0x0a], 5, 1337),
        (&[0x2a], 8, 42),
    ] {
        let mut cursor = Cursor::new(bytes);
        assert_eq!(decode_int(&mut cursor, prefix), Ok(value));
        assert_eq!(cursor.position() as usize, bytes.len());
    }
}

/// C.2.3's field is never indexed: §7.1.3 wants it kept sensitive, and an
/// encoder told so writes it that way.
#[test]
fn a_sensitive_field_is_never_indexed() {
    let mut value = HeaderValue::from_static("secret");
    value.set_sensitive(true);
    let mut wire = Vec::new();
    Encoder::default().encode(
        vec![Header::Field {
            name: Some(HeaderName::from_static("password")),
            value,
        }],
        &mut wire,
    );
    assert_eq!(wire[0] & 0xf0, 0x10, "never indexed: {wire:02x?}");
}

/// Seeds for `fuzz/`: each RFC connection as `hpack_decode` reads it, and
/// for `frames`, the request blocks (C.3, C.4) in HEADERS frames among the
/// other frame types, the way a client sends them. `cargo test --lib
/// write_rfc_fuzz_seeds -- --ignored` writes them under `fuzz/corpus/`.
#[test]
#[ignore = "writes fuzz seeds"]
fn write_rfc_fuzz_seeds() {
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/corpus");
    let hpack = corpus.join("hpack_decode");
    let frames = corpus.join("frames");
    std::fs::create_dir_all(&hpack).unwrap();
    std::fs::create_dir_all(&frames).unwrap();

    for (size, examples) in connections() {
        // The target's size byte: 1 is 256 bytes, 2 is 4096.
        let mut out = vec![if size == 256 { 1 } else { 2 }];
        for example in &examples {
            out.extend_from_slice(&(example.wire.len() as u16).to_be_bytes());
            out.extend_from_slice(example.wire);
        }
        std::fs::write(hpack.join(format!("rfc7541-{}", examples[0].section)), out).unwrap();
    }

    fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        out.extend_from_slice(&[kind, flags]);
        out.extend_from_slice(&stream.to_be_bytes());
        out.extend_from_slice(payload);
    }
    const DATA: u8 = 0;
    const HEADERS: u8 = 1;
    const PRIORITY: u8 = 2;
    const RST_STREAM: u8 = 3;
    const SETTINGS: u8 = 4;
    const PING: u8 = 6;
    const GOAWAY: u8 = 7;
    const WINDOW_UPDATE: u8 = 8;
    const CONTINUATION: u8 = 9;
    const END_STREAM: u8 = 0x1;
    const END_HEADERS: u8 = 0x4;
    const PADDED: u8 = 0x8;
    const WITH_PRIORITY: u8 = 0x20;

    for group in ["C.3", "C.4"] {
        let blocks: Vec<_> = EXAMPLES
            .iter()
            .filter(|e| e.section.starts_with(group))
            .collect();
        let mut wire = Vec::new();
        // SETTINGS_HEADER_TABLE_SIZE 4096, SETTINGS_INITIAL_WINDOW_SIZE 65535.
        frame(
            &mut wire,
            SETTINGS,
            0,
            0,
            &[0, 1, 0, 0, 0x10, 0, 0, 4, 0, 0, 0xff, 0xff],
        );
        frame(&mut wire, SETTINGS, 0x1, 0, &[]);
        frame(&mut wire, WINDOW_UPDATE, 0, 0, &1_000_000u32.to_be_bytes());
        // A whole GET.
        frame(
            &mut wire,
            HEADERS,
            END_HEADERS | END_STREAM,
            1,
            blocks[0].wire,
        );
        // A POST cut into CONTINUATION, with a padded, prioritised HEADERS and a body.
        let (head, tail) = blocks[1].wire.split_at(blocks[1].wire.len() / 2);
        let mut padded = vec![3];
        padded.extend_from_slice(&[0, 0, 0, 1, 15]);
        padded.extend_from_slice(head);
        padded.extend_from_slice(&[0; 3]);
        frame(&mut wire, HEADERS, PADDED | WITH_PRIORITY, 3, &padded);
        frame(&mut wire, CONTINUATION, END_HEADERS, 3, tail);
        frame(&mut wire, DATA, 0, 3, b"hello");
        frame(&mut wire, DATA, PADDED | END_STREAM, 3, &[2, b'!', 0, 0]);
        frame(&mut wire, HEADERS, END_HEADERS, 5, blocks[2].wire);
        frame(&mut wire, PRIORITY, 0, 5, &[0, 0, 0, 3, 7]);
        frame(&mut wire, RST_STREAM, 0, 5, &8u32.to_be_bytes());
        frame(&mut wire, PING, 0, 0, b"12345678");
        frame(&mut wire, 0xfa, 0, 0, b"an unknown type");
        frame(
            &mut wire,
            GOAWAY,
            0,
            0,
            &[0, 0, 0, 5, 0, 0, 0, 0, b'b', b'y', b'e'],
        );

        // The server side, the preface sent by the target; whole, then cut
        // into reads of 1, 7, 9, 10 and 64 bytes.
        let reads = |size: usize| {
            let mut out = vec![0];
            for chunk in wire.chunks(size) {
                out.push(chunk.len() as u8);
                out.extend_from_slice(chunk);
            }
            out
        };
        std::fs::write(frames.join(format!("rfc7541-{group}-whole")), reads(255)).unwrap();
        for size in [1, 7, 9, 10, 64] {
            std::fs::write(
                frames.join(format!("rfc7541-{group}-reads-{size}")),
                reads(size),
            )
            .unwrap();
        }
    }
}
