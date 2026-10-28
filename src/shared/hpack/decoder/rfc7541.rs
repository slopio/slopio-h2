//! RFC 7541 Appendix C: blocks another encoder wrote, Huffman-coded or not,
//! with the header lists and dynamic tables they must decode to. The round
//! trip in `round_trip.rs` cannot catch a mistake the encoder and decoder
//! share; these can.

use super::*;
use crate::shared::hpack::Encoder;

use http::header::{HeaderName, HeaderValue};

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
