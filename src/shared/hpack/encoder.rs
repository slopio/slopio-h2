use super::table::{Index, Table, static_status};
use super::{Header, huffman};

use http::header::{HeaderName, HeaderValue};

#[derive(Debug)]
pub struct Encoder {
    table: Table,
    size_update: Option<SizeUpdate>,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum SizeUpdate {
    One(usize),
    Two(usize, usize), // min, max
}

impl Encoder {
    pub fn new(max_size: usize, capacity: usize) -> Encoder {
        Encoder {
            table: Table::new(max_size, capacity),
            size_update: None,
        }
    }

    pub fn index_paths(&mut self, on: bool) {
        self.table.index_paths(on);
    }

    /// The next call to `encode` will include a dynamic size update.
    pub fn update_max_size(&mut self, val: usize) {
        match self.size_update {
            Some(SizeUpdate::One(old)) => {
                if val > old {
                    if old > self.table.max_size() {
                        self.size_update = Some(SizeUpdate::One(val));
                    } else {
                        self.size_update = Some(SizeUpdate::Two(old, val));
                    }
                } else {
                    self.size_update = Some(SizeUpdate::One(val));
                }
            }
            Some(SizeUpdate::Two(min, _)) => {
                if val < min {
                    self.size_update = Some(SizeUpdate::One(val));
                } else {
                    self.size_update = Some(SizeUpdate::Two(min, val));
                }
            }
            None => {
                if val != self.table.max_size() {
                    self.size_update = Some(SizeUpdate::One(val));
                }
            }
        }
    }

    pub fn encode<I>(&mut self, headers: I, dst: &mut Vec<u8>)
    where
        I: IntoIterator<Item = Header<Option<HeaderName>>>,
    {
        self.encode_size_updates(dst);

        let mut last_index = None;

        for header in headers {
            // One byte, with nothing to look up or index: what most
            // responses start with.
            if let Header::Status(status) = header
                && let Some(n) = static_status(status)
            {
                encode_int(n, 7, 0x80, dst);
                continue;
            }

            match header.reify() {
                Ok(header) => {
                    let index = self.table.index(header);
                    self.encode_header(&index, dst);

                    last_index = Some(index);
                }
                // No name: same as the previous header's, so reuse its index.
                Err(value) => {
                    self.encode_header_without_name(
                        last_index.as_ref().unwrap_or_else(|| {
                            panic!("encoding header without name, but no previous index to use for name");
                        }),
                        &value,
                        dst,
                    );
                }
            }
        }
    }

    fn encode_size_updates(&mut self, dst: &mut Vec<u8>) {
        match self.size_update.take() {
            Some(SizeUpdate::One(val)) => {
                self.table.resize(val);
                encode_size_update(val, dst);
            }
            Some(SizeUpdate::Two(min, max)) => {
                self.table.resize(min);
                self.table.resize(max);
                encode_size_update(min, dst);
                encode_size_update(max, dst);
            }
            None => {}
        }
    }

    fn encode_header(&mut self, index: &Index, dst: &mut Vec<u8>) {
        match *index {
            Index::Indexed(idx, _) => {
                encode_int(idx, 7, 0x80, dst);
            }
            Index::Name(idx, _) => {
                let header = self.table.resolve(index);

                encode_not_indexed(idx, header.value_slice(), header.is_sensitive(), dst);
            }
            Index::Inserted(_) => {
                let header = self.table.resolve(index);

                assert!(!header.is_sensitive());

                dst.push(0b0100_0000);

                encode_str(header.name().as_slice(), dst);
                encode_str(header.value_slice(), dst);
            }
            Index::InsertedValue(idx, _) => {
                let header = self.table.resolve(index);

                assert!(!header.is_sensitive());

                encode_int(idx, 6, 0b0100_0000, dst);
                encode_str(header.value_slice(), dst);
            }
            Index::NotIndexed(_) => {
                let header = self.table.resolve(index);

                encode_not_indexed2(
                    header.name().as_slice(),
                    header.value_slice(),
                    header.is_sensitive(),
                    dst,
                );
            }
        }
    }

    fn encode_header_without_name(&mut self, last: &Index, value: &HeaderValue, dst: &mut Vec<u8>) {
        match *last {
            Index::Indexed(..)
            | Index::Name(..)
            | Index::Inserted(..)
            | Index::InsertedValue(..) => {
                let idx = self.table.resolve_idx(last);

                encode_not_indexed(idx, value.as_ref(), value.is_sensitive(), dst);
            }
            Index::NotIndexed(_) => {
                let last = self.table.resolve(last);

                encode_not_indexed2(
                    last.name().as_slice(),
                    value.as_ref(),
                    value.is_sensitive(),
                    dst,
                );
            }
        }
    }
}

impl Default for Encoder {
    fn default() -> Encoder {
        Encoder::new(4096, 0)
    }
}

fn encode_size_update(val: usize, dst: &mut Vec<u8>) {
    encode_int(val, 5, 0b0010_0000, dst)
}

fn encode_not_indexed(name: usize, value: &[u8], sensitive: bool, dst: &mut Vec<u8>) {
    if sensitive {
        encode_int(name, 4, 0b10000, dst);
    } else {
        encode_int(name, 4, 0, dst);
    }

    encode_str(value, dst);
}

fn encode_not_indexed2(name: &[u8], value: &[u8], sensitive: bool, dst: &mut Vec<u8>) {
    if sensitive {
        dst.push(0b10000);
    } else {
        dst.push(0);
    }

    encode_str(name, dst);
    encode_str(value, dst);
}

fn encode_str(val: &[u8], dst: &mut Vec<u8>) {
    if !val.is_empty() {
        let idx = position(dst);

        dst.push(0);

        huffman::encode(val, dst);

        let huff_len = position(dst) - (idx + 1);

        if encode_int_one_byte(huff_len, 7) {
            dst[idx] = 0x80 | huff_len as u8;
        } else {
            // The length goes after the string, then moves in front of it,
            // over the placeholder.
            let end = position(dst);
            encode_int(huff_len, 7, 0x80, dst);
            let head_len = position(dst) - end;
            dst[idx..].rotate_right(head_len);
            dst.remove(idx + head_len);
        }
    } else {
        dst.push(0);
    }
}

fn encode_int(mut value: usize, prefix_bits: usize, first_byte: u8, dst: &mut Vec<u8>) {
    if encode_int_one_byte(value, prefix_bits) {
        dst.push(first_byte | value as u8);
        return;
    }

    let low = (1 << prefix_bits) - 1;

    value -= low;

    dst.push(first_byte | low as u8);

    while value >= 128 {
        dst.push(0b1000_0000 | value as u8);

        value >>= 7;
    }

    dst.push(value as u8);
}

fn encode_int_one_byte(value: usize, prefix_bits: usize) -> bool {
    value < (1 << prefix_bits) - 1
}

fn position(buf: &[u8]) -> usize {
    buf.len()
}

#[cfg(test)]
mod test {
    use super::*;
    use http::*;
    use runtime::bytes::BytesMut;

    #[test]
    fn test_encode_method_get() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(*res, [0x80 | 2]);
        assert_eq!(encoder.table.len(), 0);
    }

    #[test]
    fn test_encode_method_post() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("POST")]);
        assert_eq!(*res, [0x80 | 3]);
        assert_eq!(encoder.table.len(), 0);
    }

    #[test]
    fn test_encode_method_patch() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![method("PATCH")]);

        assert_eq!(res[0], 0b01000000 | 2); // Incremental indexing w/ name pulled from table
        assert_eq!(res[1], 0x80 | 5); // header value w/ huffman coding

        assert_eq!(huff_decode(&res[2..7]), "PATCH");
        assert_eq!(encoder.table.len(), 1);

        let res = encode(&mut encoder, vec![method("PATCH")]);

        assert_eq!(1 << 7 | 62, res[0]);
        assert_eq!(1, res.len());
    }

    #[test]
    fn test_encode_indexed_name_literal_value() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("content-language", "foo")]);

        assert_eq!(res[0], 0b01000000 | 27); // Indexed name
        assert_eq!(res[1], 0x80 | 2); // header value w/ huffman coding

        assert_eq!(huff_decode(&res[2..4]), "foo");

        let res = encode(&mut encoder, vec![header("content-language", "bar")]);
        assert_eq!(res[0], 0b01000000 | 27); // Indexed name
        assert_eq!(res[1], 0x80 | 3); // header value w/ huffman coding
        assert_eq!(huff_decode(&res[2..5]), "bar");
    }

    #[test]
    fn test_repeated_headers_are_indexed() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("foo", "hello")]);

        assert_eq!(&[0b01000000, 0x80 | 2], &res[0..2]);
        assert_eq!(huff_decode(&res[2..4]), "foo");
        assert_eq!(0x80 | 4, res[4]);
        assert_eq!(huff_decode(&res[5..]), "hello");
        assert_eq!(9, res.len());

        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "hello")]);
        assert_eq!([0x80 | 62], *res);

        assert_eq!(encoder.table.len(), 1);
    }

    #[test]
    fn test_evicting_headers() {
        let mut encoder = Encoder::default();

        for i in 0..64 {
            let key = format!("x-hello-world-{:02}", i);
            let res = encode(&mut encoder, vec![header(&key, &key)]);

            assert_eq!(&[0b01000000, 0x80 | 12], &res[0..2]);
            assert_eq!(huff_decode(&res[2..14]), key.as_str());
            assert_eq!(0x80 | 12, res[14]);
            assert_eq!(huff_decode(&res[15..]), key.as_str());
            assert_eq!(27, res.len());

            let res = encode(&mut encoder, vec![header(&key, &key)]);

            assert_eq!(0x80, res[0] & 0x80);
        }

        assert_eq!(4096, encoder.table.size());
        assert_eq!(64, encoder.table.len());

        for i in 0..64 {
            let key = format!("x-hello-world-{:02}", i);
            let res = encode(&mut encoder, vec![header(&key, &key)]);
            assert_eq!(0x80, res[0] & 0x80);
        }

        let key = "x-hello-world-64";
        let res = encode(&mut encoder, vec![header(key, key)]);

        assert_eq!(&[0b01000000, 0x80 | 12], &res[0..2]);
        assert_eq!(huff_decode(&res[2..14]), key);
        assert_eq!(0x80 | 12, res[14]);
        assert_eq!(huff_decode(&res[15..]), key);
        assert_eq!(27, res.len());

        assert_eq!(64, encoder.table.len());

        for i in 1..65 {
            let key = format!("x-hello-world-{:02}", i);
            let res = encode(&mut encoder, vec![header(&key, &key)]);
            assert_eq!(0x80 | (61 + (65 - i)), res[0]);
        }
    }

    #[test]
    fn test_large_headers_are_not_indexed() {
        let mut encoder = Encoder::new(128, 0);
        let key = "hello-world-hello-world-HELLO-zzz";

        let res = encode(&mut encoder, vec![header(key, key)]);

        assert_eq!(&[0, 0x80 | 25], &res[..2]);

        assert_eq!(0, encoder.table.len());
        assert_eq!(0, encoder.table.size());
    }

    /// From 127 bytes a string's length takes several bytes, written after
    /// it and moved in front.
    #[test]
    fn a_long_value_decodes_back() {
        let value = "0123456789".repeat(30);
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("x-long", &value)]);
        assert!(res.len() > 128 + 8, "a length of several bytes");

        let mut buf = BytesMut::from(&res[..]);
        let mut decoded = Vec::new();
        crate::shared::hpack::Decoder::default()
            .decode(&mut std::io::Cursor::new(&mut buf), |h| decoded.push(h))
            .unwrap();
        match &decoded[..] {
            [Header::Field { name, value: got }] => {
                assert_eq!(name, "x-long");
                assert_eq!(got.as_bytes(), value.as_bytes());
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_sensitive_headers_are_never_indexed() {
        use http::header::HeaderValue;

        let name = "my-password".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };

        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b10000, 0x80 | 8], &res[..2]);
        assert_eq!(huff_decode(&res[2..10]), "my-password");
        assert_eq!(0x80 | 4, res[10]);
        assert_eq!(huff_decode(&res[11..]), "12345");

        // A sensitive header with a name in the static table.
        let name = "authorization".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };

        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b11111, 8], &res[..2]);
        assert_eq!(0x80 | 4, res[2]);
        assert_eq!(huff_decode(&res[3..]), "12345");

        // The name of a previously indexed header, without the sensitive flag.
        let _ = encode(
            &mut encoder,
            vec![self::header("my-password", "not-so-secret")],
        );

        let name = "my-password".parse().unwrap();
        let mut value = HeaderValue::from_bytes(b"12345").unwrap();
        value.set_sensitive(true);

        let header = Header::Field {
            name: Some(name),
            value,
        };
        let res = encode(&mut encoder, vec![header]);

        assert_eq!(&[0b11111, 47], &res[..2]);
        assert_eq!(0x80 | 4, res[2]);
        assert_eq!(huff_decode(&res[3..]), "12345");
    }

    #[test]
    fn test_content_length_value_not_indexed() {
        let mut encoder = Encoder::default();
        let res = encode(&mut encoder, vec![header("content-length", "1234")]);

        assert_eq!(&[15, 13, 0x80 | 3], &res[0..3]);
        assert_eq!(huff_decode(&res[3..]), "1234");
        assert_eq!(6, res.len());
    }

    #[test]
    fn test_encoding_headers_with_same_name() {
        let mut encoder = Encoder::default();
        let name = "hello";

        let _ = encode(&mut encoder, vec![header(name, "one")]);

        let res = encode(&mut encoder, vec![header(name, "two")]);
        assert_eq!(&[0x40 | 62, 0x80 | 3], &res[0..2]);
        assert_eq!(huff_decode(&res[2..]), "two");
        assert_eq!(5, res.len());

        let res = encode(&mut encoder, vec![header(name, "one")]);
        assert_eq!(&[0x80 | 63], &res[..]);

        let res = encode(&mut encoder, vec![header(name, "two")]);
        assert_eq!(&[0x80 | 62], &res[..]);
    }

    #[test]
    fn test_evicting_headers_when_multiple_of_same_name_are_in_table() {
        // The encoder only has space for 2 headers
        let mut encoder = Encoder::new(76, 0);

        let _ = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(1, encoder.table.len());

        let _ = encode(&mut encoder, vec![header("bar", "foo")]);
        assert_eq!(2, encoder.table.len());

        // This will evict the first header, while still referencing the header
        // name
        let res = encode(&mut encoder, vec![header("foo", "baz")]);
        assert_eq!(&[0x40 | 63, 0, 0x80 | 3], &res[..3]);
        assert_eq!(2, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "baz")]);
        assert_eq!(&[0x80 | 62], &res[..]);
        assert_eq!(2, encoder.table.len());
    }

    #[test]
    fn test_max_size_zero() {
        let mut encoder = Encoder::new(0, 0);
        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(*res, [0x80 | 2]);
        assert_eq!(encoder.table.len(), 0);

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[0, 0x80 | 2], &res[..2]);
        assert_eq!(huff_decode(&res[2..4]), "foo");
        assert_eq!(0x80 | 3, res[4]);
        assert_eq!(huff_decode(&res[5..8]), "bar");
        assert_eq!(0, encoder.table.len());

        let res = encode(&mut encoder, vec![header("transfer-encoding", "chunked")]);
        assert_eq!(&[15, 42, 0x80 | 6], &res[..3]);
        assert_eq!(huff_decode(&res[3..]), "chunked");
    }

    #[test]
    fn test_update_max_size_combos() {
        let mut encoder = Encoder::default();
        assert!(encoder.size_update.is_none());
        assert_eq!(4096, encoder.table.max_size());

        encoder.update_max_size(4096);
        assert!(encoder.size_update.is_none());

        encoder.update_max_size(0);
        assert_eq!(Some(SizeUpdate::One(0)), encoder.size_update);

        encoder.update_max_size(100);
        assert_eq!(Some(SizeUpdate::Two(0, 100)), encoder.size_update);

        let mut encoder = Encoder::default();
        encoder.update_max_size(8000);
        assert_eq!(Some(SizeUpdate::One(8000)), encoder.size_update);

        encoder.update_max_size(100);
        assert_eq!(Some(SizeUpdate::One(100)), encoder.size_update);

        encoder.update_max_size(8000);
        assert_eq!(Some(SizeUpdate::Two(100, 8000)), encoder.size_update);

        encoder.update_max_size(4000);
        assert_eq!(Some(SizeUpdate::Two(100, 4000)), encoder.size_update);

        encoder.update_max_size(50);
        assert_eq!(Some(SizeUpdate::One(50)), encoder.size_update);
    }

    #[test]
    fn test_resizing_table() {
        let mut encoder = Encoder::default();

        let _ = encode(&mut encoder, vec![header("foo", "bar")]);

        encoder.update_max_size(1);
        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![method("GET")]);
        assert_eq!(&[32 | 1, 0x80 | 2], &res[..]);
        assert_eq!(0, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(0, res[0]);

        encoder.update_max_size(100);
        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32 | 31, 69, 64], &res[..3]);

        encoder.update_max_size(0);
        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32, 0], &res[..2]);
    }

    #[test]
    fn test_decreasing_table_size_without_eviction() {
        let mut encoder = Encoder::default();

        let _ = encode(&mut encoder, vec![header("foo", "bar")]);

        encoder.update_max_size(100);
        assert_eq!(1, encoder.table.len());

        let res = encode(&mut encoder, vec![header("foo", "bar")]);
        assert_eq!(&[32 | 31, 69, 0x80 | 62], &res[..]);
    }

    #[test]
    fn test_nameless_header() {
        let mut encoder = Encoder::default();

        let res = encode(
            &mut encoder,
            vec![
                Header::Field {
                    name: Some("hello".parse().unwrap()),
                    value: HeaderValue::from_bytes(b"world").unwrap(),
                },
                Header::Field {
                    name: None,
                    value: HeaderValue::from_bytes(b"zomg").unwrap(),
                },
            ],
        );

        assert_eq!(&[0x40, 0x80 | 4], &res[0..2]);
        assert_eq!(huff_decode(&res[2..6]), "hello");
        assert_eq!(0x80 | 4, res[6]);
        assert_eq!(huff_decode(&res[7..11]), "world");

        // Next is not indexed
        assert_eq!(&[15, 47, 0x80 | 3], &res[11..14]);
        assert_eq!(huff_decode(&res[14..]), "zomg");
    }

    #[test]
    fn test_large_size_update() {
        let mut encoder = Encoder::default();

        encoder.update_max_size(1912930560);
        assert_eq!(Some(SizeUpdate::One(1912930560)), encoder.size_update);

        let mut dst = Vec::with_capacity(6);
        encoder.encode_size_updates(&mut dst);
        assert_eq!([63, 225, 129, 148, 144, 7], &dst[..]);
    }

    #[test]
    #[ignore]
    fn test_evicted_overflow() {
        // Not sure what the best way to do this is.
    }

    use crate::shared::hpack::BytesStr;

    #[test]
    fn a_path_is_not_indexed_by_default() {
        let mut encoder = Encoder::new(4096, 4096);
        let path = || vec![Header::Path(BytesStr::from("/helloworld.Greeter/SayHello"))];

        let first = encode(&mut encoder, path());
        let second = encode(&mut encoder, path());
        assert_eq!(
            first, second,
            "the same literal, re-encoded and re-Huffman-coded every time"
        );
        assert!(
            second.len() > 20,
            "the whole string is on the wire: {second:?}"
        );
    }

    #[test]
    fn a_repeated_path_is_indexed_when_the_caller_says_they_repeat() {
        let mut encoder = Encoder::new(4096, 4096);
        encoder.index_paths(true);
        let path = || vec![Header::Path(BytesStr::from("/helloworld.Greeter/SayHello"))];

        let first = encode(&mut encoder, path());
        let second = encode(&mut encoder, path());

        // §6.2.1: the first goes out as a literal *with* incremental indexing.
        assert!(first.len() > 20, "the first still carries the string");
        assert_eq!(
            second.len(),
            1,
            "and the second is one index byte: {second:02x?}"
        );
        assert_eq!(second[0] & 0x80, 0x80, "§6.1: an indexed field");
    }

    /// The table holds both rather than one replacing the other.
    #[test]
    fn two_repeated_paths_are_both_kept() {
        let mut encoder = Encoder::new(4096, 4096);
        encoder.index_paths(true);
        let one = || vec![Header::Path(BytesStr::from("/svc/One"))];
        let two = || vec![Header::Path(BytesStr::from("/svc/Two"))];

        encode(&mut encoder, one());
        encode(&mut encoder, two());
        assert_eq!(
            encode(&mut encoder, one()).len(),
            1,
            "the first is still there"
        );
        assert_eq!(encode(&mut encoder, two()).len(), 1, "and so is the second");
    }

    /// A status in the static table is its one-byte index; any other is a
    /// literal on the `:status` name, and both decode back.
    #[test]
    fn statuses_encode_and_decode_back() {
        let mut encoder = Encoder::default();
        assert_eq!(
            encode(&mut encoder, vec![Header::Status(StatusCode::OK)]),
            [0x88]
        );
        assert_eq!(
            encode(&mut encoder, vec![Header::Status(StatusCode::NOT_FOUND)]),
            [0x8d]
        );

        let statuses = [200, 201, 404, 418, 500, 201].map(|s| StatusCode::from_u16(s).unwrap());
        let res = encode(
            &mut encoder,
            statuses.iter().map(|&s| Header::Status(s)).collect(),
        );
        assert_eq!(res[0], 0x88);

        let mut buf = BytesMut::from(&res[..]);
        let mut decoded = Vec::new();
        crate::shared::hpack::Decoder::default()
            .decode(&mut std::io::Cursor::new(&mut buf), |h| decoded.push(h))
            .unwrap();
        let back: Vec<_> = decoded
            .iter()
            .map(|h| match h {
                Header::Status(s) => *s,
                other => panic!("{other:?}"),
            })
            .collect();
        assert_eq!(back, statuses);
    }

    fn encode(e: &mut Encoder, hdrs: Vec<Header<Option<HeaderName>>>) -> Vec<u8> {
        let mut dst = Vec::with_capacity(1024);
        e.encode(hdrs, &mut dst);
        dst
    }

    fn method(s: &str) -> Header<Option<HeaderName>> {
        Header::Method(Method::from_bytes(s.as_bytes()).unwrap())
    }

    fn header(name: &str, val: &str) -> Header<Option<HeaderName>> {
        let name = HeaderName::from_bytes(name.as_bytes()).unwrap();
        let value = HeaderValue::from_bytes(val.as_bytes()).unwrap();

        Header::Field {
            name: Some(name),
            value,
        }
    }

    fn huff_decode(src: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        huffman::decode(src, &mut buf).unwrap()
    }
}
