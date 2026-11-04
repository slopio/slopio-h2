use crate::shared::codec::ext::Protocol;
use crate::shared::codec::frames::head::Head;
use crate::shared::codec::frames::stream_id::StreamId;
use crate::shared::hpack::{self, BytesStr, Error};

use slopio::http::header;
use slopio::http::{HeaderMap, Method, StatusCode};

use slopio::bytes::BytesMut;

use std::io::Cursor;

#[derive(Eq, PartialEq, Debug)]
pub struct Headers {
    stream_id: StreamId,

    stream_dep: Option<StreamDependency>,

    header_block: HeaderBlock,

    flags: HeadersFlag,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct StreamDependency {
    pub dependency_id: StreamId,
    pub weight: u8,
    pub exclusive: bool,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct HeadersFlag(u8);

// TODO: These fields shouldn't be `pub`
#[derive(Debug, Default, Eq, PartialEq)]
pub struct Pseudo {
    // Request
    pub method: Option<Method>,
    pub scheme: Option<BytesStr>,
    pub authority: Option<BytesStr>,
    pub path: Option<BytesStr>,
    pub protocol: Option<Protocol>,

    // Response
    pub status: Option<StatusCode>,
}

#[derive(Debug, PartialEq, Eq)]
struct HeaderBlock {
    fields: HeaderMap,

    field_size: usize,

    is_over_size: bool,

    pseudo: Pseudo,
}

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

impl Headers {
    pub fn load(head: Head, mut src: BytesMut) -> Result<(Self, BytesMut), Error> {
        let flags = HeadersFlag(head.flag());
        let mut pad = 0;

        if head.stream_id().is_zero() {
            return Err(Error::InvalidStreamId);
        }

        if flags.is_padded() {
            if src.is_empty() {
                return Err(Error::MalformedMessage);
            }
            pad = src[0] as usize;

            src.advance(1);
        }

        let stream_dep = if flags.is_priority() {
            if src.len() < 5 {
                return Err(Error::MalformedMessage);
            }
            let (dependency_id, exclusive) = StreamId::parse(&src[..4]);
            let weight = src[4];
            src.advance(5);
            Some(StreamDependency {
                dependency_id,
                weight,
                exclusive,
            })
        } else {
            None
        };

        if pad > 0 {
            if pad > src.len() {
                return Err(Error::TooMuchPadding);
            }

            let len = src.len() - pad;
            src.truncate(len);
        }

        let headers = Headers {
            stream_id: head.stream_id(),
            stream_dep,
            header_block: HeaderBlock {
                fields: HeaderMap::new(),
                field_size: 0,
                is_over_size: false,
                pseudo: Pseudo::default(),
            },
            flags,
        };

        Ok((headers, src))
    }

    pub fn load_hpack(
        &mut self,
        src: &mut BytesMut,
        max_header_list_size: usize,
        decoder: &mut hpack::Decoder,
    ) -> Result<(), Error> {
        self.header_block.load(src, max_header_list_size, decoder)
    }

    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    pub fn stream_dep(&self) -> Option<&StreamDependency> {
        self.stream_dep.as_ref()
    }

    pub fn is_end_headers(&self) -> bool {
        self.flags.is_end_headers()
    }

    pub fn is_end_stream(&self) -> bool {
        self.flags.is_end_stream()
    }

    pub fn is_over_size(&self) -> bool {
        self.header_block.is_over_size
    }

    pub fn pseudo(&self) -> &Pseudo {
        &self.header_block.pseudo
    }

    pub fn fields(&self) -> &HeaderMap {
        &self.header_block.fields
    }

    pub fn into_fields(self) -> HeaderMap {
        self.header_block.fields
    }
}

impl HeadersFlag {
    pub fn is_end_stream(&self) -> bool {
        self.0 & END_STREAM == END_STREAM
    }

    pub fn is_end_headers(&self) -> bool {
        self.0 & END_HEADERS == END_HEADERS
    }

    pub fn is_padded(&self) -> bool {
        self.0 & PADDED == PADDED
    }

    pub fn is_priority(&self) -> bool {
        self.0 & PRIORITY == PRIORITY
    }
}

impl HeaderBlock {
    fn load(
        &mut self,
        src: &mut BytesMut,
        max_header_list_size: usize,
        decoder: &mut hpack::Decoder,
    ) -> Result<(), Error> {
        let mut reg = !self.fields.is_empty();
        let mut malformed = false;
        let mut headers_size = self.calculate_header_list_size();

        macro_rules! set_pseudo {
            ($field:ident, $val:expr) => {{
                if reg {
                    malformed = true;
                } else if self.pseudo.$field.is_some() {
                    malformed = true;
                } else {
                    let __val = $val;
                    headers_size +=
                        decoded_header_size(stringify!($field).len() + 1, __val.as_str().len());
                    if headers_size < max_header_list_size {
                        self.pseudo.$field = Some(__val);
                    } else if !self.is_over_size {
                        self.is_over_size = true;
                    }
                }
            }};
        }

        let mut cursor = Cursor::new(src);

        // A malformed block is a stream error, but HPACK state is
        // connection-level: decoding must still complete for other streams.
        let res = decoder.decode(&mut cursor, |header| {
            use crate::shared::hpack::Header::*;

            match header {
                Field { name, value } => {
                    // Connection-specific fields must be a protocol error;
                    // `te` may stay only as `trailers`.
                    if name == header::CONNECTION
                        || name == header::TRANSFER_ENCODING
                        || name == header::UPGRADE
                        || name == "keep-alive"
                        || name == "proxy-connection"
                        || (name == header::TE && value != "trailers")
                    {
                        malformed = true;
                    } else {
                        reg = true;

                        let size = decoded_header_size(name.as_str().len(), value.len());
                        headers_size += size;
                        // `append` panics past the 24 576 names a `HeaderMap`
                        // holds, which a large enough `max_header_list_size`
                        // lets a peer reach.
                        if headers_size < max_header_list_size
                            && self.fields.try_append(name, value).is_ok()
                        {
                            self.field_size += size;
                        } else if !self.is_over_size {
                            self.is_over_size = true;
                        }
                    }
                }
                Authority(v) => set_pseudo!(authority, v),
                Method(v) => set_pseudo!(method, v),
                Scheme(v) => set_pseudo!(scheme, v),
                Path(v) => set_pseudo!(path, v),
                Protocol(v) => set_pseudo!(protocol, v),
                Status(v) => set_pseudo!(status, v),
            }
        });

        match res {
            // §8.2.1/§8.1.1: a stream error. The decoder ran the block to its
            // end first, so the table the other streams need is intact.
            Err(hpack::DecoderError::InvalidField) => malformed = true,
            Err(e) => return Err(e.into()),
            Ok(()) => {}
        }

        if malformed {
            return Err(Error::MalformedMessage);
        }

        Ok(())
    }

    /// SETTINGS_MAX_HEADER_LIST_SIZE: uncompressed name + value + 32 octets per field.
    fn calculate_header_list_size(&self) -> usize {
        macro_rules! pseudo_size {
            ($name:ident) => {{
                self.pseudo
                    .$name
                    .as_ref()
                    .map(|m| decoded_header_size(stringify!($name).len() + 1, m.as_str().len()))
                    .unwrap_or(0)
            }};
        }

        pseudo_size!(method)
            + pseudo_size!(scheme)
            + pseudo_size!(status)
            + pseudo_size!(authority)
            + pseudo_size!(path)
            + self.field_size
    }
}

fn decoded_header_size(name: usize, value: usize) -> usize {
    name + value + 32
}

/// RFC 9110 §8.6: `1*DIGIT` with no upper bound, so accumulation is checked
/// rather than allowed to wrap. A repeated field is legal only if every value
/// agrees.
pub fn content_length(fields: &HeaderMap) -> Result<Option<u64>, ()> {
    let mut declared: Option<u64> = None;

    for value in fields.get_all(header::CONTENT_LENGTH) {
        let digits = value.as_bytes();
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(());
        }

        let mut len: u64 = 0;
        for digit in digits {
            len = len
                .checked_mul(10)
                .and_then(|n| n.checked_add((digit - b'0') as u64))
                .ok_or(())?;
        }

        if declared.is_some_and(|first| first != len) {
            return Err(());
        }
        declared = Some(len);
    }

    Ok(declared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shared::codec::frames::head::Kind;
    use slopio::http;

    /// A `HeaderMap` holds `MAX_SIZE` values. With a limit this large the
    /// list is within it, so the map is what runs out.
    #[test]
    fn a_list_past_what_a_header_map_holds_is_over_size_not_a_panic() {
        let fields = http::header::MAX_SIZE as u32 + 1;
        let mut block = Vec::new();
        for i in 0..fields {
            // Literal without indexing, new name: four letters, no value.
            block.extend_from_slice(&[0x00, 4]);
            block.extend((0..4).map(|k| b'a' + (i / 26u32.pow(k) % 26) as u8));
            block.push(0);
        }
        let head = Head::new(Kind::Headers, END_HEADERS, StreamId::from(1));
        let (mut headers, mut src) = Headers::load(head, BytesMut::from(&block[..])).unwrap();

        let limit = 1 << 21;
        assert!(fields as usize * decoded_header_size(4, 0) < limit);
        headers
            .load_hpack(&mut src, limit, &mut hpack::Decoder::default())
            .expect("an over-size list is not malformed");
        assert!(headers.is_over_size());
    }
}
