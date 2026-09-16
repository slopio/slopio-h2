use crate::shared::codec::ext::Protocol;
use crate::shared::codec::frames::head::Head;
use crate::shared::codec::frames::stream_id::StreamId;
use crate::shared::hpack::{self, BytesStr, Error};

use http::header;
use http::{HeaderMap, Method, StatusCode};

use bytes::{Buf, BytesMut};

use std::io::Cursor;

/// Header frame
///
/// This could be either a request or a response.
#[derive(Eq, PartialEq, Debug)]
pub struct Headers {
    /// The ID of the stream with which this frame is associated.
    stream_id: StreamId,

    /// The stream dependency information, if any.
    stream_dep: Option<StreamDependency>,

    /// The header block fragment
    header_block: HeaderBlock,

    /// The associated flags
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
    /// The decoded header fields
    fields: HeaderMap,

    /// Precomputed size of all of our header fields, for perf reasons
    field_size: usize,

    /// Set to true if decoding went over the max header list size.
    is_over_size: bool,

    /// Pseudo headers, these are broken out as they must be sent as part of the
    /// headers frame.
    pseudo: Pseudo,
}

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;

// ===== impl Headers =====

impl Headers {
    /// Loads the header frame but doesn't actually do HPACK decoding.
    ///
    /// HPACK decoding is done in the `load_hpack` step.
    pub fn load(head: Head, mut src: BytesMut) -> Result<(Self, BytesMut), Error> {
        let flags = HeadersFlag(head.flag());
        let mut pad = 0;

        if head.stream_id().is_zero() {
            return Err(Error::InvalidStreamId);
        }

        // Read the padding length
        if flags.is_padded() {
            if src.is_empty() {
                return Err(Error::MalformedMessage);
            }
            pad = src[0] as usize;

            // Drop the padding
            src.advance(1);
        }

        // Parse priority data if present (5 bytes: 4-byte stream dependency + 1-byte weight)
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

// ===== impl HeadersFlag =====

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

// ===== HeaderBlock =====

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

        // If the header frame is malformed, we still have to continue decoding
        // the headers. A malformed header frame is a stream level error, but
        // the hpack state is connection level. In order to maintain correct
        // state for other streams, the hpack decoding process must complete.
        let res = decoder.decode(&mut cursor, |header| {
            use crate::shared::hpack::Header::*;

            match header {
                Field { name, value } => {
                    // Connection level header fields are not supported and must
                    // result in a protocol error.

                    if name == header::CONNECTION
                        || name == header::TRANSFER_ENCODING
                        || name == header::UPGRADE
                        || name == "keep-alive"
                        || name == "proxy-connection"
                    {
                        malformed = true;
                    } else if name == header::TE && value != "trailers" {
                        malformed = true;
                    } else {
                        reg = true;

                        headers_size += decoded_header_size(name.as_str().len(), value.len());
                        if headers_size < max_header_list_size {
                            self.field_size +=
                                decoded_header_size(name.as_str().len(), value.len());
                            self.fields.append(name, value);
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

        if let Err(e) = res {
            return Err(e.into());
        }

        if malformed {
            return Err(Error::MalformedMessage);
        }

        Ok(())
    }

    /// Calculates the size of the currently decoded header list.
    ///
    /// According to http://httpwg.org/specs/rfc7540.html#SETTINGS_MAX_HEADER_LIST_SIZE
    ///
    /// > The value is based on the uncompressed size of header fields,
    /// > including the length of the name and value in octets plus an
    /// > overhead of 32 octets for each header field.
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
