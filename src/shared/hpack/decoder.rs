use crate::shared::hpack::Error;

use super::{Header, header::BytesStr, huffman};
use crate::shared::codec::ext::Protocol;

use http::header::{self, HeaderName, HeaderValue};
use http::method::{self, Method};
use http::status::{self, StatusCode};
use runtime::bytes::{Bytes, BytesMut};

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Cursor;
use std::str::Utf8Error;

#[derive(Debug)]
pub struct Decoder {
    /// Largest dynamic-table size the peer may set (what we advertise as
    /// SETTINGS_HEADER_TABLE_SIZE).
    last_max_update: usize,
    /// §2.3.2: connection state — depends on every block the peer has sent.
    table: Table,
}

/// Shared per worker, not per connection. Neither arena holds anything
/// *between* calls: the slices handed out keep the memory alive.
///
/// Slices from different connections therefore live in one allocation. Each
/// holds only its own range and `Bytes` gives no way to reach a neighbour, so
/// this affects when memory is released, not who can read what. A live header
/// set can pin at most one chunk.
#[derive(Debug)]
struct Scratch {
    buffer: BytesMut,
    input: BytesMut,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = const {
        RefCell::new(Scratch {
            buffer: BytesMut::new(),
            input: BytesMut::new(),
        })
    };
}

/// Taken out of the thread-local rather than borrowed, so no `RefCell` guard
/// is alive while the caller's callback runs (a callback that decoded would
/// panic). `Drop` puts it back however the decode ends.
struct Lent(BytesMut);

impl Lent {
    fn take() -> Self {
        Self(SCRATCH.with(|scratch| std::mem::take(&mut scratch.borrow_mut().buffer)))
    }
}

impl Drop for Lent {
    fn drop(&mut self) {
        SCRATCH.with(|scratch| scratch.borrow_mut().buffer = std::mem::take(&mut self.0));
    }
}

/// A refill unit, not a limit. Nothing is compacted — that would move bytes
/// live `Bytes` point at. A larger block takes a chunk of its own size, capped
/// by the frame decoder at `max_header_block_size`.
const STAGE_CAPACITY: usize = 4096;

/// §A: entries 1 to 61; the dynamic table starts at 62.
const STATIC_LEN: usize = 61;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DecoderError {
    InvalidRepresentation,
    InvalidIntegerPrefix,
    InvalidTableIndex,
    InvalidHuffmanCode,
    /// §8.2.1, §8.3. Not a decompression failure: the block was decoded to its
    /// end and the table is in sync, so only the message is malformed.
    InvalidField,
    InvalidMaxDynamicSize,
    IntegerOverflow,
    NeedMore(NeedMore),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NeedMore {
    UnexpectedEndOfStream,
    IntegerUnderflow,
    StringUnderflow,
}

enum Representation {
    Indexed,
    LiteralWithIndexing,
    LiteralWithoutIndexing,
    /// §6.2.3: intermediaries MUST use the same representation for encoding it.
    LiteralNeverIndexed,
    SizeUpdate,
}

#[derive(Debug)]
struct Table {
    entries: VecDeque<Entry>,
    size: usize,
    max_size: usize,
}

/// HPACK indexes what the peer sent, not what HTTP accepts: a field we refuse
/// still takes its place in the table, or every later index points one off.
#[derive(Debug, Clone)]
enum Entry {
    Field(Header),
    Invalid { name: Bytes, value: Bytes },
}

impl Entry {
    fn new(name: Bytes, value: Bytes) -> Entry {
        match Header::new(&name, &value) {
            Ok(header) => Entry::Field(header),
            Err(_) => Entry::Invalid { name, value },
        }
    }

    fn with_value(&self, value: Bytes) -> Entry {
        match self {
            Entry::Field(header) => match header.name().into_entry(&value) {
                Ok(header) => Entry::Field(header),
                Err(_) => Entry::Invalid {
                    name: Bytes::copy_from_slice(header.name().as_slice()),
                    value,
                },
            },
            Entry::Invalid { name, .. } => Entry::new(name.clone(), value),
        }
    }

    /// A copy that owns its bytes, for the table. A decoded string is a slice
    /// of a chunk shared with whatever was staged or decoded beside it, and a
    /// table entry lives as long as the connection: as a slice, a 43-byte
    /// `:authority` held a padded frame's whole 16 KiB chunk, a table's worth
    /// of them about 1.5 MB. Ordinary fields are slices too; a standard name
    /// is a constant and needs no copy.
    fn detached(&self) -> Entry {
        let owned = |value: &BytesStr| BytesStr::from(value.as_str());
        match self {
            Entry::Field(Header::Field { name, value }) => Entry::Field(Header::Field {
                name: HeaderName::from_lowercase(name.as_ref()).expect("was a lowercase name"),
                value: HeaderValue::from_bytes(value.as_bytes()).expect("was a header value"),
            }),
            Entry::Field(Header::Authority(value)) => Entry::Field(Header::Authority(owned(value))),
            Entry::Field(Header::Scheme(value)) => Entry::Field(Header::Scheme(owned(value))),
            Entry::Field(Header::Path(value)) => Entry::Field(Header::Path(owned(value))),
            Entry::Field(Header::Protocol(value)) => {
                Entry::Field(Header::Protocol(Protocol::from(value.as_str())))
            }
            Entry::Field(header) => Entry::Field(header.clone()),
            Entry::Invalid { name, value } => Entry::Invalid {
                name: Bytes::copy_from_slice(name),
                value: Bytes::copy_from_slice(value),
            },
        }
    }

    /// §4.1: whether we accepted it or not.
    fn len(&self) -> usize {
        match self {
            Entry::Field(header) => header.len(),
            Entry::Invalid { name, value } => 32 + name.len() + value.len(),
        }
    }
}

struct StringMarker {
    offset: usize,
    len: usize,
    string: Option<Bytes>,
}

impl Decoder {
    pub fn new(size: usize) -> Decoder {
        Decoder {
            last_max_update: size,
            table: Table::new(size),
        }
    }

    pub fn stage(&mut self, payload: &[u8]) -> BytesMut {
        SCRATCH.with(|scratch| {
            // Too little left and the chunk is let go rather than grown:
            // whatever was carved from it holds it alive.
            let input = &mut scratch.borrow_mut().input;
            if input.capacity() < payload.len() {
                *input = BytesMut::with_capacity(payload.len().max(STAGE_CAPACITY));
            }
            input.extend_from_slice(payload);
            input.split()
        })
    }

    pub fn decode<F>(&mut self, src: &mut Cursor<&mut BytesMut>, f: F) -> Result<(), DecoderError>
    where
        F: FnMut(Header),
    {
        // Where the last whole representation ends. The cursor is committed
        // once, there or at the end, rather than after every field: a block
        // decoded only in part resumes from it.
        let mut done = 0;
        let res = self.decode_representations(src, &mut done, f);
        let end = if res.is_ok() { src.position() } else { done };
        src.get_mut().advance(end as usize);
        src.set_position(0);

        match res? {
            true => Err(DecoderError::InvalidField),
            false => Ok(()),
        }
    }

    /// Whether a field was refused. `done` follows the cursor past each
    /// whole representation; taking a literal's bytes resets the cursor, so
    /// it is relative to wherever the block starts by then.
    fn decode_representations<F>(
        &mut self,
        src: &mut Cursor<&mut BytesMut>,
        done: &mut u64,
        mut f: F,
    ) -> Result<bool, DecoderError>
    where
        F: FnMut(Header),
    {
        use self::Representation::*;

        let mut huff = Lent::take();
        let mut can_resize = true;
        // A refused field does not stop the decode: what follows it still
        // has to reach the table.
        let mut invalid = false;
        macro_rules! emit {
            ($entry:expr) => {
                match $entry {
                    Entry::Field(header) => f(header),
                    Entry::Invalid { .. } => invalid = true,
                }
            };
        }

        while let Some(ty) = peek_u8(src) {
            // Always at the start of a representation here.
            match Representation::load(ty)? {
                Indexed => {
                    can_resize = false;
                    // Made straight into the callback's argument rather than
                    // moved there through an `Entry`.
                    match decode_int(src, 7)? {
                        index @ 1..=STATIC_LEN => f(get_static(index)),
                        index => match self.table.dynamic(index)? {
                            Entry::Field(header) => f(header.clone()),
                            Entry::Invalid { .. } => invalid = true,
                        },
                    }
                }
                LiteralWithIndexing => {
                    can_resize = false;
                    let entry = self.decode_literal(src, true, &mut huff.0)?;

                    self.table.insert(entry.detached());

                    emit!(entry);
                }
                LiteralWithoutIndexing => {
                    can_resize = false;
                    let entry = self.decode_literal(src, false, &mut huff.0)?;
                    emit!(entry);
                }
                LiteralNeverIndexed => {
                    can_resize = false;
                    let entry = self.decode_literal(src, false, &mut huff.0)?;

                    // TODO: Track that this should never be indexed

                    emit!(entry);
                }
                SizeUpdate => {
                    if !can_resize {
                        return Err(DecoderError::InvalidMaxDynamicSize);
                    }

                    self.process_size_update(src)?;
                }
            }
            *done = src.position();
        }

        Ok(invalid)
    }

    fn process_size_update(&mut self, buf: &mut Cursor<&mut BytesMut>) -> Result<(), DecoderError> {
        let new_size = decode_int(buf, 5)?;

        if new_size > self.last_max_update {
            return Err(DecoderError::InvalidMaxDynamicSize);
        }

        self.table.set_max_size(new_size);

        Ok(())
    }

    fn decode_literal(
        &mut self,
        buf: &mut Cursor<&mut BytesMut>,
        index: bool,
        huff: &mut BytesMut,
    ) -> Result<Entry, DecoderError> {
        let prefix = if index { 6 } else { 4 };

        let table_idx = decode_int(buf, prefix)?;

        if table_idx == 0 {
            let old_pos = buf.position();
            let name_marker = self.try_decode_string(buf, huff)?;
            let value_marker = self.try_decode_string(buf, huff)?;
            buf.set_position(old_pos);
            let name = name_marker.consume(buf);
            let value = value_marker.consume(buf);
            Ok(Entry::new(name, value))
        } else {
            // Borrowed, not cloned: only its name is wanted.
            let e = self.table.get(table_idx)?;
            let value = self.decode_string(buf, huff)?;

            Ok(e.with_value(value))
        }
    }

    fn try_decode_string(
        &self,
        buf: &mut Cursor<&mut BytesMut>,
        arena: &mut BytesMut,
    ) -> Result<StringMarker, DecoderError> {
        let old_pos = buf.position();
        const HUFF_FLAG: u8 = 0b1000_0000;

        let huff = match peek_u8(buf) {
            Some(hdr) => (hdr & HUFF_FLAG) == HUFF_FLAG,
            None => return Err(DecoderError::NeedMore(NeedMore::UnexpectedEndOfStream)),
        };

        let len = decode_int(buf, 7)?;

        if len > rest(buf).len() {
            return Err(DecoderError::NeedMore(NeedMore::StringUnderflow));
        }

        let offset = (buf.position() - old_pos) as usize;
        if huff {
            let ret = {
                let raw = &rest(buf)[..len];
                huffman::decode(raw, arena).map(|buf| StringMarker {
                    offset,
                    len,
                    string: Some(BytesMut::freeze(buf)),
                })
            };

            skip(buf, len);
            ret
        } else {
            skip(buf, len);
            Ok(StringMarker {
                offset,
                len,
                string: None,
            })
        }
    }

    fn decode_string(
        &self,
        buf: &mut Cursor<&mut BytesMut>,
        huff: &mut BytesMut,
    ) -> Result<Bytes, DecoderError> {
        let old_pos = buf.position();
        let marker = self.try_decode_string(buf, huff)?;
        buf.set_position(old_pos);
        Ok(marker.consume(buf))
    }
}

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new(4096)
    }
}

impl Representation {
    pub fn load(byte: u8) -> Result<Representation, DecoderError> {
        const INDEXED: u8 = 0b1000_0000;
        const LITERAL_WITH_INDEXING: u8 = 0b0100_0000;
        const LITERAL_WITHOUT_INDEXING: u8 = 0b1111_0000;
        const LITERAL_NEVER_INDEXED: u8 = 0b0001_0000;
        const SIZE_UPDATE_MASK: u8 = 0b1110_0000;
        const SIZE_UPDATE: u8 = 0b0010_0000;

        if byte & INDEXED == INDEXED {
            Ok(Representation::Indexed)
        } else if byte & LITERAL_WITH_INDEXING == LITERAL_WITH_INDEXING {
            Ok(Representation::LiteralWithIndexing)
        } else if byte & LITERAL_WITHOUT_INDEXING == 0 {
            Ok(Representation::LiteralWithoutIndexing)
        } else if byte & LITERAL_WITHOUT_INDEXING == LITERAL_NEVER_INDEXED {
            Ok(Representation::LiteralNeverIndexed)
        } else if byte & SIZE_UPDATE_MASK == SIZE_UPDATE {
            Ok(Representation::SizeUpdate)
        } else {
            Err(DecoderError::InvalidRepresentation)
        }
    }
}

fn decode_int<T: AsRef<[u8]>>(buf: &mut Cursor<T>, prefix_size: u8) -> Result<usize, DecoderError> {
    // Bounds the value (~2^28 at 5 octets) so it can never overflow a u32.
    const MAX_BYTES: usize = 5;
    const VARINT_MASK: u8 = 0b0111_1111;
    const VARINT_FLAG: u8 = 0b1000_0000;

    if !(1..=8).contains(&prefix_size) {
        return Err(DecoderError::InvalidIntegerPrefix);
    }

    let Some(first) = next_u8(buf) else {
        return Err(DecoderError::NeedMore(NeedMore::IntegerUnderflow));
    };

    let mask = if prefix_size == 8 {
        0xFF
    } else {
        (1u8 << prefix_size).wrapping_sub(1)
    };

    let mut ret = (first & mask) as usize;

    if ret < mask as usize {
        return Ok(ret);
    }

    let mut bytes = 1;

    let mut shift = 0;

    while let Some(b) = next_u8(buf) {
        bytes += 1;
        ret += ((b & VARINT_MASK) as usize) << shift;
        shift += 7;

        if b & VARINT_FLAG == 0 {
            return Ok(ret);
        }

        if bytes == MAX_BYTES {
            // The spec requires that this situation is an error
            return Err(DecoderError::IntegerOverflow);
        }
    }

    Err(DecoderError::NeedMore(NeedMore::IntegerUnderflow))
}

fn peek_u8<T: AsRef<[u8]>>(buf: &Cursor<T>) -> Option<u8> {
    rest(buf).first().copied()
}

fn next_u8<T: AsRef<[u8]>>(buf: &mut Cursor<T>) -> Option<u8> {
    let b = peek_u8(buf)?;
    skip(buf, 1);
    Some(b)
}

/// What is left of the block past the cursor.
fn rest<T: AsRef<[u8]>>(buf: &Cursor<T>) -> &[u8] {
    let block = buf.get_ref().as_ref();
    &block[(buf.position() as usize).min(block.len())..]
}

fn skip<T>(buf: &mut Cursor<T>, n: usize) {
    buf.set_position(buf.position() + n as u64);
}

fn take(buf: &mut Cursor<&mut BytesMut>, n: usize) -> Bytes {
    let pos = buf.position() as usize;
    let mut head = buf.get_mut().split_to(pos + n);
    buf.set_position(0);
    head.advance(pos);
    head.freeze()
}

impl StringMarker {
    fn consume(self, buf: &mut Cursor<&mut BytesMut>) -> Bytes {
        skip(buf, self.offset);
        match self.string {
            Some(string) => {
                skip(buf, self.len);
                string
            }
            None => take(buf, self.len),
        }
    }
}

impl Table {
    fn new(max_size: usize) -> Table {
        Table {
            entries: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    #[cfg(test)]
    fn size(&self) -> usize {
        self.size
    }

    /// §2.3.3: 1-indexed, static entries then dynamic, one address space.
    fn get(&self, index: usize) -> Result<Cow<'_, Entry>, DecoderError> {
        match index {
            0 => Err(DecoderError::InvalidTableIndex),
            1..=STATIC_LEN => Ok(Cow::Owned(Entry::Field(get_static(index)))),
            _ => self.dynamic(index).map(Cow::Borrowed),
        }
    }

    /// A dynamic entry, by its index in the one address space: 62 and up.
    fn dynamic(&self, index: usize) -> Result<&Entry, DecoderError> {
        index
            .checked_sub(STATIC_LEN + 1)
            .and_then(|i| self.entries.get(i))
            .ok_or(DecoderError::InvalidTableIndex)
    }

    fn insert(&mut self, entry: Entry) {
        let len = entry.len();

        self.reserve(len);

        if self.size + len <= self.max_size {
            self.size += len;

            self.entries.push_front(entry);
        }
    }

    fn set_max_size(&mut self, size: usize) {
        self.max_size = size;
        self.consolidate();
    }

    fn reserve(&mut self, size: usize) {
        while self.size + size > self.max_size {
            match self.entries.pop_back() {
                Some(last) => {
                    self.size -= last.len();
                }
                None => return,
            }
        }
    }

    fn consolidate(&mut self) {
        while self.size > self.max_size {
            {
                let last = match self.entries.back() {
                    Some(x) => x,
                    None => {
                        // Can never happen as the size of the table must reach
                        // 0 by the time we've exhausted all elements.
                        panic!("Size of table != 0, but no headers left!");
                    }
                };

                self.size -= last.len();
            }

            self.entries.pop_back();
        }
    }
}

impl From<Utf8Error> for DecoderError {
    fn from(_: Utf8Error) -> DecoderError {
        DecoderError::InvalidField
    }
}

impl From<header::InvalidHeaderValue> for DecoderError {
    fn from(_: header::InvalidHeaderValue) -> DecoderError {
        DecoderError::InvalidField
    }
}

impl From<header::InvalidHeaderName> for DecoderError {
    fn from(_: header::InvalidHeaderName) -> DecoderError {
        DecoderError::InvalidField
    }
}

impl From<method::InvalidMethod> for DecoderError {
    fn from(_: method::InvalidMethod) -> DecoderError {
        DecoderError::InvalidField
    }
}

impl From<status::InvalidStatusCode> for DecoderError {
    fn from(_: status::InvalidStatusCode) -> DecoderError {
        DecoderError::InvalidField
    }
}

impl From<DecoderError> for Error {
    fn from(src: DecoderError) -> Self {
        Error::Hpack(src)
    }
}

pub fn get_static(idx: usize) -> Header {
    use http::header::HeaderValue;

    match idx {
        1 => Header::Authority(BytesStr::from_static("")),
        2 => Header::Method(Method::GET),
        3 => Header::Method(Method::POST),
        4 => Header::Path(BytesStr::from_static("/")),
        5 => Header::Path(BytesStr::from_static("/index.html")),
        6 => Header::Scheme(BytesStr::from_static("http")),
        7 => Header::Scheme(BytesStr::from_static("https")),
        8 => Header::Status(StatusCode::OK),
        9 => Header::Status(StatusCode::NO_CONTENT),
        10 => Header::Status(StatusCode::PARTIAL_CONTENT),
        11 => Header::Status(StatusCode::NOT_MODIFIED),
        12 => Header::Status(StatusCode::BAD_REQUEST),
        13 => Header::Status(StatusCode::NOT_FOUND),
        14 => Header::Status(StatusCode::INTERNAL_SERVER_ERROR),
        15 => Header::Field {
            name: header::ACCEPT_CHARSET,
            value: HeaderValue::from_static(""),
        },
        16 => Header::Field {
            name: header::ACCEPT_ENCODING,
            value: HeaderValue::from_static("gzip, deflate"),
        },
        17 => Header::Field {
            name: header::ACCEPT_LANGUAGE,
            value: HeaderValue::from_static(""),
        },
        18 => Header::Field {
            name: header::ACCEPT_RANGES,
            value: HeaderValue::from_static(""),
        },
        19 => Header::Field {
            name: header::ACCEPT,
            value: HeaderValue::from_static(""),
        },
        20 => Header::Field {
            name: header::ACCESS_CONTROL_ALLOW_ORIGIN,
            value: HeaderValue::from_static(""),
        },
        21 => Header::Field {
            name: header::AGE,
            value: HeaderValue::from_static(""),
        },
        22 => Header::Field {
            name: header::ALLOW,
            value: HeaderValue::from_static(""),
        },
        23 => Header::Field {
            name: header::AUTHORIZATION,
            value: HeaderValue::from_static(""),
        },
        24 => Header::Field {
            name: header::CACHE_CONTROL,
            value: HeaderValue::from_static(""),
        },
        25 => Header::Field {
            name: header::CONTENT_DISPOSITION,
            value: HeaderValue::from_static(""),
        },
        26 => Header::Field {
            name: header::CONTENT_ENCODING,
            value: HeaderValue::from_static(""),
        },
        27 => Header::Field {
            name: header::CONTENT_LANGUAGE,
            value: HeaderValue::from_static(""),
        },
        28 => Header::Field {
            name: header::CONTENT_LENGTH,
            value: HeaderValue::from_static(""),
        },
        29 => Header::Field {
            name: header::CONTENT_LOCATION,
            value: HeaderValue::from_static(""),
        },
        30 => Header::Field {
            name: header::CONTENT_RANGE,
            value: HeaderValue::from_static(""),
        },
        31 => Header::Field {
            name: header::CONTENT_TYPE,
            value: HeaderValue::from_static(""),
        },
        32 => Header::Field {
            name: header::COOKIE,
            value: HeaderValue::from_static(""),
        },
        33 => Header::Field {
            name: header::DATE,
            value: HeaderValue::from_static(""),
        },
        34 => Header::Field {
            name: header::ETAG,
            value: HeaderValue::from_static(""),
        },
        35 => Header::Field {
            name: header::EXPECT,
            value: HeaderValue::from_static(""),
        },
        36 => Header::Field {
            name: header::EXPIRES,
            value: HeaderValue::from_static(""),
        },
        37 => Header::Field {
            name: header::FROM,
            value: HeaderValue::from_static(""),
        },
        38 => Header::Field {
            name: header::HOST,
            value: HeaderValue::from_static(""),
        },
        39 => Header::Field {
            name: header::IF_MATCH,
            value: HeaderValue::from_static(""),
        },
        40 => Header::Field {
            name: header::IF_MODIFIED_SINCE,
            value: HeaderValue::from_static(""),
        },
        41 => Header::Field {
            name: header::IF_NONE_MATCH,
            value: HeaderValue::from_static(""),
        },
        42 => Header::Field {
            name: header::IF_RANGE,
            value: HeaderValue::from_static(""),
        },
        43 => Header::Field {
            name: header::IF_UNMODIFIED_SINCE,
            value: HeaderValue::from_static(""),
        },
        44 => Header::Field {
            name: header::LAST_MODIFIED,
            value: HeaderValue::from_static(""),
        },
        45 => Header::Field {
            name: header::LINK,
            value: HeaderValue::from_static(""),
        },
        46 => Header::Field {
            name: header::LOCATION,
            value: HeaderValue::from_static(""),
        },
        47 => Header::Field {
            name: header::MAX_FORWARDS,
            value: HeaderValue::from_static(""),
        },
        48 => Header::Field {
            name: header::PROXY_AUTHENTICATE,
            value: HeaderValue::from_static(""),
        },
        49 => Header::Field {
            name: header::PROXY_AUTHORIZATION,
            value: HeaderValue::from_static(""),
        },
        50 => Header::Field {
            name: header::RANGE,
            value: HeaderValue::from_static(""),
        },
        51 => Header::Field {
            name: header::REFERER,
            value: HeaderValue::from_static(""),
        },
        52 => Header::Field {
            name: header::REFRESH,
            value: HeaderValue::from_static(""),
        },
        53 => Header::Field {
            name: header::RETRY_AFTER,
            value: HeaderValue::from_static(""),
        },
        54 => Header::Field {
            name: header::SERVER,
            value: HeaderValue::from_static(""),
        },
        55 => Header::Field {
            name: header::SET_COOKIE,
            value: HeaderValue::from_static(""),
        },
        56 => Header::Field {
            name: header::STRICT_TRANSPORT_SECURITY,
            value: HeaderValue::from_static(""),
        },
        57 => Header::Field {
            name: header::TRANSFER_ENCODING,
            value: HeaderValue::from_static(""),
        },
        58 => Header::Field {
            name: header::USER_AGENT,
            value: HeaderValue::from_static(""),
        },
        59 => Header::Field {
            name: header::VARY,
            value: HeaderValue::from_static(""),
        },
        60 => Header::Field {
            name: header::VIA,
            value: HeaderValue::from_static(""),
        },
        61 => Header::Field {
            name: header::WWW_AUTHENTICATE,
            value: HeaderValue::from_static(""),
        },
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod arena {
    use super::*;

    /// The huffman arena is shared by every connection on the worker.
    #[test]
    fn a_failed_huffman_string_leaves_nothing_for_the_next_decoder() {
        fn block(huffman: &[u8]) -> BytesMut {
            // `:method GET`, `:scheme https`, then `:path` as a literal
            // without indexing (name index 4), huffman-coded.
            let mut block = BytesMut::from(&[0x82, 0x87, 0x04, 0x80 | huffman.len() as u8][..]);
            block.extend_from_slice(huffman);
            block
        }

        // Valid codes for "/admin?x=", then EOS: decodes nine bytes and fails.
        let mut poisoned = Vec::new();
        huffman::encode(b"/admin?x=", &mut poisoned);
        poisoned.extend_from_slice(&[0xff; 5]);
        let mut attacker = Decoder::new(4096);
        let mut buf = block(&poisoned);
        assert!(attacker.decode(&mut Cursor::new(&mut buf), |_| {}).is_err());

        let mut honest = Vec::new();
        huffman::encode(b"/ok", &mut honest);
        let mut victim = Decoder::new(4096);
        let mut buf = block(&honest);
        let mut path = None;
        victim
            .decode(&mut Cursor::new(&mut buf), |header| {
                if let Header::Path(value) = header {
                    path = Some(value.as_str().to_owned());
                }
            })
            .expect("a valid block decodes");
        assert_eq!(path.as_deref(), Some("/ok"));
    }

    #[test]
    fn two_decoders_carve_from_the_same_chunk() {
        let mut one = Decoder::new(4096);
        let mut two = Decoder::new(4096);

        let first = one.stage(&[1, 2, 3, 4]);
        let second = two.stage(&[5, 6, 7, 8]);

        assert_eq!(
            first.as_ptr() as usize + first.len(),
            second.as_ptr() as usize,
            "the second block begins where the first ended"
        );
    }

    #[test]
    fn a_full_chunk_is_replaced_and_what_it_lent_survives() {
        let mut de = Decoder::new(4096);

        let block = vec![b'a'; 1000];
        let mut kept: Vec<BytesMut> = Vec::new();
        for _ in 0..4 {
            kept.push(de.stage(&block));
        }

        let after = de.stage(&vec![b'b'; 1000]);
        assert_ne!(
            kept[0].as_ptr() as usize + 4000,
            after.as_ptr() as usize,
            "a fresh chunk, not the tail of the old one"
        );

        for slice in &kept {
            assert!(slice.iter().all(|&b| b == b'a'), "the old chunk is intact");
        }
        assert!(after.iter().all(|&b| b == b'b'));

        drop(kept);
        assert!(after.iter().all(|&b| b == b'b'));
    }

    #[test]
    fn a_block_larger_than_the_refill_size_gets_its_own_chunk() {
        let mut de = Decoder::new(4096);
        let big = vec![b'z'; STAGE_CAPACITY * 3];

        let staged = de.stage(&big);
        assert_eq!(staged.len(), STAGE_CAPACITY * 3);
        assert!(staged.iter().all(|&b| b == b'z'));
    }
}

#[cfg(test)]
mod rfc7541;

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_peek_u8() {
        let b = 0xff;
        let mut buf = Cursor::new(vec![b]);
        assert_eq!(peek_u8(&buf), Some(b));
        assert_eq!(next_u8(&mut buf), Some(b));
        assert_eq!(peek_u8(&buf), None);
    }

    #[test]
    fn test_decode_string_empty() {
        let de = Decoder::new(0);
        let mut buf = BytesMut::new();
        let mut huff = BytesMut::new();
        let err = de
            .decode_string(&mut Cursor::new(&mut buf), &mut huff)
            .unwrap_err();
        assert_eq!(err, DecoderError::NeedMore(NeedMore::UnexpectedEndOfStream));
    }

    #[test]
    fn test_decode_empty() {
        let mut de = Decoder::new(0);
        let mut buf = BytesMut::new();
        let _: () = de.decode(&mut Cursor::new(&mut buf), |_| {}).unwrap();
    }

    #[test]
    fn test_decode_indexed_larger_than_table() {
        let mut de = Decoder::new(0);

        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0b01000000, 0x80 | 2]);
        buf.extend_from_slice(&huff_encode(b"foo"));
        buf.extend_from_slice(&[0x80 | 3]);
        buf.extend_from_slice(&huff_encode(b"bar"));

        let mut res = vec![];
        de.decode(&mut Cursor::new(&mut buf), |h| {
            res.push(h);
        })
        .unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(de.table.size(), 0);

        match res[0] {
            Header::Field {
                ref name,
                ref value,
            } => {
                assert_eq!(name, "foo");
                assert_eq!(value, "bar");
            }
            _ => panic!(),
        }
    }

    fn huff_encode(src: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        huffman::encode(src, &mut buf);
        buf
    }

    /// A field is a view on the block it came in, not a copy; what the table
    /// keeps for later blocks owns its bytes.
    #[test]
    fn a_field_shares_the_block_and_the_table_copies_it() {
        let mut de = Decoder::new(4096);
        let mut buf = BytesMut::new();
        // Literal with indexing, new name, neither Huffman-coded.
        buf.extend_from_slice(&[0b0100_0000, 5]);
        buf.extend_from_slice(b"x-foo");
        buf.extend_from_slice(&[3]);
        buf.extend_from_slice(b"bar");
        let block = buf.as_ptr_range();

        let mut fields = Vec::new();
        de.decode(&mut Cursor::new(&mut buf), |h| fields.push(h))
            .unwrap();
        let [Header::Field { name, value }] = &fields[..] else {
            panic!("{fields:?}");
        };
        assert!(block.contains(&value.as_bytes().as_ptr()), "a view");
        assert!(block.contains(&name.as_str().as_ptr()), "a view");

        let Ok(Entry::Field(Header::Field { value: kept, .. })) = de.table.dynamic(62) else {
            panic!("indexed");
        };
        assert_eq!(kept, value);
        assert!(!block.contains(&kept.as_bytes().as_ptr()), "a copy");
    }

    #[test]
    fn test_decode_continuation_header_with_non_huff_encoded_name() {
        let mut de = Decoder::new(0);
        let value = huff_encode(b"bar");
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[0b01000000, 3]);
        buf.extend(b"foo");
        buf.extend_from_slice(&[0x80 | 3]);
        buf.extend(&value[0..1]);

        let mut res = vec![];
        let e = de
            .decode(&mut Cursor::new(&mut buf), |h| {
                res.push(h);
            })
            .unwrap_err();
        assert_eq!(e, DecoderError::NeedMore(NeedMore::StringUnderflow));

        buf.extend(&value[1..]);
        de.decode(&mut Cursor::new(&mut buf), |h| {
            res.push(h);
        })
        .unwrap();

        assert_eq!(res.len(), 1);
        assert_eq!(de.table.size(), 0);

        match res[0] {
            Header::Field {
                ref name,
                ref value,
            } => {
                assert_eq!(name, "foo");
                assert_eq!(value, "bar");
            }
            _ => panic!(),
        }
    }

    /// The whole fields before the cut are decoded once: resuming starts
    /// after them, past a literal whose bytes moved the start of the block.
    #[test]
    fn resuming_a_cut_block_skips_its_whole_fields() {
        let mut de = Decoder::new(4096);
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&indexed_literal(b"foo", b"bar"));
        buf.extend_from_slice(&[0x82]); // :method GET
        let last = indexed_literal(b"baz", b"qux");
        buf.extend(&last[..last.len() - 1]);

        let mut fields = vec![];
        let e = de
            .decode(&mut Cursor::new(&mut buf), |h| fields.push(h))
            .unwrap_err();
        assert_eq!(e, DecoderError::NeedMore(NeedMore::StringUnderflow));
        assert_eq!(fields.len(), 2);

        buf.extend(&last[last.len() - 1..]);
        de.decode(&mut Cursor::new(&mut buf), |h| fields.push(h))
            .unwrap();
        assert!(buf.is_empty());

        let names: Vec<_> = fields
            .iter()
            .map(|h| match h {
                Header::Field { name, value } => format!("{}: {}", name, value.to_str().unwrap()),
                Header::Method(m) => format!(":method: {m}"),
                _ => panic!("unexpected {h:?}"),
            })
            .collect();
        assert_eq!(names, ["foo: bar", ":method: GET", "baz: qux"]);
        assert_eq!(de.table.size(), 2 * (32 + 6));
    }

    fn decode_block(de: &mut Decoder, block: &[u8]) -> (Vec<Header>, Result<(), DecoderError>) {
        let mut buf = BytesMut::from(block);
        let mut fields = vec![];
        let res = de.decode(&mut Cursor::new(&mut buf), |h| fields.push(h));
        (fields, res)
    }

    fn indexed_literal(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut block = vec![0x40, name.len() as u8];
        block.extend_from_slice(name);
        block.push(value.len() as u8);
        block.extend_from_slice(value);
        block
    }

    /// Otherwise the peer's indexes and ours part ways.
    #[test]
    fn a_refused_field_still_takes_its_place_in_the_table() {
        let mut de = Decoder::new(4096);

        let mut block = indexed_literal(b"x-bad", b"a\rb");
        block.extend(indexed_literal(b"x-good", b"ok"));
        let (fields, res) = decode_block(&mut de, &block);
        assert_eq!(res, Err(DecoderError::InvalidField));
        assert_eq!(fields.len(), 1, "the good field after it was still decoded");
        assert_eq!(de.table.size(), (32 + 5 + 3) + (32 + 6 + 2));

        // 62 is the newest entry, 63 the one before it.
        let (fields, res) = decode_block(&mut de, &[0x80 | 62]);
        assert_eq!(res, Ok(()));
        assert!(matches!(&fields[..], [Header::Field { name, .. }] if name == "x-good"));

        let (_, res) = decode_block(&mut de, &[0x80 | 63]);
        assert_eq!(res, Err(DecoderError::InvalidField));

        // Name index 63 overflows the 4-bit prefix: 15, then 48.
        let (fields, res) = decode_block(&mut de, &[0x0f, 48, 4, b'f', b'i', b'n', b'e']);
        assert_eq!(res, Ok(()));
        assert!(
            matches!(&fields[..], [Header::Field { name, value }] if name == "x-bad" && value == "fine")
        );
    }

    #[test]
    fn a_table_entry_owns_its_bytes() {
        let raw = indexed_literal(b":authority", b"example.com");
        // Name index 1, `:authority`; the value huffman-coded, so decoded
        // into the worker's arena rather than sliced from the block.
        let coded = huff_encode(b"example.com");
        let mut huffman = vec![0x41, 0x80 | coded.len() as u8];
        huffman.extend_from_slice(&coded);

        for block in [raw, huffman] {
            let mut de = Decoder::new(4096);
            let (fields, res) = decode_block(&mut de, &block);
            assert_eq!(res, Ok(()));
            let [Header::Authority(given)] = &fields[..] else {
                panic!("{fields:?}");
            };
            let Ok(Entry::Field(Header::Authority(kept))) = de.table.dynamic(62) else {
                panic!("the entry is in the table");
            };
            assert_eq!(kept.as_str(), "example.com");
            assert_ne!(
                kept.as_str().as_ptr(),
                given.as_str().as_ptr(),
                "a copy, not a slice of the chunk the block was decoded from"
            );
        }
    }

    #[test]
    fn fields_http_refuses_are_invalid_fields() {
        let refused: [&[u8]; 8] = [
            // `:path` with CR LF, name index 4, literal without indexing.
            &[
                0x04, 9, b'/', b'a', b'\r', b'\n', b'X', b':', b' ', b'y', b'\0',
            ],
            // `:authority` with a space, name index 1.
            &[0x01, 3, b'a', b' ', b'b'],
            // An uppercase name.
            &[0x00, 3, b'X', b'-', b'a', 1, b'y'],
            // An unknown pseudo-header.
            &[0x00, 4, b':', b'f', b'o', b'o', 1, b'y'],
            // A value with NUL.
            &[0x00, 1, b'x', 3, b'a', 0, b'b'],
            // A value with whitespace at either end.
            &[0x00, 1, b'x', 2, b' ', b'y'],
            &[0x00, 1, b'x', 2, b'y', b'\t'],
            // An empty name.
            &[0x00, 0, 1, b'y'],
        ];
        for block in refused {
            let (fields, res) = decode_block(&mut Decoder::new(4096), block);
            assert_eq!(res, Err(DecoderError::InvalidField), "{block:02x?}");
            assert!(fields.is_empty(), "{block:02x?}: {fields:?}");
        }
    }

    /// There is no telling where the next field starts.
    #[test]
    fn a_bad_encoding_is_not_an_invalid_field() {
        // `:path`, huffman-coded, as a lone EOS.
        let (_, res) = decode_block(
            &mut Decoder::new(4096),
            &[0x04, 0x84, 0xff, 0xff, 0xff, 0xff],
        );
        assert_eq!(res, Err(DecoderError::InvalidHuffmanCode));
    }
}
