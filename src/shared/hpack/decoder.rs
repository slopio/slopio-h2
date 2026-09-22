use crate::shared::hpack::Error;

use super::{Header, header::BytesStr, huffman};

use bytes::{Buf, Bytes, BytesMut};
use http::header;
use http::method::{self, Method};
use http::status::{self, StatusCode};

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Cursor;
use std::str::Utf8Error;

/// Decodes headers using HPACK
#[derive(Debug)]
pub struct Decoder {
    /// Largest dynamic-table size the peer may set (what we advertise as
    /// SETTINGS_HEADER_TABLE_SIZE; fixed at the default).
    last_max_update: usize,
    /// §2.3.2: the dynamic table, which is connection state and stays here —
    /// what the peer indexes against depends on every block it has sent.
    table: Table,
}

/// The two arenas a decode carves from: one set per worker, not one per
/// connection.
///
/// Both are the same trick. An HPACK block arrives in a ring buffer that is
/// owed straight back, while the values decoded out of it must outlive the
/// request, so the block is copied once into memory we own and every field is
/// then a refcounted slice of that copy — one copy per block instead of one
/// allocation per field. [`Scratch::buffer`] does the same for huffman-coded
/// strings, which cannot be slices of the input at all because they have to be
/// decompressed somewhere.
///
/// Neither holds anything *between* calls: a decode appends and hands out
/// slices, and it is the slices that keep the memory alive. So there is nothing
/// per-connection about them — on a thread per core, no two connections decode
/// at once — and owning them per connection cost 8 KiB apiece, pinned for the
/// life of every connection whether or not it ever sent a header again. Shared,
/// that measured 20.9 KiB down to 12.9 KiB per connection at 20 000 of them:
/// 408 MB to 251 MB, for no throughput difference this machine could resolve.
///
/// What the worst case becomes is worth stating, because it is the obvious
/// objection. A live header set pins the whole chunk it was carved from, and
/// chunks are now shared, so one long-lived stream can pin bytes that other
/// connections carved beside it. The amount is bounded by the chunk, and if
/// every live header set pinned a chunk of its own, the cost would be one per
/// header set — which is exactly what is paid *today, always, per connection*.
/// The trade improves the common case and cannot lose the pathological one.
///
/// Slices from different connections therefore live in one allocation. Each
/// holds only its own range and `Bytes` hands out no way to reach a neighbour,
/// so this is a matter of when memory is released rather than of who can read
/// what.
#[derive(Debug)]
struct Scratch {
    /// Huffman output, decompressed here and split out as it is produced.
    buffer: BytesMut,
    /// Staging for the compressed header blocks, see [`Decoder::stage`].
    input: BytesMut,
}

thread_local! {
    static SCRATCH: RefCell<Scratch> = RefCell::new(Scratch {
        buffer: BytesMut::new(),
        input: BytesMut::new(),
    });
}

/// The huffman arena, borrowed for the length of one decode.
///
/// Taken out of the thread-local rather than borrowed from it, so that no
/// `RefCell` guard is alive while the caller's callback runs — a callback that
/// decoded something itself would otherwise panic, and the callback is the
/// caller's code, not ours. It goes back however the decode ends, which is what
/// the `Drop` is for: a block that fails halfway out is the common case, not an
/// exotic one.
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

/// Chunk size the header blocks are staged in.
///
/// A refill unit, not a limit: a block that does not fit in what is left of the
/// current chunk gets a fresh one, and the old chunk lives on as long as any
/// slice carved from it. Nothing is grown and nothing is compacted — compacting
/// would mean moving bytes that live `Bytes` point at. A block larger than this
/// takes a chunk of its own size; the frame decoder caps that at
/// `MAX_HEADER_BLOCK_SIZE`.
const STAGE_CAPACITY: usize = 4096;

/// Represents all errors that can be encountered while performing the decoding
/// of an HPACK header set.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DecoderError {
    InvalidRepresentation,
    InvalidIntegerPrefix,
    InvalidTableIndex,
    InvalidHuffmanCode,
    /// A field HTTP refuses (§8.2.1, §8.3): its name or its value. Unlike
    /// every other error here it is not a decompression failure — the block
    /// was decoded to its end regardless and the table is in sync — so it is
    /// the message that is malformed, not the connection.
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
    /// Indexed header field representation
    ///
    /// An indexed header field representation identifies an entry in either the
    /// static table or the dynamic table (see Section 2.3).
    ///
    /// # Header encoding
    ///
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 1 |        Index (7+)         |
    /// +---+---------------------------+
    /// ```
    Indexed,

    /// Literal Header Field with Incremental Indexing
    ///
    /// A literal header field with incremental indexing representation results
    /// in appending a header field to the decoded header list and inserting it
    /// as a new entry into the dynamic table.
    ///
    /// # Header encoding
    ///
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 1 |      Index (6+)       |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// | Value String (Length octets)  |
    /// +-------------------------------+
    /// ```
    LiteralWithIndexing,

    /// Literal Header Field without Indexing
    ///
    /// A literal header field without indexing representation results in
    /// appending a header field to the decoded header list without altering the
    /// dynamic table.
    ///
    /// # Header encoding
    ///
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 0 |  Index (4+)   |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// | Value String (Length octets)  |
    /// +-------------------------------+
    /// ```
    LiteralWithoutIndexing,

    /// Literal Header Field Never Indexed
    ///
    /// A literal header field never-indexed representation results in appending
    /// a header field to the decoded header list without altering the dynamic
    /// table. Intermediaries MUST use the same representation for encoding this
    /// header field.
    ///
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 0 | 1 |  Index (4+)   |
    /// +---+---+-----------------------+
    /// | H |     Value Length (7+)     |
    /// +---+---------------------------+
    /// | Value String (Length octets)  |
    /// +-------------------------------+
    /// ```
    LiteralNeverIndexed,

    /// Dynamic Table Size Update
    ///
    /// A dynamic table size update signals a change to the size of the dynamic
    /// table.
    ///
    /// # Header encoding
    ///
    /// ```text
    ///   0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | 0 | 0 | 1 |   Max size (5+)   |
    /// +---+---------------------------+
    /// ```
    SizeUpdate,
}

#[derive(Debug)]
struct Table {
    entries: VecDeque<Entry>,
    size: usize,
    max_size: usize,
}

/// What a dynamic-table slot holds. HPACK indexes what the peer sent, not
/// what HTTP accepts: a field we refuse still takes its place in the table,
/// or every index the peer uses after it points one entry off.
#[derive(Debug, Clone)]
enum Entry {
    Field(Header),
    /// Kept raw, for its size and for its name: the peer may reuse the name
    /// with a value that is fine.
    Invalid {
        name: Bytes,
        value: Bytes,
    },
}

impl Entry {
    fn new(name: Bytes, value: Bytes) -> Entry {
        match Header::new(&name, &value) {
            Ok(header) => Entry::Field(header),
            Err(_) => Entry::Invalid { name, value },
        }
    }

    /// The field under this entry's name with another value, as a literal
    /// with an indexed name makes.
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

    /// §4.1: name, value and 32 octets, whether we accepted it or not.
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

// ===== impl Decoder =====

impl Decoder {
    /// Creates a new `Decoder` with all settings set to default values.
    pub fn new(size: usize) -> Decoder {
        Decoder {
            last_max_update: size,
            table: Table::new(size),
        }
    }

    /// Copy a compressed header block into the staging buffer and hand out that
    /// slice, to be decoded from.
    ///
    /// A buffer per frame would cost two allocations each: the buffer, and the
    /// promotion to a shared one that the first `split_to` of the decode forces.
    /// Refilling by the chunk amortizes both over every block a chunk holds.
    pub fn stage(&mut self, payload: &[u8]) -> BytesMut {
        SCRATCH.with(|scratch| {
            // After a `split`, `capacity` is what is left of the chunk. Too
            // little for this block and the chunk is let go rather than grown:
            // whatever was carved from it holds it alive, and the copy below
            // has somewhere contiguous to land.
            let input = &mut scratch.borrow_mut().input;
            if input.capacity() < payload.len() {
                *input = BytesMut::with_capacity(payload.len().max(STAGE_CAPACITY));
            }
            input.extend_from_slice(payload);
            input.split()
        })
    }

    /// Decodes the headers found in the given buffer.
    pub fn decode<F>(
        &mut self,
        src: &mut Cursor<&mut BytesMut>,
        mut f: F,
    ) -> Result<(), DecoderError>
    where
        F: FnMut(Header),
    {
        use self::Representation::*;

        // Once per block rather than once per string: the arena comes out of
        // the thread-local here and goes back when `huff` drops.
        let mut huff = Lent::take();
        let mut can_resize = true;
        // A refused field does not stop the decode: what follows it still
        // has to reach the table. It is reported once the block is done.
        let mut invalid = false;
        let mut emit = |entry: Entry| match entry {
            Entry::Field(header) => f(header),
            Entry::Invalid { .. } => invalid = true,
        };

        while let Some(ty) = peek_u8(src) {
            // At this point we are always at the beginning of the next block
            // within the HPACK data. The type of the block can always be
            // determined from the first byte.
            match Representation::load(ty)? {
                Indexed => {
                    can_resize = false;
                    let entry = self.decode_indexed(src)?;
                    consume(src);
                    emit(entry);
                }
                LiteralWithIndexing => {
                    can_resize = false;
                    let entry = self.decode_literal(src, true, &mut huff.0)?;

                    // Insert the header into the table
                    self.table.insert(entry.clone());
                    consume(src);

                    emit(entry);
                }
                LiteralWithoutIndexing => {
                    can_resize = false;
                    let entry = self.decode_literal(src, false, &mut huff.0)?;
                    consume(src);
                    emit(entry);
                }
                LiteralNeverIndexed => {
                    can_resize = false;
                    let entry = self.decode_literal(src, false, &mut huff.0)?;
                    consume(src);

                    // TODO: Track that this should never be indexed

                    emit(entry);
                }
                SizeUpdate => {
                    if !can_resize {
                        return Err(DecoderError::InvalidMaxDynamicSize);
                    }

                    // Handle the dynamic table size update
                    self.process_size_update(src)?;
                    consume(src);
                }
            }
        }

        if invalid {
            return Err(DecoderError::InvalidField);
        }
        Ok(())
    }

    fn process_size_update(&mut self, buf: &mut Cursor<&mut BytesMut>) -> Result<(), DecoderError> {
        let new_size = decode_int(buf, 5)?;

        if new_size > self.last_max_update {
            return Err(DecoderError::InvalidMaxDynamicSize);
        }

        self.table.set_max_size(new_size);

        Ok(())
    }

    fn decode_indexed(&self, buf: &mut Cursor<&mut BytesMut>) -> Result<Entry, DecoderError> {
        let index = decode_int(buf, 7)?;
        self.table.get(index)
    }

    fn decode_literal(
        &mut self,
        buf: &mut Cursor<&mut BytesMut>,
        index: bool,
        huff: &mut BytesMut,
    ) -> Result<Entry, DecoderError> {
        let prefix = if index { 6 } else { 4 };

        // Extract the table index for the name, or 0 if not indexed
        let table_idx = decode_int(buf, prefix)?;

        // First, read the header name
        if table_idx == 0 {
            let old_pos = buf.position();
            let name_marker = self.try_decode_string(buf, huff)?;
            let value_marker = self.try_decode_string(buf, huff)?;
            buf.set_position(old_pos);
            // Read the name as a literal
            let name = name_marker.consume(buf);
            let value = value_marker.consume(buf);
            Ok(Entry::new(name, value))
        } else {
            let e = self.table.get(table_idx)?;
            let value = self.decode_string(buf, huff)?;

            Ok(e.with_value(value))
        }
    }

    fn try_decode_string(
        &mut self,
        buf: &mut Cursor<&mut BytesMut>,
        arena: &mut BytesMut,
    ) -> Result<StringMarker, DecoderError> {
        let old_pos = buf.position();
        const HUFF_FLAG: u8 = 0b1000_0000;

        // The first bit in the first byte contains the huffman encoded flag.
        let huff = match peek_u8(buf) {
            Some(hdr) => (hdr & HUFF_FLAG) == HUFF_FLAG,
            None => return Err(DecoderError::NeedMore(NeedMore::UnexpectedEndOfStream)),
        };

        // Decode the string length using 7 bit prefix
        let len = decode_int(buf, 7)?;

        if len > buf.remaining() {
            return Err(DecoderError::NeedMore(NeedMore::StringUnderflow));
        }

        let offset = (buf.position() - old_pos) as usize;
        if huff {
            let ret = {
                let raw = &buf.chunk()[..len];
                huffman::decode(raw, arena).map(|buf| StringMarker {
                    offset,
                    len,
                    string: Some(BytesMut::freeze(buf)),
                })
            };

            buf.advance(len);
            ret
        } else {
            buf.advance(len);
            Ok(StringMarker {
                offset,
                len,
                string: None,
            })
        }
    }

    fn decode_string(
        &mut self,
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

// ===== impl Representation =====

impl Representation {
    pub fn load(byte: u8) -> Result<Representation, DecoderError> {
        const INDEXED: u8 = 0b1000_0000;
        const LITERAL_WITH_INDEXING: u8 = 0b0100_0000;
        const LITERAL_WITHOUT_INDEXING: u8 = 0b1111_0000;
        const LITERAL_NEVER_INDEXED: u8 = 0b0001_0000;
        const SIZE_UPDATE_MASK: u8 = 0b1110_0000;
        const SIZE_UPDATE: u8 = 0b0010_0000;

        // TODO: What did I even write here?

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

fn decode_int<B: Buf>(buf: &mut B, prefix_size: u8) -> Result<usize, DecoderError> {
    // The octet limit is chosen such that the maximum allowed *value* can
    // never overflow an unsigned 32-bit integer. The maximum value of any
    // integer that can be encoded with 5 octets is ~2^28
    const MAX_BYTES: usize = 5;
    const VARINT_MASK: u8 = 0b0111_1111;
    const VARINT_FLAG: u8 = 0b1000_0000;

    if prefix_size < 1 || prefix_size > 8 {
        return Err(DecoderError::InvalidIntegerPrefix);
    }

    if !buf.has_remaining() {
        return Err(DecoderError::NeedMore(NeedMore::IntegerUnderflow));
    }

    let mask = if prefix_size == 8 {
        0xFF
    } else {
        (1u8 << prefix_size).wrapping_sub(1)
    };

    let mut ret = (buf.get_u8() & mask) as usize;

    if ret < mask as usize {
        // Value fits in the prefix bits
        return Ok(ret);
    }

    // The int did not fit in the prefix bits, so continue reading.
    //
    // The total number of bytes used to represent the int. The first byte was
    // the prefix, so start at 1.
    let mut bytes = 1;

    // The rest of the int is stored as a varint -- 7 bits for the value and 1
    // bit to indicate if it is the last byte.
    let mut shift = 0;

    while buf.has_remaining() {
        let b = buf.get_u8();

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

fn peek_u8<B: Buf>(buf: &B) -> Option<u8> {
    if buf.has_remaining() {
        Some(buf.chunk()[0])
    } else {
        None
    }
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
        buf.advance(self.offset);
        match self.string {
            Some(string) => {
                buf.advance(self.len);
                string
            }
            None => take(buf, self.len),
        }
    }
}

fn consume(buf: &mut Cursor<&mut BytesMut>) {
    // remove bytes from the internal BytesMut when they have been successfully
    // decoded. This is a more permanent cursor position, which will be
    // used to resume if decoding was only partial.
    take(buf, 0);
}

// ===== impl Table =====

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

    /// Returns the entry located at the given index.
    ///
    /// The table is 1-indexed and constructed in such a way that the first
    /// entries belong to the static table, followed by entries in the dynamic
    /// table. They are merged into a single index address space, though.
    ///
    /// This is according to the [HPACK spec, section 2.3.3.]
    /// (http://http2.github.io/http2-spec/compression.html#index.address.space)
    fn get(&self, index: usize) -> Result<Entry, DecoderError> {
        if index == 0 {
            return Err(DecoderError::InvalidTableIndex);
        }

        if index <= 61 {
            return Ok(Entry::Field(get_static(index)));
        }

        // Convert the index for lookup in the entries structure.
        match self.entries.get(index - 62) {
            Some(e) => Ok(e.clone()),
            None => Err(DecoderError::InvalidTableIndex),
        }
    }

    fn insert(&mut self, entry: Entry) {
        let len = entry.len();

        self.reserve(len);

        if self.size + len <= self.max_size {
            self.size += len;

            // Track the entry
            self.entries.push_front(entry);
        }
    }

    fn set_max_size(&mut self, size: usize) {
        self.max_size = size;
        // Make the table size fit within the new constraints.
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

// ===== impl DecoderError =====
//
// Every way HTTP refuses a name or a value is the same error: the answer —
// the stream is malformed — does not depend on which rule it broke.

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

/// Get an entry from the static table
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

    /// The huffman arena is the worker's, not the connection's, so a string
    /// that fails to decode on one connection must leave nothing in it: what
    /// it left would come out in front of the next string decoded on this
    /// thread, which belongs to somebody else.
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
        assert!(
            attacker
                .decode(&mut Cursor::new(&mut buf), |_| {})
                .is_err()
        );

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

    /// One chunk for every connection on the worker, which is the whole point:
    /// two decoders that know nothing of each other carve from the same
    /// allocation, one after the other.
    #[test]
    fn two_decoders_carve_from_the_same_chunk() {
        let mut one = Decoder::new(4096);
        let mut two = Decoder::new(4096);

        let first = one.stage(&[1, 2, 3, 4]);
        let second = two.stage(&[5, 6, 7, 8]);

        // Addresses rather than pointers: what is being asserted is adjacency
        // in one allocation, and comparing them as integers says exactly that
        // without reaching past either slice.
        assert_eq!(
            first.as_ptr() as usize + first.len(),
            second.as_ptr() as usize,
            "the second block begins where the first ended"
        );
    }

    /// What "the arena is full" does: nothing announces it, nothing fails, and
    /// what was lent before the rollover stays readable — those slices hold the
    /// old chunk alive themselves. Nothing is grown and nothing is compacted,
    /// because compacting would move bytes that live `Bytes` point at.
    #[test]
    fn a_full_chunk_is_replaced_and_what_it_lent_survives() {
        let mut de = Decoder::new(4096);

        let block = vec![b'a'; 1000];
        let mut kept: Vec<BytesMut> = Vec::new();
        for _ in 0..4 {
            kept.push(de.stage(&block));
        }

        // The fifth no longer fits in what is left of a 4096-byte chunk.
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

        // And the old chunk dies with its last slice, not with the rollover.
        drop(kept);
        assert!(after.iter().all(|&b| b == b'b'));
    }

    /// §6.10 lets a block outgrow the refill size; it takes a chunk of its own
    /// rather than being refused or split.
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
mod test {
    use super::*;

    #[test]
    fn test_peek_u8() {
        let b = 0xff;
        let mut buf = Cursor::new(vec![b]);
        assert_eq!(peek_u8(&buf), Some(b));
        assert_eq!(buf.get_u8(), b);
        assert_eq!(peek_u8(&buf), None);
    }

    #[test]
    fn test_decode_string_empty() {
        let mut de = Decoder::new(0);
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
        buf.extend([0b01000000, 0x80 | 2]);
        buf.extend(huff_encode(b"foo"));
        buf.extend([0x80 | 3]);
        buf.extend(huff_encode(b"bar"));

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

    fn huff_encode(src: &[u8]) -> BytesMut {
        let mut buf = BytesMut::new();
        huffman::encode(src, &mut buf);
        buf
    }

    #[test]
    fn test_decode_continuation_header_with_non_huff_encoded_name() {
        let mut de = Decoder::new(0);
        let value = huff_encode(b"bar");
        let mut buf = BytesMut::new();
        // header name is non_huff encoded
        buf.extend([0b01000000, 3]);
        buf.extend(b"foo");
        // header value is partial
        buf.extend([0x80 | 3]);
        buf.extend(&value[0..1]);

        let mut res = vec![];
        let e = de
            .decode(&mut Cursor::new(&mut buf), |h| {
                res.push(h);
            })
            .unwrap_err();
        // decode error because the header value is partial
        assert_eq!(e, DecoderError::NeedMore(NeedMore::StringUnderflow));

        // extend buf with the remaining header value
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

    /// Decodes one block, returning what it emitted and how it ended.
    fn decode_block(de: &mut Decoder, block: &[u8]) -> (Vec<Header>, Result<(), DecoderError>) {
        let mut buf = BytesMut::from(block);
        let mut fields = vec![];
        let res = de.decode(&mut Cursor::new(&mut buf), |h| fields.push(h));
        (fields, res)
    }

    /// A literal with incremental indexing, new name, neither string
    /// huffman-coded.
    fn indexed_literal(name: &[u8], value: &[u8]) -> Vec<u8> {
        let mut block = vec![0x40, name.len() as u8];
        block.extend_from_slice(name);
        block.push(value.len() as u8);
        block.extend_from_slice(value);
        block
    }

    /// A field we refuse still takes its slot in the dynamic table, or the
    /// peer's indexes and ours part ways and every later block on the
    /// connection decodes to the wrong fields.
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

        // The refused entry's name, with a value that is fine: a field like
        // any other. Name index 63 overflows the 4-bit prefix: 15, then 48.
        let (fields, res) = decode_block(&mut de, &[0x0f, 48, 4, b'f', b'i', b'n', b'e']);
        assert_eq!(res, Ok(()));
        assert!(
            matches!(&fields[..], [Header::Field { name, value }] if name == "x-bad" && value == "fine")
        );
    }

    /// §8.2.1 and the URI grammar, one refusal each: what the decoder turns
    /// into `InvalidField` rather than into a field.
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

    /// What is wrong with the encoding, not with the field, is still a
    /// decompression failure: there is no telling where the next field
    /// starts.
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
