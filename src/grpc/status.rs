use http::{HeaderMap, HeaderValue};

/// §9.1's status codes: what a call ended as, which is not what the HTTP
/// exchange ended as. `:status` is 200 for nearly all of these — the request
/// was carried perfectly, and the call it carried failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    Ok,
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
}

impl Code {
    /// The decimal `grpc-status` puts on the wire. A `&'static str` rather
    /// than a number, this being written into a header and never read as one.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "0",
            Self::Cancelled => "1",
            Self::Unknown => "2",
            Self::InvalidArgument => "3",
            Self::DeadlineExceeded => "4",
            Self::NotFound => "5",
            Self::AlreadyExists => "6",
            Self::PermissionDenied => "7",
            Self::ResourceExhausted => "8",
            Self::FailedPrecondition => "9",
            Self::Aborted => "10",
            Self::OutOfRange => "11",
            Self::Unimplemented => "12",
            Self::Internal => "13",
            Self::Unavailable => "14",
            Self::DataLoss => "15",
            Self::Unauthenticated => "16",
        }
    }

    /// The decimal back into a code. `None` is a number outside the table —
    /// a peer using a code we do not know, which is not the same as a
    /// malformed one but is read the same way.
    pub fn of(decimal: &str) -> Option<Self> {
        Some(match decimal.trim() {
            "0" => Self::Ok,
            "1" => Self::Cancelled,
            "2" => Self::Unknown,
            "3" => Self::InvalidArgument,
            "4" => Self::DeadlineExceeded,
            "5" => Self::NotFound,
            "6" => Self::AlreadyExists,
            "7" => Self::PermissionDenied,
            "8" => Self::ResourceExhausted,
            "9" => Self::FailedPrecondition,
            "10" => Self::Aborted,
            "11" => Self::OutOfRange,
            "12" => Self::Unimplemented,
            "13" => Self::Internal,
            "14" => Self::Unavailable,
            "15" => Self::DataLoss,
            "16" => Self::Unauthenticated,
            _ => return None,
        })
    }
}

/// How a call ended: a [`Code`], and something to say about it.
///
/// What a handler returns, so that answering is not something it can forget
/// to do — and what every error the library can raise turns into, each of
/// them knowing the code it deserves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub code: Code,
    pub message: String,
}

impl Status {
    pub fn new(code: Code, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// The call succeeded. No message: §9.1 has `grpc-message` accompany a
    /// failure, and a peer reading one on an `OK` has nothing to do with it.
    pub fn ok() -> Self {
        Self::new(Code::Ok, "")
    }

    pub fn is_ok(&self) -> bool {
        self.code == Code::Ok
    }

    pub fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(Code::InvalidArgument, message)
    }

    pub fn deadline_exceeded(message: impl Into<String>) -> Self {
        Self::new(Code::DeadlineExceeded, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Code::NotFound, message)
    }

    pub fn resource_exhausted(message: impl Into<String>) -> Self {
        Self::new(Code::ResourceExhausted, message)
    }

    pub fn unimplemented(message: impl Into<String>) -> Self {
        Self::new(Code::Unimplemented, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(Code::Internal, message)
    }

    /// §9.1: the status a response carries, read back out of the fields
    /// [`fields`](Self::fields) wrote it into — a trailer section, or the head
    /// of a Trailers-Only response.
    ///
    /// `None` is no `grpc-status` at all, which is not the same as `OK`: it is
    /// a response that never said how the call ended, and what to make of that
    /// is [`of_http`](Self::of_http)'s business. A `grpc-status` that is not a
    /// number, or names no code, is UNKNOWN — the peer said something and we
    /// could not read it, which is exactly what that code is for.
    pub fn of(fields: &HeaderMap) -> Option<Self> {
        let code = fields.get("grpc-status")?.to_str().ok()?;
        let code = Code::of(code).unwrap_or(Code::Unknown);
        let message = fields
            .get("grpc-message")
            .and_then(|value| value.to_str().ok())
            .map(percent_decode)
            .unwrap_or_default();
        Some(Self::new(code, message))
    }

    /// §9.1's table, for a response that carried no `grpc-status`.
    ///
    /// A gateway that never reached the server, a proxy that refused the
    /// request, a server that answered the HTTP exchange without ever meaning
    /// to answer a call: all of them produce an HTTP status and no gRPC one,
    /// and the caller deserves better than UNKNOWN for the ones that have an
    /// obvious meaning.
    ///
    /// A `200` among them is the awkward case, and it is real: a response that
    /// completed with neither a status nor a reason to doubt it. §9.1 calls
    /// that INTERNAL, because a well-formed call always ends in a status.
    pub fn of_http(status: http::StatusCode) -> Self {
        let code = match status.as_u16() {
            400 => Code::Internal,
            401 => Code::Unauthenticated,
            403 => Code::PermissionDenied,
            404 => Code::Unimplemented,
            429 | 502 | 503 | 504 => Code::Unavailable,
            _ => Code::Internal,
        };
        Self::new(code, format!("no grpc-status; HTTP {}", status.as_u16()))
    }

    /// The fields that carry this — in a trailer section, or in the head of a
    /// Trailers-Only response, which are the same fields either way.
    pub(crate) fn fields(&self) -> HeaderMap {
        let mut fields = HeaderMap::with_capacity(2);
        fields.insert("grpc-status", HeaderValue::from_static(self.code.as_str()));
        if !self.message.is_empty()
            && let Ok(value) = HeaderValue::from_str(&percent_encode(&self.message))
        {
            fields.insert("grpc-message", value);
        }
        fields
    }
}

/// §9.1's Percent-Encoded, read back. The inverse of [`percent_encode`], and
/// forgiving where it has to be: a `%` that does not introduce two hex digits
/// is taken literally rather than dropped.
///
/// The bytes an escape produces need not be UTF-8 on their own — a message in
/// any encoding survives the trip — so they are collected and converted at the
/// end, lossily. A status message is for a human to read; refusing to show one
/// because a byte was not what we hoped is the worse failure.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            // Read as bytes rather than by slicing the `str`: a `%` followed
            // by anything multi-byte would put the slice inside a character,
            // and this is a peer's field value.
            b'%' if at + 2 < bytes.len() => match (hex(bytes[at + 1]), hex(bytes[at + 2])) {
                (Some(high), Some(low)) => {
                    out.push(high << 4 | low);
                    at += 3;
                }
                _ => {
                    out.push(b'%');
                    at += 1;
                }
            },
            byte => {
                out.push(byte);
                at += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One hex digit's value, upper or lower case. `None` is not a hex digit,
/// which is what makes the `%` before it literal.
fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// §9.1's Percent-Encoded: printable ASCII goes as it is, `%` and everything
/// else becomes `%XX`.
///
/// Not the URI rule, which escapes far more. What this protects is the header
/// value itself — a status message is whatever the handler had to say, and
/// that can hold a path, a peer's input, or a language HPACK would not carry.
/// `%` is escaped because otherwise a message that merely *contains* one would
/// be decoded as an escape it never was.
fn percent_encode(message: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(message.len());
    for byte in message.as_bytes() {
        match byte {
            b' '..=b'~' if *byte != b'%' => out.push(*byte as char),
            byte => {
                out.push('%');
                out.push(HEX[(byte >> 4) as usize] as char);
                out.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn printable_ascii_goes_as_it_is() {
        assert_eq!(percent_encode("unknown service"), "unknown service");
        assert_eq!(
            percent_encode("~ !\"#$&'()*+,-./:;<=>?@[\\]^_`{|}"),
            "~ !\"#$&'()*+,-./:;<=>?@[\\]^_`{|}"
        );
    }

    /// The one printable byte that has to be escaped: a message holding a
    /// percent would otherwise be read as an escape it never was.
    #[test]
    fn a_percent_is_escaped() {
        assert_eq!(percent_encode("100% done"), "100%25 done");
        assert_eq!(percent_encode("%41"), "%2541", "not decoded back to `A`");
    }

    #[test]
    fn everything_else_is_escaped_byte_by_byte() {
        // Two bytes in UTF-8, so two escapes.
        assert_eq!(percent_encode("café"), "caf%C3%A9");
        assert_eq!(percent_encode("a\nb\tc"), "a%0Ab%09c");
        assert_eq!(percent_encode("日本"), "%E6%97%A5%E6%9C%AC");
    }

    /// `HeaderValue` takes only visible ASCII, which is what the encoding
    /// leaves — so a message is never dropped for what it contained.
    #[test]
    fn any_message_survives_into_its_fields() {
        let fields = Status::new(Code::Internal, "échec: 50% du flux\n").fields();
        assert_eq!(fields.get("grpc-status").unwrap(), "13");
        assert_eq!(
            fields.get("grpc-message").unwrap(),
            "%C3%A9chec: 50%25 du flux%0A"
        );
    }

    #[test]
    fn a_successful_call_carries_no_message() {
        let fields = Status::ok().fields();
        assert_eq!(fields.get("grpc-status").unwrap(), "0");
        assert!(!fields.contains_key("grpc-message"));
    }

    /// What one end writes, the other reads back — which is the only property
    /// either half of the encoding has to have.
    #[test]
    fn a_message_survives_the_round_trip() {
        for message in [
            "échec: 50% du flux\n",
            "not found",
            "%41",
            "日本",
            "a\0b",
            "",
        ] {
            let fields = Status::new(Code::Internal, message).fields();
            let read = Status::of(&fields).expect("a status went in");
            assert_eq!(read.code, Code::Internal);
            assert_eq!(read.message, message, "round trip of {message:?}");
        }
    }

    /// A `%` that introduces nothing is a `%`. A peer's message is not
    /// necessarily one we encoded, and dropping characters out of it would be
    /// worse than showing the escape that was not one.
    #[test]
    fn a_percent_that_escapes_nothing_is_kept() {
        assert_eq!(percent_decode("100% done"), "100% done");
        assert_eq!(percent_decode("ends with %"), "ends with %");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%4"), "%4");
    }

    /// Lower case hex is hex. §9.1 does not say which case a sender uses, and
    /// the ones that matter do not agree.
    #[test]
    fn either_case_of_hex_decodes() {
        assert_eq!(percent_decode("%c3%a9"), "é");
        assert_eq!(percent_decode("%C3%A9"), "é");
    }

    /// §9.1: no `grpc-status` is not an `OK`, and the difference is the whole
    /// reason a caller cannot read a bare `200` as success.
    #[test]
    fn fields_without_a_status_are_not_a_status() {
        let mut fields = HeaderMap::new();
        fields.insert("grpc-message", HeaderValue::from_static("nearly"));
        assert_eq!(Status::of(&fields), None);
    }

    /// A code outside the table is UNKNOWN rather than a refusal: the peer
    /// said how the call ended and we could not read it, which is what that
    /// code means.
    #[test]
    fn an_unreadable_code_is_unknown() {
        let mut fields = HeaderMap::new();
        fields.insert("grpc-status", HeaderValue::from_static("99"));
        assert_eq!(Status::of(&fields).unwrap().code, Code::Unknown);

        fields.insert("grpc-status", HeaderValue::from_static("banana"));
        assert_eq!(Status::of(&fields).unwrap().code, Code::Unknown);
    }
}
