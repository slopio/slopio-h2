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
        assert_eq!(percent_encode("~ !\"#$&'()*+,-./:;<=>?@[\\]^_`{|}"), "~ !\"#$&'()*+,-./:;<=>?@[\\]^_`{|}");
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
}
