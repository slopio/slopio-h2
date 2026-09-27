use http::{HeaderMap, HeaderValue, StatusCode};

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

    /// §9.1 has `grpc-message` accompany a failure, not an `OK`.
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

    /// §9.1. `None` is no `grpc-status` at all, which is not the same as `OK`.
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

    /// §9.1: what a response head alone says of the call: the status it
    /// carries (Trailers-Only), or a failed HTTP status. `None`: the outcome
    /// is in the trailers, and messages may come. The one rule both the
    /// client's stream, choosing to gather messages, and its `Call`, reading
    /// the head, go by.
    pub(crate) fn settled_by_head(status: StatusCode, fields: &HeaderMap) -> Option<Self> {
        Self::of(fields).or_else(|| (!status.is_success()).then(|| Self::of_http(status)))
    }

    /// §9.1's table, for a response that carried no `grpc-status`. A `200`
    /// without one is INTERNAL: a well-formed call always ends in a status.
    pub fn of_http(status: http::StatusCode) -> Self {
        let (code, message) = match status.as_u16() {
            400 => (Code::Internal, "no grpc-status; HTTP 400"),
            401 => (Code::Unauthenticated, "no grpc-status; HTTP 401"),
            403 => (Code::PermissionDenied, "no grpc-status; HTTP 403"),
            404 => (Code::Unimplemented, "no grpc-status; HTTP 404"),
            429 => (Code::Unavailable, "no grpc-status; HTTP 429"),
            502 => (Code::Unavailable, "no grpc-status; HTTP 502"),
            503 => (Code::Unavailable, "no grpc-status; HTTP 503"),
            504 => (Code::Unavailable, "no grpc-status; HTTP 504"),
            _ => (Code::Internal, "no grpc-status"),
        };
        Self::new(code, message)
    }

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

/// §9.1's Percent-Encoded, read back. A `%` that does not introduce two hex
/// digits is taken literally rather than dropped.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            // Read as bytes rather than by slicing the `str`: this is a peer's
            // field value, and a slice could land inside a character.
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

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// §9.1's Percent-Encoded. `%` is escaped too, or a message that merely
/// contains one would be decoded as an escape it never was.
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

    #[test]
    fn a_percent_is_escaped() {
        assert_eq!(percent_encode("100% done"), "100%25 done");
        assert_eq!(percent_encode("%41"), "%2541", "not decoded back to `A`");
    }

    #[test]
    fn everything_else_is_escaped_byte_by_byte() {
        assert_eq!(percent_encode("café"), "caf%C3%A9");
        assert_eq!(percent_encode("a\nb\tc"), "a%0Ab%09c");
        assert_eq!(percent_encode("日本"), "%E6%97%A5%E6%9C%AC");
    }

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

    #[test]
    fn a_percent_that_escapes_nothing_is_kept() {
        assert_eq!(percent_decode("100% done"), "100% done");
        assert_eq!(percent_decode("ends with %"), "ends with %");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%4"), "%4");
    }

    #[test]
    fn either_case_of_hex_decodes() {
        assert_eq!(percent_decode("%c3%a9"), "é");
        assert_eq!(percent_decode("%C3%A9"), "é");
    }

    #[test]
    fn fields_without_a_status_are_not_a_status() {
        let mut fields = HeaderMap::new();
        fields.insert("grpc-message", HeaderValue::from_static("nearly"));
        assert_eq!(Status::of(&fields), None);
    }

    #[test]
    fn an_unreadable_code_is_unknown() {
        let mut fields = HeaderMap::new();
        fields.insert("grpc-status", HeaderValue::from_static("99"));
        assert_eq!(Status::of(&fields).unwrap().code, Code::Unknown);

        fields.insert("grpc-status", HeaderValue::from_static("banana"));
        assert_eq!(Status::of(&fields).unwrap().code, Code::Unknown);
    }
}
