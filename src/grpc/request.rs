use http::{HeaderMap, Method, header};

use super::GrpcEncoding;
use crate::shared::codec::frames::headers::Headers;

/// What a gRPC request's messages are serialised as: the subtype after
/// `application/grpc` in its `content-type`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcFormat {
    /// `application/grpc+proto` — and bare `application/grpc`, which the
    /// protocol defines as the same thing.
    Proto,
    /// `application/grpc+json`.
    Json,
    /// Some other `+subtype`. The request's `content-type` still has its
    /// name.
    Other,
}

impl GrpcFormat {
    /// `Some` is a gRPC request: a POST whose `content-type` is
    /// `application/grpc`, bare or followed by a `+subtype` or a parameter.
    ///
    /// All there is to go on at HEADERS. `te: trailers` is required of clients
    /// and not asked for here, some proxies having been known to drop it.
    pub fn of(headers: &Headers) -> Option<Self> {
        if headers.pseudo().method != Some(Method::POST) {
            return None;
        }
        const GRPC: &[u8] = b"application/grpc";
        let value = headers.fields().get(header::CONTENT_TYPE)?.as_bytes();
        if value.len() < GRPC.len() || !value[..GRPC.len()].eq_ignore_ascii_case(GRPC) {
            return None;
        }
        Self::of_suffix(&value[GRPC.len()..])
    }

    /// What follows `application/grpc`: nothing, `;parameters`, or `+subtype`
    /// and perhaps parameters after it. Anything else is another media type
    /// that only starts the same way.
    fn of_suffix(suffix: &[u8]) -> Option<Self> {
        match suffix {
            [] | [b';', ..] => Some(Self::Proto),
            [b'+', rest @ ..] => {
                let subtype = rest.split(|byte| *byte == b';').next().unwrap_or(rest);
                let subtype = subtype.trim_ascii();
                Some(if subtype.eq_ignore_ascii_case(b"proto") {
                    Self::Proto
                } else if subtype.eq_ignore_ascii_case(b"json") {
                    Self::Json
                } else {
                    Self::Other
                })
            }
            _ => None,
        }
    }
}

/// What a request's `grpc-encoding` says its compressed messages are
/// compressed with. It says nothing of whether any message *is*: that is each
/// prefix's Compressed-Flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnouncedEncoding {
    /// No `grpc-encoding`, or `identity`: a set Compressed-Flag has nothing
    /// to mean.
    None,
    Known(GrpcEncoding),
    /// One this side has no name for.
    Unknown,
}

impl AnnouncedEncoding {
    pub fn of(fields: &HeaderMap) -> Self {
        let Some(value) = fields.get("grpc-encoding") else {
            return Self::None;
        };
        let value = value.as_bytes();
        if value.eq_ignore_ascii_case(b"identity") {
            Self::None
        } else if value.eq_ignore_ascii_case(b"gzip") {
            Self::Known(GrpcEncoding::Gzip)
        } else if value.eq_ignore_ascii_case(b"deflate") {
            Self::Known(GrpcEncoding::Deflate)
        } else {
            Self::Unknown
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn announced(value: Option<&'static str>) -> AnnouncedEncoding {
        let mut fields = HeaderMap::new();
        if let Some(value) = value {
            fields.insert("grpc-encoding", http::HeaderValue::from_static(value));
        }
        AnnouncedEncoding::of(&fields)
    }

    /// What follows `application/grpc` in the `content-type`.
    #[test]
    fn the_subtype_names_the_format_and_none_means_proto() {
        for (suffix, expected) in [
            ("", Some(GrpcFormat::Proto)),
            ("+proto", Some(GrpcFormat::Proto)),
            ("+PROTO", Some(GrpcFormat::Proto)),
            ("+json", Some(GrpcFormat::Json)),
            ("+json; charset=utf-8", Some(GrpcFormat::Json)),
            (";charset=utf-8", Some(GrpcFormat::Proto)),
            ("+thrift", Some(GrpcFormat::Other)),
            // Another media type that only starts the same way.
            ("-web", None),
            ("web+proto", None),
        ] {
            assert_eq!(GrpcFormat::of_suffix(suffix.as_bytes()), expected, "{suffix:?}");
        }
    }

    #[test]
    fn identity_is_the_absence_of_an_encoding() {
        assert_eq!(announced(None), AnnouncedEncoding::None);
        assert_eq!(announced(Some("identity")), AnnouncedEncoding::None);
        assert_eq!(
            announced(Some("gzip")),
            AnnouncedEncoding::Known(GrpcEncoding::Gzip)
        );
        assert_eq!(
            announced(Some("deflate")),
            AnnouncedEncoding::Known(GrpcEncoding::Deflate)
        );
        assert_eq!(announced(Some("snappy")), AnnouncedEncoding::Unknown);
    }
}
