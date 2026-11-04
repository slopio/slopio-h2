use slopio::http::{HeaderMap, Method, header};

use super::GrpcEncoding;
use crate::shared::codec::frames::headers::Headers;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcFormat {
    Proto,
    Json,
    Other,
}

impl GrpcFormat {
    /// `te: trailers` is required of clients and not asked for here, some
    /// proxies having been known to drop it.
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

    /// §4.1 requires the same `content-type` back, and a response without one
    /// is not carrying messages — most often a proxy's error page.
    pub(crate) fn of_response(fields: &HeaderMap) -> Option<Self> {
        const GRPC: &[u8] = b"application/grpc";
        let value = fields.get(header::CONTENT_TYPE)?.as_bytes();
        if value.len() < GRPC.len() || !value[..GRPC.len()].eq_ignore_ascii_case(GRPC) {
            return None;
        }
        Self::of_suffix(&value[GRPC.len()..])
    }

    /// Anything but nothing, `;parameters` or `+subtype` is another media type
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnnouncedEncoding {
    None,
    Known(GrpcEncoding),
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
    use slopio::http;

    fn announced(value: Option<&'static str>) -> AnnouncedEncoding {
        let mut fields = HeaderMap::new();
        if let Some(value) = value {
            fields.insert("grpc-encoding", http::HeaderValue::from_static(value));
        }
        AnnouncedEncoding::of(&fields)
    }

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
            assert_eq!(
                GrpcFormat::of_suffix(suffix.as_bytes()),
                expected,
                "{suffix:?}"
            );
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
