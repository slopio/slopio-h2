use crate::shared::codec::ext::Protocol;

use super::DecoderError;

use http::header::{HeaderName, HeaderValue};
use http::{Method, StatusCode};
use runtime::bytes::Bytes;
use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Header<T = HeaderName> {
    Field { name: T, value: HeaderValue },
    // TODO: Change these types to `http::uri` types.
    Authority(BytesStr),
    Method(Method),
    Scheme(BytesStr),
    Path(BytesStr),
    Protocol(Protocol),
    Status(StatusCode),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum Name<'a> {
    Field(&'a HeaderName),
    Authority,
    Method,
    Scheme,
    Path,
    Protocol,
    Status,
}

#[doc(hidden)]
#[derive(Clone, Eq, PartialEq, Default)]
pub struct BytesStr(Bytes);

pub fn len(name: &HeaderName, value: &HeaderValue) -> usize {
    let n: &str = name.as_ref();
    32 + n.len() + value.len()
}

impl Header<Option<HeaderName>> {
    pub fn reify(self) -> Result<Header, HeaderValue> {
        use self::Header::*;

        Ok(match self {
            Field {
                name: Some(n),
                value,
            } => Field { name: n, value },
            Field { name: None, value } => return Err(value),
            Authority(v) => Authority(v),
            Method(v) => Method(v),
            Scheme(v) => Scheme(v),
            Path(v) => Path(v),
            Protocol(v) => Protocol(v),
            Status(v) => Status(v),
        })
    }
}

impl Header {
    /// A refused field is not dropped: the decoder still owes the dynamic
    /// table an entry for it.
    pub fn new(name: &[u8], value: &Bytes) -> Result<Header, DecoderError> {
        if name.is_empty() {
            return Err(DecoderError::InvalidField);
        }
        if name[0] == b':' {
            match &name[1..] {
                b"authority" => Ok(Header::Authority(pseudo_value(value)?)),
                b"method" => {
                    let method = Method::from_bytes(value)?;
                    Ok(Header::Method(method))
                }
                b"scheme" => Ok(Header::Scheme(pseudo_value(value)?)),
                b"path" => Ok(Header::Path(pseudo_value(value)?)),
                b"protocol" => Ok(Header::Protocol(Protocol::new(pseudo_value(value)?))),
                b"status" => {
                    let status = StatusCode::from_bytes(value)?;
                    Ok(Header::Status(status))
                }
                _ => Err(DecoderError::InvalidField),
            }
        } else {
            // HTTP/2 requires lower case header names
            let name = HeaderName::from_lowercase(name)?;
            Ok(Header::Field {
                name,
                value: field_value(value)?,
            })
        }
    }

    pub fn len(&self) -> usize {
        match *self {
            Header::Field {
                ref name,
                ref value,
            } => len(name, value),
            Header::Authority(ref v) => 32 + 10 + v.len(),
            Header::Method(ref v) => 32 + 7 + v.as_ref().len(),
            Header::Scheme(ref v) => 32 + 7 + v.len(),
            Header::Path(ref v) => 32 + 5 + v.len(),
            Header::Protocol(ref v) => 32 + 9 + v.as_str().len(),
            Header::Status(_) => 32 + 7 + 3,
        }
    }

    pub fn name(&self) -> Name<'_> {
        match *self {
            Header::Field { ref name, .. } => Name::Field(name),
            Header::Authority(..) => Name::Authority,
            Header::Method(..) => Name::Method,
            Header::Scheme(..) => Name::Scheme,
            Header::Path(..) => Name::Path,
            Header::Protocol(..) => Name::Protocol,
            Header::Status(..) => Name::Status,
        }
    }

    pub fn value_slice(&self) -> &[u8] {
        match *self {
            Header::Field { ref value, .. } => value.as_ref(),
            Header::Authority(ref v) => v.as_ref(),
            Header::Method(ref v) => v.as_ref().as_ref(),
            Header::Scheme(ref v) => v.as_ref(),
            Header::Path(ref v) => v.as_ref(),
            Header::Protocol(ref v) => v.as_ref(),
            Header::Status(ref v) => v.as_str().as_ref(),
        }
    }

    pub fn value_eq(&self, other: &Header) -> bool {
        match *self {
            Header::Field { ref value, .. } => {
                let a = value;
                match *other {
                    Header::Field { ref value, .. } => a == value,
                    _ => false,
                }
            }
            Header::Authority(ref a) => match *other {
                Header::Authority(ref b) => a == b,
                _ => false,
            },
            Header::Method(ref a) => match *other {
                Header::Method(ref b) => a == b,
                _ => false,
            },
            Header::Scheme(ref a) => match *other {
                Header::Scheme(ref b) => a == b,
                _ => false,
            },
            Header::Path(ref a) => match *other {
                Header::Path(ref b) => a == b,
                _ => false,
            },
            Header::Protocol(ref a) => match *other {
                Header::Protocol(ref b) => a == b,
                _ => false,
            },
            Header::Status(ref a) => match *other {
                Header::Status(ref b) => a == b,
                _ => false,
            },
        }
    }

    pub fn is_sensitive(&self) -> bool {
        match *self {
            Header::Field { ref value, .. } => value.is_sensitive(),
            // TODO: Technically these other header values can be sensitive too.
            _ => false,
        }
    }

    pub fn skip_value_index(&self, index_paths: bool) -> bool {
        use http::header;

        match *self {
            Header::Field { ref name, .. } => matches!(
                *name,
                header::AGE
                    | header::AUTHORIZATION
                    | header::CONTENT_LENGTH
                    | header::ETAG
                    | header::IF_MODIFIED_SINCE
                    | header::IF_NONE_MATCH
                    | header::LOCATION
                    | header::COOKIE
                    | header::SET_COOKIE
            ),
            Header::Path(..) => !index_paths,
            _ => false,
        }
    }
}

impl From<Header> for Header<Option<HeaderName>> {
    fn from(src: Header) -> Self {
        match src {
            Header::Field { name, value } => Header::Field {
                name: Some(name),
                value,
            },
            Header::Authority(v) => Header::Authority(v),
            Header::Method(v) => Header::Method(v),
            Header::Scheme(v) => Header::Scheme(v),
            Header::Path(v) => Header::Path(v),
            Header::Protocol(v) => Header::Protocol(v),
            Header::Status(v) => Header::Status(v),
        }
    }
}

impl<'a> Name<'a> {
    pub fn into_entry(self, value: &Bytes) -> Result<Header, DecoderError> {
        match self {
            Name::Field(name) => Ok(Header::Field {
                name: name.clone(),
                value: field_value(value)?,
            }),
            Name::Authority => Ok(Header::Authority(pseudo_value(value)?)),
            Name::Method => Ok(Header::Method(Method::from_bytes(value)?)),
            Name::Scheme => Ok(Header::Scheme(pseudo_value(value)?)),
            Name::Path => Ok(Header::Path(pseudo_value(value)?)),
            Name::Protocol => Ok(Header::Protocol(Protocol::new(pseudo_value(value)?))),
            Name::Status => Ok(Header::Status(StatusCode::from_bytes(value)?)),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match *self {
            Name::Field(ref name) => name.as_ref(),
            Name::Authority => b":authority",
            Name::Method => b":method",
            Name::Scheme => b":scheme",
            Name::Path => b":path",
            Name::Protocol => b":protocol",
            Name::Status => b":status",
        }
    }
}

/// §8.2.1: `HeaderValue` refuses NUL, CR, LF and other controls; whitespace
/// at either end is ours to check.
fn field_value(value: &[u8]) -> Result<HeaderValue, DecoderError> {
    if value
        .first()
        .into_iter()
        .chain(value.last())
        .any(|&b| b == b' ' || b == b'\t')
    {
        return Err(DecoderError::InvalidField);
    }
    Ok(HeaderValue::from_bytes(value)?)
}

/// No control character, space or DEL fits these grammars. Refusing them keeps
/// a `:path` of `/a\r\nX: y` from reaching a handler that relays it to HTTP/1.1.
fn pseudo_value(value: &Bytes) -> Result<BytesStr, DecoderError> {
    if value.iter().any(|&b| b <= b' ' || b == 0x7f) {
        return Err(DecoderError::InvalidField);
    }
    Ok(BytesStr::try_from(value.clone())?)
}

impl BytesStr {
    pub(crate) const fn from_static(value: &'static str) -> Self {
        BytesStr(Bytes::from_static(value.as_bytes()))
    }

    pub(crate) fn from(value: &str) -> Self {
        BytesStr(Bytes::copy_from_slice(value.as_bytes()))
    }

    #[doc(hidden)]
    pub fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        std::str::from_utf8(bytes.as_ref())?;
        Ok(BytesStr(bytes))
    }

    pub(crate) fn as_str(&self) -> &str {
        // Safety: check valid utf-8 in constructor
        unsafe { std::str::from_utf8_unchecked(self.0.as_ref()) }
    }
}

impl std::ops::Deref for BytesStr {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<[u8]> for BytesStr {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Debug for BytesStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
