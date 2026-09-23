use std::time::Duration;

use http::HeaderMap;

/// The longest one `Sleep` will take. The runtime's timewheel holds a minute
/// and `unimplemented!`s past it.
const SLICE: Duration = Duration::from_secs(30);

/// §5's `grpc-timeout`: at most eight digits and a unit.
///
/// An unreadable one is `None`, no deadline: §5 gives no way to answer a
/// malformed timeout.
pub fn parse_timeout(fields: &HeaderMap) -> Option<Duration> {
    let value = fields.get("grpc-timeout")?.as_bytes();
    let (unit, digits) = value.split_last()?;
    // Eight digits is the cap, so the count cannot overflow a u64 before the
    // unit multiplies it.
    if digits.is_empty() || digits.len() > 8 || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let count: u64 = digits.iter().fold(0, |n, d| n * 10 + (d - b'0') as u64);
    Some(match unit {
        b'H' => Duration::from_secs(count * 3600),
        b'M' => Duration::from_secs(count * 60),
        b'S' => Duration::from_secs(count),
        b'm' => Duration::from_millis(count),
        b'u' => Duration::from_micros(count),
        b'n' => Duration::from_nanos(count),
        _ => return None,
    })
}

/// `Sleep` panics past a minute, so anything longer is taken in slices. Each
/// slice re-reads the clock, so the slicing cannot drift the deadline later.
pub async fn sleep(duration: Duration) {
    let deadline = runtime::runtime::now() + duration;
    loop {
        let left = deadline
            .duration_since(runtime::runtime::now())
            .unwrap_or_default();
        if left.is_zero() {
            return;
        }
        runtime::runtime::time::Sleep::during(left.min(SLICE)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timeout(value: &'static str) -> Option<Duration> {
        let mut fields = HeaderMap::new();
        fields.insert("grpc-timeout", http::HeaderValue::from_static(value));
        parse_timeout(&fields)
    }

    #[test]
    fn a_count_and_a_unit() {
        assert_eq!(timeout("10S"), Some(Duration::from_secs(10)));
        assert_eq!(timeout("500m"), Some(Duration::from_millis(500)));
        assert_eq!(timeout("1H"), Some(Duration::from_secs(3600)));
        assert_eq!(timeout("2M"), Some(Duration::from_secs(120)));
        assert_eq!(timeout("250u"), Some(Duration::from_micros(250)));
        assert_eq!(timeout("99n"), Some(Duration::from_nanos(99)));
        assert_eq!(timeout("0S"), Some(Duration::ZERO), "already over");
    }

    #[test]
    fn no_header_is_no_deadline() {
        assert_eq!(parse_timeout(&HeaderMap::new()), None);
    }

    #[test]
    fn what_cannot_be_read_is_no_deadline() {
        for value in ["", "S", "10", "10X", "-1S", "1.5S", "999999999S", "ten S"] {
            let mut fields = HeaderMap::new();
            if let Ok(value) = http::HeaderValue::from_str(value) {
                fields.insert("grpc-timeout", value);
            }
            assert_eq!(parse_timeout(&fields), None, "{value:?}");
        }
    }

    #[test]
    fn eight_digits_is_the_cap_and_it_is_allowed() {
        assert_eq!(timeout("99999999S"), Some(Duration::from_secs(99_999_999)));
    }
}
