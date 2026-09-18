//! The `Date` header field, formatted once a second per worker.
//!
//! RFC 9110 §6.6.1 requires an origin server with a clock to send `Date` on
//! every 2xx, 3xx and 4xx response, and §5.6.7 allows exactly one format in
//! a new message: IMF-fixdate, which is always the same 29 bytes wide.
//!
//! Formatting it per response would be a waste twice over — the value only
//! changes once a second, and the `HeaderValue` holding it would be an
//! allocation per response. So a worker keeps the one it built, hands out
//! clones of it (a refcount bump, the value being `Bytes`-backed), and
//! rebuilds it when the second turns over.
//!
//! The clock is the runtime's, sampled once per scheduler pass and read from
//! the timewheel, so asking the time costs no syscall either.

use std::cell::RefCell;
use std::time::UNIX_EPOCH;

use http::HeaderValue;

thread_local! {
    /// The second this worker last formatted, and what it formatted. One per
    /// worker because that is the sharing the runtime already has: a worker
    /// owns its connections and nothing crosses between them.
    static CACHED: RefCell<Option<(u64, HeaderValue)>> = const { RefCell::new(None) };
}

/// `Date` for right now, as a header value ready to encode.
pub fn now() -> HeaderValue {
    let secs = runtime::runtime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());

    CACHED.with(|cached| {
        let mut cached = cached.borrow_mut();
        if let Some((at, value)) = cached.as_ref()
            && *at == secs
        {
            return value.clone();
        }
        let value =
            HeaderValue::from_bytes(&imf_fixdate(secs)).expect("IMF-fixdate is printable ASCII");
        *cached = Some((secs, value.clone()));
        value
    })
}

/// `Sun, 06 Nov 1994 08:49:37 GMT` — IMF-fixdate (§5.6.7), from seconds since
/// the epoch. Always 29 bytes: the day of month is zero-padded and the year
/// is four digits, which is what makes the width fixed.
///
/// Four digits is also the format's own ceiling, so this is right up to
/// 9999-12-31 and wraps to 0000 after it. Eight thousand years of margin,
/// and no way to do better without leaving IMF-fixdate.
fn imf_fixdate(secs: u64) -> [u8; 29] {
    const DAY: u64 = 86_400;
    const WEEKDAYS: [&[u8; 3]; 7] = [b"Thu", b"Fri", b"Sat", b"Sun", b"Mon", b"Tue", b"Wed"];
    const MONTHS: [&[u8; 3]; 12] = [
        b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov",
        b"Dec",
    ];

    let days = secs / DAY;
    let time = secs % DAY;
    // 1970-01-01 was a Thursday, which is why the table starts there.
    let weekday = WEEKDAYS[(days % 7) as usize];
    let (year, month, day) = civil_from_days(days);

    let mut out = *b"Thu, 01 Jan 1970 00:00:00 GMT";
    out[0..3].copy_from_slice(weekday);
    write_two(&mut out[5..7], day as u64);
    out[8..11].copy_from_slice(MONTHS[month as usize - 1]);
    write_two(&mut out[12..14], year as u64 / 100);
    write_two(&mut out[14..16], year as u64 % 100);
    write_two(&mut out[17..19], time / 3600);
    write_two(&mut out[20..22], time % 3600 / 60);
    write_two(&mut out[23..25], time % 60);
    out
}

fn write_two(out: &mut [u8], value: u64) {
    out[0] = b'0' + (value / 10 % 10) as u8;
    out[1] = b'0' + (value % 10) as u8;
}

/// Days since 1970-01-01 to a civil date, by Howard Hinnant's algorithm: it
/// shifts the year to start in March so that the leap day lands at the end
/// and the month-length pattern becomes an arithmetic one, which is what
/// removes the table and the branches.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> String {
        String::from_utf8(imf_fixdate(secs).to_vec()).expect("ASCII")
    }

    #[test]
    fn formats_the_examples_the_rfc_gives() {
        // RFC 9110 §5.6.7's own example, in the one format it allows.
        assert_eq!(at(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(at(0), "Thu, 01 Jan 1970 00:00:00 GMT");
    }

    #[test]
    fn formats_the_dates_that_break_naive_arithmetic() {
        // A leap day, in a year divisible by 100 and by 400 — the case the
        // every-four-years rule gets wrong twice over.
        assert_eq!(at(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
        // The last second of a year, and the first of the next.
        assert_eq!(at(1_483_228_799), "Sat, 31 Dec 2016 23:59:59 GMT");
        assert_eq!(at(1_483_228_800), "Sun, 01 Jan 2017 00:00:00 GMT");
        // A leap day in an ordinary leap year.
        assert_eq!(at(1_709_164_800), "Thu, 29 Feb 2024 00:00:00 GMT");
    }

    #[test]
    fn is_always_twenty_nine_bytes() {
        // What lets a proxy and an HPACK encoder size it without looking.
        for secs in [0, 1, 951_782_400, 1_709_164_800, 4_102_444_800] {
            assert_eq!(imf_fixdate(secs).len(), 29);
            assert_eq!(at(secs).len(), 29);
        }
    }

    /// Checked against an independent implementation (`strftime` via
    /// Python) over forty timestamps spread to 2103; these five are what is
    /// worth keeping in the file.
    #[test]
    fn agrees_with_an_independent_implementation() {
        assert_eq!(at(161_042_648), "Fri, 07 Feb 1975 22:04:08 GMT");
        assert_eq!(at(369_140_570), "Sat, 12 Sep 1981 11:02:50 GMT");
        assert_eq!(at(1_390_851_128), "Mon, 27 Jan 2014 19:32:08 GMT");
        assert_eq!(at(2_301_595_691), "Sun, 07 Dec 2042 20:08:11 GMT");
        assert_eq!(at(2_708_517_688), "Sat, 30 Oct 2055 14:01:28 GMT");
    }

    #[test]
    fn every_weekday_lands_where_it_should() {
        // Seven consecutive days from a known Thursday.
        let names = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
        for (day, name) in names.iter().enumerate() {
            assert_eq!(&at(day as u64 * 86_400)[..3], *name);
        }
    }
}
