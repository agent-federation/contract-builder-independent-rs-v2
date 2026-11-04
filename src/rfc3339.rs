//! RFC 3339 date-time parsing/formatting (RFC §4.4 §6.4, §9.8).
//!
//! Accepted form (Appendix A `date-time` profile, RFC 3339):
//!   YYYY-MM-DD[Tt]HH:MM:SS[.f+](Z|z|±HH:MM)
//! - fraction, when present, has 1–9 digits;
//! - leap second `:60` is rejected;
//! - offsets are normalized to UTC;
//! - values are compared as instants.

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Instant {
    /// Whole seconds since the Unix epoch.
    pub seconds: i64,
    /// Sub-second nanoseconds, 0..=999_999_999.
    pub nanos: u32,
}

impl Instant {
    pub fn from_system_time(t: SystemTime) -> Instant {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => Instant {
                seconds: d.as_secs() as i64,
                nanos: d.subsec_nanos(),
            },
            Err(e) => {
                let d = e.duration();
                let mut secs = -(d.as_secs() as i64);
                let mut nanos = d.subsec_nanos();
                if nanos > 0 {
                    secs -= 1;
                    nanos = 1_000_000_000 - nanos;
                }
                Instant { seconds: secs, nanos }
            }
        }
    }
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap(y) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Days from the civil epoch (0000-03-01 based Howard days algorithm)
/// computed directly; year proleptic Gregorian.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = if y2 >= 0 { y2 } else { y2 - 399 } / 400;
    let yoe = (y2 - era * 400) as i64; // 0..=399
    let mp = ((m + 9) % 12) as i64; // March = 0
    let doy = (153 * mp + 2) / 5 + (d as i64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468 // shift to 1970-01-01
}

/// Parse an RFC 3339 date-time string into an instant.
pub fn parse(s: &str) -> Option<Instant> {
    let b = s.as_bytes();
    // YYYY-MM-DD
    if b.len() < 20 {
        return None;
    }
    let digits = |sl: &[u8]| -> Option<i64> {
        let t = std::str::from_utf8(sl).ok()?;
        if !t.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        t.parse::<i64>().ok()
    };
    let year = digits(&b[0..4])?;
    if b[4] != b'-' {
        return None;
    }
    let month = digits(&b[5..7])? as u32;
    if b[7] != b'-' {
        return None;
    }
    let day = digits(&b[8..10])? as u32;
    if b[10] != b'T' && b[10] != b't' {
        return None;
    }
    let hour = digits(&b[11..13])?;
    if b[13] != b':' {
        return None;
    }
    let minute = digits(&b[14..16])?;
    if b[16] != b':' {
        return None;
    }
    let second = digits(&b[17..19])?;
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        // leap second :60 rejected by RFC §9.8
        return None;
    }
    let mut i = 19;
    let mut nanos: u32 = 0;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let nfrac = i - start;
        if nfrac < 1 || nfrac > 9 {
            return None;
        }
        // decode up to 9 digits
        let mut scale = 100_000_000u32;
        for &c in &b[start..i] {
            nanos += ((c - b'0') as u32) * scale;
            scale /= 10;
        }
    }
    if i >= b.len() {
        return None;
    }
    // Offset
    let off_secs: i64 = match b[i] {
        b'Z' | b'z' => {
            i += 1;
            0
        }
        b'+' | b'-' => {
            let neg = b[i] == b'-';
            i += 1;
            if i + 5 > b.len() {
                return None;
            }
            let oh = digits(&b[i..i + 2])?;
            if b[i + 2] != b':' {
                return None;
            }
            let om = digits(&b[i + 3..i + 5])?;
            if oh > 23 || om > 59 {
                return None;
            }
            i += 5;
            let v = oh * 3600 + om * 60;
            if neg {
                -v
            } else {
                v
            }
        }
        _ => return None,
    };
    if i != b.len() {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second - off_secs;
    Some(Instant { seconds: secs, nanos })
}

/// Render an instant as RFC 3339 UTC `Z` form. The fraction is rendered with
/// up to 9 digits with trailing zeros stripped (§9.8; `--now` fractions are 1–9
/// digits so the round trip is exact).
pub fn format(instant: Instant) -> String {
    let (year, month, day, hour, minute, second) = civil_from_unix(instant.seconds);
    let mut out = String::with_capacity(32);
    if year < 0 || year > 99_999 {
        // Out of the RFC 3339 range; callers never produce this from parsed
        // input and the local clock cannot underflow this far.
        out.push_str(&format!("{year:04}"));
    } else {
        out.push_str(&format!("{year:04}"));
    }
    out.push_str(&format!("-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}"));
    if instant.nanos > 0 {
        let frac = format!("{:09}", instant.nanos);
        let trimmed = frac.trim_end_matches('0');
        out.push('.');
        out.push_str(trimmed);
    }
    out.push('Z');
    out
}

fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let hour = (rem / 3_600) as u32;
    let minute = ((rem % 3_600) / 60) as u32;
    let second = (rem % 60) as u32;
    // Howard Hinnant's civil_from_days, shifted to 1970 base:
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // 0..=146096
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // 0..=399
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, hour, minute, second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_known_dates() {
        let t = parse("2026-11-02T00:00:00Z").unwrap();
        assert_eq!(format(t), "2026-11-02T00:00:00Z");
        let t = parse("2026-12-01T00:00:01Z").unwrap();
        assert_eq!(format(t), "2026-12-01T00:00:01Z");
        // offsets normalize to UTC
        let t = parse("2026-11-02T05:00:00+05:00").unwrap();
        assert_eq!(format(t), "2026-11-02T00:00:00Z");
        let t = parse("2026-11-01T19:30:00-04:30").unwrap();
        assert_eq!(format(t), "2026-11-02T00:00:00Z");
        // fractions preserved, trailing zeros stripped
        let t = parse("2026-11-02T00:00:00.100Z").unwrap();
        assert_eq!(format(t), "2026-11-02T00:00:00.1Z");
        let t = parse("2026-11-02T00:00:00.123456789Z").unwrap();
        assert_eq!(format(t), "2026-11-02T00:00:00.123456789Z");
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "2026-11-02",                   // no time
            "2026-11-02T00:00:00",          // no offset
            "2026-11-02T00:00:60Z",         // leap second
            "26-11-02T00:00:00Z",           // short year pattern is still digits4 off
            "2026-13-02T00:00:00Z",         // month range
            "2026-02-30T00:00:00Z",         // day range
            "2027-02-29T00:00:00Z",         // non-leap Feb 29
            "2026-11-02 00:00:00Z",         // space separator
            "2026-11-02T25:00:00Z",         // hour
            "2026-11-02T00:00:00.1234567890Z", // 10 fraction digits
            "2026-11-02T00:00:00+24:00",    // offset hour
            "2026-11-02T00:00:00Z ",        // trailing space
            "2026-11-02T00:00:00+00:60",    // offset minutes
        ] {
            assert!(parse(bad).is_none(), "should reject: {bad}");
        }
    }

    #[test]
    fn leap_day_2024() {
        assert!(parse("2024-02-29T00:00:00Z").is_some());
    }

    #[test]
    fn ordering_instant() {
        let a = parse("2026-11-01T00:00:00Z").unwrap();
        let b = parse("2026-11-02T00:00:00Z").unwrap();
        assert!(a < b);
        // same instant different spellings (19:00-05:00 == Nov 2 00:00Z)
        let c = parse("2026-11-01T19:00:00-05:00").unwrap();
        assert_eq!(b, c);
        let d = parse("2026-11-01T02:00:00+02:00").unwrap();
        assert_eq!(a, d);
    }
}
