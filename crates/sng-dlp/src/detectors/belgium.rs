//! Belgium National Register Number (Rijksregisternummer) validator.

use crate::validators::digits;

/// Strip the "bis" century offset (`+20` / `+40`) some National
/// Register Numbers add to the month field, returning the real month
/// `0..=12` (`0` = unknown), or `None` for an out-of-range field.
fn real_month(field: u32) -> Option<u32> {
    let m = match field {
        0..=12 => field,
        20..=32 => field - 20,
        40..=52 => field - 40,
        _ => return None,
    };
    Some(m)
}

/// Belgium National Register Number: eleven digits — `YYMMDD`, a
/// 3-digit serial, and a 2-digit checksum.
///
/// The checksum is `97 - (body mod 97)`, where `body` is the leading
/// nine digits for holders born before 2000 and those nine digits
/// prefixed with a `2` for holders born from 2000 on; a number is
/// valid when either reading matches. The embedded month (after any
/// "bis" offset) and day are range-checked so a checksum collision on
/// an impossible date is still rejected.
#[must_use]
pub fn belgium_national_number(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 {
        return false;
    }
    // Plausible birth date (month allows the bis offsets; day 0..=31,
    // with 0 reserved for an unknown date).
    let month_field = u32::from(d[2]) * 10 + u32::from(d[3]);
    if real_month(month_field).is_none() {
        return false;
    }
    let day = u32::from(d[4]) * 10 + u32::from(d[5]);
    if day > 31 {
        return false;
    }

    let body: u64 = d[..9].iter().fold(0u64, |acc, &x| acc * 10 + u64::from(x));
    let check = u64::from(d[9]) * 10 + u64::from(d[10]);
    // Pre-2000 reading uses the 9-digit body; 2000-on prefixes a `2`.
    let pre_2000 = 97 - body % 97;
    let post_2000 = 97 - (2_000_000_000 + body) % 97;
    check == pre_2000 || check == post_2000
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two-digit checksum for a 9-digit body under the chosen century
    /// reading (`prefix_2 = true` for holders born from 2000 on).
    fn check(body: u64, prefix_2: bool) -> u64 {
        let n = if prefix_2 { 2_000_000_000 + body } else { body };
        97 - n % 97
    }

    fn body_of(yy: u32, mm: u32, dd: u32, serial: u32) -> u64 {
        u64::from(yy) * 10_000_000
            + u64::from(mm) * 100_000
            + u64::from(dd) * 1_000
            + u64::from(serial)
    }

    #[test]
    fn national_number_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let yy = (seed * 7 + 1) % 100;
            let mm = (seed % 12) + 1;
            let dd = (seed % 28) + 1;
            let serial = (seed * 91 + 1) % 1000;
            let prefix_2 = seed % 2 == 0;
            let body = body_of(yy, mm, dd, serial);
            let pre = check(body, false);
            let post = check(body, true);
            let cc = if prefix_2 { post } else { pre };
            let good = format!("{yy:02}{mm:02}{dd:02}{serial:03}{cc:02}");
            assert!(
                belgium_national_number(&good),
                "expected valid NN {good} (prefix_2={prefix_2})"
            );
            valid += 1;

            // Pick a checksum that matches neither century reading.
            let bad_cc = (0u64..=99)
                .find(|c| *c != pre && *c != post)
                .expect("a non-matching checksum exists");
            let bad = format!("{yy:02}{mm:02}{dd:02}{serial:03}{bad_cc:02}");
            assert!(!belgium_national_number(&bad), "expected invalid NN {bad}");
            invalid += 1;
        }
        // Structural / date rejects.
        assert!(!belgium_national_number("9001010012"), "10 digits");
        assert!(!belgium_national_number("90130100123"), "month 13 invalid");
        assert!(!belgium_national_number("90014000123"), "day 40 invalid");
        invalid += 3;
        assert!(valid >= 30, "only {valid} valid NN vectors");
        assert!(invalid >= 30, "only {invalid} invalid NN vectors");
    }

    #[test]
    fn known_valid_vector() {
        // Born 1990-01-01, serial 001: 900101001 mod 97 = 74, check = 23.
        assert!(belgium_national_number("90010100123"));
        assert!(belgium_national_number("90.01.01-001.23"), "separators");
    }
}
