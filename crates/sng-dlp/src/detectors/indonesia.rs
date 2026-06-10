//! Indonesia NIK (Nomor Induk Kependudukan / KTP) validator.

use crate::validators::{digits, valid_ymd};

/// Indonesia NIK: sixteen digits encoding region, an embedded date of
/// birth, and a serial.
///
/// Layout: province `(2)`, regency `(2)`, district `(2)`, date of
/// birth `DDMMYY (6)` and a `(4)` serial. For female holders 40 is
/// added to the day field, so the day is normalised by subtracting 40
/// when it exceeds 40 before being validated as a real calendar date.
/// The province code is in the issued range `11..=94`, and the serial
/// is never `0000`. The NIK has no trailing check digit; this is a
/// structural + embedded-date validator.
#[must_use]
pub fn indonesia_nik(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 16 {
        return false;
    }
    let province = u32::from(d[0]) * 10 + u32::from(d[1]);
    if !(11..=94).contains(&province) {
        return false;
    }
    let mut day = u32::from(d[6]) * 10 + u32::from(d[7]);
    let month = u32::from(d[8]) * 10 + u32::from(d[9]);
    // Female holders: day field carries +40.
    if day > 40 {
        day -= 40;
    }
    // Year is two digits (century ambiguous); 2000 is a leap year so a
    // 29 February birthday is accepted.
    if !valid_ymd(2000, month, day) {
        return false;
    }
    // Serial (last four digits) is never all zero.
    !(d[12] == 0 && d[13] == 0 && d[14] == 0 && d[15] == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nik_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let province = 11 + (seed % 84); // 11..=94
            let regency = seed % 100;
            let district = seed % 100;
            let day = 1 + (seed % 28); // safe day
            let female = seed % 2 == 0;
            let day_field = if female { day + 40 } else { day };
            let month = 1 + (seed % 12);
            let year = seed % 100;
            let serial = 1 + (seed % 9998);
            let s = format!(
                "{province:02}{regency:02}{district:02}{day_field:02}{month:02}{year:02}{serial:04}"
            );
            assert_eq!(s.len(), 16);
            assert!(indonesia_nik(&s), "expected valid NIK {s}");
            valid += 1;

            // Corrupt the month to 13 → invalid.
            let bad = format!(
                "{province:02}{regency:02}{district:02}{day_field:02}13{year:02}{serial:04}"
            );
            assert!(!indonesia_nik(&bad), "expected invalid NIK {bad}");
            invalid += 1;
        }
        // Structural rejects, built field-by-field so the layout is
        // unambiguous: province(2) regency(2) district(2) DD MM YY serial(4).
        let bad = [
            format!("{:02}{:02}{:02}{:02}{:02}{:02}{:04}", 0, 1, 1, 15, 6, 90, 1), // province 00
            format!(
                "{:02}{:02}{:02}{:02}{:02}{:02}{:04}",
                99, 1, 1, 15, 6, 90, 1
            ), // province 99
            format!(
                "{:02}{:02}{:02}{:02}{:02}{:02}{:04}",
                31, 74, 1, 15, 13, 90, 1
            ), // month 13
            format!(
                "{:02}{:02}{:02}{:02}{:02}{:02}{:04}",
                31, 74, 1, 80, 6, 90, 1
            ), // day 80 → 40 after −40, no month has 40 days
            format!(
                "{:02}{:02}{:02}{:02}{:02}{:02}{:04}",
                31, 74, 1, 15, 6, 90, 0
            ), // serial 0000
            "317404329900".to_string(),                                            // too short
            "3174043299001234567".to_string(),                                     // too long
        ];
        for s in &bad {
            assert!(!indonesia_nik(s), "expected invalid NIK {s}");
            invalid += 1;
        }
        assert!(valid >= 30, "only {valid} valid NIK vectors");
        assert!(invalid >= 30, "only {invalid} invalid NIK vectors");
    }
}
