//! Poland PESEL validator.

use crate::validators::{digits, valid_ymd};

/// Decode the PESEL month field into `(century, real_month)`. PESEL
/// encodes the birth century by offsetting the month: `+0` for the
/// 1900s, `+20` for the 2000s, `+40` for 2100s, `+60` for 2200s, and
/// `+80` for the 1800s. Returns `None` for an out-of-range field.
fn decode_month(field: u32) -> Option<(u32, u32)> {
    match field {
        1..=12 => Some((1900, field)),
        21..=32 => Some((2000, field - 20)),
        41..=52 => Some((2100, field - 40)),
        61..=72 => Some((2200, field - 60)),
        81..=92 => Some((1800, field - 80)),
        _ => None,
    }
}

/// Poland PESEL: eleven digits embedding the holder's date of birth
/// and closed by a weighted modulo-10 check digit.
///
/// The first six digits are `YYMMDD` with the century folded into the
/// month field (see [`decode_month`]); that date must be a real
/// calendar date. The check digit is `(10 - (Σ wᵢ·dᵢ mod 10)) mod 10`
/// over the leading ten digits with weights `1, 3, 7, 9` repeating.
#[must_use]
pub fn poland_pesel(s: &str) -> bool {
    const WEIGHTS: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];

    let d = digits(s);
    if d.len() != 11 {
        return false;
    }
    let Some((century, month)) = decode_month(u32::from(d[2]) * 10 + u32::from(d[3])) else {
        return false;
    };
    let year = century + u32::from(d[0]) * 10 + u32::from(d[1]);
    let day = u32::from(d[4]) * 10 + u32::from(d[5]);
    if !valid_ymd(year, month, day) {
        return false;
    }

    let sum: u32 = d[..10]
        .iter()
        .zip(WEIGHTS)
        .map(|(&x, w)| u32::from(x) * w)
        .sum();
    let expected = (10 - sum % 10) % 10;
    u32::from(d[10]) == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Final check digit that closes a valid PESEL over the leading 10.
    fn pesel_check(base: &[u8; 10]) -> u8 {
        const WEIGHTS: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
        let sum: u32 = base
            .iter()
            .zip(WEIGHTS)
            .map(|(&x, w)| u32::from(x) * w)
            .sum();
        ((10 - sum % 10) % 10) as u8
    }

    #[test]
    fn pesel_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        // Sweep real dates across every supported century offset.
        let offsets = [0u8, 20, 40, 60, 80];
        for (i, &off) in offsets.iter().enumerate() {
            for seed in 0u32..12 {
                let yy = (seed * 7 + 3) % 100;
                let month = (seed % 12) + 1; // 1..=12
                let day = (seed % 28) + 1; // always a real day
                let serial = (seed * 137 + i as u32 * 11) % 10000;
                let mm = month + u32::from(off);
                let mut base = [0u8; 10];
                base[0] = (yy / 10) as u8;
                base[1] = (yy % 10) as u8;
                base[2] = (mm / 10) as u8;
                base[3] = (mm % 10) as u8;
                base[4] = (day / 10) as u8;
                base[5] = (day % 10) as u8;
                base[6] = (serial / 1000) as u8;
                base[7] = (serial / 100 % 10) as u8;
                base[8] = (serial / 10 % 10) as u8;
                base[9] = (serial % 10) as u8;
                let check = pesel_check(&base);
                let good: String = base
                    .iter()
                    .chain(std::iter::once(&check))
                    .map(|d| char::from(b'0' + d))
                    .collect();
                assert!(poland_pesel(&good), "expected valid PESEL {good}");
                valid += 1;

                let bad_check = (check + 1) % 10;
                if bad_check != check {
                    let bad: String = base
                        .iter()
                        .chain(std::iter::once(&bad_check))
                        .map(|d| char::from(b'0' + d))
                        .collect();
                    assert!(!poland_pesel(&bad), "expected invalid PESEL {bad}");
                    invalid += 1;
                }
            }
        }
        // Structural / date rejects.
        assert!(!poland_pesel("4405140145"), "10 digits");
        assert!(!poland_pesel("44131401458"), "month field 13 invalid");
        assert!(!poland_pesel("44051401457"), "wrong check digit");
        invalid += 3;
        assert!(valid >= 40, "only {valid} valid PESEL vectors");
        assert!(invalid >= 30, "only {invalid} invalid PESEL vectors");
    }

    #[test]
    fn known_valid_vector() {
        // 44051401458 — the canonical Wikipedia example (1944-05-14).
        assert!(poland_pesel("44051401458"));
    }
}
