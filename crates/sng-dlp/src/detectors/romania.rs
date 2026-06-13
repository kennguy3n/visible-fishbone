//! Romania CNP (Cod Numeric Personal) validator.
//!
//! The CNP is thirteen digits `S YYMMDD JJ NNN C`: a sex/century digit,
//! a six-digit date of birth, a two-digit county code, a three-digit
//! serial and a weighted mod-11 check digit. The check weights the
//! first twelve digits by `279146358279`; if `Σ mod 11 == 10` the check
//! digit is `1`, otherwise it is `Σ mod 11`.

use crate::validators::{digits, valid_ymd};

const WEIGHTS: [u32; 12] = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9];

/// Birth-century base year for the sex/century digit, or `None` when it
/// is not a CNP-issued value (`7`/`8` cover foreign residents whose
/// birth century is not encoded, so they are treated as 2000s for date
/// validity).
fn century(sex: u8) -> Option<u32> {
    match sex {
        1 | 2 => Some(1900),
        3 | 4 => Some(1800),
        // 5/6 are 2000s; 7/8 are foreign residents whose century is not
        // encoded, so treat them as 2000s for date validity.
        5..=8 => Some(2000),
        _ => None,
    }
}

/// The weighted mod-11 CNP check digit over the twelve-digit `body`.
fn check_digit(body: &[u8]) -> u8 {
    let sum: u32 = (0..12).map(|i| WEIGHTS[i] * u32::from(body[i])).sum();
    let r = sum % 11;
    if r == 10 { 1 } else { r as u8 }
}

/// Romania CNP: thirteen digits with a valid sex/century digit, a real
/// date of birth, a county code in `01..=52` or `70`, a non-zero serial
/// and the weighted mod-11 check digit.
#[must_use]
pub fn romania_cnp(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 13 {
        return false;
    }
    let Some(base) = century(d[0]) else {
        return false;
    };
    let yy = u32::from(d[1]) * 10 + u32::from(d[2]);
    let mm = u32::from(d[3]) * 10 + u32::from(d[4]);
    let dd = u32::from(d[5]) * 10 + u32::from(d[6]);
    if !valid_ymd(base + yy, mm, dd) {
        return false;
    }
    let county = u32::from(d[7]) * 10 + u32::from(d[8]);
    if !(1..=52).contains(&county) && county != 70 {
        return false;
    }
    let serial = u32::from(d[9]) * 100 + u32::from(d[10]) * 10 + u32::from(d[11]);
    if serial == 0 {
        return false;
    }
    check_digit(&d[..12]) == d[12]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid CNP from a sex digit, date, county and serial.
    fn make(sex: u8, yy: u8, mm: u8, dd: u8, county: u8, serial: u16) -> String {
        let mut body = vec![
            sex,
            yy / 10,
            yy % 10,
            mm / 10,
            mm % 10,
            dd / 10,
            dd % 10,
            county / 10,
            county % 10,
            (serial / 100 % 10) as u8,
            (serial / 10 % 10) as u8,
            (serial % 10) as u8,
        ];
        body.push(check_digit(&body));
        body.iter().map(|d| char::from(b'0' + d)).collect()
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let sex = (seed % 8 + 1) as u8;
            let yy = (seed * 7 % 100) as u8;
            let mm = (seed % 12 + 1) as u8;
            let dd = (seed % 28 + 1) as u8;
            let county = (seed % 52 + 1) as u8;
            let serial = (seed % 999 + 1) as u16;
            let good = make(sex, yy, mm, dd, county, serial);
            assert!(romania_cnp(&good), "expected valid {good}");
            valid += 1;

            let check = good.bytes().last().unwrap() - b'0';
            let bad = format!("{}{}", &good[..12], (check + 1) % 10);
            assert!(!romania_cnp(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 20, "only {valid} valid vectors");
        assert!(invalid >= 20, "only {invalid} invalid vectors");
    }

    #[test]
    fn structural_rejects() {
        let good = make(1, 80, 6, 15, 40, 123);
        // Impossible month.
        let bad_month = format!("{}{}{}", &good[..3], "99", &good[5..]);
        assert!(!romania_cnp(&bad_month), "month 99");
        // County code out of range (00).
        let bad_county = format!("{}{}{}", &good[..7], "00", &good[9..]);
        assert!(!romania_cnp(&bad_county), "county 00");
        // Sex/century digit 0 and 9 are not CNP-issued.
        assert!(!romania_cnp(&format!("0{}", &good[1..])), "sex digit 0");
        assert!(!romania_cnp(&format!("9{}", &good[1..])), "sex digit 9");
        assert!(!romania_cnp(&good[..12]), "12 digits");
    }
}
