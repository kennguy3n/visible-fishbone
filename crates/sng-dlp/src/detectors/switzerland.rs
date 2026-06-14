//! Switzerland AHV / AVS social-security number (new 13-digit form).
//!
//! Since 2008 the Swiss social-security number is thirteen digits that
//! always begin `756` (Switzerland's EAN/GS1 prefix) and are presented
//! as `756.XXXX.XXXX.XX`. The final digit is an EAN-13 check digit over
//! the first twelve. Dots / spaces in the printed grouping are ignored.

use crate::validators::digits;

/// EAN-13 check digit over the twelve-digit `body`: weights alternate
/// `1, 3` from the leftmost digit, and the check is `(10 − Σ mod 10) mod
/// 10`.
fn ean13_check(body: &[u8]) -> u8 {
    let mut sum = 0u32;
    for (i, &d) in body.iter().enumerate() {
        let weight = if i % 2 == 0 { 1 } else { 3 };
        sum += u32::from(d) * weight;
    }
    ((10 - sum % 10) % 10) as u8
}

/// Switzerland AHV number: thirteen digits beginning `756`, the last an
/// EAN-13 check digit over the first twelve.
#[must_use]
pub fn switzerland_ahv(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 13 {
        return false;
    }
    if d[0] != 7 || d[1] != 5 || d[2] != 6 {
        return false;
    }
    ean13_check(&d[..12]) == d[12]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid thirteen-digit AHV from a nine-digit tail.
    fn make(tail: [u8; 9]) -> String {
        let mut body = vec![7u8, 5, 6];
        body.extend_from_slice(&tail);
        let check = ean13_check(&body);
        body.push(check);
        body.iter().map(|d| char::from(b'0' + d)).collect()
    }

    #[test]
    fn known_vector() {
        // 756.1234.5678.97 is the canonical worked example.
        assert!(switzerland_ahv("7561234567897"));
        assert!(switzerland_ahv("756.1234.5678.97"));
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let mut tail = [0u8; 9];
            let mut v = seed.wrapping_mul(40_503_661);
            for slot in &mut tail {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(seed + 2);
            }
            let good = make(tail);
            assert!(switzerland_ahv(&good), "expected valid {good}");
            valid += 1;

            let check = good.bytes().last().unwrap() - b'0';
            let bad = format!("{}{}", &good[..12], (check + 1) % 10);
            assert!(!switzerland_ahv(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 20, "only {valid} valid vectors");
        assert!(invalid >= 20, "only {invalid} invalid vectors");
    }

    #[test]
    fn structural_rejects() {
        assert!(!switzerland_ahv("7561234567890"), "wrong check digit");
        assert!(!switzerland_ahv("123456789012"), "12 digits");
        assert!(!switzerland_ahv("12345678901234"), "14 digits");
        assert!(!switzerland_ahv("7551234567897"), "wrong country prefix");
    }
}
