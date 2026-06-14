//! Israel national identification number (Teudat Zehut) validator.
//!
//! The Israeli ID is nine digits (shorter numbers are zero-padded to
//! nine). It is closed by a Luhn-style check: each digit is weighted
//! `1` in the odd positions and `2` in the even positions (counting
//! from the left, one-based); a two-digit product has its digits
//! summed (equivalently, subtract nine), and the running total must be
//! a multiple of ten.

use crate::validators::digits;

/// Israel Teudat Zehut: nine digits with the alternating `1,2` Luhn
/// check described above.
#[must_use]
pub fn israel_id(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &digit) in d.iter().enumerate() {
        let mut v = u32::from(digit) * if i % 2 == 0 { 1 } else { 2 };
        if v > 9 {
            v -= 9;
        }
        sum += v;
    }
    sum.is_multiple_of(10)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The check digit (position 9, weight 1) that closes an eight-digit
    /// body.
    fn check_digit(body: &[u8; 8]) -> u8 {
        let mut sum = 0u32;
        for (i, &digit) in body.iter().enumerate() {
            let mut v = u32::from(digit) * if i % 2 == 0 { 1 } else { 2 };
            if v > 9 {
                v -= 9;
            }
            sum += v;
        }
        ((10 - sum % 10) % 10) as u8
    }

    #[test]
    fn known_vector() {
        // 123456782 is a widely cited valid Teudat Zehut.
        assert!(israel_id("123456782"));
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let mut body = [0u8; 8];
            let mut v = seed.wrapping_mul(2_246_822_519);
            for slot in &mut body {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(seed + 3);
            }
            let check = check_digit(&body);
            let good: String = body
                .iter()
                .chain(std::iter::once(&check))
                .map(|d| char::from(b'0' + d))
                .collect();
            assert!(israel_id(&good), "expected valid {good}");
            valid += 1;

            let bad = format!("{}{}", &good[..8], (check + 1) % 10);
            assert!(!israel_id(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 20, "only {valid} valid vectors");
        assert!(invalid >= 20, "only {invalid} invalid vectors");
    }

    #[test]
    fn structural_rejects() {
        assert!(!israel_id("12345678"), "8 digits");
        assert!(!israel_id("1234567890"), "10 digits");
        assert!(!israel_id("123456789"), "wrong check digit");
    }
}
