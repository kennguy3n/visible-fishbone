//! Canada Social Insurance Number (SIN) validator.

use crate::validators::{digits, luhn_digits};

/// Canada Social Insurance Number: nine digits guarded by a Luhn
/// (mod-10) check digit.
///
/// The leading digit encodes the issuing province/program and is never
/// `0` (and `8` is unassigned), so a leading `0` is rejected outright;
/// the Luhn check over all nine digits suppresses same-shaped random
/// runs. Spaces / hyphens the pattern allows are stripped first.
#[must_use]
pub fn canada_sin(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    if d[0] == 0 {
        return false;
    }
    luhn_digits(&d)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Final Luhn check digit that makes `base` (8 digits) valid.
    fn luhn_check(base: &[u8; 8]) -> u8 {
        for c in 0u8..10 {
            let mut full = Vec::with_capacity(9);
            full.extend_from_slice(base);
            full.push(c);
            if luhn_digits(&full) {
                return c;
            }
        }
        unreachable!("a Luhn check digit always exists")
    }

    #[test]
    fn sin_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 1u32..40 {
            let mut base = [0u8; 8];
            let mut v = seed.wrapping_mul(2_246_822_519);
            for slot in &mut base {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(seed + 3);
            }
            // Force a non-zero leading digit.
            if base[0] == 0 {
                base[0] = 1;
            }
            let check = luhn_check(&base);
            let digits_str: String = base
                .iter()
                .chain(std::iter::once(&check))
                .map(|d| char::from(b'0' + d))
                .collect();
            assert!(canada_sin(&digits_str), "expected valid SIN {digits_str}");
            // Grouped 3-3-3 presentation validates identically.
            let grouped = format!(
                "{} {} {}",
                &digits_str[0..3],
                &digits_str[3..6],
                &digits_str[6..9]
            );
            assert!(canada_sin(&grouped), "expected valid grouped SIN {grouped}");
            valid += 2;

            let bad_check = (check + 1) % 10;
            if bad_check != check {
                let bad: String = base
                    .iter()
                    .chain(std::iter::once(&bad_check))
                    .map(|d| char::from(b'0' + d))
                    .collect();
                assert!(!canada_sin(&bad), "expected invalid SIN {bad}");
                invalid += 1;
            }
        }
        // Structural rejects.
        assert!(!canada_sin("046454286"), "leading-zero region");
        assert!(!canada_sin("12345678"), "8 digits");
        assert!(!canada_sin("1234567890"), "10 digits");
        invalid += 3;
        assert!(valid >= 30, "only {valid} valid SIN vectors");
        assert!(invalid >= 20, "only {invalid} invalid SIN vectors");
    }

    #[test]
    fn sin_known_valid_vector() {
        // 046 454 286 is the canonical Wikipedia SIN example (Luhn-valid)
        // but starts with 0; strip the leading-zero guard to confirm the
        // Luhn math matches the published example.
        assert!(luhn_digits(&[0, 4, 6, 4, 5, 4, 2, 8, 6]));
    }
}
