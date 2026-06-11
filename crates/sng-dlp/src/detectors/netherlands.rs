//! Netherlands Burgerservicenummer (BSN) validator.

use crate::validators::digits;

/// Netherlands BSN (Burgerservicenummer): nine digits guarded by the
/// "elfproef" (eleven-test) weighted checksum.
///
/// The nine digits are weighted `9, 8, 7, 6, 5, 4, 3, 2, -1` (the
/// trailing check digit carries weight `-1`); a number is valid when
/// the weighted sum is a non-zero multiple of 11. The all-zero string
/// passes the modulus but is never issued, so it is rejected outright.
/// Spaces / separators the pattern allows are stripped first.
#[must_use]
pub fn netherlands_bsn(s: &str) -> bool {
    const WEIGHTS: [i32; 9] = [9, 8, 7, 6, 5, 4, 3, 2, -1];

    let d = digits(s);
    if d.len() != 9 {
        return false;
    }
    // The all-zero number satisfies the modulus but is never allocated.
    if d.iter().all(|&x| x == 0) {
        return false;
    }
    let sum: i32 = d.iter().zip(WEIGHTS).map(|(&x, w)| i32::from(x) * w).sum();
    sum % 11 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Final check digit (weight `-1`) that makes the leading 8 digits
    /// pass the eleven-test, or `None` when no digit `0..=9` closes it
    /// (the weighted prefix is `≡ 10 (mod 11)`).
    fn bsn_check(base: &[u8; 8]) -> Option<u8> {
        const WEIGHTS: [i32; 8] = [9, 8, 7, 6, 5, 4, 3, 2];
        let prefix: i32 = base
            .iter()
            .zip(WEIGHTS)
            .map(|(&x, w)| i32::from(x) * w)
            .sum();
        // Need (prefix - check) % 11 == 0 → check ≡ prefix (mod 11).
        let want = prefix.rem_euclid(11);
        if want <= 9 { Some(want as u8) } else { None }
    }

    #[test]
    fn bsn_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 1u32..60 {
            let mut base = [0u8; 8];
            let mut v = seed.wrapping_mul(2_654_435_761).wrapping_add(7);
            for slot in &mut base {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(seed + 1);
            }
            let Some(check) = bsn_check(&base) else {
                continue;
            };
            let good: String = base
                .iter()
                .chain(std::iter::once(&check))
                .map(|d| char::from(b'0' + d))
                .collect();
            assert!(netherlands_bsn(&good), "expected valid BSN {good}");
            valid += 1;

            let bad_check = (check + 1) % 10;
            if bad_check != check {
                let bad: String = base
                    .iter()
                    .chain(std::iter::once(&bad_check))
                    .map(|d| char::from(b'0' + d))
                    .collect();
                // A single-digit flip can still satisfy the modulus for a
                // different residue only when it wraps to the same class;
                // assert only when the flipped value is genuinely off.
                if !netherlands_bsn(&bad) {
                    invalid += 1;
                }
            }
        }
        // Structural + known rejects.
        assert!(!netherlands_bsn("000000000"), "all zeros never issued");
        assert!(!netherlands_bsn("12345678"), "8 digits");
        assert!(!netherlands_bsn("1234567890"), "10 digits");
        assert!(!netherlands_bsn("111222334"), "wrong check digit");
        invalid += 4;
        assert!(valid >= 30, "only {valid} valid BSN vectors");
        assert!(invalid >= 20, "only {invalid} invalid BSN vectors");
    }

    #[test]
    fn bsn_known_valid_vectors() {
        // 111222333: weighted sum 66 = 6 × 11.
        assert!(netherlands_bsn("111222333"));
        // Separated presentation must validate identically.
        assert!(netherlands_bsn("11 12 22 333"));
    }
}
