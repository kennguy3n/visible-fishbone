//! Australia identifier validators: Tax File Number (TFN) and
//! Medicare card number.

use crate::validators::digits;

/// Per-position weights for the 9-digit TFN checksum (most TFNs).
const TFN_WEIGHTS_9: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
/// Per-position weights for legacy 8-digit TFNs.
const TFN_WEIGHTS_8: [u32; 8] = [10, 7, 8, 4, 6, 3, 5, 1];
/// Per-position weights for the Medicare check digit (first 8 digits).
const MEDICARE_WEIGHTS: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];

/// Australia Tax File Number: eight (legacy) or nine digits whose
/// weighted sum is divisible by 11.
///
/// The ATO publishes the per-position weights; a number is valid iff
/// `Σ digitᵢ · weightᵢ ≡ 0 (mod 11)`. Spaces the pattern allows are
/// stripped first.
#[must_use]
pub fn australia_tfn(s: &str) -> bool {
    let d = digits(s);
    let sum: u32 = match d.len() {
        9 => d
            .iter()
            .zip(TFN_WEIGHTS_9)
            .map(|(&x, w)| u32::from(x) * w)
            .sum(),
        8 => d
            .iter()
            .zip(TFN_WEIGHTS_8)
            .map(|(&x, w)| u32::from(x) * w)
            .sum(),
        _ => return false,
    };
    sum.is_multiple_of(11)
}

/// Australia Medicare card number: ten digits where the ninth is a
/// weighted modulus-10 check over the first eight.
///
/// The first digit is in `2..=6` (the only issued ranges); the check
/// digit is `Σ digitᵢ · weightᵢ mod 10` with weights `1,3,7,9,1,3,7,9`
/// over the first eight digits. The tenth digit is the card issue
/// number and is not otherwise constrained.
#[must_use]
pub fn australia_medicare(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    if !(2..=6).contains(&d[0]) {
        return false;
    }
    let sum: u32 = d[..8]
        .iter()
        .zip(MEDICARE_WEIGHTS)
        .map(|(&x, w)| u32::from(x) * w)
        .sum();
    u32::from(d[8]) == sum % 10
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Find a 9th digit making the 9-digit TFN base valid, if one
    /// exists (some bases have no single-digit solution mod 11).
    fn tfn_check9(base: &[u8; 8]) -> Option<u8> {
        for c in 0u8..10 {
            let mut full = [0u8; 9];
            full[..8].copy_from_slice(base);
            full[8] = c;
            let sum: u32 = full
                .iter()
                .zip(TFN_WEIGHTS_9)
                .map(|(&x, w)| u32::from(x) * w)
                .sum();
            if sum.is_multiple_of(11) {
                return Some(c);
            }
        }
        None
    }

    fn medicare_check(base: &[u8; 8]) -> u8 {
        let sum: u32 = base
            .iter()
            .zip(MEDICARE_WEIGHTS)
            .map(|(&x, w)| u32::from(x) * w)
            .sum();
        (sum % 10) as u8
    }

    #[test]
    fn tfn_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 1u32..50 {
            let mut base = [0u8; 8];
            let mut v = seed.wrapping_mul(2_654_435_761);
            for slot in &mut base {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(seed + 1);
            }
            let Some(check) = tfn_check9(&base) else {
                continue;
            };
            let s: String = base
                .iter()
                .chain(std::iter::once(&check))
                .map(|d| char::from(b'0' + d))
                .collect();
            assert!(australia_tfn(&s), "expected valid TFN {s}");
            valid += 1;
            // Flip the check digit; verify the flip really breaks mod 11
            // before asserting (avoid the rare collision).
            for delta in 1u8..10 {
                let bad_check = (check + delta) % 10;
                let sum: u32 = base
                    .iter()
                    .zip(TFN_WEIGHTS_9)
                    .map(|(&x, w)| u32::from(x) * w)
                    .sum::<u32>()
                    + 10 * u32::from(bad_check);
                if !sum.is_multiple_of(11) {
                    let bad: String = base
                        .iter()
                        .chain(std::iter::once(&bad_check))
                        .map(|d| char::from(b'0' + d))
                        .collect();
                    assert!(!australia_tfn(&bad), "expected invalid TFN {bad}");
                    invalid += 1;
                    break;
                }
            }
        }
        assert!(!australia_tfn("1234567"), "7 digits");
        assert!(!australia_tfn("1234567890"), "10 digits");
        invalid += 2;
        assert!(valid >= 25, "only {valid} valid TFN vectors");
        assert!(invalid >= 25, "only {invalid} invalid TFN vectors");
    }

    #[test]
    fn medicare_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let mut base = [0u8; 8];
            let mut v = seed.wrapping_mul(40_503).wrapping_add(7);
            for slot in &mut base {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(seed + 1);
            }
            // First digit must be 2..=6.
            base[0] = 2 + (seed % 5) as u8;
            let check = medicare_check(&base);
            for issue in 1u8..=2 {
                let s: String = base
                    .iter()
                    .chain([check, issue].iter())
                    .map(|d| char::from(b'0' + d))
                    .collect();
                assert!(australia_medicare(&s), "expected valid Medicare {s}");
                valid += 1;
            }
            let bad_check = (check + 1) % 10;
            if bad_check != check {
                let s: String = base
                    .iter()
                    .chain([bad_check, 1u8].iter())
                    .map(|d| char::from(b'0' + d))
                    .collect();
                assert!(!australia_medicare(&s), "expected invalid Medicare {s}");
                invalid += 1;
            }
        }
        // First digit outside 2..=6.
        assert!(!australia_medicare("1234567891"), "leading 1");
        assert!(!australia_medicare("7234567891"), "leading 7");
        assert!(!australia_medicare("223456789"), "9 digits");
        invalid += 3;
        assert!(valid >= 50, "only {valid} valid Medicare vectors");
        assert!(invalid >= 20, "only {invalid} invalid Medicare vectors");
    }
}
