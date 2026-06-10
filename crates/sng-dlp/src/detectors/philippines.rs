//! Philippines UMID / Common Reference Number (CRN) validator.

use crate::validators::digits;

/// Philippines UMID / CRN: a twelve-digit common reference number.
///
/// The CRN carries no publicly documented check digit, so this is a
/// structural validator: exactly twelve digits, a non-zero leading
/// digit (the series block is never `0000`), and not a single repeated
/// digit (which is never issued). Combined with the regex shape and
/// the proximity `umid` / `crn` / `sss` cues this keeps false
/// positives low. Separators (spaces / hyphens) the pattern allows are
/// stripped first.
#[must_use]
pub fn philippines_umid(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 12 {
        return false;
    }
    if d[0] == 0 {
        return false;
    }
    // Reject a single repeated digit.
    if d.windows(2).all(|w| w[0] == w[1]) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn umid_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let mut d = [0u8; 12];
            let mut v = (u64::from(seed))
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(19);
            for slot in &mut d {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(u64::from(seed) + 1);
            }
            d[0] = 1 + (seed % 9) as u8; // non-zero leading digit
            let s: String = d.iter().map(|x| char::from(b'0' + x)).collect();
            assert!(philippines_umid(&s), "expected valid UMID {s}");
            // Grouped 4-7-1 presentation validates identically.
            let grouped = format!("{}-{}-{}", &s[0..4], &s[4..11], &s[11..12]);
            assert!(
                philippines_umid(&grouped),
                "expected valid grouped UMID {grouped}"
            );
            valid += 2;
        }
        // Structural rejects.
        let bad = [
            "000000000000",  // leading zero + repdigit
            "111111111111",  // repdigit
            "012345678901",  // leading zero
            "12345678901",   // 11 digits
            "1234567890123", // 13 digits
            "1234abcd5678",  // non-digit body
        ];
        for s in bad {
            assert!(!philippines_umid(s), "expected invalid UMID {s}");
            invalid += 1;
        }
        assert!(valid >= 50, "only {valid} valid UMID vectors");
        assert!(invalid >= 5, "only {invalid} invalid UMID vectors");
    }
}
