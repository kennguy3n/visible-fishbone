//! United Kingdom identifier validators: National Insurance Number
//! (NINO) and NHS number.

use crate::validators::digits;

/// Two-letter NINO prefixes that are never allocated. Mirrors
/// `ukNinoInvalidPrefixes` in the Go twin.
const INVALID_NINO_PREFIXES: [&str; 7] = ["BG", "GB", "KN", "NK", "NT", "TN", "ZZ"];

/// UK National Insurance Number: two prefix letters, six digits and a
/// single suffix letter `A`–`D`.
///
/// NINOs carry no check digit; validity is defined by HMRC's
/// allocation rules instead:
/// * the first letter is not `D`, `F`, `I`, `Q`, `U` or `V`;
/// * the second letter is additionally not `O`;
/// * the two-letter prefix is none of the administrative-reserved
///   combinations (`BG`, `GB`, `KN`, `NK`, `NT`, `TN`, `ZZ`); and
/// * the suffix is one of `A`, `B`, `C`, `D`.
///
/// Separators (spaces) the pattern allows are stripped first.
#[must_use]
pub fn uk_nino(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() != 9 {
        return false;
    }
    if !c[..2].iter().all(char::is_ascii_alphabetic) {
        return false;
    }
    if !c[2..8].iter().all(char::is_ascii_digit) {
        return false;
    }
    // First letter: not D, F, I, Q, U, V.
    if matches!(c[0], 'D' | 'F' | 'I' | 'Q' | 'U' | 'V') {
        return false;
    }
    // Second letter: not D, F, I, O, Q, U, V.
    if matches!(c[1], 'D' | 'F' | 'I' | 'O' | 'Q' | 'U' | 'V') {
        return false;
    }
    let prefix: String = c[..2].iter().collect();
    if INVALID_NINO_PREFIXES.contains(&prefix.as_str()) {
        return false;
    }
    matches!(c[8], 'A' | 'B' | 'C' | 'D')
}

/// UK NHS number: ten digits guarded by a weighted modulus-11 check
/// digit.
///
/// The first nine digits are weighted `10, 9, … 2`; the remainder of
/// the weighted sum modulo 11 is subtracted from 11 to give the check
/// digit. A computed value of 11 means a check digit of 0; a computed
/// value of 10 is invalid (such a number is never issued) and so the
/// whole identifier is rejected.
#[must_use]
pub fn uk_nhs(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    let sum: u32 = d[..9]
        .iter()
        .zip((2..=10u32).rev())
        .map(|(&x, w)| u32::from(x) * w)
        .sum();
    let remainder = sum % 11;
    let check = (11 - remainder) % 11;
    // A computed check of 10 is never issued.
    check != 10 && u32::from(d[9]) == check
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compute the NHS check digit for a 9-digit base, or `None` when
    /// the base yields the unissued value 10.
    fn nhs_check(base: &[u8; 9]) -> Option<u8> {
        let sum: u32 = (0..9).map(|i| u32::from(base[i]) * (10 - i as u32)).sum();
        let check = (11 - sum % 11) % 11;
        if check == 10 { None } else { Some(check as u8) }
    }

    fn nhs_string(base: &[u8; 9], check: u8) -> String {
        base.iter()
            .chain(std::iter::once(&check))
            .map(|d| char::from(b'0' + d))
            .collect()
    }

    #[test]
    fn nino_accepts_valid_prefixes() {
        // Sweep allowed prefix letters and suffixes for >50 vectors.
        let first = ['A', 'B', 'C', 'E', 'G', 'H', 'J', 'M', 'P', 'R'];
        let second = ['A', 'B', 'C', 'E', 'G', 'H', 'J', 'M', 'P', 'R'];
        let suffixes = ['A', 'B', 'C', 'D'];
        let mut count = 0;
        for (i, &f) in first.iter().enumerate() {
            let s = second[i];
            for &suf in &suffixes {
                let prefix = format!("{f}{s}");
                if INVALID_NINO_PREFIXES.contains(&prefix.as_str()) {
                    continue;
                }
                let nino = format!("{prefix}123456{suf}");
                assert!(uk_nino(&nino), "expected valid NINO {nino}");
                // Spaced presentation must validate identically.
                let spaced = format!("{f}{s} 12 34 56 {suf}");
                assert!(uk_nino(&spaced), "expected valid spaced NINO {spaced}");
                count += 2;
            }
        }
        assert!(count >= 50, "only {count} valid NINO vectors");
    }

    #[test]
    fn nino_rejects_invalid() {
        let bad = [
            "DA123456C",  // first letter D
            "FA123456C",  // first letter F
            "IA123456C",  // first letter I
            "QA123456C",  // first letter Q
            "UA123456C",  // first letter U
            "VA123456C",  // first letter V
            "AO123456C",  // second letter O
            "AD123456C",  // second letter D
            "AF123456C",  // second letter F
            "AI123456C",  // second letter I
            "AQ123456C",  // second letter Q
            "AU123456C",  // second letter U
            "AV123456C",  // second letter V
            "BG123456C",  // reserved prefix
            "GB123456C",  // reserved prefix
            "KN123456C",  // reserved prefix
            "NK123456C",  // reserved prefix
            "NT123456C",  // reserved prefix
            "TN123456C",  // reserved prefix
            "ZZ123456C",  // reserved prefix
            "AB123456E",  // suffix E
            "AB123456F",  // suffix F
            "AB123456Z",  // suffix Z
            "AB12345C",   // too few digits
            "AB1234567C", // too many digits
            "A1123456C",  // digit in prefix
            "ABC23456C",  // letter in body
            "AB12345 6",  // missing suffix letter
            "1234567890", // all digits
        ];
        for s in bad {
            assert!(!uk_nino(s), "expected invalid NINO {s}");
        }
        assert!(bad.len() >= 25);
    }

    #[test]
    fn nhs_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        // Sweep many 9-digit bases; build the valid number then flip the
        // check digit to a different value (guaranteed invalid).
        for seed in 0u32..40 {
            let mut base = [0u8; 9];
            let mut v = seed.wrapping_mul(2_654_435_761);
            for slot in &mut base {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(seed + 1);
            }
            let Some(check) = nhs_check(&base) else {
                continue;
            };
            let good = nhs_string(&base, check);
            assert!(uk_nhs(&good), "expected valid NHS {good}");
            // Spaced 3-3-4 presentation validates identically.
            let spaced = format!("{} {} {}", &good[0..3], &good[3..6], &good[6..10]);
            assert!(uk_nhs(&spaced), "expected valid spaced NHS {spaced}");
            valid += 2;

            let bad_check = (check + 1) % 10;
            if Some(bad_check) != Some(check) {
                let bad = nhs_string(&base, bad_check);
                if nhs_check(&base) != Some(bad_check) {
                    assert!(!uk_nhs(&bad), "expected invalid NHS {bad}");
                    invalid += 1;
                }
            }
        }
        // Structural rejects.
        assert!(!uk_nhs("123456789"), "9 digits");
        assert!(!uk_nhs("12345678901"), "11 digits");
        assert!(!uk_nhs("ABCDEFGHIJ"), "non-digits");
        invalid += 3;
        assert!(valid >= 30, "only {valid} valid NHS vectors");
        assert!(invalid >= 20, "only {invalid} invalid NHS vectors");
    }
}
