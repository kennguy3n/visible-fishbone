//! South Africa national ID validator.
//!
//! The South African ID number is thirteen digits
//! `YYMMDD SSSS C A Z`: a six-digit date of birth, a four-digit gender
//! serial, a citizenship digit, a (now-unused) race digit `A`, and a
//! final Luhn (mod-10) check digit `Z` over the first twelve.

/// Strip separators and return exactly thirteen digits, or `None`.
fn thirteen_digits(s: &str) -> Option<[u32; 13]> {
    let mut out = [0u32; 13];
    let mut n = 0;
    for c in s.chars() {
        if c.is_whitespace() || c == '-' {
            continue;
        }
        let d = c.to_digit(10)?;
        if n == 13 {
            return None;
        }
        out[n] = d;
        n += 1;
    }
    if n == 13 { Some(out) } else { None }
}

/// The Luhn check digit over the twelve-digit `body` (most-significant
/// digit first), doubling every second digit from the right.
fn luhn_check(body: &[u32]) -> u32 {
    let mut sum = 0;
    let len = body.len();
    for (i, &d) in body.iter().enumerate() {
        // Position from the right (0-based); the check digit will sit at
        // the rightmost slot, so the last body digit is at index 1.
        let from_right = len - i;
        let v = if from_right % 2 == 1 { d * 2 } else { d };
        sum += if v > 9 { v - 9 } else { v };
    }
    (10 - (sum % 10)) % 10
}

/// South Africa ID: thirteen digits whose final digit is the Luhn
/// check over the preceding twelve. Separators (`-`, whitespace) are
/// ignored.
#[must_use]
pub fn south_africa_id(s: &str) -> bool {
    let Some(d) = thirteen_digits(s) else {
        return false;
    };
    luhn_check(&d[..12]) == d[12]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(body12: [u32; 12]) -> String {
        let check = luhn_check(&body12);
        let mut s: String = body12.iter().map(|d| char::from(b'0' + *d as u8)).collect();
        s.push(char::from(b'0' + check as u8));
        s
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in (0u64..=999_999_999_999).step_by(33_333_333_337) {
            let mut body = [0u32; 12];
            let mut v = seed;
            for slot in body.iter_mut().rev() {
                *slot = (v % 10) as u32;
                v /= 10;
            }
            let good = make(body);
            assert!(south_africa_id(&good), "expected valid {good}");
            valid += 1;

            let check = good.chars().last().unwrap().to_digit(10).unwrap();
            let bad = format!("{}{}", &good[..12], (check + 1) % 10);
            assert!(!south_africa_id(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 25, "only {valid} valid vectors");
        assert!(invalid >= 25, "only {invalid} invalid vectors");
    }

    #[test]
    fn known_vector_and_separators() {
        // Widely-used valid sample ID 8001015009087 (Luhn-valid).
        assert!(south_africa_id("8001015009087"));
        assert!(south_africa_id("800101 5009 087"), "grouped with spaces");
    }

    #[test]
    fn structural_rejects() {
        assert!(!south_africa_id("800101500908"), "12 digits");
        assert!(!south_africa_id("80010150090876"), "14 digits");
        assert!(!south_africa_id("8001015009086"), "wrong check digit");
        assert!(!south_africa_id("800101500908X"), "non-digit");
    }
}
