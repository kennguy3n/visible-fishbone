//! Turkey T.C. Kimlik No validator.
//!
//! The Turkish national identity number is eleven digits `d1…d11`,
//! where `d1 ≠ 0` and the last two digits are checks over the first:
//!
//! ```text
//! d10 = ((d1+d3+d5+d7+d9)·7 − (d2+d4+d6+d8)) mod 10
//! d11 = (d1+d2+…+d10) mod 10
//! ```

/// Strip whitespace and return exactly eleven digits, or `None`.
fn eleven_digits(s: &str) -> Option<[u32; 11]> {
    let mut out = [0u32; 11];
    let mut n = 0;
    for c in s.chars() {
        if c.is_whitespace() {
            continue;
        }
        let d = c.to_digit(10)?;
        if n == 11 {
            return None;
        }
        out[n] = d;
        n += 1;
    }
    if n == 11 { Some(out) } else { None }
}

/// The tenth digit (`d10`) for the first nine digits.
fn check_ten(d: &[u32]) -> u32 {
    let odd = d[0] + d[2] + d[4] + d[6] + d[8];
    let even = d[1] + d[3] + d[5] + d[7];
    // d10 = (odd·7 − even) mod 10. Done entirely in unsigned arithmetic
    // by replacing `−even` with `+9·even`: 9 ≡ −1 (mod 10), so the two
    // are congruent, and there is no negative intermediate to underflow.
    (odd * 7 + even * 9) % 10
}

/// Turkey T.C. Kimlik No: eleven digits, non-zero leading digit, with
/// the two trailing check digits computed from the first nine (and, for
/// `d11`, the running total through `d10`).
#[must_use]
pub fn turkey_tckn(s: &str) -> bool {
    let Some(d) = eleven_digits(s) else {
        return false;
    };
    if d[0] == 0 {
        return false;
    }
    if check_ten(&d[..9]) != d[9] {
        return false;
    }
    let sum10: u32 = d[..10].iter().sum();
    sum10 % 10 == d[10]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid eleven-digit TCKN from a nine-digit body (with a
    /// non-zero leading digit).
    fn make(body9: [u32; 9]) -> String {
        let d10 = check_ten(&body9);
        let sum10: u32 = body9.iter().sum::<u32>() + d10;
        let d11 = sum10 % 10;
        let mut s: String = body9.iter().map(|d| char::from(b'0' + *d as u8)).collect();
        s.push(char::from(b'0' + d10 as u8));
        s.push(char::from(b'0' + d11 as u8));
        s
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in (100_000_000u32..=999_999_999).step_by(13_654_321) {
            let body = [
                seed / 100_000_000 % 10,
                seed / 10_000_000 % 10,
                seed / 1_000_000 % 10,
                seed / 100_000 % 10,
                seed / 10_000 % 10,
                seed / 1_000 % 10,
                seed / 100 % 10,
                seed / 10 % 10,
                seed % 10,
            ];
            let good = make(body);
            assert!(turkey_tckn(&good), "expected valid {good}");
            valid += 1;

            // Perturb d10 → must be rejected.
            let d10 = good.chars().nth(9).unwrap().to_digit(10).unwrap();
            let bad = format!("{}{}{}", &good[..9], (d10 + 1) % 10, &good[10..]);
            assert!(!turkey_tckn(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 30, "only {valid} valid vectors");
        assert!(invalid >= 30, "only {invalid} invalid vectors");
    }

    #[test]
    fn known_vector() {
        // Canonical worked example: 10000000146.
        assert!(turkey_tckn("10000000146"));
        assert!(turkey_tckn("1000 0000 146"), "whitespace tolerated");
    }

    #[test]
    fn structural_rejects() {
        assert!(!turkey_tckn("00000000146"), "leading zero");
        assert!(!turkey_tckn("1000000014"), "10 digits");
        assert!(!turkey_tckn("100000001460"), "12 digits");
        assert!(!turkey_tckn("10000000147"), "wrong final check digit");
        assert!(!turkey_tckn("1000000014X"), "non-digit");
    }
}
