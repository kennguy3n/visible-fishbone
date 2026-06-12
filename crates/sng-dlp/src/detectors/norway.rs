//! Norway fødselsnummer validator.
//!
//! The Norwegian birth number is eleven digits `DDMMYY-IIICC`: six
//! date digits, a three-digit individual number, and two check digits
//! `k1`, `k2`. Each check digit is a mod-11 control:
//!
//! ```text
//! k1 = 11 - ((3·d1 + 7·d2 + 6·d3 + 1·d4 + 8·d5 + 9·d6
//!             + 4·d7 + 5·d8 + 2·d9) mod 11)
//! k2 = 11 - ((5·d1 + 4·d2 + 3·d3 + 2·d4 + 7·d5 + 6·d6
//!             + 5·d7 + 4·d8 + 3·d9 + 2·k1) mod 11)
//! ```
//!
//! A control of `11` is taken as `0`; a control of `10` makes the
//! number invalid (no such fødselsnummer is issued).

/// Strip separators and return exactly eleven digits, or `None`.
fn eleven_digits(s: &str) -> Option<[u32; 11]> {
    let mut out = [0u32; 11];
    let mut n = 0;
    for c in s.chars() {
        if c.is_whitespace() || c == '-' {
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

/// Apply a mod-11 weight vector to `digits`, returning the control
/// digit, or `None` when the control is 10 (an invalid number).
fn control(weights: &[u32], digits: &[u32]) -> Option<u32> {
    let sum: u32 = weights.iter().zip(digits).map(|(w, d)| w * d).sum();
    let c = (11 - (sum % 11)) % 11;
    if c == 10 { None } else { Some(c) }
}

/// Norway fødselsnummer: eleven digits whose final two are the mod-11
/// control digits over the preceding nine (and, for `k2`, over `k1`).
/// Separators (`-`, whitespace) are ignored.
#[must_use]
pub fn norway_fodselsnummer(s: &str) -> bool {
    let Some(d) = eleven_digits(s) else {
        return false;
    };
    let Some(k1) = control(&[3, 7, 6, 1, 8, 9, 4, 5, 2], &d[..9]) else {
        return false;
    };
    if k1 != d[9] {
        return false;
    }
    let mut body2 = [0u32; 10];
    body2[..9].copy_from_slice(&d[..9]);
    body2[9] = k1;
    let Some(k2) = control(&[5, 4, 3, 2, 7, 6, 5, 4, 3, 2], &body2) else {
        return false;
    };
    k2 == d[10]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid eleven-digit fødselsnummer from a nine-digit body
    /// by computing both control digits, or `None` if this body has no
    /// valid pair (a control of 10).
    fn make(body9: [u32; 9]) -> Option<String> {
        let k1 = control(&[3, 7, 6, 1, 8, 9, 4, 5, 2], &body9)?;
        let mut body2 = [0u32; 10];
        body2[..9].copy_from_slice(&body9);
        body2[9] = k1;
        let k2 = control(&[5, 4, 3, 2, 7, 6, 5, 4, 3, 2], &body2)?;
        let mut s: String = body9.iter().map(|d| char::from(b'0' + *d as u8)).collect();
        s.push(char::from(b'0' + k1 as u8));
        s.push(char::from(b'0' + k2 as u8));
        Some(s)
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in (0u32..=999_999_999).step_by(7_654_321) {
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
            let Some(good) = make(body) else {
                continue;
            };
            assert!(norway_fodselsnummer(&good), "expected valid {good}");
            valid += 1;

            // Perturb the first check digit → must be rejected.
            let k1 = good.chars().nth(9).unwrap().to_digit(10).unwrap();
            let bad = format!("{}{}{}", &good[..9], (k1 + 1) % 10, &good[10..]);
            assert!(!norway_fodselsnummer(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 30, "only {valid} valid vectors");
        assert!(invalid >= 30, "only {invalid} invalid vectors");
    }

    #[test]
    fn separators_and_structural_rejects() {
        let good = make([0, 1, 0, 1, 5, 0, 1, 2, 3]).expect("body has valid controls");
        assert!(norway_fodselsnummer(&good));
        let spaced = format!("{} {}", &good[..6], &good[6..]);
        assert!(norway_fodselsnummer(&spaced), "whitespace separator");

        assert!(!norway_fodselsnummer(&good[..10]), "10 digits");
        assert!(!norway_fodselsnummer(&format!("{good}4")), "12 digits");
        assert!(!norway_fodselsnummer("0101501230"), "wrong length");
        assert!(!norway_fodselsnummer("0101501X234"), "non-digit");
    }
}
