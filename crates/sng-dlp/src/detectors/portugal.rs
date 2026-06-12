//! Portugal NIF / NIPC validator.
//!
//! The Portuguese tax identification number (Número de Identificação
//! Fiscal, also NIPC for legal persons) is nine digits. The ninth is a
//! mod-11 check digit over the first eight, weighted `9,8,7,6,5,4,3,2`
//! (most-significant digit first): `c = 11 - (Σ wᵢ·dᵢ mod 11)`, where a
//! computed control of 10 or 11 is taken as 0.

/// Strip separators and return exactly nine digits, or `None`.
fn nine_digits(s: &str) -> Option<[u32; 9]> {
    let mut out = [0u32; 9];
    let mut n = 0;
    for c in s.chars() {
        if c.is_whitespace() || c == '-' || c == '.' {
            continue;
        }
        let d = c.to_digit(10)?;
        if n == 9 {
            return None;
        }
        out[n] = d;
        n += 1;
    }
    if n == 9 { Some(out) } else { None }
}

/// The mod-11 NIF check digit over the eight-digit `body`.
fn check_digit(body: &[u32]) -> u32 {
    const WEIGHTS: [u32; 8] = [9, 8, 7, 6, 5, 4, 3, 2];
    let sum: u32 = body.iter().zip(WEIGHTS).map(|(d, w)| d * w).sum();
    let c = 11 - (sum % 11);
    if c >= 10 { 0 } else { c }
}

/// Portugal NIF/NIPC: nine digits whose final digit is the mod-11
/// check over the preceding eight. Separators (`-`, `.`, whitespace)
/// are ignored.
#[must_use]
pub fn portugal_nif(s: &str) -> bool {
    let Some(d) = nine_digits(s) else {
        return false;
    };
    check_digit(&d[..8]) == d[8]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(body8: [u32; 8]) -> String {
        let check = check_digit(&body8);
        let mut s: String = body8.iter().map(|d| char::from(b'0' + *d as u8)).collect();
        s.push(char::from(b'0' + check as u8));
        s
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in (0u32..=99_999_999).step_by(1_234_567) {
            let body = [
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
            assert!(portugal_nif(&good), "expected valid {good}");
            valid += 1;

            let check = good.chars().last().unwrap().to_digit(10).unwrap();
            let bad = format!("{}{}", &good[..8], (check + 1) % 10);
            assert!(!portugal_nif(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 30, "only {valid} valid vectors");
        assert!(invalid >= 30, "only {invalid} invalid vectors");
    }

    #[test]
    fn known_vector_and_separators() {
        // Σ(9·1+8·2+…+2·8) = 156; 156 mod 11 = 2; 11-2 = 9 → check 9.
        assert!(portugal_nif("123456789"));
        assert!(portugal_nif("123 456 789"), "grouped with spaces");
        assert!(portugal_nif("123.456.789"), "grouped with dots");
    }

    #[test]
    fn structural_rejects() {
        assert!(!portugal_nif("12345678"), "8 digits");
        assert!(!portugal_nif("1234567890"), "10 digits");
        assert!(!portugal_nif("123456788"), "wrong check digit");
        assert!(!portugal_nif("12345678X"), "non-digit");
    }
}
