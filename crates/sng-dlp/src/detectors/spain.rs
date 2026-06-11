//! Spain DNI / NIE identifier validators.
//!
//! Both the DNI (citizen) and NIE (foreigner) numbers close with a
//! control letter drawn from a fixed 23-entry table indexed by the
//! numeric body modulo 23. The NIE simply maps its leading letter
//! (`X`/`Y`/`Z`) to a digit (`0`/`1`/`2`) to form that body.

/// The 23-letter control table shared by the DNI and NIE: the body
/// value modulo 23 indexes directly into it.
const CONTROL: [u8; 23] = *b"TRWAGMYFPDXBNJZSQVHLCKE";

/// Strip separators and upper-case `s` into a character vector.
fn normalize(s: &str) -> Vec<char> {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// The expected control letter for a `body` value (`0..=99_999_999`).
fn control_letter(body: u32) -> char {
    char::from(CONTROL[(body % 23) as usize])
}

/// Spain DNI (Documento Nacional de Identidad): eight digits and a
/// control letter `CONTROL[number % 23]`. Spaces / hyphens the pattern
/// allows are stripped first.
#[must_use]
pub fn spain_dni(s: &str) -> bool {
    let c = normalize(s);
    if c.len() != 9 {
        return false;
    }
    let mut body = 0u32;
    for &ch in &c[..8] {
        let Some(d) = ch.to_digit(10) else {
            return false;
        };
        body = body * 10 + d;
    }
    c[8] == control_letter(body)
}

/// Spain NIE (Número de Identidad de Extranjero): a leading `X`, `Y`
/// or `Z` (mapped to `0`, `1`, `2`), seven digits, and the same
/// `CONTROL` letter over the resulting eight-digit body.
#[must_use]
pub fn spain_nie(s: &str) -> bool {
    let c = normalize(s);
    if c.len() != 9 {
        return false;
    }
    let lead = match c[0] {
        'X' => 0,
        'Y' => 1,
        'Z' => 2,
        _ => return false,
    };
    let mut body = lead;
    for &ch in &c[1..8] {
        let Some(d) = ch.to_digit(10) else {
            return false;
        };
        body = body * 10 + d;
    }
    c[8] == control_letter(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dni_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for body in (0u32..=99_999_999).step_by(1_234_567) {
            let letter = control_letter(body);
            let good = format!("{body:08}{letter}");
            assert!(spain_dni(&good), "expected valid DNI {good}");
            valid += 1;

            // Pick any other control letter → must be rejected.
            let wrong = char::from(CONTROL[((body % 23) as usize + 1) % 23]);
            if wrong != letter {
                let bad = format!("{body:08}{wrong}");
                assert!(!spain_dni(&bad), "expected invalid DNI {bad}");
                invalid += 1;
            }
        }
        // Structural rejects.
        assert!(!spain_dni("1234567Z"), "7 digits");
        assert!(!spain_dni("123456789"), "no control letter");
        assert!(!spain_dni("X1234567L"), "NIE shape is not a DNI");
        invalid += 3;
        assert!(valid >= 30, "only {valid} valid DNI vectors");
        assert!(invalid >= 25, "only {invalid} invalid DNI vectors");
    }

    #[test]
    fn nie_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for (prefix, lead) in [('X', 0u32), ('Y', 1), ('Z', 2)] {
            for serial in (0u32..=9_999_999).step_by(345_677) {
                let body = lead * 10_000_000 + serial;
                let letter = control_letter(body);
                let good = format!("{prefix}{serial:07}{letter}");
                assert!(spain_nie(&good), "expected valid NIE {good}");
                valid += 1;

                let wrong = char::from(CONTROL[((body % 23) as usize + 1) % 23]);
                if wrong != letter {
                    let bad = format!("{prefix}{serial:07}{wrong}");
                    assert!(!spain_nie(&bad), "expected invalid NIE {bad}");
                    invalid += 1;
                }
            }
        }
        // Structural rejects.
        assert!(!spain_nie("12345678Z"), "DNI shape is not a NIE");
        assert!(!spain_nie("W1234567L"), "bad leading letter");
        invalid += 2;
        assert!(valid >= 30, "only {valid} valid NIE vectors");
        assert!(invalid >= 25, "only {invalid} invalid NIE vectors");
    }

    #[test]
    fn known_valid_vectors() {
        // 12345678 % 23 = 14 → Z (the canonical worked example).
        assert!(spain_dni("12345678Z"));
        assert!(spain_dni("12345678-Z"), "hyphen separator");
        // X1234567 → body 1234567, 1234567 % 23 = 19 → L.
        assert!(spain_nie("X1234567L"));
    }
}
