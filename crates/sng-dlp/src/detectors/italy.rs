//! Italy Codice Fiscale validator.

/// Value of an odd-position (1-indexed) character. Digits and letters
/// share one table per the Agenzia delle Entrate specification.
fn odd_value(c: char) -> Option<u32> {
    let v = match c {
        '0' | 'A' => 1,
        '1' | 'B' => 0,
        '2' | 'C' => 5,
        '3' | 'D' => 7,
        '4' | 'E' => 9,
        '5' | 'F' => 13,
        '6' | 'G' => 15,
        '7' | 'H' => 17,
        '8' | 'I' => 19,
        '9' | 'J' => 21,
        'K' => 2,
        'L' => 4,
        'M' => 18,
        'N' => 20,
        'O' => 11,
        'P' => 3,
        'Q' => 6,
        'R' => 8,
        'S' => 12,
        'T' => 14,
        'U' => 16,
        'V' => 10,
        'W' => 22,
        'X' => 25,
        'Y' => 24,
        'Z' => 23,
        _ => return None,
    };
    Some(v)
}

/// Value of an even-position (1-indexed) character: the natural
/// alphanumeric value (`0`–`9` → `0..=9`, `A`–`Z` → `0..=25`).
fn even_value(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        c.to_digit(10)
    } else if c.is_ascii_uppercase() {
        Some(u32::from(c as u8 - b'A'))
    } else {
        None
    }
}

/// Italy Codice Fiscale: sixteen alphanumeric characters whose final
/// letter is a control character over the leading fifteen.
///
/// Each of the first fifteen characters contributes a value chosen by
/// its 1-indexed position — an odd-position table and an even-position
/// table that the Agenzia delle Entrate defines — and the control
/// letter is `A..=Z` indexed by the summed value modulo 26. The check
/// is computed over upper-cased characters, so a lower-cased code
/// validates identically.
#[must_use]
pub fn italy_codice_fiscale(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() != 16 {
        return false;
    }
    if !c.iter().all(char::is_ascii_alphanumeric) {
        return false;
    }
    let mut sum = 0u32;
    for (i, &ch) in c[..15].iter().enumerate() {
        // Position is 1-indexed; even indices here are the odd positions.
        let value = if i % 2 == 0 {
            odd_value(ch)
        } else {
            even_value(ch)
        };
        let Some(v) = value else {
            return false;
        };
        sum += v;
    }
    let expected = char::from(b'A' + (sum % 26) as u8);
    c[15] == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The control letter for a 15-character body, mirroring the
    /// validator's tables so the test can synthesise valid codes.
    fn control(body: &[char; 15]) -> char {
        let sum: u32 = body
            .iter()
            .enumerate()
            .map(|(i, &ch)| {
                if i % 2 == 0 {
                    odd_value(ch).unwrap()
                } else {
                    even_value(ch).unwrap()
                }
            })
            .sum();
        char::from(b'A' + (sum % 26) as u8)
    }

    const ALPHANUM: [char; 36] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    ];

    #[test]
    fn codice_fiscale_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let mut body = ['A'; 15];
            let mut v = seed.wrapping_mul(2_654_435_761).wrapping_add(13);
            for slot in &mut body {
                *slot = ALPHANUM[(v % 36) as usize];
                v /= 36;
                v = v.wrapping_add(seed + 1);
            }
            let check = control(&body);
            let good: String = body.iter().copied().chain(std::iter::once(check)).collect();
            assert!(
                italy_codice_fiscale(&good),
                "expected valid Codice Fiscale {good}"
            );
            // Lower-cased form must validate identically.
            assert!(
                italy_codice_fiscale(&good.to_lowercase()),
                "expected valid lower-cased {good}"
            );
            valid += 2;

            // Shift the control letter → must be rejected.
            let bad_check = char::from(b'A' + ((check as u8 - b'A' + 1) % 26));
            let bad: String = body
                .iter()
                .copied()
                .chain(std::iter::once(bad_check))
                .collect();
            assert!(
                !italy_codice_fiscale(&bad),
                "expected invalid Codice Fiscale {bad}"
            );
            invalid += 1;
        }
        // Structural rejects.
        assert!(!italy_codice_fiscale("RSSMRA85T10A562"), "15 chars");
        assert!(!italy_codice_fiscale("RSSMRA85T10A562SX"), "17 chars");
        assert!(
            !italy_codice_fiscale("RSSMRA85T10A562!"),
            "non-alphanumeric"
        );
        invalid += 3;
        assert!(valid >= 30, "only {valid} valid Codice Fiscale vectors");
        assert!(
            invalid >= 25,
            "only {invalid} invalid Codice Fiscale vectors"
        );
    }

    #[test]
    fn known_valid_vector() {
        // Canonical worked example: control letter computes to S.
        assert!(italy_codice_fiscale("RSSMRA85T10A562S"));
        assert!(italy_codice_fiscale("rssmra85t10a562s"), "lower-cased");
        // Flipping the control letter must fail.
        assert!(!italy_codice_fiscale("RSSMRA85T10A562T"));
    }
}
