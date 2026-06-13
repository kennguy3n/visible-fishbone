//! Ireland PPS Number (Personal Public Service Number) validator.
//!
//! A PPSN is seven digits, a check letter, and — in the modern form —
//! an optional second letter. The check letter is selected from the
//! alphabet `WABCDEFGHIJKLMNOPQRSTUV` by the weighted sum of the seven
//! digits (weights `8..=2`) taken modulo 23. For the nine-character
//! form the second letter contributes nine times its value (`A`=1 …
//! `I`=9, `W`=0) to the same sum, so the check letter still closes the
//! identifier. Spaces / hyphens the pattern allows are ignored.

/// The check-character alphabet: index `Σ mod 23` selects the letter,
/// where index `0` maps to `W`.
const CHECK_ALPHABET: &[u8; 23] = b"WABCDEFGHIJKLMNOPQRSTUV";

/// Position weights applied to the seven leading digits.
const WEIGHTS: [u32; 7] = [8, 7, 6, 5, 4, 3, 2];

/// Ireland PPSN: seven digits, a check letter, and an optional second
/// letter (`A`..=`I` or `W`).
#[must_use]
pub fn ireland_ppsn(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '-')
        .collect();
    if c.len() != 8 && c.len() != 9 {
        return false;
    }
    let mut sum = 0u32;
    for (i, ch) in c[..7].iter().enumerate() {
        let Some(d) = ch.to_digit(10) else {
            return false;
        };
        sum += d * WEIGHTS[i];
    }
    let check = c[7].to_ascii_uppercase();
    if !check.is_ascii_uppercase() {
        return false;
    }
    if c.len() == 9 {
        let extra = c[8].to_ascii_uppercase();
        let val = match extra {
            'W' => 0,
            'A'..='I' => extra as u32 - 'A' as u32 + 1,
            _ => return false,
        };
        sum += val * 9;
    }
    CHECK_ALPHABET[(sum % 23) as usize] == check as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid eight-character PPSN from a seven-digit body.
    fn make(body: [u8; 7]) -> String {
        let sum: u32 = (0..7).map(|i| u32::from(body[i]) * WEIGHTS[i]).sum();
        let letter = CHECK_ALPHABET[(sum % 23) as usize];
        let mut s: String = body.iter().map(|d| char::from(b'0' + d)).collect();
        s.push(char::from(letter));
        s
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let mut body = [0u8; 7];
            let mut v = seed.wrapping_mul(2_654_435_761);
            for slot in &mut body {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(seed + 1);
            }
            let good = make(body);
            assert!(ireland_ppsn(&good), "expected valid {good}");
            valid += 1;

            // Swap the check letter for the next one in the alphabet.
            let last = good.bytes().last().unwrap();
            let pos = CHECK_ALPHABET.iter().position(|&b| b == last).unwrap();
            let bad_letter = CHECK_ALPHABET[(pos + 1) % 23];
            let bad = format!("{}{}", &good[..7], char::from(bad_letter));
            assert!(!ireland_ppsn(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 20, "only {valid} valid vectors");
        assert!(invalid >= 20, "only {invalid} invalid vectors");
    }

    #[test]
    fn nine_character_form_validates() {
        // The second letter feeds the same modulus, so a valid 8-char
        // PPSN with a "W" appended (value 0, no contribution) stays valid.
        let good = make([1, 2, 3, 4, 5, 6, 7]);
        let nine = format!("{good}W");
        assert!(ireland_ppsn(&nine), "W contributes zero, must validate");
    }

    #[test]
    fn unicode_whitespace_is_stripped() {
        // Parity with the Go twin: NBSP (U+00A0), em-space (U+2003),
        // ASCII space and hyphens are all ignored before validation.
        let good = make([1, 2, 3, 4, 5, 6, 7]);
        let spaced = format!(
            "{}\u{00a0}{}\u{2003}{} -{}",
            &good[..3],
            &good[3..5],
            &good[5..7],
            &good[7..]
        );
        assert!(ireland_ppsn(&spaced), "unicode whitespace must be stripped");
    }

    #[test]
    fn structural_rejects() {
        assert!(!ireland_ppsn("123456T"), "7 chars (missing digit)");
        assert!(!ireland_ppsn("12345678"), "no check letter");
        assert!(!ireland_ppsn("1234567TZ"), "illegal second letter Z");
        assert!(!ireland_ppsn("A234567T"), "letter where digit expected");
    }
}
