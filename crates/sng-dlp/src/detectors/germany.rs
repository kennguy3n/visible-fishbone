//! Germany Personalausweis (national identity card) number validator.

/// Alphanumeric value used by the German document check digit: digits
/// map to their value, letters `A`–`Z` map to `10`–`35`.
fn alnum_value(c: char) -> Option<u32> {
    if c.is_ascii_digit() {
        Some(u32::from(c as u8 - b'0'))
    } else if c.is_ascii_uppercase() {
        Some(u32::from(c as u8 - b'A') + 10)
    } else {
        None
    }
}

/// Germany Personalausweis number: nine alphanumeric document
/// characters followed by a single check digit.
///
/// German identity documents use the weight pattern `7, 3, 1`
/// (repeating) over the document characters — each character mapped to
/// a value (`0`–`9` for digits, `10`–`35` for `A`–`Z`) — and take the
/// check digit as the weighted sum modulo 10. The trailing check
/// character must be a decimal digit.
#[must_use]
pub fn germany_personalausweis(s: &str) -> bool {
    const WEIGHTS: [u32; 3] = [7, 3, 1];

    let c: Vec<char> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() != 10 {
        return false;
    }
    let mut sum = 0u32;
    for (i, &ch) in c[..9].iter().enumerate() {
        let Some(v) = alnum_value(ch) else {
            return false;
        };
        sum += v * WEIGHTS[i % 3];
    }
    // The check character is always a decimal digit.
    let Some(check) = c[9].to_digit(10) else {
        return false;
    };
    sum % 10 == check
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_digit(base: &[char; 9]) -> u8 {
        const WEIGHTS: [u32; 3] = [7, 3, 1];
        let sum: u32 = base
            .iter()
            .enumerate()
            .map(|(i, &ch)| alnum_value(ch).unwrap() * WEIGHTS[i % 3])
            .sum();
        (sum % 10) as u8
    }

    const ALPHABET: [char; 36] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
    ];

    #[test]
    fn personalausweis_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let mut base = ['0'; 9];
            let mut v = seed.wrapping_mul(2_654_435_761).wrapping_add(11);
            for slot in &mut base {
                *slot = ALPHABET[(v % 36) as usize];
                v /= 36;
                v = v.wrapping_add(seed + 1);
            }
            let check = check_digit(&base);
            let good: String = base
                .iter()
                .copied()
                .chain(std::iter::once(char::from(b'0' + check)))
                .collect();
            assert!(
                germany_personalausweis(&good),
                "expected valid Personalausweis {good}"
            );
            valid += 1;

            let bad_check = (check + 1) % 10;
            if bad_check != check {
                let bad: String = base
                    .iter()
                    .copied()
                    .chain(std::iter::once(char::from(b'0' + bad_check)))
                    .collect();
                assert!(
                    !germany_personalausweis(&bad),
                    "expected invalid Personalausweis {bad}"
                );
                invalid += 1;
            }
        }
        // Structural rejects.
        assert!(!germany_personalausweis("12345678"), "too short");
        assert!(!germany_personalausweis("12345678901"), "too long");
        assert!(
            !germany_personalausweis("T22000129K"),
            "check char must be a digit"
        );
        invalid += 3;
        assert!(valid >= 30, "only {valid} valid Personalausweis vectors");
        assert!(
            invalid >= 25,
            "only {invalid} invalid Personalausweis vectors"
        );
    }
}
