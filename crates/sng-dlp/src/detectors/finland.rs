//! Finland henkilötunnus (HETU) validator.
//!
//! The Finnish personal identity code is `DDMMYY C ZZZ Q`: six date
//! digits, a century sign `C`, a three-digit individual number `ZZZ`,
//! and a control character `Q`. The control is the nine-digit integer
//! `DDMMYYZZZ` taken modulo 31, indexed into a fixed 31-character
//! table (digits `0-9` then `ABCDEFHJKLMNPRSTUVWXY` — the letters
//! `G`, `I`, `O`, `Q`, `Z` are intentionally absent to avoid
//! confusion with similar glyphs).

/// The 31-entry control table indexed by `number % 31`.
const CONTROL: &[u8; 31] = b"0123456789ABCDEFHJKLMNPRSTUVWXY";

/// Century signs Finland has assigned. Each maps to a century but the
/// validator only needs to accept the sign as structurally valid; the
/// `2023` reform added the extended `A..F` / `U..Y` set alongside the
/// historic `+` (1800s), `-` (1900s), and `A` (2000s).
const CENTURY_SIGNS: &[char] = &[
    '+', '-', 'A', 'B', 'C', 'D', 'E', 'F', 'U', 'V', 'W', 'X', 'Y',
];

/// Finland HETU: `DDMMYY`, a valid century sign, `ZZZ`, and the
/// control character `CONTROL[DDMMYYZZZ % 31]`. Surrounding whitespace
/// is ignored; the code itself carries no internal separators.
#[must_use]
pub fn finland_hetu(s: &str) -> bool {
    let c: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    if c.len() != 11 {
        return false;
    }
    // Positions 0..6 date digits, 6 century sign, 7..10 individual
    // number, 10 control character.
    if !CENTURY_SIGNS.contains(&c[6]) {
        return false;
    }
    let mut number = 0u32;
    for &ch in c[..6].iter().chain(&c[7..10]) {
        let Some(d) = ch.to_digit(10) else {
            return false;
        };
        number = number * 10 + d;
    }
    let expected = char::from(CONTROL[(number % 31) as usize]);
    c[10].to_ascii_uppercase() == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid HETU for a six-digit date and three-digit serial
    /// using the `-` century sign.
    fn make(date: u32, serial: u32) -> String {
        let number = date * 1000 + serial;
        let q = char::from(CONTROL[(number % 31) as usize]);
        format!("{date:06}-{serial:03}{q}")
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        for date in (10_100u32..=311_299).step_by(9_973) {
            for serial in (2u32..=899).step_by(311) {
                let good = make(date, serial);
                assert!(finland_hetu(&good), "expected valid {good}");
                valid += 1;

                // Replace the control char with the next table entry →
                // must be rejected.
                let number = date * 1000 + serial;
                let wrong = char::from(CONTROL[((number % 31) as usize + 1) % 31]);
                let bad = format!("{}{}", &good[..good.len() - 1], wrong);
                if bad != good {
                    assert!(!finland_hetu(&bad), "expected invalid {bad}");
                    invalid += 1;
                }
            }
        }
        assert!(valid >= 30, "only {valid} valid vectors");
        assert!(invalid >= 30, "only {invalid} invalid vectors");
    }

    #[test]
    fn known_vector() {
        // Canonical worked example: 131052-308T (131052308 % 31 = 25 → T).
        assert!(finland_hetu("131052-308T"));
        assert!(
            finland_hetu("131052-308t"),
            "control char is case-insensitive"
        );
    }

    #[test]
    fn century_signs_and_rejects() {
        assert!(finland_hetu("131052A308T"), "2000s 'A' sign accepted");
        assert!(!finland_hetu("131052G308T"), "invalid century sign 'G'");
        assert!(!finland_hetu("131052-308U"), "wrong control char");
        assert!(!finland_hetu("131052-308"), "missing control char");
        assert!(!finland_hetu("13105-2308T"), "bad shape");
    }
}
