//! Mexico CURP (Clave Única de Registro de Población) validator.
//!
//! The CURP is eighteen characters `AAAA DDMMDD S EE CCC H V`: four
//! name letters, a six-digit date of birth, a sex letter (`H`/`M`), a
//! two-letter federal-entity (state) code, three internal consonants,
//! an alphanumeric homoclave and a mod-10 check digit. The check digit
//! is computed over the first seventeen characters via the RENAPO
//! dictionary `0-9 A-N Ñ O-Z` (values `0..=36`) weighted `18..=2`.

use crate::validators::valid_ymd;

/// Valid two-letter Mexican federal-entity (state) codes, plus `NE` for
/// births registered abroad.
const STATE_CODES: [&str; 33] = [
    "AS", "BC", "BS", "CC", "CL", "CM", "CS", "CH", "DF", "DG", "GT", "GR", "HG", "JC", "MC", "MN",
    "MS", "NT", "NL", "OC", "PL", "QT", "QR", "SP", "SL", "SR", "TC", "TS", "TL", "VZ", "YN", "ZS",
    "NE",
];

/// Value of a CURP character in the RENAPO check-digit dictionary
/// `0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZ` (`0..=36`), or `None` for any
/// character outside it.
fn curp_value(ch: char) -> Option<u32> {
    match ch {
        '0'..='9' => Some(ch as u32 - '0' as u32),
        'A'..='N' => Some(ch as u32 - 'A' as u32 + 10),
        'Ñ' => Some(24),
        'O'..='Z' => Some(ch as u32 - 'O' as u32 + 25),
        _ => None,
    }
}

/// The mod-10 RENAPO check digit over the seventeen-character `head`.
fn check_digit(head: &[char]) -> Option<u8> {
    let mut sum = 0u32;
    let mut weight = 18u32;
    for &ch in head {
        let v = curp_value(ch)?;
        sum += v * weight;
        weight -= 1;
    }
    Some(((10 - sum % 10) % 10) as u8)
}

/// Mexico CURP: eighteen characters with a valid date of birth, sex
/// letter, federal-entity code and the RENAPO mod-10 check digit.
#[must_use]
pub fn mexico_curp(s: &str) -> bool {
    let c: Vec<char> = s.chars().collect();
    if c.len() != 18 {
        return false;
    }
    // 1-4: name letters.
    if !c[..4].iter().all(char::is_ascii_uppercase) {
        return false;
    }
    // 5-10: date of birth digits.
    let mut date = [0u32; 6];
    for (slot, ch) in date.iter_mut().zip(&c[4..10]) {
        let Some(d) = ch.to_digit(10) else {
            return false;
        };
        *slot = d;
    }
    // 11: sex.
    if c[10] != 'H' && c[10] != 'M' {
        return false;
    }
    // 12-13: federal-entity code.
    let state: String = c[11..13].iter().collect();
    if !STATE_CODES.contains(&state.as_str()) {
        return false;
    }
    // 14-16: internal consonants.
    if !c[13..16].iter().all(char::is_ascii_uppercase) {
        return false;
    }
    // 17: homoclave (alphanumeric; a digit for pre-2000 births).
    if !(c[16].is_ascii_digit() || c[16].is_ascii_uppercase()) {
        return false;
    }
    // 18: check digit.
    let Some(last) = c[17].to_digit(10) else {
        return false;
    };
    let yy = date[0] * 10 + date[1];
    let mm = date[2] * 10 + date[3];
    let dd = date[4] * 10 + date[5];
    let base = if c[16].is_ascii_digit() { 1900 } else { 2000 };
    if !valid_ymd(base + yy, mm, dd) {
        return false;
    }
    let Some(check) = check_digit(&c[..17]) else {
        return false;
    };
    u32::from(check) == last
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid CURP from a seventeen-character head.
    fn make(head: &str) -> String {
        let chars: Vec<char> = head.chars().collect();
        assert_eq!(chars.len(), 17);
        let check = check_digit(&chars).expect("head is dictionary-valid");
        format!("{head}{check}")
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let names = ["PEPP", "MARL", "GOHM", "LOAN", "RAQU"];
        let consonants = ["RRL", "NXX", "BCD", "FGH", "JKL"];
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let name = names[seed as usize % names.len()];
            let cons = consonants[seed as usize % consonants.len()];
            let state = STATE_CODES[seed as usize % (STATE_CODES.len() - 1)]; // skip NE for shape
            let yy = seed % 100;
            let mm = seed % 12 + 1;
            let dd = seed % 28 + 1;
            let sex = if seed % 2 == 0 { 'H' } else { 'M' };
            // Digit homoclave keeps the pre-2000 century branch.
            let homoclave = (seed % 10) as u8;
            let head = format!("{name}{yy:02}{mm:02}{dd:02}{sex}{state}{cons}{homoclave}");
            let good = make(&head);
            assert!(mexico_curp(&good), "expected valid {good}");
            valid += 1;

            let check = good.chars().last().unwrap().to_digit(10).unwrap();
            let bad = format!("{}{}", head, (check + 1) % 10);
            assert!(!mexico_curp(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 20, "only {valid} valid vectors");
        assert!(invalid >= 20, "only {invalid} invalid vectors");
    }

    #[test]
    fn structural_rejects() {
        let good = make("PEPP900101HDFRRL0");
        // Impossible month.
        let bad_month = format!("PEPP9099{}", &good[8..]);
        assert!(!mexico_curp(&bad_month), "month 99");
        // Unknown state code.
        let bad_state = format!("{}ZZ{}", &good[..11], &good[13..]);
        assert!(!mexico_curp(&bad_state), "state ZZ");
        // Wrong sex letter.
        let bad_sex = format!("{}X{}", &good[..10], &good[11..]);
        assert!(!mexico_curp(&bad_sex), "sex X");
        assert!(!mexico_curp(&good[..17]), "17 chars");
    }
}
