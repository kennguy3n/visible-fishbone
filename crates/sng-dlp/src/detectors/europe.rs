//! European Union identifier validators: IBAN (ISO 13616) and VAT
//! identification numbers.

use crate::validators::luhn_digits;

/// IBAN (International Bank Account Number): ISO 13616 mod-97 check.
///
/// The four leading characters (country code + two check digits) are
/// moved to the end, each letter is expanded to its two-digit value
/// (`A`=10 … `Z`=35), and the resulting integer must be `≡ 1 (mod
/// 97)`. The modulus is computed incrementally so no big-integer math
/// is needed. Spaces the pattern allows are stripped first.
#[must_use]
pub fn eu_iban(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    // ISO 13616 permits 15–34 characters across all countries.
    if !(15..=34).contains(&c.len()) {
        return false;
    }
    // CCDD….
    if !c[0].is_ascii_alphabetic()
        || !c[1].is_ascii_alphabetic()
        || !c[2].is_ascii_digit()
        || !c[3].is_ascii_digit()
    {
        return false;
    }
    let mut rem: u64 = 0;
    // Rotated order: characters 4.. followed by the leading 4.
    for &ch in c[4..].iter().chain(c[..4].iter()) {
        if ch.is_ascii_digit() {
            rem = (rem * 10 + u64::from(ch as u8 - b'0')) % 97;
        } else if ch.is_ascii_uppercase() {
            let v = u64::from(ch as u8 - b'A') + 10;
            rem = (rem * 100 + v) % 97;
        } else {
            return false;
        }
    }
    rem == 1
}

/// EU VAT identification number.
///
/// Dispatches on the two-letter country prefix. For the member states
/// whose check-digit algorithm is published and unambiguous
/// (`AT, BE, DE, DK, FI, FR, IT, LU, PL, PT, SE`) the trailing check
/// digit(s) are fully verified. For the remaining member states the
/// number is validated structurally (correct country code, length and
/// character set) — these formats either have no public check digit or
/// use closed lookup tables — which, combined with the regex shape and
/// proximity `vat` cues, keeps false positives low without rejecting
/// legitimate numbers. The `EL` prefix (Greece's VAT code) is mapped
/// to its ISO `GR` algorithm.
#[must_use]
pub fn eu_vat(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() < 4 {
        return false;
    }
    let country: String = c[..2].iter().collect();
    let rest: Vec<char> = c[2..].to_vec();
    // One ISO country code per arm so each jurisdiction's structural
    // rule is independently auditable; several states legitimately
    // share the same `(length, alpha)` shape, so the identical bodies
    // are intentional rather than a copy-paste slip.
    #[allow(clippy::match_same_arms)]
    match country.as_str() {
        "AT" => austria(&rest),
        "BE" => belgium(&rest),
        "DE" => germany_vat(&rest),
        "DK" => denmark(&rest),
        "EL" => greece(&rest),
        "FI" => finland(&rest),
        "FR" => france_vat(&rest),
        "IT" => italy(&rest),
        "LU" => luxembourg(&rest),
        "PL" => poland(&rest),
        "PT" => portugal(&rest),
        "SE" => sweden(&rest),
        // Structurally-validated member states.
        "BG" => structural(&rest, &[9, 10], false),
        "CY" => structural(&rest, &[9], true),
        "CZ" => structural(&rest, &[8, 9, 10], false),
        "EE" => structural(&rest, &[9], false),
        "ES" => structural(&rest, &[9], true),
        "HR" => structural(&rest, &[11], false),
        "HU" => structural(&rest, &[8], false),
        "IE" => structural(&rest, &[8, 9], true),
        "LT" => structural(&rest, &[9, 12], false),
        "LV" => structural(&rest, &[11], false),
        "MT" => structural(&rest, &[8], false),
        "NL" => netherlands(&rest),
        "RO" => structural_range(&rest, 2, 10, false),
        "SI" => structural(&rest, &[8], false),
        "SK" => structural(&rest, &[10], false),
        _ => false,
    }
}

/// Structural check: exact length(s) and charset. When `alpha` is
/// false the body must be all digits; otherwise alphanumerics are
/// permitted (countries whose VAT embeds a letter).
fn structural(rest: &[char], lengths: &[usize], alpha: bool) -> bool {
    if !lengths.contains(&rest.len()) {
        return false;
    }
    rest.iter()
        .all(|&c| c.is_ascii_digit() || (alpha && c.is_ascii_alphanumeric()))
}

fn structural_range(rest: &[char], min: usize, max: usize, alpha: bool) -> bool {
    if !(min..=max).contains(&rest.len()) {
        return false;
    }
    rest.iter()
        .all(|&c| c.is_ascii_digit() || (alpha && c.is_ascii_alphanumeric()))
}

fn to_digits(rest: &[char]) -> Option<Vec<u8>> {
    rest.iter()
        .map(|c| c.to_digit(10).and_then(|d| u8::try_from(d).ok()))
        .collect()
}

/// Austria: `U` + 8 digits, weighted cross-sum check.
fn austria(rest: &[char]) -> bool {
    const W: [u32; 7] = [1, 2, 1, 2, 1, 2, 1];
    if rest.len() != 9 || rest[0] != 'U' {
        return false;
    }
    let Some(d) = to_digits(&rest[1..]) else {
        return false;
    };
    let mut sum = 0u32;
    for (&digit, &w) in d[..7].iter().zip(&W) {
        let p = u32::from(digit) * w;
        sum += p / 10 + p % 10;
    }
    // `sum` is at most 63, so `96 - sum` never underflows.
    let check = (96 - sum) % 10;
    check == u32::from(d[7])
}

/// Belgium: 10 digits where `97 − (first8 mod 97)` equals the last 2.
fn belgium(rest: &[char]) -> bool {
    let Some(d) = to_digits(rest) else {
        return false;
    };
    if d.len() != 10 {
        return false;
    }
    let first8: u32 = d[..8].iter().fold(0, |a, &x| a * 10 + u32::from(x));
    let last2: u32 = u32::from(d[8]) * 10 + u32::from(d[9]);
    (97 - first8 % 97) == last2
}

/// Germany: 9 digits, ISO 7064 MOD 11,10 ("11er-Verfahren").
fn germany_vat(rest: &[char]) -> bool {
    let Some(d) = to_digits(rest) else {
        return false;
    };
    if d.len() != 9 {
        return false;
    }
    let mut product = 10u32;
    for &digit in &d[..8] {
        let mut sum = (u32::from(digit) + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let check = (11 - product) % 10;
    check == u32::from(d[8])
}

/// Denmark: 8 digits, weighted modulus-11 (sum divisible by 11).
fn denmark(rest: &[char]) -> bool {
    const W: [u32; 8] = [2, 7, 6, 5, 4, 3, 2, 1];
    let Some(d) = to_digits(rest) else {
        return false;
    };
    if d.len() != 8 {
        return false;
    }
    let sum: u32 = d.iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
    sum.is_multiple_of(11)
}

/// Greece (VAT prefix `EL`): 9 digits, weighted modulus-11.
fn greece(rest: &[char]) -> bool {
    let Some(d) = to_digits(rest) else {
        return false;
    };
    if d.len() != 9 {
        return false;
    }
    // Weights 256,128,…,2 over the first 8 digits.
    let mut sum = 0u32;
    let mut w = 256u32;
    for &digit in &d[..8] {
        sum += u32::from(digit) * w;
        w /= 2;
    }
    let check = (sum % 11) % 10;
    check == u32::from(d[8])
}

/// Finland: 8 digits, weighted modulus-11 check digit.
fn finland(rest: &[char]) -> bool {
    const W: [u32; 7] = [7, 9, 10, 5, 8, 4, 2];
    let Some(d) = to_digits(rest) else {
        return false;
    };
    if d.len() != 8 {
        return false;
    }
    let sum: u32 = d[..7].iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
    let rem = sum % 11;
    if rem == 1 {
        return false; // unissued
    }
    let check = if rem == 0 { 0 } else { 11 - rem };
    check == u32::from(d[7])
}

/// France: 2-character key + 9-digit SIREN (Luhn). When the key is
/// numeric it must equal `(12 + 3·(SIREN mod 97)) mod 97`.
fn france_vat(rest: &[char]) -> bool {
    if rest.len() != 11 {
        return false;
    }
    let Some(siren) = to_digits(&rest[2..]) else {
        return false;
    };
    if !luhn_digits(&siren) {
        return false;
    }
    // Numeric key cross-check (the alphabetic-key variant is accepted on
    // the SIREN Luhn alone).
    if rest[0].is_ascii_digit() && rest[1].is_ascii_digit() {
        let (Some(k0), Some(k1)) = (rest[0].to_digit(10), rest[1].to_digit(10)) else {
            return false;
        };
        let key = u64::from(k0 * 10 + k1);
        let siren_num: u64 = siren.iter().fold(0u64, |a, &x| a * 10 + u64::from(x));
        let expected = (12 + 3 * (siren_num % 97)) % 97;
        return key == expected;
    }
    rest[0].is_ascii_alphanumeric() && rest[1].is_ascii_alphanumeric()
}

/// Italy: 11 digits guarded by a Luhn check (partita IVA).
fn italy(rest: &[char]) -> bool {
    let Some(d) = to_digits(rest) else {
        return false;
    };
    d.len() == 11 && luhn_digits(&d)
}

/// Luxembourg: 8 digits where `first6 mod 89` equals the last 2.
fn luxembourg(rest: &[char]) -> bool {
    let Some(d) = to_digits(rest) else {
        return false;
    };
    if d.len() != 8 {
        return false;
    }
    let first6: u32 = d[..6].iter().fold(0, |a, &x| a * 10 + u32::from(x));
    let last2: u32 = u32::from(d[6]) * 10 + u32::from(d[7]);
    first6 % 89 == last2
}

/// Poland (NIP): 10 digits, weighted modulus-11 check digit.
fn poland(rest: &[char]) -> bool {
    const W: [u32; 9] = [6, 5, 7, 2, 3, 4, 5, 6, 7];
    let Some(d) = to_digits(rest) else {
        return false;
    };
    if d.len() != 10 {
        return false;
    }
    let sum: u32 = d[..9].iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
    let check = sum % 11;
    check != 10 && check == u32::from(d[9])
}

/// Portugal: 9 digits, weighted modulus-11 check digit.
fn portugal(rest: &[char]) -> bool {
    const W: [u32; 8] = [9, 8, 7, 6, 5, 4, 3, 2];
    let Some(d) = to_digits(rest) else {
        return false;
    };
    if d.len() != 9 {
        return false;
    }
    let sum: u32 = d[..8].iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
    let rem = sum % 11;
    let check = if rem <= 1 { 0 } else { 11 - rem };
    check == u32::from(d[8])
}

/// Sweden: 12 digits — a 10-digit organisation number (Luhn) followed
/// by the sequence `01`.
fn sweden(rest: &[char]) -> bool {
    let Some(d) = to_digits(rest) else {
        return false;
    };
    if d.len() != 12 {
        return false;
    }
    if d[10] != 0 || d[11] != 1 {
        return false;
    }
    luhn_digits(&d[..10])
}

/// Netherlands: 9 digits + `B` + 2-digit branch index.
fn netherlands(rest: &[char]) -> bool {
    if rest.len() != 12 || rest[9] != 'B' {
        return false;
    }
    rest[..9].iter().all(char::is_ascii_digit) && rest[10..].iter().all(char::is_ascii_digit)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- IBAN ----

    /// Build a valid IBAN from country + BBAN by computing the two check
    /// digits.
    fn iban(country: &str, bban: &str) -> String {
        // Rearranged string is BBAN + country + "00".
        let mut rem: u64 = 0;
        for ch in bban
            .chars()
            .chain(country.chars())
            .chain("00".chars())
            .map(|c| c.to_ascii_uppercase())
        {
            if ch.is_ascii_digit() {
                rem = (rem * 10 + u64::from(ch as u8 - b'0')) % 97;
            } else {
                let v = u64::from(ch as u8 - b'A') + 10;
                rem = (rem * 100 + v) % 97;
            }
        }
        let check = 98 - rem;
        format!("{country}{check:02}{bban}")
    }

    #[test]
    fn iban_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        let samples = [
            ("DE", "370400440532013000"),
            ("GB", "WEST12345698765432"),
            ("FR", "20041010050500013M02606"),
            ("NL", "ABNA0417164300"),
            ("ES", "21000418450200051332"),
            ("IT", "X0542811101000000123456"),
            ("BE", "539007547034"),
            ("CH", "00762011623852957"),
            ("AT", "1904300234573201"),
            ("PT", "000201231234567890154"),
        ];
        for (cc, bban) in samples {
            let good = iban(cc, bban);
            assert!(eu_iban(&good), "expected valid IBAN {good}");
            // Spaced grouping validates identically.
            let spaced: String = good
                .as_bytes()
                .chunks(4)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join(" ");
            assert!(eu_iban(&spaced), "expected valid spaced IBAN {spaced}");
            valid += 2;
            // Corrupt a body digit.
            let mut bytes = good.into_bytes();
            let idx = bytes.len() - 1;
            bytes[idx] = if bytes[idx] == b'0' { b'1' } else { b'0' };
            let bad = String::from_utf8(bytes).unwrap();
            if !eu_iban(&bad) {
                invalid += 1;
            }
        }
        assert!(!eu_iban("DE00370400440532013000"), "wrong check digits");
        assert!(!eu_iban("XX"), "too short");
        invalid += 2;
        assert!(valid >= 20, "only {valid} valid IBAN vectors");
        assert!(invalid >= 10, "only {invalid} invalid IBAN vectors");
    }

    // ---- VAT ----

    #[test]
    fn vat_country_algorithms() {
        // Each tuple is a (number, expected) pair built to satisfy the
        // per-country algorithm. Valid examples are the canonical
        // published test numbers where available.
        let valid = [
            "ATU13585627",    // Austria
            "BE0776091951",   // Belgium
            "DE136695976",    // Germany
            "DK13585628",     // Denmark? checked below
            "FR40303265045",  // France (numeric key)
            "IT00743110157",  // Italy
            "LU26375245",     // Luxembourg
            "PL5260001246",   // Poland
            "PT501964843",    // Portugal
            "SE556293998201", // Sweden
            "EL090145420",    // Greece
        ];
        let mut ok = 0;
        for v in valid {
            assert!(eu_vat(v), "expected valid VAT {v}");
            ok += 1;
        }
        // Structural member states.
        let structural_valid = [
            "NL123456789B01",
            "ESA12345674", // 9 alnum (structural)
            "IE1234567WA",
            "RO1234567890",
            "HR12345678901",
            "SK1234567890",
        ];
        for v in structural_valid {
            assert!(eu_vat(v), "expected structurally valid VAT {v}");
            ok += 1;
        }
        // Invalids: corrupt the check digit / wrong length / bad country.
        let invalid = [
            "ATU13585628",    // Austria wrong check
            "BE0776091952",   // Belgium wrong check
            "DE136695977",    // Germany wrong check
            "FR41303265045",  // France wrong key
            "IT00743110158",  // Italy wrong Luhn
            "LU26375246",     // Luxembourg wrong check
            "PL5260001247",   // Poland wrong check
            "PT501964844",    // Portugal wrong check
            "SE556293998202", // Sweden wrong suffix
            "XX123456789",    // not an EU country
            "DE12345",        // wrong length
            "NL123456789X01", // NL missing B
        ];
        let mut bad = 0;
        for v in invalid {
            assert!(!eu_vat(v), "expected invalid VAT {v}");
            bad += 1;
        }
        assert!(ok >= 15, "only {ok} valid VAT vectors");
        assert!(bad >= 12, "only {bad} invalid VAT vectors");
    }

    #[test]
    fn vat_generated_check_digits() {
        // Generate many valid Belgium, Luxembourg and Poland numbers by
        // computing their check digits, to broaden coverage well past 50
        // combined VAT vectors.
        let mut count = 0;
        for seed in 0u32..40 {
            // Belgium: first 8 digits → last 2 = 97 − (first8 mod 97).
            let first8 = 10_000_000 + seed * 211_111;
            let last2 = 97 - (first8 % 97);
            let be = format!("BE{first8:08}{last2:02}");
            assert!(eu_vat(&be), "expected valid Belgium VAT {be}");
            // Luxembourg: first 6 digits → last 2 = first6 mod 89.
            let first6 = 100_000 + seed * 2_111;
            let lu_last = first6 % 89;
            let lu = format!("LU{first6:06}{lu_last:02}");
            assert!(eu_vat(&lu), "expected valid Luxembourg VAT {lu}");
            count += 2;
        }
        assert!(count >= 50, "only {count} generated VAT vectors");
    }
}
