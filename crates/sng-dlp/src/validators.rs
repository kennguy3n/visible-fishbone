//! National-ID check-digit validators.
//!
//! These functions confirm that a string the [`crate::classifier`]
//! regex layer matched is a *structurally valid* national identifier
//! — its check digit (or date / prefix invariants) actually holds —
//! rather than a same-shaped random digit run. They are the
//! false-positive suppressor for the Asia + GCC PII detectors, the
//! same role [`crate::classifier::luhn_valid`] plays for
//! `credit_card`.
//!
//! Every validator here has a byte-identical twin in
//! `internal/service/dlp/engine/validators.go`; the two must stay in
//! lock-step so a rule authored once decides the same way on the
//! endpoint and in the control-plane SWG. The unit tests at the foot
//! of this module and `validators_test.go` cover the same vectors.
//!
//! Validators accept the raw matched span (which may carry the
//! separators the pattern allowed — spaces and hyphens) and strip
//! them internally, so the caller hands the matched text straight in.

/// Collect the decimal digits of `s`, ignoring any other byte
/// (separators, letters). Each element is the digit's value `0..=9`.
fn digits(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect()
}

/// Luhn (mod-10) checksum over an exact digit slice. Unlike
/// [`crate::classifier::luhn_valid`] this imposes no length window,
/// so it can back the fixed-width GCC identifiers (Emirates ID = 15,
/// Saudi national ID = 10).
fn luhn_digits(d: &[u8]) -> bool {
    if d.is_empty() {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &digit in d.iter().rev() {
        let mut v = u32::from(digit);
        if double {
            v *= 2;
            if v > 9 {
                v -= 9;
            }
        }
        sum += v;
        double = !double;
    }
    sum % 10 == 0
}

/// True iff `(year, month, day)` is a real Gregorian calendar date.
/// Used by the identifiers that embed a date of birth.
fn valid_ymd(year: u32, month: u32, day: u32) -> bool {
    if !(1..=12).contains(&month) || day < 1 {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let max = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day <= max
}

/// China resident identity card (居民身份证): 18 characters — 17
/// digits plus a check character that is a digit or `X`. The check
/// uses ISO 7064 MOD 11-2 over the first 17 digits; bytes 6..14 carry
/// the holder's `YYYYMMDD` date of birth, which must be a real date.
#[must_use]
pub fn china_resident_id(s: &str) -> bool {
    // ISO 7064 MOD 11-2 weights for the 17 body digits.
    const WEIGHTS: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];

    let chars: Vec<char> = s.chars().filter(|c| !c.is_whitespace()).collect();
    if chars.len() != 18 {
        return false;
    }
    let mut body = [0u32; 17];
    for (slot, c) in body.iter_mut().zip(&chars[..17]) {
        let Some(d) = c.to_digit(10) else {
            return false;
        };
        *slot = d;
    }

    // Date of birth in positions 6..14 (YYYYMMDD).
    let year = body[6] * 1000 + body[7] * 100 + body[8] * 10 + body[9];
    let month = body[10] * 10 + body[11];
    let day = body[12] * 10 + body[13];
    if !(1900..=2100).contains(&year) || !valid_ymd(year, month, day) {
        return false;
    }

    let sum: u32 = body.iter().zip(WEIGHTS).map(|(&d, w)| d * w).sum();
    let expected = (12 - sum % 11) % 11;
    let actual = match chars.get(17) {
        Some('X' | 'x') => 10,
        Some(c) => match c.to_digit(10) {
            Some(d) => d,
            None => return false,
        },
        None => return false,
    };
    expected == actual
}

/// Japan Individual Number (マイナンバー): 12 digits where the last
/// is a MOD 11 check over the leading 11. The per-position weights
/// cycle 2..=7 from the least-significant data digit, per the MIC
/// specification.
#[must_use]
pub fn japan_my_number(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 12 {
        return false;
    }
    // P_n is the n-th digit counting from the least-significant data
    // digit (index 10 down to 0); Q_n = n+1 for 1..=6, n-5 for 7..=11.
    let mut sum = 0u32;
    for n in 1..=11u32 {
        let p = u32::from(d[11 - n as usize]);
        let q = if n <= 6 { n + 1 } else { n - 5 };
        sum += p * q;
    }
    let rem = sum % 11;
    let expected = if rem <= 1 { 0 } else { 11 - rem };
    u32::from(d[11]) == expected
}

/// South Korea Resident Registration Number (주민등록번호): 13 digits
/// — 6 date-of-birth, 1 gender/century, 5 serial, 1 check — with a
/// weighted MOD 11 check digit. The embedded `YYMMDD` must be a real
/// date.
#[must_use]
pub fn korea_rrn(s: &str) -> bool {
    const WEIGHTS: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];

    let d = digits(s);
    if d.len() != 13 {
        return false;
    }
    // Gender digit selects the birth century; reject unknown codes.
    let year_prefix = match d.get(6) {
        Some(1 | 2 | 5 | 6) => 1900,
        Some(3 | 4 | 7 | 8) => 2000,
        Some(0 | 9) => 1800,
        _ => return false,
    };
    let year = year_prefix + u32::from(d[0]) * 10 + u32::from(d[1]);
    let month = u32::from(d[2]) * 10 + u32::from(d[3]);
    let day = u32::from(d[4]) * 10 + u32::from(d[5]);
    if !valid_ymd(year, month, day) {
        return false;
    }

    let sum: u32 = d[..12]
        .iter()
        .zip(WEIGHTS)
        .map(|(&x, w)| u32::from(x) * w)
        .sum();
    let expected = (11 - sum % 11) % 10;
    u32::from(d[12]) == expected
}

/// Singapore NRIC / FIN: a prefix letter (`S`/`T`/`F`/`G`/`M`), 7
/// digits, and a check letter. The check letter is drawn from a
/// per-series table indexed by a weighted sum of the 7 digits.
#[must_use]
pub fn singapore_nric(s: &str) -> bool {
    const WEIGHTS: [u32; 7] = [2, 7, 6, 5, 4, 3, 2];

    let chars: Vec<char> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if chars.len() != 9 {
        return false;
    }
    let prefix = chars[0];
    let check = chars[8];
    let mut nums = [0u32; 7];
    for (slot, c) in nums.iter_mut().zip(&chars[1..8]) {
        let Some(v) = c.to_digit(10) else {
            return false;
        };
        *slot = v;
    }

    let mut sum: u32 = nums.iter().zip(WEIGHTS).map(|(&d, w)| d * w).sum();
    // Series offset: T/G shift by 4, M (post-2021 FIN) by 3.
    match prefix {
        'T' | 'G' => sum += 4,
        'M' => sum += 3,
        'S' | 'F' => {}
        _ => return false,
    }

    let expected = match prefix {
        'S' | 'T' => {
            const TABLE: [char; 11] = ['J', 'Z', 'I', 'H', 'G', 'F', 'E', 'D', 'C', 'B', 'A'];
            TABLE[(sum % 11) as usize]
        }
        'F' | 'G' => {
            const TABLE: [char; 11] = ['X', 'W', 'U', 'T', 'R', 'Q', 'P', 'N', 'M', 'L', 'K'];
            TABLE[(sum % 11) as usize]
        }
        'M' => {
            const TABLE: [char; 11] = ['K', 'L', 'J', 'N', 'P', 'Q', 'R', 'T', 'U', 'W', 'X'];
            TABLE[(10 - sum % 11) as usize]
        }
        _ => return false,
    };
    expected == check
}

/// Set of Malaysian MyKad place-of-birth (state) codes that the
/// 7th–8th digits may hold. Codes 60–82 are reserved / unused.
const fn malaysia_state_ok(code: u8) -> bool {
    matches!(code, 1..=59 | 82..=99)
}

/// Malaysia MyKad: 12 digits — `YYMMDD`, a 2-digit place-of-birth
/// code, then a 4-digit serial. There is no check digit, so validity
/// rests on a real date of birth and a recognised state code.
#[must_use]
pub fn malaysia_mykad(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 12 {
        return false;
    }
    let yy = u32::from(d[0]) * 10 + u32::from(d[1]);
    // Two-digit year: no century in the number, so accept any real
    // month/day against a leap-tolerant year (use 2000 as the pivot —
    // both 1900s and 2000s share Feb-29 only on /4 years, and MyKad
    // serial holders born on 29 Feb exist in both).
    let month = u32::from(d[2]) * 10 + u32::from(d[3]);
    let day = u32::from(d[4]) * 10 + u32::from(d[5]);
    if !valid_ymd(2000 + yy, month, day) {
        return false;
    }
    let state = d[6] * 10 + d[7];
    malaysia_state_ok(state)
}

/// Thailand national ID: 13 digits with a weighted MOD 11 check
/// digit (weights 13..=2 over the leading 12 digits).
#[must_use]
pub fn thailand_id(s: &str) -> bool {
    // Position weights 13..=2 over the leading 12 digits.
    const WEIGHTS: [u32; 12] = [13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2];

    let d = digits(s);
    if d.len() != 13 {
        return false;
    }
    let sum: u32 = d[..12]
        .iter()
        .zip(WEIGHTS)
        .map(|(&x, w)| u32::from(x) * w)
        .sum();
    let expected = (11 - sum % 11) % 10;
    u32::from(d[12]) == expected
}

/// India Aadhaar: 12 digits guarded by a Verhoeff check digit. The
/// leading digit is never 0 or 1 (UIDAI reserves those ranges).
#[must_use]
pub fn india_aadhaar(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 12 || d[0] < 2 {
        return false;
    }
    verhoeff_valid(&d)
}

/// India PAN: 5 letters, 4 digits, 1 letter. The 4th letter encodes
/// the holder type and must be one of the recognised classes.
#[must_use]
pub fn india_pan(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() != 10 {
        return false;
    }
    if !c[..5].iter().all(char::is_ascii_alphabetic) {
        return false;
    }
    if !c[5..9].iter().all(char::is_ascii_digit) {
        return false;
    }
    if !c[9].is_ascii_alphabetic() {
        return false;
    }
    // 4th character is the holder-type code.
    matches!(
        c[3],
        'A' | 'B' | 'C' | 'F' | 'G' | 'H' | 'J' | 'L' | 'P' | 'T' | 'E' | 'K'
    )
}

/// UAE Emirates ID: 15 digits beginning `784` with a Luhn check over
/// all 15 digits.
#[must_use]
pub fn uae_emirates_id(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 15 {
        return false;
    }
    if d[0] != 7 || d[1] != 8 || d[2] != 4 {
        return false;
    }
    luhn_digits(&d)
}

/// Saudi national / Iqama ID: 10 digits beginning `1` (citizen) or
/// `2` (resident) with a Luhn check over all 10 digits.
#[must_use]
pub fn saudi_national_id(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    if d[0] != 1 && d[0] != 2 {
        return false;
    }
    luhn_digits(&d)
}

/// Kuwait Civil ID: 12 digits — a century digit, `YYMMDD`, a 3-digit
/// serial, and a weighted MOD 11 check digit.
#[must_use]
pub fn kuwait_civil_id(s: &str) -> bool {
    const WEIGHTS: [u32; 11] = [2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];

    let d = digits(s);
    if d.len() != 12 {
        return false;
    }
    let century = match d.first() {
        Some(1) => 1800,
        Some(2) => 1900,
        Some(3) => 2000,
        _ => return false,
    };
    let year = century + u32::from(d[1]) * 10 + u32::from(d[2]);
    let month = u32::from(d[3]) * 10 + u32::from(d[4]);
    let day = u32::from(d[5]) * 10 + u32::from(d[6]);
    if !valid_ymd(year, month, day) {
        return false;
    }

    let sum: u32 = d[..11]
        .iter()
        .zip(WEIGHTS)
        .map(|(&x, w)| u32::from(x) * w)
        .sum();
    let check = 11 - sum % 11;
    check < 10 && u32::from(d[11]) == check
}

/// Verhoeff checksum (dihedral group D5) over a digit slice whose
/// final element is the check digit. Backs [`india_aadhaar`].
fn verhoeff_valid(d: &[u8]) -> bool {
    // Multiplication table for D5.
    const MUL: [[u8; 10]; 10] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
        [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
        [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
        [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
        [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
        [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
        [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
        [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
        [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
    ];
    // Permutation table.
    const PERM: [[u8; 10]; 8] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
        [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
        [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
        [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
        [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
        [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
        [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
        [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
    ];
    let mut c = 0u8;
    // Fold from the least-significant digit (the check digit) up.
    for (i, &digit) in d.iter().rev().enumerate() {
        c = MUL[c as usize][PERM[i % 8][digit as usize] as usize];
    }
    c == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn china_resident_id_accepts_valid() {
        // 17 body digits with a valid 1990-01-01 DOB; MOD 11-2 check = 5.
        assert!(china_resident_id("110101199001010015"));
        assert!(china_resident_id("110101 1990 0101 0015"));
    }

    #[test]
    fn china_resident_id_rejects_bad_check_and_date() {
        assert!(!china_resident_id("110101199001010010")); // wrong check
        assert!(!china_resident_id("110101199013010015")); // month 13
        assert!(!china_resident_id("1101011990010100")); // too short
    }

    #[test]
    fn japan_my_number_roundtrips() {
        // Build a valid number from 11 data digits.
        let base = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1];
        let mut sum = 0u32;
        for n in 1..=11u32 {
            let p = u32::from(base[11 - n as usize]);
            let q = if n <= 6 { n + 1 } else { n - 5 };
            sum += p * q;
        }
        let rem = sum % 11;
        let check = if rem <= 1 { 0 } else { 11 - rem };
        let s: String = base
            .iter()
            .chain(std::iter::once(&(check as u8)))
            .map(|d| char::from(b'0' + d))
            .collect();
        assert!(japan_my_number(&s));
        // Flip the check digit → exactly one value is valid, so a
        // different one must be rejected.
        let bad: String = base
            .iter()
            .chain(std::iter::once(&(((check + 1) % 10) as u8)))
            .map(|d| char::from(b'0' + d))
            .collect();
        assert!(!japan_my_number(&bad));
    }

    #[test]
    fn korea_rrn_accepts_valid_and_rejects_bad_date() {
        const W: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
        // Deterministic: build a valid one for DOB 1990-01-01, gender 1.
        let mut d = [9u8, 0, 0, 1, 0, 1, 1, 2, 3, 4, 5, 6, 0];
        let sum: u32 = d[..12].iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
        d[12] = ((11 - sum % 11) % 10) as u8;
        let s: String = d.iter().map(|x| char::from(b'0' + x)).collect();
        assert!(korea_rrn(&s));
        // Month 13 → reject.
        let mut bad = d;
        bad[2] = 1;
        bad[3] = 3;
        let bs: String = bad.iter().map(|x| char::from(b'0' + x)).collect();
        assert!(!korea_rrn(&bs));
    }

    #[test]
    fn singapore_nric_known_vectors() {
        assert!(singapore_nric("S1234567D"));
        assert!(!singapore_nric("S1234567A"));
        assert!(!singapore_nric("Z1234567D")); // bad prefix
        assert!(!singapore_nric("S123456D")); // too short
    }

    #[test]
    fn malaysia_mykad_date_and_state() {
        assert!(malaysia_mykad("900101-01-1234"));
        assert!(malaysia_mykad("900101011234"));
        assert!(!malaysia_mykad("901301011234")); // month 13
        assert!(!malaysia_mykad("900101701234")); // state 70 reserved
    }

    #[test]
    fn thailand_id_roundtrips() {
        let mut d = [1u8, 1, 0, 1, 7, 0, 0, 1, 2, 3, 4, 5, 0];
        let sum: u32 = (0..12).map(|i| u32::from(d[i]) * (13 - i as u32)).sum();
        let check = ((11 - sum % 11) % 10) as u8;
        d[12] = check;
        let s: String = d.iter().map(|x| char::from(b'0' + x)).collect();
        assert!(thailand_id(&s));
        // Flip the check digit → reject.
        d[12] = (check + 1) % 10;
        let bad: String = d.iter().map(|x| char::from(b'0' + x)).collect();
        assert!(!thailand_id(&bad));
    }

    #[test]
    fn india_aadhaar_verhoeff() {
        // Build a valid one deterministically.
        let body = [2u8, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8];
        let check = verhoeff_check_digit(&body);
        let mut full = body.to_vec();
        full.push(check);
        let s: String = full.iter().map(|x| char::from(b'0' + x)).collect();
        assert!(india_aadhaar(&s));
        // First digit < 2 invalid.
        assert!(!india_aadhaar("123412345678"));
    }

    #[test]
    fn india_pan_format() {
        assert!(india_pan("ABCPK1234L"));
        assert!(!india_pan("ABCXK1234L")); // X not a holder type
        assert!(!india_pan("ABCP12345L")); // digit where letter expected
        assert!(!india_pan("ABCPK1234")); // too short
    }

    #[test]
    fn uae_emirates_id_luhn_and_prefix() {
        let mut d = [7u8, 8, 4, 1, 9, 8, 7, 1, 2, 3, 4, 5, 6, 7, 0];
        // Set the last digit so Luhn passes.
        for c in 0..10u8 {
            d[14] = c;
            if luhn_digits(&d) {
                break;
            }
        }
        let s: String = d.iter().map(|x| char::from(b'0' + x)).collect();
        assert!(uae_emirates_id(&s));
        assert!(!uae_emirates_id("123198712345670")); // wrong prefix
    }

    #[test]
    fn saudi_national_id_luhn_and_prefix() {
        let mut d = [1u8, 0, 2, 3, 4, 5, 6, 7, 8, 0];
        for c in 0..10u8 {
            d[9] = c;
            if luhn_digits(&d) {
                break;
            }
        }
        let s: String = d.iter().map(|x| char::from(b'0' + x)).collect();
        assert!(saudi_national_id(&s));
        assert!(!saudi_national_id("3023456780")); // prefix 3 invalid
    }

    #[test]
    fn kuwait_civil_id_check() {
        const W: [u32; 11] = [2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
        let mut d = [2u8, 9, 0, 0, 1, 0, 1, 1, 2, 3, 4, 0];
        let sum: u32 = d[..11].iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
        let check = 11 - sum % 11;
        if check < 10 {
            d[11] = check as u8;
            let s: String = d.iter().map(|x| char::from(b'0' + x)).collect();
            assert!(kuwait_civil_id(&s));
        }
        assert!(!kuwait_civil_id("290013011234")); // month 00 invalid
    }

    #[test]
    fn luhn_digits_basic() {
        assert!(luhn_digits(&[0, 0, 0, 0])); // trivially divisible
        assert!(!luhn_digits(&[]));
    }

    // Helper mirroring the Verhoeff *generation* (not just validation)
    // for building valid test vectors.
    fn verhoeff_check_digit(body: &[u8]) -> u8 {
        const MUL: [[u8; 10]; 10] = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
            [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
            [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
            [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
            [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
            [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
            [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
            [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
            [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
        ];
        const PERM: [[u8; 10]; 8] = [
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
            [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
            [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
            [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
            [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
            [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
            [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
            [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
        ];
        const INV: [u8; 10] = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];
        let mut c = 0u8;
        for (i, &digit) in body.iter().rev().enumerate() {
            c = MUL[c as usize][PERM[(i + 1) % 8][digit as usize] as usize];
        }
        INV[c as usize]
    }
}
