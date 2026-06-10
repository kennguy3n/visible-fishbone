//! Brazil identifier validators: CPF (natural persons) and CNPJ
//! (legal entities).

use crate::validators::digits;

/// Brazilian modulus-11 check digit over `body` with descending
/// weights starting at `start_weight` (e.g. 10 then 9 … for CPF's
/// first digit). A remainder `< 2` yields a check digit of `0`.
fn mod11_check(body: &[u8], start_weight: u32) -> u32 {
    let sum: u32 = body
        .iter()
        .zip((2..=start_weight).rev())
        .map(|(&d, w)| u32::from(d) * w)
        .sum();
    let r = sum % 11;
    if r < 2 { 0 } else { 11 - r }
}

/// True when every digit is identical (e.g. `111.111.111-11`) — these
/// pass the checksum arithmetically but are never issued.
fn all_same(d: &[u8]) -> bool {
    d.windows(2).all(|w| w[0] == w[1])
}

/// Brazil CPF (Cadastro de Pessoas Físicas): eleven digits with two
/// trailing modulus-11 check digits. Repdigit numbers (all identical
/// digits) are rejected even though they satisfy the arithmetic.
#[must_use]
pub fn brazil_cpf(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 11 || all_same(&d) {
        return false;
    }
    let c1 = mod11_check(&d[..9], 10);
    let c2 = mod11_check(&d[..10], 11);
    u32::from(d[9]) == c1 && u32::from(d[10]) == c2
}

/// Per-position weights for the CNPJ check digits.
const CNPJ_W1: [u32; 12] = [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];
const CNPJ_W2: [u32; 13] = [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2];

/// Brazil CNPJ (Cadastro Nacional da Pessoa Jurídica): fourteen digits
/// with two trailing modulus-11 check digits computed with fixed
/// per-position weights. Repdigit numbers are rejected.
#[must_use]
pub fn brazil_cnpj(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 14 || all_same(&d) {
        return false;
    }
    let c1 = cnpj_check(&d[..12], &CNPJ_W1);
    let c2 = cnpj_check(&d[..13], &CNPJ_W2);
    u32::from(d[12]) == c1 && u32::from(d[13]) == c2
}

fn cnpj_check(body: &[u8], weights: &[u32]) -> u32 {
    let sum: u32 = body
        .iter()
        .zip(weights)
        .map(|(&d, &w)| u32::from(d) * w)
        .sum();
    let r = sum % 11;
    if r < 2 { 0 } else { 11 - r }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpf_string(base: &[u8; 9]) -> String {
        let c1 = mod11_check(base, 10) as u8;
        let mut ten = base.to_vec();
        ten.push(c1);
        let c2 = mod11_check(&ten, 11) as u8;
        base.iter()
            .chain([c1, c2].iter())
            .map(|d| char::from(b'0' + d))
            .collect()
    }

    fn cnpj_string(base: &[u8; 12]) -> String {
        let c1 = cnpj_check(base, &CNPJ_W1) as u8;
        let mut thirteen = base.to_vec();
        thirteen.push(c1);
        let c2 = cnpj_check(&thirteen, &CNPJ_W2) as u8;
        base.iter()
            .chain([c1, c2].iter())
            .map(|d| char::from(b'0' + d))
            .collect()
    }

    #[test]
    fn cpf_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let mut base = [0u8; 9];
            let mut v = seed.wrapping_mul(2_654_435_761).wrapping_add(13);
            for slot in &mut base {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(seed + 1);
            }
            if all_same(&base) {
                base[0] = (base[0] + 1) % 10;
            }
            let good = cpf_string(&base);
            assert!(brazil_cpf(&good), "expected valid CPF {good}");
            // Dotted presentation validates identically.
            let dotted = format!(
                "{}.{}.{}-{}",
                &good[0..3],
                &good[3..6],
                &good[6..9],
                &good[9..11]
            );
            assert!(brazil_cpf(&dotted), "expected valid dotted CPF {dotted}");
            valid += 2;

            // Corrupt the first check digit.
            let mut chars: Vec<u8> = good.bytes().map(|b| b - b'0').collect();
            chars[9] = (chars[9] + 1) % 10;
            let bad: String = chars.iter().map(|d| char::from(b'0' + d)).collect();
            if !brazil_cpf(&bad) {
                invalid += 1;
            }
        }
        assert!(!brazil_cpf("11111111111"), "repdigit");
        assert!(!brazil_cpf("123456789"), "9 digits");
        assert!(!brazil_cpf("000000000000"), "12 digits repdigit");
        invalid += 3;
        assert!(valid >= 50, "only {valid} valid CPF vectors");
        assert!(invalid >= 25, "only {invalid} invalid CPF vectors");
    }

    #[test]
    fn cnpj_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in 0u32..40 {
            let mut base = [0u8; 12];
            let mut v = (u64::from(seed))
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(17);
            for slot in &mut base {
                *slot = (v % 10) as u8;
                v /= 10;
                v = v.wrapping_add(u64::from(seed) + 1);
            }
            if all_same(&base) {
                base[0] = (base[0] + 1) % 10;
            }
            let good = cnpj_string(&base);
            assert!(brazil_cnpj(&good), "expected valid CNPJ {good}");
            let dotted = format!(
                "{}.{}.{}/{}-{}",
                &good[0..2],
                &good[2..5],
                &good[5..8],
                &good[8..12],
                &good[12..14]
            );
            assert!(brazil_cnpj(&dotted), "expected valid dotted CNPJ {dotted}");
            valid += 2;

            let mut chars: Vec<u8> = good.bytes().map(|b| b - b'0').collect();
            chars[12] = (chars[12] + 1) % 10;
            let bad: String = chars.iter().map(|d| char::from(b'0' + d)).collect();
            if !brazil_cnpj(&bad) {
                invalid += 1;
            }
        }
        assert!(!brazil_cnpj("11111111111111"), "repdigit");
        assert!(!brazil_cnpj("123456789012"), "12 digits");
        invalid += 2;
        assert!(valid >= 50, "only {valid} valid CNPJ vectors");
        assert!(invalid >= 25, "only {invalid} invalid CNPJ vectors");
    }
}
