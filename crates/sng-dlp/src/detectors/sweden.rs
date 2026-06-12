//! Sweden personnummer validator.
//!
//! A Swedish personal identity number is `YYMMDD-NNNC` (ten digits,
//! optionally written with a `YYYY` century prefix and/or a `-`/`+`
//! separator). The final digit `C` is a Luhn (mod-10) check digit over
//! the nine preceding digits of the ten-digit short form, using the
//! standard `2,1,2,1,…` weighting starting at the first digit. The
//! twelve-digit long form (`YYYYMMDD-NNNC`) carries the same check
//! digit, so the century pair is dropped before the Luhn fold.

/// Strip separators and return the decimal digits, or `None` if any
/// non-digit / non-separator character is present.
fn digits(s: &str) -> Option<Vec<u32>> {
    let mut out = Vec::with_capacity(12);
    for c in s.chars() {
        if c.is_whitespace() || c == '-' || c == '+' {
            continue;
        }
        out.push(c.to_digit(10)?);
    }
    Some(out)
}

/// The Luhn check digit over `body` (most-significant digit first),
/// weighting the first digit by 2 and alternating `2,1,2,1,…`.
fn luhn_check(body: &[u32]) -> u32 {
    let mut sum = 0;
    for (i, &d) in body.iter().enumerate() {
        // The leftmost digit is doubled (weight 2), matching the
        // Swedish personnummer convention.
        let v = if i % 2 == 0 { d * 2 } else { d };
        sum += if v > 9 { v - 9 } else { v };
    }
    (10 - (sum % 10)) % 10
}

/// Sweden personnummer: ten digits (or twelve with a `YYYY` prefix)
/// whose final digit is the Luhn check over the preceding nine of the
/// short form. Separators (`-`, `+`, whitespace) are ignored.
#[must_use]
pub fn sweden_personnummer(s: &str) -> bool {
    let Some(d) = digits(s) else {
        return false;
    };
    // Reduce a twelve-digit long form to the ten-digit short form the
    // check digit is defined over.
    let short: &[u32] = match d.len() {
        10 => &d,
        12 => &d[2..],
        _ => return false,
    };
    let (body, check) = short.split_at(9);
    luhn_check(body) == check[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid ten-digit personnummer from a nine-digit body by
    /// appending the correct Luhn check digit.
    fn make(body9: [u32; 9]) -> String {
        let check = luhn_check(&body9);
        let mut s: String = body9.iter().map(|d| char::from(b'0' + *d as u8)).collect();
        s.push(char::from(b'0' + check as u8));
        s
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        // Sweep a spread of nine-digit bodies; each gets its true check
        // digit (accept) and a deliberately wrong one (reject).
        for seed in (0u32..=999_999_999).step_by(37_654_321) {
            let body = [
                seed / 100_000_000 % 10,
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
            assert!(sweden_personnummer(&good), "expected valid {good}");
            valid += 1;

            let check = good.chars().last().unwrap().to_digit(10).unwrap();
            let wrong = (check + 1) % 10;
            let bad = format!("{}{}", &good[..9], wrong);
            assert!(!sweden_personnummer(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 25, "only {valid} valid vectors");
        assert!(invalid >= 25, "only {invalid} invalid vectors");
    }

    #[test]
    fn known_vector_and_forms() {
        // 811218-9876: Luhn check over 811218987 is 6.
        assert!(sweden_personnummer("8112189876"));
        assert!(sweden_personnummer("811218-9876"), "hyphen separator");
        assert!(
            sweden_personnummer("811218+9876"),
            "plus (100+ years) separator"
        );
        // Twelve-digit long form carries the same check digit.
        assert!(sweden_personnummer("198112189876"));
        assert!(sweden_personnummer("19811218-9876"));
    }

    #[test]
    fn structural_rejects() {
        assert!(!sweden_personnummer("811218987"), "9 digits");
        assert!(!sweden_personnummer("81121898765"), "11 digits");
        assert!(!sweden_personnummer("8112189875"), "wrong check digit");
        assert!(!sweden_personnummer("81121898AB"), "non-digit body");
    }
}
