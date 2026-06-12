//! Estonia isikukood (personal code) validator.
//!
//! The Estonian personal code is eleven digits `G DDMMYY SSS C`: a
//! century/sex digit, a six-digit date of birth, a three-digit serial,
//! and a mod-11 check digit `C` over the first ten.
//!
//! The check uses two weight rounds. Round one weights the ten digits
//! `1,2,3,4,5,6,7,8,9,1`; if `Σ mod 11 < 10` that is the check digit.
//! Otherwise round two weights `3,4,5,6,7,8,9,1,2,3`; if `Σ mod 11 < 10`
//! that is the check digit, and if it is again `10` the check digit is
//! `0`.

const ROUND1: [u32; 10] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 1];
const ROUND2: [u32; 10] = [3, 4, 5, 6, 7, 8, 9, 1, 2, 3];

/// Strip whitespace and return exactly eleven digits, or `None`.
fn eleven_digits(s: &str) -> Option<[u32; 11]> {
    let mut out = [0u32; 11];
    let mut n = 0;
    for c in s.chars() {
        if c.is_whitespace() {
            continue;
        }
        let d = c.to_digit(10)?;
        if n == 11 {
            return None;
        }
        out[n] = d;
        n += 1;
    }
    if n == 11 { Some(out) } else { None }
}

/// The mod-11 isikukood check digit over the ten-digit `body`.
fn check_digit(body: &[u32]) -> u32 {
    let sum1: u32 = (0..10).map(|i| ROUND1[i] * body[i]).sum();
    let r1 = sum1 % 11;
    if r1 < 10 {
        return r1;
    }
    let sum2: u32 = (0..10).map(|i| ROUND2[i] * body[i]).sum();
    let r2 = sum2 % 11;
    if r2 < 10 { r2 } else { 0 }
}

/// Estonia isikukood: eleven digits, leading digit `1..=8` (century /
/// sex), whose final digit is the two-round mod-11 check over the
/// preceding ten. Whitespace is ignored.
#[must_use]
pub fn estonia_isikukood(s: &str) -> bool {
    let Some(d) = eleven_digits(s) else {
        return false;
    };
    if d[0] == 0 || d[0] > 8 {
        return false;
    }
    check_digit(&d[..10]) == d[10]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid eleven-digit isikukood from a ten-digit body whose
    /// leading digit is forced into the `1..=8` range.
    fn make(mut body10: [u32; 10]) -> String {
        if body10[0] == 0 || body10[0] > 8 {
            body10[0] = 1 + body10[0] % 8;
        }
        let check = check_digit(&body10);
        let mut s: String = body10.iter().map(|d| char::from(b'0' + *d as u8)).collect();
        s.push(char::from(b'0' + check as u8));
        s
    }

    #[test]
    fn accepts_generated_and_rejects_perturbations() {
        let mut valid = 0;
        let mut invalid = 0;
        for seed in (0u64..=9_999_999_999).step_by(303_030_307) {
            let mut body = [0u32; 10];
            let mut v = seed;
            for slot in body.iter_mut().rev() {
                *slot = (v % 10) as u32;
                v /= 10;
            }
            let good = make(body);
            assert!(estonia_isikukood(&good), "expected valid {good}");
            valid += 1;

            let check = good.chars().last().unwrap().to_digit(10).unwrap();
            let bad = format!("{}{}", &good[..10], (check + 1) % 10);
            assert!(!estonia_isikukood(&bad), "expected invalid {bad}");
            invalid += 1;
        }
        assert!(valid >= 20, "only {valid} valid vectors");
        assert!(invalid >= 20, "only {invalid} invalid vectors");
    }

    #[test]
    fn known_vector() {
        // Canonical worked example: 37605030299 (round-one check = 9).
        assert!(estonia_isikukood("37605030299"));
    }

    #[test]
    fn second_weight_round_is_exercised() {
        // Body 1030000000: round one Σ = 1·1 + 3·3 = 10, so the mod-11
        // fold falls through to round two (Σ = 1·3 + 3·5 = 18; 18 mod 11
        // = 7), giving check digit 7 → 10300000007.
        let body = [1, 0, 3, 0, 0, 0, 0, 0, 0, 0];
        let r1: u32 = (0..10).map(|i| ROUND1[i] * body[i]).sum::<u32>() % 11;
        assert_eq!(r1, 10, "this body must trigger the second round");
        assert_eq!(check_digit(&body), 7);
        assert!(estonia_isikukood("10300000007"));
    }

    #[test]
    fn structural_rejects() {
        assert!(!estonia_isikukood("3760503029"), "10 digits");
        assert!(!estonia_isikukood("376050302990"), "12 digits");
        assert!(!estonia_isikukood("37605030298"), "wrong check digit");
        assert!(
            !estonia_isikukood("07605030299"),
            "invalid century/sex digit 0"
        );
        assert!(
            !estonia_isikukood("97605030299"),
            "invalid century/sex digit 9"
        );
        assert!(!estonia_isikukood("3760503029X"), "non-digit");
    }
}
