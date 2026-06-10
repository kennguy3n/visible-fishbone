//! France INSEE / social-security number (NIR) validator.

/// True for months the NIR permits: the calendar months `1..=12` plus
/// the "fictitious" months INSEE assigns when the birth month is
/// unknown or for certain registration regimes (`20`, `30..=42`, `50`,
/// `99`).
fn plausible_month(m: u32) -> bool {
    matches!(m, 1..=12 | 20 | 30..=42 | 50 | 99)
}

/// France INSEE number (NIR): a 13-character body followed by a
/// two-digit control key.
///
/// The body is `sex(1) year(2) month(2) department(2) commune(3)
/// order(3)`. The control key is `97 − (body mod 97)`, where for the
/// Corsican departments the alphabetic department codes `2A` / `2B`
/// are folded into the numeric body by replacing the letter with `0`
/// and subtracting `1_000_000` / `2_000_000` respectively (the
/// official INSEE rule). Spaces / hyphens the pattern allows are
/// stripped first.
#[must_use]
pub fn france_insee(s: &str) -> bool {
    let c: Vec<char> = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if c.len() != 15 {
        return false;
    }

    // Sex digit: 1/2 (and historically 3/4 for some territories).
    let Some(sex) = c[0].to_digit(10) else {
        return false;
    };
    if !(1..=4).contains(&sex) {
        return false;
    }

    // Month plausibility.
    let (Some(m1), Some(m2)) = (c[3].to_digit(10), c[4].to_digit(10)) else {
        return false;
    };
    if !plausible_month(m1 * 10 + m2) {
        return false;
    }

    // Build the numeric body, folding Corsica letters at the department
    // position (index 6).
    let mut body = String::with_capacity(13);
    let mut corsica_offset: u64 = 0;
    for (i, &ch) in c[..13].iter().enumerate() {
        match ch {
            '0'..='9' => body.push(ch),
            'A' if i == 6 => {
                body.push('0');
                corsica_offset = 1_000_000;
            }
            'B' if i == 6 => {
                body.push('0');
                corsica_offset = 2_000_000;
            }
            _ => return false,
        }
    }
    let Ok(mut n) = body.parse::<u64>() else {
        return false;
    };
    if n < corsica_offset {
        return false;
    }
    n -= corsica_offset;

    // Control key.
    let (Some(k0), Some(k1)) = (c[13].to_digit(10), c[14].to_digit(10)) else {
        return false;
    };
    let key = u64::from(k0) * 10 + u64::from(k1);
    if !(1..=97).contains(&key) {
        return false;
    }
    97 - (n % 97) == key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a valid 15-char NIR from a numeric 13-digit body.
    fn nir_from_body(body: u64) -> String {
        let key = 97 - (body % 97);
        format!("{body:013}{key:02}")
    }

    #[test]
    fn insee_accepts_and_rejects() {
        let mut valid = 0;
        let mut invalid = 0;
        // Sweep plausible bodies: sex 1/2, year, months 1..=12, dept 75,
        // commune + order.
        for seed in 0u32..30 {
            let sex = 1 + (seed % 2);
            let year = seed % 100;
            let month = 1 + (seed % 12);
            let dept = 75;
            let commune = 100 + (seed % 800);
            let order = 1 + (seed % 900);
            let body: u64 = format!("{sex}{year:02}{month:02}{dept:02}{commune:03}{order:03}")
                .parse()
                .unwrap();
            let good = nir_from_body(body);
            assert!(france_insee(&good), "expected valid NIR {good}");
            // Spaced presentation validates identically.
            let spaced = format!(
                "{} {} {} {} {} {} {}",
                &good[0..1],
                &good[1..3],
                &good[3..5],
                &good[5..7],
                &good[7..10],
                &good[10..13],
                &good[13..15]
            );
            assert!(france_insee(&spaced), "expected valid spaced NIR {spaced}");
            valid += 2;

            // Wrong key.
            let key = 97 - (body % 97);
            let bad_key = if key == 97 { 1 } else { key + 1 };
            let bad = format!("{body:013}{bad_key:02}");
            assert!(!france_insee(&bad), "expected invalid NIR {bad}");
            invalid += 1;
        }

        // Corsica: department 2A. The 13-char body "269052A588157" folds
        // to the digits "2690520588157" (A→0) minus 1_000_000.
        let folded: u64 = "2690520588157".parse::<u64>().unwrap() - 1_000_000;
        let key = 97 - (folded % 97);
        let corsica = format!("269052A588157{key:02}");
        assert_eq!(corsica.len(), 15);
        assert!(
            france_insee(&corsica),
            "expected valid Corsica NIR {corsica}"
        );
        valid += 1;

        // Structural rejects.
        assert!(!france_insee("26905049588157"), "14 chars");
        assert!(!france_insee("2690513495881580"), "month 13");
        assert!(!france_insee("0690549588157 80"), "sex 0");
        invalid += 3;
        assert!(valid >= 50, "only {valid} valid INSEE vectors");
        assert!(invalid >= 25, "only {invalid} invalid INSEE vectors");
    }
}
