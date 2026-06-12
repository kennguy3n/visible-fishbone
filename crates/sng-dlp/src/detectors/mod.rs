//! Jurisdiction-specific DLP detectors (Workstream 5).
//!
//! This module is the catalog of national / regional identifier
//! detectors the endpoint DLP engine recognises. Each
//! [`JurisdictionDetector`] binds together the three things the
//! [`crate::classifier`] needs to turn a builtin pattern name into a
//! low-false-positive detector:
//!
//! 1. a precompiled-friendly **regex shape** ([`JurisdictionDetector::pattern`]);
//! 2. a **check-digit / format validator**
//!    ([`JurisdictionDetector::validator`]) that confirms a shape match
//!    is a structurally valid identifier rather than a same-shaped
//!    random run — the false-positive suppressor; and
//! 3. **proximity context cues** ([`JurisdictionDetector::context`]) —
//!    the field labels (local language + English) a real document
//!    carries near the identifier, used by the proximity analyzer.
//!
//! ## Relationship to [`crate::validators`] and the Go twin
//!
//! The check-digit math for every detector added here lives in this
//! module (one submodule per jurisdiction, each with its own
//! exhaustive test-vector suite). The original Asia + GCC detectors
//! keep their validators in [`crate::validators`]; this module
//! references them so the registry is a single, complete catalog of
//! all jurisdiction detectors. Every validator — wherever it lives —
//! has a byte-identical twin in
//! `internal/service/dlp/engine/validators.go`, and every pattern has
//! a twin entry in `internal/service/dlp/engine/regex.go`; the two
//! sides must stay in lock-step so a rule authored once decides the
//! same way on the endpoint and in the control-plane SWG.
//!
//! ## Redaction invariant
//!
//! Detectors only ever decide *whether* a span is a real identifier;
//! they never retain or emit the matched bytes (see the
//! [`crate::classifier`] redaction invariant).

pub mod australia;
pub mod belgium;
pub mod brazil;
pub mod canada;
pub mod estonia;
pub mod europe;
pub mod finland;
pub mod france;
pub mod germany;
pub mod indonesia;
pub mod italy;
pub mod netherlands;
pub mod norway;
pub mod philippines;
pub mod poland;
pub mod portugal;
pub mod south_africa;
pub mod spain;
pub mod sweden;
pub mod turkey;
pub mod uk;

use crate::validators;

/// A check-digit / structural validator applied to a regex hit to
/// suppress same-shaped false positives. Matches the signature of
/// every function in [`crate::validators`] and the per-jurisdiction
/// submodules here.
pub type Validator = fn(&str) -> bool;

/// A single jurisdiction detector: the regex shape, the validator that
/// confirms a hit, and the proximity context cues a real document
/// carries near the identifier.
#[derive(Clone, Copy, Debug)]
pub struct JurisdictionDetector {
    /// Builtin pattern name used as a rule's `pattern_data` (e.g.
    /// `brazil_cpf`). Stable wire identifier shared with the Go side.
    pub name: &'static str,
    /// ISO 3166 region (or `EU`) this detector serves, for the catalog.
    pub jurisdiction: &'static str,
    /// Human-readable identifier name, for templates / documentation.
    pub title: &'static str,
    /// The regex shape the classifier compiles for this detector.
    pub pattern: &'static str,
    /// The check-digit / format validator, or `None` when the detector
    /// relies on regex shape + proximity context alone.
    pub validator: Option<Validator>,
    /// Locale field-label cues (local language + English) used by the
    /// proximity analyzer; empty when the detector has none.
    pub context: &'static [&'static str],
}

/// The complete catalog of jurisdiction detectors WS5 ships. The
/// classifier resolves a builtin pattern name through this registry
/// (in addition to the generic builtins in
/// [`crate::classifier::builtin_pattern`]).
///
/// The list is intentionally exhaustive across the 33 supported
/// national / regional identifiers so a single lookup answers
/// "pattern, validator, and context for `name`".
// The body is one flat `JurisdictionDetector` literal per supported
// identifier; it is a declarative data table, not branching logic, so
// keeping all entries in a single function is more readable and
// auditable than splitting it across helpers.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn registry() -> &'static [JurisdictionDetector] {
    use australia::{australia_medicare, australia_tfn};
    use belgium::belgium_national_number;
    use brazil::{brazil_cnpj, brazil_cpf};
    use canada::canada_sin;
    use estonia::estonia_isikukood;
    use europe::{eu_iban, eu_vat};
    use finland::finland_hetu;
    use france::france_insee;
    use germany::germany_personalausweis;
    use indonesia::indonesia_nik;
    use italy::italy_codice_fiscale;
    use netherlands::netherlands_bsn;
    use norway::norway_fodselsnummer;
    use philippines::philippines_umid;
    use poland::poland_pesel;
    use portugal::portugal_nif;
    use south_africa::south_africa_id;
    use spain::{spain_dni, spain_nie};
    use sweden::sweden_personnummer;
    use turkey::turkey_tckn;
    use uk::{uk_nhs, uk_nino};

    &[
        // --- United Kingdom ---
        JurisdictionDetector {
            name: "ni_uk",
            jurisdiction: "GB",
            title: "UK National Insurance Number",
            pattern: r"(?i)\b[A-CEGHJ-PR-TW-Z]{2}\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
            validator: Some(uk_nino),
            context: &["national insurance", "nino", "ni number", "ni no"],
        },
        JurisdictionDetector {
            name: "uk_nhs",
            jurisdiction: "GB",
            title: "UK NHS Number",
            pattern: r"\b\d{3}\s?\d{3}\s?\d{4}\b",
            validator: Some(uk_nhs),
            context: &["nhs", "nhs number", "national health"],
        },
        // --- Canada ---
        JurisdictionDetector {
            name: "canada_sin",
            jurisdiction: "CA",
            title: "Canada Social Insurance Number",
            pattern: r"\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b",
            validator: Some(canada_sin),
            context: &[
                "social insurance",
                "sin",
                "numéro d'assurance sociale",
                "nas",
            ],
        },
        // --- Australia ---
        JurisdictionDetector {
            name: "tfn_au",
            jurisdiction: "AU",
            title: "Australia Tax File Number",
            pattern: r"\b\d{3}\s?\d{3}\s?\d{2,3}\b",
            validator: Some(australia_tfn),
            context: &["tax file number", "tfn", "ato"],
        },
        JurisdictionDetector {
            name: "australia_medicare",
            jurisdiction: "AU",
            title: "Australia Medicare Number",
            pattern: r"\b[2-6]\d{3}\s?\d{5}\s?\d\b",
            validator: Some(australia_medicare),
            context: &["medicare"],
        },
        // --- Germany ---
        JurisdictionDetector {
            name: "germany_personalausweis",
            jurisdiction: "DE",
            title: "Germany Personalausweis (ID card) number",
            pattern: r"\b[0-9A-Z]{9}\d\b",
            validator: Some(germany_personalausweis),
            context: &[
                "personalausweis",
                "ausweisnummer",
                "identity card",
                "id card",
            ],
        },
        // --- France ---
        JurisdictionDetector {
            name: "france_insee",
            jurisdiction: "FR",
            title: "France INSEE / social security number (NIR)",
            pattern: r"\b[1-8]\s?\d{2}\s?\d{2}\s?\d[AB0-9]\s?\d{3}\s?\d{3}\s?\d{2}\b",
            validator: Some(france_insee),
            context: &[
                "insee",
                "sécurité sociale",
                "securite sociale",
                "numéro de sécurité sociale",
                "social security",
                "nir",
            ],
        },
        // --- Japan / Korea (validators in crate::validators) ---
        JurisdictionDetector {
            name: "japan_my_number",
            jurisdiction: "JP",
            title: "Japan Individual Number (My Number)",
            pattern: r"\b\d{4}\s?\d{4}\s?\d{4}\b",
            validator: Some(validators::japan_my_number),
            context: &["マイナンバー", "個人番号", "my number"],
        },
        JurisdictionDetector {
            name: "korea_rrn",
            jurisdiction: "KR",
            title: "Korea Resident Registration Number",
            pattern: r"\b\d{6}-?\d{7}\b",
            validator: Some(validators::korea_rrn),
            context: &["주민등록번호", "rrn", "resident registration"],
        },
        // --- India (validators in crate::validators) ---
        JurisdictionDetector {
            name: "india_aadhaar",
            jurisdiction: "IN",
            title: "India Aadhaar",
            pattern: r"\b\d{4}\s?\d{4}\s?\d{4}\b",
            validator: Some(validators::india_aadhaar),
            context: &["आधार", "aadhaar", "uid"],
        },
        JurisdictionDetector {
            name: "india_pan",
            jurisdiction: "IN",
            title: "India Permanent Account Number (PAN)",
            pattern: r"\b[A-Z]{5}\d{4}[A-Z]\b",
            validator: Some(validators::india_pan),
            context: &["pan", "permanent account", "income tax"],
        },
        // --- Brazil ---
        JurisdictionDetector {
            name: "brazil_cpf",
            jurisdiction: "BR",
            title: "Brazil CPF",
            pattern: r"\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b",
            validator: Some(brazil_cpf),
            context: &["cpf", "cadastro de pessoas", "receita federal"],
        },
        JurisdictionDetector {
            name: "brazil_cnpj",
            jurisdiction: "BR",
            title: "Brazil CNPJ",
            pattern: r"\b\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}\b",
            validator: Some(brazil_cnpj),
            context: &["cnpj", "cadastro nacional", "pessoa jurídica"],
        },
        // --- European Union ---
        JurisdictionDetector {
            name: "iban",
            jurisdiction: "EU",
            title: "IBAN (International Bank Account Number)",
            pattern: r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b",
            validator: Some(eu_iban),
            context: &["iban", "bank account", "account number", "swift", "bic"],
        },
        JurisdictionDetector {
            name: "eu_vat",
            jurisdiction: "EU",
            title: "EU VAT identification number",
            pattern: r"\b(?:AT|BE|BG|CY|CZ|DE|DK|EE|EL|ES|FI|FR|HR|HU|IE|IT|LT|LU|LV|MT|NL|PL|PT|RO|SE|SI|SK)[0-9A-Za-z+*]{2,12}\b",
            validator: Some(eu_vat),
            context: &[
                "vat",
                "vat number",
                "ust-idnr",
                "tva",
                "btw",
                "p.iva",
                "iva",
            ],
        },
        // --- Spain ---
        JurisdictionDetector {
            name: "spain_dni",
            jurisdiction: "ES",
            title: "Spain DNI (Documento Nacional de Identidad)",
            pattern: r"\b\d{8}[\s-]?[A-Za-z]\b",
            validator: Some(spain_dni),
            context: &[
                "dni",
                "documento nacional",
                "número de identidad",
                "numero de identidad",
            ],
        },
        JurisdictionDetector {
            name: "spain_nie",
            jurisdiction: "ES",
            title: "Spain NIE (Número de Identidad de Extranjero)",
            pattern: r"\b[XYZxyz][\s-]?\d{7}[\s-]?[A-Za-z]\b",
            validator: Some(spain_nie),
            context: &[
                "nie",
                "número de identidad de extranjero",
                "numero de identidad de extranjero",
                "foreigner id",
            ],
        },
        // --- Italy ---
        JurisdictionDetector {
            name: "italy_codice_fiscale",
            jurisdiction: "IT",
            title: "Italy Codice Fiscale",
            pattern: r"\b[A-Za-z]{6}\d{2}[A-Za-z]\d{2}[A-Za-z]\d{3}[A-Za-z]\b",
            validator: Some(italy_codice_fiscale),
            context: &["codice fiscale", "cod. fisc", "agenzia delle entrate"],
        },
        // --- Netherlands ---
        JurisdictionDetector {
            name: "netherlands_bsn",
            jurisdiction: "NL",
            title: "Netherlands BSN (Burgerservicenummer)",
            pattern: r"\b\d{9}\b",
            validator: Some(netherlands_bsn),
            context: &[
                "bsn",
                "burgerservicenummer",
                "sofinummer",
                "citizen service number",
            ],
        },
        // --- Poland ---
        JurisdictionDetector {
            name: "poland_pesel",
            jurisdiction: "PL",
            title: "Poland PESEL",
            pattern: r"\b\d{11}\b",
            validator: Some(poland_pesel),
            context: &["pesel", "numer pesel"],
        },
        // --- Belgium ---
        JurisdictionDetector {
            name: "belgium_national_number",
            jurisdiction: "BE",
            title: "Belgium National Register Number (Rijksregisternummer)",
            pattern: r"\b\d{2}[.\s-]?\d{2}[.\s-]?\d{2}[.\s-]?\d{3}[.\s-]?\d{2}\b",
            validator: Some(belgium_national_number),
            context: &[
                "rijksregisternummer",
                "numéro de registre national",
                "numero de registre national",
                "national register",
                "rrn",
            ],
        },
        // --- Philippines ---
        JurisdictionDetector {
            name: "philippines_umid",
            jurisdiction: "PH",
            title: "Philippines UMID / CRN",
            pattern: r"\b\d{4}-?\d{7}-?\d\b",
            validator: Some(philippines_umid),
            context: &["umid", "crn", "common reference", "sss", "gsis"],
        },
        // --- Thailand (validator in crate::validators) ---
        JurisdictionDetector {
            name: "thailand_id",
            jurisdiction: "TH",
            title: "Thailand National ID",
            pattern: r"\b\d{1}-?\d{4}-?\d{5}-?\d{2}-?\d{1}\b",
            validator: Some(validators::thailand_id),
            context: &["บัตรประชาชน", "national id", "thai id"],
        },
        // --- Indonesia ---
        JurisdictionDetector {
            name: "indonesia_nik",
            jurisdiction: "ID",
            title: "Indonesia NIK (KTP)",
            pattern: r"\b\d{16}\b",
            validator: Some(indonesia_nik),
            context: &["nik", "ktp", "nomor induk kependudukan"],
        },
        // --- GCC (validators in crate::validators) ---
        JurisdictionDetector {
            name: "uae_emirates_id",
            jurisdiction: "AE",
            title: "UAE Emirates ID",
            pattern: r"\b784-?\d{4}-?\d{7}-?\d{1}\b",
            validator: Some(validators::uae_emirates_id),
            context: &["الهوية", "emirates id", "هوية"],
        },
        JurisdictionDetector {
            name: "saudi_id",
            jurisdiction: "SA",
            title: "Saudi national / Iqama ID",
            pattern: r"\b[12]\d{9}\b",
            validator: Some(validators::saudi_national_id),
            context: &["الهوية الوطنية", "national id", "إقامة", "iqama"],
        },
        // --- Sweden ---
        JurisdictionDetector {
            name: "sweden_personnummer",
            jurisdiction: "SE",
            title: "Sweden Personnummer",
            pattern: r"\b(?:\d{2})?\d{6}[-+]?\d{4}\b",
            validator: Some(sweden_personnummer),
            context: &["personnummer", "personal number", "född", "skatteverket"],
        },
        // --- Norway ---
        JurisdictionDetector {
            name: "norway_fodselsnummer",
            jurisdiction: "NO",
            title: "Norway Fødselsnummer (birth number)",
            pattern: r"\b\d{6}\s?\d{5}\b",
            validator: Some(norway_fodselsnummer),
            context: &[
                "fødselsnummer",
                "fodselsnummer",
                "birth number",
                "personnummer",
                "folkeregister",
            ],
        },
        // --- Finland ---
        JurisdictionDetector {
            name: "finland_hetu",
            jurisdiction: "FI",
            title: "Finland Henkilötunnus (HETU)",
            pattern: r"\b\d{6}[-+ABCDEFUVWXY]\d{3}[0-9A-Ya-y]\b",
            validator: Some(finland_hetu),
            context: &[
                "henkilötunnus",
                "henkilotunnus",
                "hetu",
                "personal identity code",
                "social security",
            ],
        },
        // --- Portugal ---
        JurisdictionDetector {
            name: "portugal_nif",
            jurisdiction: "PT",
            title: "Portugal NIF / NIPC (tax number)",
            pattern: r"\b\d{3}[.\s]?\d{3}[.\s]?\d{3}\b",
            validator: Some(portugal_nif),
            context: &[
                "nif",
                "nipc",
                "número de identificação fiscal",
                "numero de identificacao fiscal",
                "contribuinte",
                "tax number",
            ],
        },
        // --- Turkey ---
        JurisdictionDetector {
            name: "turkey_tckn",
            jurisdiction: "TR",
            title: "Turkey T.C. Kimlik No",
            pattern: r"\b[1-9]\d{10}\b",
            validator: Some(turkey_tckn),
            context: &[
                "kimlik",
                "tc kimlik",
                "t.c. kimlik",
                "kimlik no",
                "identity number",
            ],
        },
        // --- South Africa ---
        JurisdictionDetector {
            name: "south_africa_id",
            jurisdiction: "ZA",
            title: "South Africa National ID",
            pattern: r"\b\d{6}\s?\d{4}\s?\d{3}\b",
            validator: Some(south_africa_id),
            context: &["id number", "identity number", "south african id", "rsa id"],
        },
        // --- Estonia ---
        JurisdictionDetector {
            name: "estonia_isikukood",
            jurisdiction: "EE",
            title: "Estonia Isikukood (personal code)",
            pattern: r"\b[1-8]\d{10}\b",
            validator: Some(estonia_isikukood),
            context: &["isikukood", "personal code", "personal identification"],
        },
    ]
}

/// Look up a detector by its builtin pattern name.
#[must_use]
pub fn detector(name: &str) -> Option<&'static JurisdictionDetector> {
    registry().iter().find(|d| d.name == name)
}

/// The regex shape for a jurisdiction detector, or `None` if `name` is
/// not a jurisdiction detector.
#[must_use]
pub fn pattern(name: &str) -> Option<&'static str> {
    detector(name).map(|d| d.pattern)
}

/// The validator for a jurisdiction detector, or `None` when the name
/// is unknown or the detector has no validator.
#[must_use]
pub fn validator(name: &str) -> Option<Validator> {
    detector(name).and_then(|d| d.validator)
}

/// The proximity context cues for a jurisdiction detector, or `None`
/// when the name is unknown or has no cues.
#[must_use]
pub fn context(name: &str) -> Option<&'static [&'static str]> {
    let d = detector(name)?;
    if d.context.is_empty() {
        None
    } else {
        Some(d.context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::builtin_pattern;
    use regex::Regex;

    /// The full set of jurisdiction identifiers the catalog must support.
    const EXPECTED_NAMES: [&str; 33] = [
        "ni_uk",
        "uk_nhs",
        "canada_sin",
        "tfn_au",
        "australia_medicare",
        "germany_personalausweis",
        "france_insee",
        "japan_my_number",
        "korea_rrn",
        "india_aadhaar",
        "india_pan",
        "brazil_cpf",
        "brazil_cnpj",
        "iban",
        "eu_vat",
        "spain_dni",
        "spain_nie",
        "italy_codice_fiscale",
        "netherlands_bsn",
        "poland_pesel",
        "belgium_national_number",
        "philippines_umid",
        "thailand_id",
        "indonesia_nik",
        "uae_emirates_id",
        "saudi_id",
        "sweden_personnummer",
        "norway_fodselsnummer",
        "finland_hetu",
        "portugal_nif",
        "turkey_tckn",
        "south_africa_id",
        "estonia_isikukood",
    ];

    #[test]
    fn registry_covers_all_detectors() {
        assert_eq!(
            registry().len(),
            EXPECTED_NAMES.len(),
            "registry size must match the expected catalog"
        );
        for name in EXPECTED_NAMES {
            assert!(detector(name).is_some(), "missing detector {name}");
        }
        // Names are unique.
        let mut names: Vec<&str> = registry().iter().map(|d| d.name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            EXPECTED_NAMES.len(),
            "detector names must be unique"
        );
    }

    #[test]
    fn every_detector_has_validator_and_context() {
        for d in registry() {
            assert!(d.validator.is_some(), "{} has no validator", d.name);
            assert!(!d.context.is_empty(), "{} has no context cues", d.name);
            assert!(!d.title.is_empty(), "{} has no title", d.name);
            assert!(!d.jurisdiction.is_empty(), "{} has no jurisdiction", d.name);
        }
    }

    #[test]
    fn finland_hetu_regex_admits_lowercase_control_char() {
        // The validator case-folds the control character, so the regex
        // gate must too — otherwise a valid HETU with a lowercase control
        // (e.g. `131052-308t`) is dropped before the validator sees it.
        let d = detector("finland_hetu").expect("finland in registry");
        let re = Regex::new(d.pattern).expect("valid regex");
        assert!(
            re.is_match("131052-308t"),
            "lowercase control rejected by gate"
        );
        assert!(
            re.is_match("131052-308T"),
            "uppercase control rejected by gate"
        );
        let validate = d.validator.expect("finland has a validator");
        assert!(validate("131052-308t") && validate("131052-308T"));
    }

    #[test]
    fn every_pattern_compiles() {
        for d in registry() {
            assert!(Regex::new(d.pattern).is_ok(), "{} regex invalid", d.name);
        }
    }

    #[test]
    fn classifier_resolves_every_detector() {
        // The classifier must surface a pattern, validator and context
        // for every catalog detector (via its own arms or the registry
        // fallback).
        for d in registry() {
            assert!(
                builtin_pattern(d.name).is_some(),
                "classifier has no pattern for {}",
                d.name
            );
        }
    }

    #[test]
    fn registry_patterns_match_classifier_for_shared_names() {
        // For detectors whose pattern lives in the classifier's own
        // builtin arms (the original Asia/GCC set plus ni_uk/tfn_au/iban),
        // the registry must carry the byte-identical regex so the two
        // sources never drift.
        let shared = [
            "ni_uk",
            "tfn_au",
            "iban",
            "japan_my_number",
            "korea_rrn",
            "india_aadhaar",
            "india_pan",
            "thailand_id",
            "uae_emirates_id",
            "saudi_id",
        ];
        for name in shared {
            assert_eq!(
                Some(pattern(name).unwrap()),
                builtin_pattern(name),
                "registry/classifier pattern drift for {name}"
            );
        }
    }
}
