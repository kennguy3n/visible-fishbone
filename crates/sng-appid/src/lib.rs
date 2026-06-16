// Test code uses `.unwrap()` / `.expect("fixture")` / `panic!` for
// fast-failing assertions, and casts freely when synthesising fuzz
// inputs. Allow the panicking / cast restriction lints in test builds
// only — production paths keep the workspace's strict posture.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation,
    )
)]

//! # sng-appid — ShieldNet Gateway application identification
//!
//! A data-driven replacement for the hard-coded, closed set of L7
//! protocols and the handful of inline CASB apps the data plane used
//! to recognise. Applications are described declaratively in a signed,
//! versioned [`Catalog`]; a pre-compiled [`Matcher`] maps the features
//! the data plane observes for a connection ([`ConnFeatures`]) to a
//! best-match application identity ([`AppMatch`]) in bounded time.
//!
//! ## Why
//! Market leaders identify thousands of applications. The legacy code
//! could name about seven protocols and a few SaaS apps, all hard
//! coded. This crate ships a real seed catalog of a few hundred common
//! SaaS / enterprise apps grouped by category, and — crucially — makes
//! the catalog *data*: the control plane can publish new, signed
//! versions without shipping new binaries.
//!
//! ## Cost / safety
//! The matcher uses hash lookups and a longest-suffix walk with no
//! regex and no backtracking, so a hostile peer cannot drive
//! super-linear CPU. Memory is bounded by the catalog. See
//! [`matcher`] for the per-identification cost breakdown. Loading an
//! untrusted catalog returns a typed [`AppIdError`] instead of
//! panicking, so a bad bundle can never take down the data path — the
//! caller falls back to the embedded baseline.
//!
//! ## Example
//! ```
//! use sng_appid::{ConnFeatures, Matcher};
//!
//! let matcher = Matcher::builtin();
//! let feat = ConnFeatures::from_sni("teams.microsoft.com", 443);
//! let m = matcher.identify(&feat).expect("known app");
//! assert_eq!(m.app_id, "microsoft.teams");
//! assert_eq!(m.category, "collaboration");
//! ```

mod catalog;
mod error;
mod features;
mod matcher;
mod signature;

pub use catalog::Catalog;
pub use error::AppIdError;
pub use features::{AppMatch, ConnFeatures, MAX_HOST_LABELS, MAX_PROBE_BYTES, Transport};
pub use matcher::Matcher;
pub use signature::{AppSignature, RawApp, RawCatalog, SCHEMA_VERSION, normalise_host};

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::fmt::Write as _;

    fn builtin() -> &'static Matcher {
        Matcher::builtin()
    }

    #[test]
    fn embedded_catalog_parses_and_is_meaningful() {
        let catalog = Catalog::parse_embedded().expect("embedded catalog must parse");
        // A "real, meaningful seed" — a few hundred apps.
        assert!(
            catalog.len() >= 200,
            "expected >= 200 seed apps, got {}",
            catalog.len()
        );
    }

    #[test]
    fn embedded_app_ids_are_unique_and_well_formed() {
        let catalog = Catalog::parse_embedded().expect("parse");
        let mut ids: Vec<&str> = catalog
            .signatures()
            .iter()
            .map(|s| s.app_id.as_str())
            .collect();
        let total = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), total, "app_ids must be unique");

        for sig in catalog.signatures() {
            assert!(!sig.app_id.is_empty());
            assert!(!sig.category.is_empty());
            assert!(sig.confidence <= 100);
            let has_match_key = !sig.sni_suffixes.is_empty()
                || !sig.host_suffixes.is_empty()
                || !sig.ja3.is_empty()
                || !sig.byte_prefixes.is_empty();
            assert!(has_match_key, "{} has no match key", sig.app_id);
        }
    }

    #[test]
    fn exact_sni_match_beats_suffix() {
        let m = builtin();
        let out = m
            .identify(&ConnFeatures::from_sni("teams.microsoft.com", 443))
            .expect("match");
        assert_eq!(out.app_id, "microsoft.teams");
        assert_eq!(out.category, "collaboration");
        assert!(out.confidence >= 90);
    }

    #[test]
    fn subdomain_matches_via_suffix() {
        let m = builtin();
        // Not an exact catalog entry, but a subdomain of slack.com.
        let out = m
            .identify(&ConnFeatures::from_sni("files.edge.slack.com", 443))
            .expect("match");
        assert_eq!(out.app_id, "slack");
    }

    #[test]
    fn http_host_is_matched_like_sni() {
        let m = builtin();
        let out = m
            .identify(&ConnFeatures::from_host("api.dropboxapi.com", 443))
            .expect("match");
        assert_eq!(out.app_id, "dropbox");
        assert_eq!(out.category, "storage");
    }

    #[test]
    fn unknown_host_is_none() {
        let m = builtin();
        assert!(
            m.identify(&ConnFeatures::from_sni("nope.example.invalid", 443))
                .is_none()
        );
    }

    #[test]
    fn exact_match_scores_above_parent_suffix_match() {
        // Build a tiny catalog where one app claims the apex and we can
        // observe the exact-vs-suffix confidence delta deterministically.
        let json = r#"{
          "schema_version": 1,
          "apps": [
            {"app_id":"acme","category":"test","sni_suffixes":["acme.com"],
             "host_suffixes":[],"ja3":[],"ports":[443],"transport":"tcp",
             "byte_prefixes":[],"confidence":80}
          ]
        }"#;
        let cat = Catalog::from_json(json).expect("parse");
        let m = Matcher::from_catalog(&cat);
        let exact = m
            .identify(&ConnFeatures::from_sni("acme.com", 443))
            .expect("exact");
        let suffix = m
            .identify(&ConnFeatures::from_sni("www.acme.com", 443))
            .expect("suffix");
        assert!(
            exact.confidence > suffix.confidence,
            "exact {} should beat suffix {}",
            exact.confidence,
            suffix.confidence
        );
    }

    #[test]
    fn more_specific_suffix_wins_across_apps() {
        // Two apps overlap on a parent domain; the one that matches the
        // longer, more specific suffix must win even though both share
        // the same confidence and neither is an exact match. Without
        // specificity ranking the alphabetical tie-break would wrongly
        // pick the generic `acme` over `acme.api`.
        let json = r#"{
          "schema_version": 1,
          "apps": [
            {"app_id":"acme","category":"test","sni_suffixes":["acme.com"],
             "host_suffixes":[],"ja3":[],"ports":[443],"transport":"tcp",
             "byte_prefixes":[],"confidence":90},
            {"app_id":"acme.api","category":"test","sni_suffixes":["api.acme.com"],
             "host_suffixes":[],"ja3":[],"ports":[443],"transport":"tcp",
             "byte_prefixes":[],"confidence":90}
          ]
        }"#;
        let cat = Catalog::from_json(json).expect("parse");
        let m = Matcher::from_catalog(&cat);
        // A host under the specific suffix resolves to the specific app.
        let specific = m
            .identify(&ConnFeatures::from_sni("edge.api.acme.com", 443))
            .expect("match");
        assert_eq!(specific.app_id, "acme.api");
        // A host that only matches the parent resolves to the generic app.
        let generic = m
            .identify(&ConnFeatures::from_sni("www.acme.com", 443))
            .expect("match");
        assert_eq!(generic.app_id, "acme");
    }

    #[test]
    fn seed_s3_host_resolves_to_s3_not_generic_aws() {
        // Regression for the aws / aws.s3 overlap: an S3 endpoint must
        // resolve to the specific `aws.s3`, while a non-S3 amazonaws
        // host falls back to the generic `aws`.
        let m = builtin();
        let s3 = m
            .identify(&ConnFeatures::from_sni("my-bucket.s3.amazonaws.com", 443))
            .expect("s3");
        assert_eq!(s3.app_id, "aws.s3");
        let generic = m
            .identify(&ConnFeatures::from_sni("ec2.amazonaws.com", 443))
            .expect("aws");
        assert_eq!(generic.app_id, "aws");
    }

    #[test]
    fn deeply_nested_host_beyond_label_bound_still_matches_short_suffix() {
        // A pathological host with far more than MAX_HOST_LABELS labels
        // must still resolve via its short registrable suffix. The
        // adversarial label bound only drops the longest (most specific)
        // suffixes from the walk, so a 2-label catalog suffix stays
        // reachable; the matcher remains bounded and never panics. The
        // only observable effect of the bound is that such a host can
        // never earn the exact-match bonus (its full name is skipped).
        let json = r#"{
          "schema_version": 1,
          "apps": [
            {"app_id":"acme","category":"test","sni_suffixes":["acme.example"],
             "host_suffixes":[],"ja3":[],"ports":[],"transport":"tcp",
             "byte_prefixes":[],"confidence":80}
          ]
        }"#;
        let cat = Catalog::from_json(json).expect("parse");
        let m = Matcher::from_catalog(&cat);

        // 20 leading labels (well beyond MAX_HOST_LABELS = 12) under the
        // catalog's 2-label suffix.
        let mut host = String::new();
        for i in 0..20 {
            let _ = write!(host, "l{i}.");
        }
        host.push_str("acme.example");
        assert!(
            host.matches('.').count() + 1 > MAX_HOST_LABELS,
            "fixture must exceed the label bound"
        );

        let out = m
            .identify(&ConnFeatures::from_sni(&host, 443))
            .expect("deeply nested host still matches the short suffix");
        assert_eq!(out.app_id, "acme");
        // Matched via the 2-label suffix, not the (skipped) full name, so
        // no exact bonus is applied: confidence stays at the base.
        assert_eq!(out.confidence, 80);
    }

    #[test]
    fn byte_probe_identifies_ssh() {
        let m = builtin();
        let out = m
            .identify(&ConnFeatures {
                first_bytes: Some(b"SSH-2.0-OpenSSH_9.6"),
                port: Some(22),
                transport: Some(Transport::Tcp),
                ..ConnFeatures::default()
            })
            .expect("ssh");
        assert_eq!(out.app_id, "protocol.ssh");
    }

    #[test]
    fn ja3_alone_is_weak_but_present() {
        let json = r#"{
          "schema_version": 1,
          "apps": [
            {"app_id":"acme","category":"test","sni_suffixes":["acme.com"],
             "host_suffixes":[],"ja3":["abc123"],"ports":[443],"transport":"tcp",
             "byte_prefixes":[],"confidence":90}
          ]
        }"#;
        let cat = Catalog::from_json(json).expect("parse");
        let m = Matcher::from_catalog(&cat);
        // JA3 only -> weak standalone confidence.
        let only = m
            .identify(&ConnFeatures {
                ja3: Some("abc123"),
                ..ConnFeatures::default()
            })
            .expect("ja3-only");
        assert_eq!(only.app_id, "acme");
        assert!(only.confidence <= 50, "ja3-only should be weak");
        // SNI + JA3 -> corroborated, stronger than SNI alone.
        let sni_only = m
            .identify(&ConnFeatures::from_sni("acme.com", 443))
            .expect("sni");
        let both = m
            .identify(&ConnFeatures {
                sni: Some("acme.com"),
                ja3: Some("abc123"),
                port: Some(443),
                transport: Some(Transport::Tcp),
                ..ConnFeatures::default()
            })
            .expect("both");
        assert!(both.confidence > sni_only.confidence);
    }

    #[test]
    fn deterministic_tie_break_by_app_id() {
        // Two apps share a suffix and confidence; the smaller app_id
        // must win, every time.
        let json = r#"{
          "schema_version": 1,
          "apps": [
            {"app_id":"zzz","category":"test","sni_suffixes":["shared.example"],
             "host_suffixes":[],"ja3":[],"ports":[],"transport":"tcp",
             "byte_prefixes":[],"confidence":70},
            {"app_id":"aaa","category":"test","sni_suffixes":["shared.example"],
             "host_suffixes":[],"ja3":[],"ports":[],"transport":"tcp",
             "byte_prefixes":[],"confidence":70}
          ]
        }"#;
        let cat = Catalog::from_json(json).expect("parse");
        let m = Matcher::from_catalog(&cat);
        for _ in 0..50 {
            let out = m
                .identify(&ConnFeatures::from_sni("shared.example", 443))
                .expect("match");
            assert_eq!(out.app_id, "aaa");
        }
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let json = r#"{"schema_version": 9999, "apps": []}"#;
        match Catalog::from_json(json) {
            Err(AppIdError::UnsupportedSchema(v)) => assert_eq!(v, 9999),
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_app_id() {
        let json = r#"{
          "schema_version": 1,
          "apps": [
            {"app_id":"dup","category":"a","sni_suffixes":["a.com"],"host_suffixes":[],
             "ja3":[],"ports":[],"transport":"tcp","byte_prefixes":[],"confidence":50},
            {"app_id":"dup","category":"b","sni_suffixes":["b.com"],"host_suffixes":[],
             "ja3":[],"ports":[],"transport":"tcp","byte_prefixes":[],"confidence":50}
          ]
        }"#;
        assert!(matches!(
            Catalog::from_json(json),
            Err(AppIdError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_entry_with_no_match_key() {
        let json = r#"{
          "schema_version": 1,
          "apps": [
            {"app_id":"weak","category":"a","sni_suffixes":[],"host_suffixes":[],
             "ja3":[],"ports":[443],"transport":"tcp","byte_prefixes":[],"confidence":50}
          ]
        }"#;
        assert!(matches!(
            Catalog::from_json(json),
            Err(AppIdError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_malformed_byte_probe() {
        let json = r#"{
          "schema_version": 1,
          "apps": [
            {"app_id":"x","category":"a","sni_suffixes":[],"host_suffixes":[],
             "ja3":[],"ports":[],"transport":"tcp","byte_prefixes":["zz"],"confidence":50}
          ]
        }"#;
        assert!(matches!(
            Catalog::from_json(json),
            Err(AppIdError::Invalid(_))
        ));
    }

    #[test]
    fn confidence_is_clamped() {
        let json = r#"{
          "schema_version": 1,
          "apps": [
            {"app_id":"x","category":"a","sni_suffixes":["x.com"],"host_suffixes":[],
             "ja3":[],"ports":[],"transport":"tcp","byte_prefixes":[],"confidence":250}
          ]
        }"#;
        let cat = Catalog::from_json(json).expect("parse");
        assert_eq!(cat.signatures()[0].confidence, 100);
    }

    #[test]
    fn host_normalisation_strips_wildcard_and_case() {
        assert_eq!(normalise_host("*.Example.COM."), "example.com");
        assert_eq!(normalise_host("  Foo.Bar  "), "foo.bar");
    }

    #[test]
    fn malformed_json_is_typed_error() {
        assert!(matches!(
            Catalog::from_json("{not json"),
            Err(AppIdError::Malformed(_))
        ));
    }

    /// Fuzz-style: the matcher must never panic and must always return
    /// a well-formed result (or `None`) on arbitrary, adversarial input
    /// — deeply nested names, huge strings, random bytes, weird ports.
    #[test]
    fn fuzz_never_panics_and_stays_bounded() {
        let m = builtin();
        // Deterministic xorshift PRNG so the test is reproducible.
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };

        for _ in 0..20_000 {
            let r = next();
            // Build a pathological host: many labels, random bytes.
            let label_count = (r % 40) as usize;
            let mut host = String::new();
            for _ in 0..label_count {
                let b = (next() % 26) as u8 + b'a';
                host.push(b as char);
                if next() % 3 == 0 {
                    host.push('.');
                }
            }
            // Occasionally make an absurdly long name.
            if r % 50 == 0 {
                host = "a.".repeat(2000);
            }
            let bytes: [u8; 8] = (next()).to_le_bytes();
            let feat = ConnFeatures {
                sni: Some(&host),
                host: Some(&host),
                ja3: Some("deadbeef"),
                first_bytes: Some(&bytes),
                port: Some((next() % 65536) as u16),
                transport: if r % 2 == 0 {
                    Some(Transport::Tcp)
                } else {
                    Some(Transport::Udp)
                },
            };
            if let Some(out) = m.identify(&feat) {
                assert!(out.confidence >= 1 && out.confidence <= 100);
                assert!(!out.app_id.is_empty());
            }
        }
    }

    #[test]
    fn empty_features_match_nothing() {
        let m = builtin();
        assert!(m.identify(&ConnFeatures::default()).is_none());
    }
}
