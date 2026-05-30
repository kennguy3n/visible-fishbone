//! Subject- and predicate-matcher language.
//!
//! The Go side stores subject / predicate match data as
//! `json.RawMessage` (`internal/service/policy/graph.go::Subject.Match`)
//! — intentionally untyped at the compiler so each enforcement
//! subsystem can ship its own matcher schema. This crate decodes
//! the JSON into a typed sum so the evaluation hot path can
//! dispatch by variant rather than re-parsing JSON per flow.
//!
//! Matchers are intentionally open-ended at the bottom: an
//! [`SubjectMatch::Unknown`] / [`PredicateMatch::Unknown`] variant
//! preserves any matcher shape this crate doesn't recognise so
//! the bundle still loads — the rule simply does not match
//! against the local engine (a "fail-closed for unrecognised"
//! posture). New matcher kinds added by future graph compilers
//! ship through here without a bundle-format-breaking change.
//!
//! Determining whether a matcher matches a concrete value is the
//! responsibility of [`SubjectMatch::matches_string`] /
//! [`SubjectMatch::matches_ip`] / [`PredicateMatch::matches_context`].

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Subject matcher payload. The JSON shape on the wire is a
/// tagged object — `{"kind":"literal","value":"alice"}`,
/// `{"kind":"any_of","values":["alice","bob"]}`, etc. — so a
/// future schema bump can add new variants without breaking
/// existing receivers.
///
/// Tag chosen to match what the compiler's documentation
/// promises for the matcher schema; receivers ahead of this
/// crate's schema knowledge fall through to
/// [`SubjectMatch::Unknown`] and the rule is treated as a
/// non-match (no implicit allow).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SubjectMatch {
    /// Wildcard — matches every value. Used by graph-level
    /// "everyone" subjects.
    Any,
    /// Exact, case-sensitive string match.
    Literal {
        /// The exact value to compare against.
        value: String,
    },
    /// Set membership — `value ∈ values`.
    AnyOf {
        /// The set of acceptable values.
        values: Vec<String>,
    },
    /// Domain wildcard — matches `value` (case-insensitive,
    /// dot-suffix). `*.example.com` matches `mail.example.com`
    /// but not `example.com` (the canonical RFC 6125 §6.4
    /// semantics). To match the apex domain include it
    /// explicitly via [`Self::Literal`] or [`Self::AnyOf`].
    DomainSuffix {
        /// The suffix value, with or without a leading `*.`.
        /// Both forms are normalised at load time.
        suffix: String,
    },
    /// IP-network membership — for `kind: network` subjects.
    /// Stored as a parsed [`IpNet`] so the hot path doesn't
    /// re-parse the textual CIDR.
    Cidr {
        /// The CIDR range.
        cidr: IpNet,
    },
    /// Forward-compatibility escape hatch — preserves the raw
    /// JSON for matcher shapes the local engine doesn't
    /// understand. Treated as non-matching at evaluation time so
    /// an out-of-band matcher cannot grant access; control-plane
    /// telemetry surfaces the unknown kind so operators see
    /// which rules are dark on which agents.
    #[serde(other)]
    Unknown,
}

impl Default for SubjectMatch {
    /// `Any` is the default — when a Subject vertex omits its
    /// matcher (`{"kind":"user","name":"all-users"}`), Go side
    /// treats it as "any value of this kind". Encoded here as
    /// `SubjectMatch::Any` so receivers preserve that semantic.
    fn default() -> Self {
        Self::Any
    }
}

impl SubjectMatch {
    /// Check whether this matcher accepts `value` as a string.
    /// Returns `false` for IP / CIDR matchers (callers should
    /// dispatch through [`Self::matches_ip`] instead) and for
    /// any matcher shape the local engine doesn't recognise.
    #[must_use]
    pub fn matches_string(&self, value: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Literal { value: lit } => lit == value,
            Self::AnyOf { values } => values.iter().any(|v| v == value),
            Self::DomainSuffix { suffix } => domain_suffix_match(suffix, value),
            Self::Cidr { .. } | Self::Unknown => false,
        }
    }

    /// Check whether this matcher accepts `addr` as an IP. Only
    /// [`Self::Cidr`] and [`Self::Any`] return `true`; literal /
    /// any-of / domain-suffix matchers are non-matching against
    /// IPs (use [`Self::matches_string`] for a textual
    /// representation if the operator really meant string-match
    /// the IP literal).
    #[must_use]
    pub fn matches_ip(&self, addr: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Cidr { cidr } => cidr.contains(&addr),
            Self::Literal { .. }
            | Self::AnyOf { .. }
            | Self::DomainSuffix { .. }
            | Self::Unknown => false,
        }
    }
}

/// Predicate matcher payload. Predicates are domain-specific
/// conditions on the flow (time-of-day, geo, URL category, etc.).
/// The set of variants here is intentionally small — the engine
/// only enforces ones it understands. Unknown predicate shapes
/// are preserved into [`Self::Unknown`] and treated as
/// non-matching (a rule guarded by an unrecognised predicate
/// will not fire), which is the safe default.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PredicateMatch {
    /// Always true. Lets a rule declare "no extra precondition".
    Always,
    /// Key-equals-value lookup against a free-form context map
    /// the caller supplies at evaluation time. The most common
    /// schema for the categorisation-style predicates the SWG
    /// and DNS subsystems consume.
    ContextEquals {
        /// The context key to look up.
        key: String,
        /// The exact value the context must hold.
        value: String,
    },
    /// Key-in-set membership.
    ContextIn {
        /// The context key.
        key: String,
        /// Accepted values.
        values: Vec<String>,
    },
    /// Forward-compat escape hatch.
    #[serde(other)]
    Unknown,
}

impl Default for PredicateMatch {
    /// Default predicate is `Always` — when a Predicate vertex
    /// has no `match` field, it is unconstrained.
    fn default() -> Self {
        Self::Always
    }
}

impl PredicateMatch {
    /// Check whether this predicate is satisfied for the
    /// supplied flow context.
    ///
    /// The context is a borrowed `&[(&str, &str)]` slice rather
    /// than a `HashMap` so callers can build it on the stack
    /// per flow with zero heap allocation.
    #[must_use]
    pub fn matches_context(&self, ctx: &[(&str, &str)]) -> bool {
        match self {
            Self::Always => true,
            Self::ContextEquals { key, value } => ctx
                .iter()
                .any(|(k, v)| k == &key.as_str() && v == &value.as_str()),
            Self::ContextIn { key, values } => ctx
                .iter()
                .any(|(k, v)| k == &key.as_str() && values.iter().any(|w| w == v)),
            Self::Unknown => false,
        }
    }
}

/// Implements the RFC 6125 §6.4 dot-suffix matcher used by the
/// `DomainSuffix` subject matcher. `*.example.com` matches
/// `mail.example.com` (a single label of arbitrary value) but
/// NOT `example.com` (the apex) and NOT `a.b.example.com`
/// (multi-label). `example.com` (no leading `*.`) is treated
/// the same way as `*.example.com` — both forms accept "one
/// label below example.com".
///
/// Case-insensitive (DNS is case-insensitive at the protocol
/// level). Empty suffix matches nothing — a graph that ships an
/// empty subject matcher is a control-plane bug and we should
/// not silently match every flow.
///
/// **Contrast with the steering table matcher.** `steering::domain_matches_suffix`
/// uses the steering compiler's `match_any` semantics where the
/// apex IS included (`host == suffix` returns `true`). Here we
/// follow RFC 6125 §6.4 — apex is rejected, only subdomains
/// match. The two are deliberately different and not interchangeable;
/// see the matching cross-reference comment in `steering.rs`.
fn domain_suffix_match(suffix: &str, value: &str) -> bool {
    let suffix = suffix.strip_prefix("*.").unwrap_or(suffix);
    if suffix.is_empty() || value.is_empty() {
        return false;
    }
    let value_lc = value.to_ascii_lowercase();
    let suffix_lc = suffix.to_ascii_lowercase();
    if value_lc == suffix_lc {
        // Reject the apex — wildcard subdomain semantics.
        return false;
    }
    let Some(prefix) = value_lc.strip_suffix(&suffix_lc) else {
        return false;
    };
    // Must end on a `.` separator, and the prefix before it must
    // be a single label (no further dots).
    let Some(label) = prefix.strip_suffix('.') else {
        return false;
    };
    !label.is_empty() && !label.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn subject_match_any_accepts_everything() {
        let m = SubjectMatch::Any;
        assert!(m.matches_string("alice"));
        assert!(m.matches_string(""));
        assert!(m.matches_ip("127.0.0.1".parse().unwrap()));
        assert!(m.matches_ip("::1".parse().unwrap()));
    }

    #[test]
    fn subject_match_literal_is_case_sensitive() {
        let m = SubjectMatch::Literal {
            value: "alice".into(),
        };
        assert!(m.matches_string("alice"));
        assert!(!m.matches_string("Alice"));
        assert!(!m.matches_string("alic"));
        assert!(!m.matches_string("alicee"));
    }

    #[test]
    fn subject_match_any_of_matches_set_members() {
        let m = SubjectMatch::AnyOf {
            values: vec!["alice".into(), "bob".into()],
        };
        assert!(m.matches_string("alice"));
        assert!(m.matches_string("bob"));
        assert!(!m.matches_string("carol"));
    }

    #[test]
    fn subject_match_domain_suffix_matches_single_subdomain_label() {
        let m = SubjectMatch::DomainSuffix {
            suffix: "example.com".into(),
        };
        assert!(m.matches_string("mail.example.com"));
        assert!(m.matches_string("MAIL.Example.COM"));
        assert!(!m.matches_string("example.com"), "apex must not match");
        assert!(
            !m.matches_string("a.b.example.com"),
            "two labels must not match"
        );
        assert!(!m.matches_string("notexample.com"));
        assert!(!m.matches_string("example.org"));
        assert!(!m.matches_string(""));
    }

    #[test]
    fn subject_match_domain_suffix_accepts_leading_star_dot_form() {
        let m = SubjectMatch::DomainSuffix {
            suffix: "*.example.com".into(),
        };
        assert!(m.matches_string("mail.example.com"));
        assert!(!m.matches_string("example.com"));
    }

    #[test]
    fn subject_match_domain_suffix_rejects_empty_suffix() {
        let m = SubjectMatch::DomainSuffix {
            suffix: String::new(),
        };
        assert!(!m.matches_string("anything.test"));
    }

    #[test]
    fn subject_match_cidr_matches_ip_in_range() {
        let m = SubjectMatch::Cidr {
            cidr: "10.0.0.0/8".parse().unwrap(),
        };
        assert!(m.matches_ip("10.1.2.3".parse().unwrap()));
        assert!(!m.matches_ip("192.168.1.1".parse().unwrap()));
        assert!(!m.matches_string("10.1.2.3"));
    }

    #[test]
    fn subject_match_unknown_never_matches() {
        let json = r#"{"kind":"future_kind","detail":"…"}"#;
        let m: SubjectMatch = serde_json::from_str(json).unwrap();
        assert_eq!(m, SubjectMatch::Unknown);
        assert!(!m.matches_string("anything"));
        assert!(!m.matches_ip("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn predicate_match_always_is_satisfied_by_empty_context() {
        let p = PredicateMatch::Always;
        assert!(p.matches_context(&[]));
    }

    #[test]
    fn predicate_match_context_equals_compares_exact_values() {
        let p = PredicateMatch::ContextEquals {
            key: "category".into(),
            value: "malware".into(),
        };
        assert!(p.matches_context(&[("category", "malware")]));
        assert!(!p.matches_context(&[("category", "social")]));
        assert!(!p.matches_context(&[("kind", "malware")]));
        assert!(!p.matches_context(&[]));
    }

    #[test]
    fn predicate_match_context_in_matches_set_members() {
        let p = PredicateMatch::ContextIn {
            key: "geo".into(),
            values: vec!["US".into(), "CA".into()],
        };
        assert!(p.matches_context(&[("geo", "US")]));
        assert!(p.matches_context(&[("geo", "CA")]));
        assert!(!p.matches_context(&[("geo", "RU")]));
    }

    #[test]
    fn predicate_match_unknown_never_satisfies() {
        let json = r#"{"kind":"time_of_day","range":"weekday"}"#;
        let p: PredicateMatch = serde_json::from_str(json).unwrap();
        assert_eq!(p, PredicateMatch::Unknown);
        assert!(!p.matches_context(&[]));
        assert!(!p.matches_context(&[("any", "thing")]));
    }

    #[test]
    fn subject_match_default_is_any() {
        let m = SubjectMatch::default();
        assert_eq!(m, SubjectMatch::Any);
    }

    #[test]
    fn predicate_match_default_is_always() {
        let p = PredicateMatch::default();
        assert_eq!(p, PredicateMatch::Always);
    }

    #[test]
    fn subject_match_roundtrips_through_json() {
        for m in [
            SubjectMatch::Any,
            SubjectMatch::Literal {
                value: "alice".into(),
            },
            SubjectMatch::AnyOf {
                values: vec!["a".into(), "b".into()],
            },
            SubjectMatch::DomainSuffix {
                suffix: "example.com".into(),
            },
            SubjectMatch::Cidr {
                cidr: "10.0.0.0/8".parse().unwrap(),
            },
        ] {
            let encoded = serde_json::to_string(&m).unwrap();
            let decoded: SubjectMatch = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, m);
        }
    }

    #[test]
    fn predicate_match_roundtrips_through_json() {
        for p in [
            PredicateMatch::Always,
            PredicateMatch::ContextEquals {
                key: "k".into(),
                value: "v".into(),
            },
            PredicateMatch::ContextIn {
                key: "k".into(),
                values: vec!["a".into(), "b".into()],
            },
        ] {
            let encoded = serde_json::to_string(&p).unwrap();
            let decoded: PredicateMatch = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, p);
        }
    }

    #[test]
    fn domain_suffix_match_rejects_label_with_internal_dot() {
        // A leading `.` in the label position (before the
        // suffix) should not let `a.b.example.com` slip through
        // by claiming the label is `a.b`. The single-label
        // requirement excludes any dots in the label slot.
        assert!(!domain_suffix_match(
            "example.com",
            "two.labels.example.com"
        ));
    }
}
