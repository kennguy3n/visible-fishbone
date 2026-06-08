//! TLS decrypt-versus-bypass decision engine.
//!
//! When a flow is identified as TLS (via [`crate::l7::AppIdentifier`])
//! and the L4 rule selects [`crate::rule::RuleAction::Inspect`], the SWG /
//! IPS asks this module whether to MITM the flow and decrypt
//! the inner stream, or to bypass it (forward the flow opaquely
//! and only record metadata).
//!
//! The decision is driven by three lists, evaluated in order:
//!
//! 1. **Operator deny list** — `decrypt_denylist` — operators
//!    add domain suffixes here when they want a flow to *always*
//!    bypass (a regulatory carve-out, an internal exception).
//!    Highest priority.
//! 2. **Industry default bypass list** — embedded at compile
//!    time, covers the three categories with strong legal /
//!    professional norms against MITM: regulated finance, health
//!    portals, government tax / authentication portals. This
//!    list is sourced from public industry recommendations
//!    (Mozilla's "Avoid TLS Interception" guidance, CIS Controls
//!    v8 §13). It can be disabled per-policy when the operator
//!    has equivalent in-tenant controls.
//! 3. **Allow list** — `decrypt_allowlist` — domain suffixes
//!    the operator has expressly opted into decrypting. Used to
//!    re-enable inspection for a vendor that would otherwise hit
//!    the industry default list (e.g. a company-managed Google
//!    Workspace tenant).
//!
//! The first hit wins. If no list matches, the default policy
//! (`default_action`) decides — typically `Decrypt` when the
//! tenant has consented to full inspection, or `Bypass` for the
//! conservative profile.
//!
//! No live network I/O happens in this module — the decision
//! engine consumes the SNI as already extracted by
//! [`crate::l7::SniExtractor`] and returns a structured
//! [`TlsDecision`] enum. The MITM machinery itself (certificate
//! issuance, tunnel wiring) lives in `sng-swg`; this module is
//! the policy authority.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::error::FirewallError;

/// The decision: decrypt (MITM) or bypass (forward opaquely).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsDecision {
    /// Intercept and decrypt the flow.
    #[default]
    Decrypt,
    /// Forward opaquely. Record metadata only.
    Bypass,
}

/// Reason a flow was bypassed — recorded on every bypass
/// decision so the operator can audit "why is this flow not
/// being inspected?" via the telemetry stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TlsBypassReason {
    /// The SNI matched the operator's explicit deny list.
    OperatorDenylist {
        /// The suffix that matched.
        suffix: String,
    },
    /// The SNI matched a category in the industry default list.
    IndustryDefault {
        /// The category — `finance`, `healthcare`, `government`.
        category: String,
        /// The suffix that matched.
        suffix: String,
    },
    /// The flow's SNI was missing or malformed and the policy
    /// is configured to bypass un-classifiable flows. Operators
    /// who prefer the strict profile (drop on missing SNI) can
    /// configure `missing_sni_policy = "drop"` and this variant
    /// will never appear in telemetry.
    MissingSni,
    /// The default policy bypassed the flow.
    DefaultPolicy,
}

/// Why a flow was selected for decryption — included in the
/// audit event so a security analyst can trace "this flow was
/// decrypted because…".
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TlsDecryptReason {
    /// The SNI matched the operator's explicit allow list.
    OperatorAllowlist {
        /// The suffix that matched.
        suffix: String,
    },
    /// The default policy chose to decrypt.
    DefaultPolicy,
}

/// The structured result returned by [`TlsPolicy::decide`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum TlsVerdict {
    /// Decrypt the flow.
    Decrypt {
        /// Why the engine selected `Decrypt`.
        reason: TlsDecryptReason,
    },
    /// Forward opaquely.
    Bypass {
        /// Why the engine selected `Bypass`.
        reason: TlsBypassReason,
    },
}

impl TlsVerdict {
    /// Strip the reason and return only the bare decision.
    #[must_use]
    pub fn decision(&self) -> TlsDecision {
        match self {
            Self::Decrypt { .. } => TlsDecision::Decrypt,
            Self::Bypass { .. } => TlsDecision::Bypass,
        }
    }
}

/// How to treat a TLS flow whose SNI we couldn't extract.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MissingSniPolicy {
    /// Conservative: forward opaquely. Most operators want this.
    #[default]
    Bypass,
    /// Strict: drop the flow. Used when the operator's profile
    /// forbids any opaque traffic.
    Drop,
}

/// Operator-facing configuration for the policy engine.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsPolicyConfig {
    /// Default action when no list matches.
    #[serde(default = "default_action_default")]
    pub default_action: TlsDecision,
    /// SNI suffixes the operator never wants decrypted.
    /// Suffixes may begin with `*.`; both forms accept the apex.
    #[serde(default)]
    pub decrypt_denylist: Vec<String>,
    /// SNI suffixes the operator wants decrypted *even if* they
    /// would otherwise hit the industry default list.
    #[serde(default)]
    pub decrypt_allowlist: Vec<String>,
    /// Whether the industry default list is consulted. Defaults
    /// to `true`; can be disabled for tenants who have their own
    /// in-policy carve-outs.
    #[serde(default = "default_industry_enabled")]
    pub enable_industry_defaults: bool,
    /// Treatment of TLS flows with no extractable SNI.
    #[serde(default)]
    pub missing_sni_policy: MissingSniPolicy,
}

impl Default for TlsPolicyConfig {
    /// Default policy: decrypt unless the SNI hits the industry
    /// default list or operator denylist. Mirrors the
    /// `#[serde(default = ...)]` attributes above so a
    /// hand-built [`TlsPolicyConfig`] behaves the same as one
    /// decoded from an empty JSON object.
    fn default() -> Self {
        Self {
            default_action: default_action_default(),
            decrypt_denylist: Vec::new(),
            decrypt_allowlist: Vec::new(),
            enable_industry_defaults: default_industry_enabled(),
            missing_sni_policy: MissingSniPolicy::default(),
        }
    }
}

const fn default_action_default() -> TlsDecision {
    TlsDecision::Decrypt
}

const fn default_industry_enabled() -> bool {
    true
}

/// Compiled, ready-to-evaluate policy. Constructed via
/// [`TlsPolicy::compile`].
#[derive(Clone, Debug)]
pub struct TlsPolicy {
    default_action: TlsDecision,
    decrypt_denylist: BTreeSet<String>,
    decrypt_allowlist: BTreeSet<String>,
    enable_industry_defaults: bool,
    missing_sni_policy: MissingSniPolicy,
}

impl TlsPolicy {
    /// Default policy: decrypt everything that doesn't hit the
    /// industry list. Used by tests and as the "bootstrap"
    /// policy before the first bundle arrives.
    #[must_use]
    pub fn default_policy() -> Self {
        // The default `TlsPolicyConfig` carries empty deny/allow
        // lists, so `compile` cannot fail — the only fallible
        // step is `normalize_suffixes`, which only rejects
        // user-supplied strings. We still match exhaustively
        // here instead of `expect()` so a future addition to
        // the default config that introduces a fallible
        // validation surfaces as a debug-time panic with a
        // typed cause.
        match Self::compile(&TlsPolicyConfig::default()) {
            Ok(p) => p,
            Err(e) => {
                // Unreachable today — defensive against future
                // changes to the default config.
                debug_assert!(false, "default TLS policy must always compile: {e}");
                Self {
                    default_action: TlsDecision::Decrypt,
                    decrypt_denylist: BTreeSet::new(),
                    decrypt_allowlist: BTreeSet::new(),
                    enable_industry_defaults: true,
                    missing_sni_policy: MissingSniPolicy::default(),
                }
            }
        }
    }

    /// Compile a config into an evaluator. Validates every
    /// suffix and lowercases them.
    pub fn compile(cfg: &TlsPolicyConfig) -> Result<Self, FirewallError> {
        let denylist = normalize_suffixes(&cfg.decrypt_denylist)?;
        let allowlist = normalize_suffixes(&cfg.decrypt_allowlist)?;
        Ok(Self {
            default_action: cfg.default_action,
            decrypt_denylist: denylist,
            decrypt_allowlist: allowlist,
            enable_industry_defaults: cfg.enable_industry_defaults,
            missing_sni_policy: cfg.missing_sni_policy,
        })
    }

    /// What this policy does when SNI is missing or malformed.
    /// The TLS engine here always returns
    /// [`TlsVerdict::Bypass`] with reason
    /// [`TlsBypassReason::MissingSni`]; the firewall consults
    /// this knob to decide whether to *drop* the flow at the
    /// chain level instead of allowing a TLS bypass.
    #[must_use]
    pub const fn missing_sni_policy(&self) -> MissingSniPolicy {
        self.missing_sni_policy
    }

    /// Decide a verdict for a flow. `sni` is the extracted SNI
    /// host (lowercase); `None` means SNI was missing or
    /// malformed.
    #[must_use]
    pub fn decide(&self, sni: Option<&str>) -> TlsVerdict {
        let Some(sni) = sni else {
            // Both `Bypass` and `Drop` produce the same
            // `TlsVerdict::Bypass { MissingSni }` so the SWG
            // gets a consistent signal. The actual drop is
            // enforced upstream in the firewall engine when the
            // operator picks `MissingSniPolicy::Drop` — the
            // policy module just records the bypass reason here.
            return TlsVerdict::Bypass {
                reason: TlsBypassReason::MissingSni,
            };
        };
        // 1. Operator deny list wins.
        if let Some(suffix) = match_any_suffix(&self.decrypt_denylist, sni) {
            return TlsVerdict::Bypass {
                reason: TlsBypassReason::OperatorDenylist { suffix },
            };
        }
        // 2. Industry defaults (skippable per policy).
        if self.enable_industry_defaults
            && let Some((category, suffix)) = match_industry_list(sni)
        {
            // 3. Operator allow list overrides the industry default.
            if let Some(allow_suffix) = match_any_suffix(&self.decrypt_allowlist, sni) {
                return TlsVerdict::Decrypt {
                    reason: TlsDecryptReason::OperatorAllowlist {
                        suffix: allow_suffix,
                    },
                };
            }
            return TlsVerdict::Bypass {
                reason: TlsBypassReason::IndustryDefault {
                    category: category.into(),
                    suffix: suffix.into(),
                },
            };
        }
        // 4. Operator allow list — explicit decrypt-this opt-in.
        if let Some(suffix) = match_any_suffix(&self.decrypt_allowlist, sni) {
            return TlsVerdict::Decrypt {
                reason: TlsDecryptReason::OperatorAllowlist { suffix },
            };
        }
        // 5. Fall back to the configured default.
        match self.default_action {
            TlsDecision::Decrypt => TlsVerdict::Decrypt {
                reason: TlsDecryptReason::DefaultPolicy,
            },
            TlsDecision::Bypass => TlsVerdict::Bypass {
                reason: TlsBypassReason::DefaultPolicy,
            },
        }
    }
}

fn normalize_suffixes(input: &[String]) -> Result<BTreeSet<String>, FirewallError> {
    let mut out = BTreeSet::new();
    for s in input {
        let stripped = s.strip_prefix("*.").unwrap_or(s);
        let lower = stripped.to_ascii_lowercase();
        if lower.is_empty() {
            return Err(FirewallError::RuleInvalid(
                "tls policy suffix must not be empty".into(),
            ));
        }
        if !lower.chars().all(valid_dns_char) {
            return Err(FirewallError::RuleInvalid(format!(
                "tls policy suffix '{lower}' contains invalid characters"
            )));
        }
        out.insert(lower);
    }
    Ok(out)
}

fn valid_dns_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
}

fn match_any_suffix(suffixes: &BTreeSet<String>, sni: &str) -> Option<String> {
    let sni = sni.to_ascii_lowercase();
    for s in suffixes {
        if sni == *s {
            return Some(s.clone());
        }
        if let Some(prefix) = sni.strip_suffix(s.as_str())
            && prefix.ends_with('.')
        {
            return Some(s.clone());
        }
    }
    None
}

/// Industry default bypass list.
///
/// Sourced from public guidance:
///
/// * Mozilla's "TLS interception is dangerous"
///   recommendation against MITM of regulated finance and
///   healthcare portals.
/// * CIS Controls v8 §13 "Network Monitoring and Defense"
///   carve-outs for legally-protected categories.
/// * Public lists of US tax / authentication portals (IRS,
///   login.gov) and major government ID portals.
///
/// The list is intentionally conservative — it covers the
/// well-known cases where MITM would be inappropriate.
/// Operators with broader or narrower needs should use the
/// `decrypt_denylist` / `decrypt_allowlist` knobs.
fn industry_default_list() -> &'static [(&'static str, &'static [&'static str])] {
    const LIST: &[(&str, &[&str])] = &[
        (
            "finance",
            &[
                "chase.com",
                "bankofamerica.com",
                "wellsfargo.com",
                "citi.com",
                "capitalone.com",
                "usbank.com",
                "barclays.co.uk",
                "hsbc.com",
                "santander.com",
                "fidelity.com",
                "schwab.com",
                "vanguard.com",
                "etrade.com",
                "ameritrade.com",
                "paypal.com",
                "stripe.com",
                "square.com",
                "venmo.com",
            ],
        ),
        (
            "healthcare",
            &[
                "myuhc.com",
                "cigna.com",
                "aetna.com",
                "anthem.com",
                "kp.org",
                "humana.com",
                "mayoclinic.org",
                "clevelandclinic.org",
                "epic.com",
                "epiccare.com",
                "mychart.com",
                "drchrono.com",
                "athenahealth.com",
                "nih.gov",
            ],
        ),
        (
            "government",
            &[
                "irs.gov",
                "login.gov",
                "ssa.gov",
                "usa.gov",
                "uscis.gov",
                "state.gov",
                "treasury.gov",
                "dhs.gov",
                "gov.uk",
                "service.gov.uk",
                "canada.ca",
                "australia.gov.au",
                "europa.eu",
            ],
        ),
    ];
    LIST
}

fn match_industry_list(sni: &str) -> Option<(&'static str, &'static str)> {
    let sni = sni.to_ascii_lowercase();
    for (category, suffixes) in industry_default_list() {
        for suffix in *suffixes {
            if sni == *suffix {
                return Some((category, suffix));
            }
            if let Some(prefix) = sni.strip_suffix(*suffix)
                && prefix.ends_with('.')
            {
                return Some((category, suffix));
            }
        }
    }
    None
}

/// Public read-only view of the industry default list — used by
/// audit / docs / the SWG admin UI.
#[must_use]
pub fn industry_default_categories() -> Vec<(&'static str, Vec<&'static str>)> {
    industry_default_list()
        .iter()
        .map(|(cat, list)| (*cat, list.to_vec()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn cfg(default: TlsDecision) -> TlsPolicyConfig {
        TlsPolicyConfig {
            default_action: default,
            decrypt_denylist: vec![],
            decrypt_allowlist: vec![],
            enable_industry_defaults: true,
            missing_sni_policy: MissingSniPolicy::Bypass,
        }
    }

    #[test]
    fn default_policy_decrypts_by_default() {
        let p = TlsPolicy::default_policy();
        let v = p.decide(Some("anywhere.example.com"));
        assert_eq!(v.decision(), TlsDecision::Decrypt);
    }

    #[test]
    fn industry_finance_domains_are_bypassed_by_default() {
        let p = TlsPolicy::default_policy();
        // Apex matches.
        let v = p.decide(Some("chase.com"));
        assert!(matches!(
            v,
            TlsVerdict::Bypass {
                reason: TlsBypassReason::IndustryDefault { ref category, .. }
            } if category == "finance"
        ));
        // Subdomain matches via suffix.
        let v = p.decide(Some("login.bankofamerica.com"));
        assert!(matches!(
            v,
            TlsVerdict::Bypass {
                reason: TlsBypassReason::IndustryDefault { ref category, .. }
            } if category == "finance"
        ));
    }

    #[test]
    fn industry_healthcare_domains_are_bypassed_by_default() {
        let p = TlsPolicy::default_policy();
        let v = p.decide(Some("portal.myuhc.com"));
        assert!(matches!(
            v,
            TlsVerdict::Bypass {
                reason: TlsBypassReason::IndustryDefault { ref category, .. }
            } if category == "healthcare"
        ));
    }

    #[test]
    fn industry_government_domains_are_bypassed_by_default() {
        let p = TlsPolicy::default_policy();
        let v = p.decide(Some("www.irs.gov"));
        assert!(matches!(
            v,
            TlsVerdict::Bypass {
                reason: TlsBypassReason::IndustryDefault { ref category, .. }
            } if category == "government"
        ));
    }

    #[test]
    fn operator_denylist_wins_over_default_decrypt() {
        let mut c = cfg(TlsDecision::Decrypt);
        c.decrypt_denylist.push("*.partner.example".into());
        let p = TlsPolicy::compile(&c).unwrap();
        let v = p.decide(Some("api.partner.example"));
        assert!(matches!(
            v,
            TlsVerdict::Bypass {
                reason: TlsBypassReason::OperatorDenylist { ref suffix }
            } if suffix == "partner.example"
        ));
    }

    #[test]
    fn operator_denylist_does_not_match_unrelated_apex() {
        let mut c = cfg(TlsDecision::Decrypt);
        c.decrypt_denylist.push("*.partner.example".into());
        let p = TlsPolicy::compile(&c).unwrap();
        // Apex matches a stripped *.partner.example entry.
        let v = p.decide(Some("partner.example"));
        assert!(matches!(v, TlsVerdict::Bypass { .. }));
        // Unrelated host stays on default policy.
        let v = p.decide(Some("other.example"));
        assert_eq!(v.decision(), TlsDecision::Decrypt);
    }

    #[test]
    fn operator_allowlist_overrides_industry_default() {
        let mut c = cfg(TlsDecision::Decrypt);
        // Tenant manages its own Google Workspace and wants to
        // decrypt mychart.com despite the industry default.
        c.decrypt_allowlist.push("mychart.com".into());
        let p = TlsPolicy::compile(&c).unwrap();
        let v = p.decide(Some("portal.mychart.com"));
        assert!(matches!(
            v,
            TlsVerdict::Decrypt {
                reason: TlsDecryptReason::OperatorAllowlist { ref suffix }
            } if suffix == "mychart.com"
        ));
    }

    #[test]
    fn enable_industry_defaults_false_skips_list() {
        let mut c = cfg(TlsDecision::Decrypt);
        c.enable_industry_defaults = false;
        let p = TlsPolicy::compile(&c).unwrap();
        // Would have hit finance category — but the list is off.
        let v = p.decide(Some("chase.com"));
        assert_eq!(v.decision(), TlsDecision::Decrypt);
    }

    #[test]
    fn missing_sni_with_bypass_policy_returns_bypass() {
        let p = TlsPolicy::default_policy();
        let v = p.decide(None);
        assert!(matches!(
            v,
            TlsVerdict::Bypass {
                reason: TlsBypassReason::MissingSni
            }
        ));
    }

    #[test]
    fn missing_sni_with_drop_policy_still_returns_bypass_tagged_missing() {
        let mut c = cfg(TlsDecision::Decrypt);
        c.missing_sni_policy = MissingSniPolicy::Drop;
        let p = TlsPolicy::compile(&c).unwrap();
        let v = p.decide(None);
        // Engine still reports Bypass (the rule engine will drop
        // upstream); the reason is the missing SNI so audit can
        // distinguish.
        assert!(matches!(
            v,
            TlsVerdict::Bypass {
                reason: TlsBypassReason::MissingSni
            }
        ));
    }

    #[test]
    fn empty_suffix_in_config_is_rejected() {
        let mut c = cfg(TlsDecision::Decrypt);
        c.decrypt_denylist.push(String::new());
        let e = TlsPolicy::compile(&c).unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn invalid_chars_in_suffix_are_rejected() {
        let mut c = cfg(TlsDecision::Decrypt);
        c.decrypt_denylist.push("bad domain.com".into());
        let e = TlsPolicy::compile(&c).unwrap_err();
        assert!(matches!(e, FirewallError::RuleInvalid(_)));
    }

    #[test]
    fn star_prefix_is_stripped_during_compile() {
        let mut c = cfg(TlsDecision::Decrypt);
        c.decrypt_denylist.push("*.example.org".into());
        let p = TlsPolicy::compile(&c).unwrap();
        // Both apex and subdomain match.
        assert_eq!(
            p.decide(Some("example.org")).decision(),
            TlsDecision::Bypass
        );
        assert_eq!(
            p.decide(Some("api.example.org")).decision(),
            TlsDecision::Bypass
        );
    }

    #[test]
    fn industry_categories_view_returns_all_categories() {
        let cats = industry_default_categories();
        let names: Vec<&str> = cats.iter().map(|(c, _)| *c).collect();
        assert!(names.contains(&"finance"));
        assert!(names.contains(&"healthcare"));
        assert!(names.contains(&"government"));
        for (_, list) in cats {
            assert!(!list.is_empty(), "category list must not be empty");
        }
    }

    #[test]
    fn default_decision_when_no_list_matches_uses_configured_default() {
        let mut c = cfg(TlsDecision::Bypass);
        c.enable_industry_defaults = false;
        let p = TlsPolicy::compile(&c).unwrap();
        let v = p.decide(Some("example.com"));
        assert!(matches!(
            v,
            TlsVerdict::Bypass {
                reason: TlsBypassReason::DefaultPolicy
            }
        ));
    }
}
