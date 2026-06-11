//! ZTNA policy + evaluator.
//!
//! The brain joins three signals — identity (groups +
//! MFA freshness), device (enrolment + posture
//! freshness), and the per-app catalog (required groups,
//! minimum posture) — into a single
//! [`ZtnaDecision`].
//!
//! Two crisp invariants hold:
//!
//! 1. **Deny-by-default.** Any signal that cannot be
//!    confirmed — unknown app, unenrolled device, missing
//!    identity record, stale MFA, stale posture — is a
//!    deny. The orchestrator never allows on a missing
//!    signal.
//! 2. **Reason is structured.** The decision carries a
//!    [`ZtnaDecisionReason`] that maps onto a stable wire
//!    string ([`ZtnaDecisionReason::as_str`]), so
//!    dashboards bucket denies by cause without parsing a
//!    free-form message.
//!
//! Reload semantics mirror the SWG brain
//! ([`crate::ZtnaPolicyHolder::replace`]): the holder
//! wraps the active [`ZtnaPolicy`] in `arc_swap::ArcSwap`
//! so the data path reads without taking a lock and the
//! bundle adapter swaps whole policies atomically.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::app::App;
use crate::device::{DevicePosture, DeviceTrust};
use crate::error::ZtnaError;
use crate::identity::UserIdentity;
use crate::request::NetworkType;

/// Minimum device-posture requirement an app may declare.
///
/// The primary axis is a numeric floor on
/// [`DevicePosture::risk_score`] (0–100). This replaced the
/// prior three-bucket `None` / `Basic` / `Strict` enum:
/// operators can set a threshold at any granularity (e.g.
/// "this app needs a 75") instead of being pinned to three
/// points. The old buckets survive as the [`Self::NONE`],
/// [`Self::BASIC`], and [`Self::STRICT`] sugar constants
/// (mapping to scores 0 / 60 / 90) so existing catalog
/// entries keep a readable spelling.
///
/// Alongside the score floor an app may declare **hard
/// gates** on the expanded posture signals that the
/// weighted score deliberately leaves out (see
/// [`DevicePosture::risk_score`]):
///
/// * [`Self::require_edr`] — the device's EDR sensor must
///   be healthy.
/// * [`Self::min_patch_days`] — the OS must have been
///   patched within this many days.
/// * [`Self::max_av_definition_age_hours`] — antivirus must
///   be enabled and its definitions no older than this.
///
/// Each gate is independent of the score: a device can have
/// a 100 score and still be denied because its EDR sensor
/// was killed or its AV definitions went stale. Gates are
/// `Option` (and `false` for the bool) so an app that does
/// not opt in keeps the pre-expansion behaviour.
///
/// `Ord` orders requirements **least-to-most strict**,
/// matching the old enum's ordering contract. Because the
/// hard gates are independent, strictness is genuinely a
/// *partial* order (e.g. "require EDR" and "patch within 7
/// days" are incomparable); the [`Ord`] impl is a fixed
/// *linear extension* of it — primary key `min_score`, then
/// `require_edr` (`false` < `true`), then the two
/// `Option<u32>` caps where **no gain (`None`) is loosest
/// and a smaller cap is stricter** (so `None` <
/// `Some(30)` < `Some(7)`). Whenever one requirement
/// strictly dominates another on every axis it compares
/// greater, and the order is total and consistent with
/// `Eq`, so it is safe as a `BTreeMap`/`BTreeSet` key or
/// for picking the strictest of a set via `max`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PostureRequirement {
    /// Minimum [`DevicePosture::risk_score`] (0–100) the
    /// device must reach to satisfy this requirement.
    pub min_score: u8,
    /// When `true`, the device's EDR sensor must report
    /// healthy ([`DevicePosture::edr_healthy`]). A killed or
    /// non-reporting sensor fails the requirement regardless
    /// of score.
    #[serde(default)]
    pub require_edr: bool,
    /// Maximum number of days since the most recent OS patch
    /// the device may report and still satisfy this
    /// requirement — i.e. the device must have patched
    /// within the last `min_patch_days` days
    /// ([`DevicePosture::os_patch_days_since`] `<=`
    /// `min_patch_days`). `None` imposes no patch-recency
    /// gate. Named for the *minimum patch cadence* the
    /// tenant requires.
    #[serde(default)]
    pub min_patch_days: Option<u32>,
    /// Maximum age, in hours, of the antivirus signature
    /// definitions. When set, the device must additionally
    /// have antivirus enabled
    /// ([`DevicePosture::antivirus_enabled`]) and its
    /// definitions no older than this
    /// ([`DevicePosture::antivirus_definitions_age_hours`]
    /// `<=` this). `None` imposes no AV-freshness gate.
    #[serde(default)]
    pub max_av_definition_age_hours: Option<u32>,
}

impl PostureRequirement {
    /// Total-order key that linearises the (partial)
    /// strictness order, ascending = looser → stricter, and
    /// is injective over the field set so the resulting
    /// [`Ord`] stays consistent with the derived [`Eq`].
    ///
    /// For an `Option<u32>` cap a *smaller* value is stricter
    /// and `None` (no gate) is the loosest of all, so each
    /// maps to a `(has_gate, descending-cap)` pair: `None` →
    /// `(0, 0)` sorts below every `Some`, and `Some(c)` →
    /// `(1, u32::MAX - c)` sorts larger caps (looser) before
    /// smaller caps (stricter).
    fn strictness_key(self) -> (u8, bool, (u8, u32), (u8, u32)) {
        const fn cap_key(cap: Option<u32>) -> (u8, u32) {
            match cap {
                None => (0, 0),
                Some(c) => (1, u32::MAX - c),
            }
        }
        (
            self.min_score,
            self.require_edr,
            cap_key(self.min_patch_days),
            cap_key(self.max_av_definition_age_hours),
        )
    }

    /// No posture floor (score 0) and no hard gates. Every
    /// device — even a fully un-attested one — satisfies it.
    /// The spelling the catalog uses for low-risk apps open
    /// to any authenticated user.
    pub const NONE: Self = Self::new(0);
    /// Basic posture floor (score 60). Roughly "disk
    /// encryption + OS patched plus one more signal" under
    /// the [`DevicePosture::risk_score`] weights — the
    /// floor for most internal-tooling apps.
    pub const BASIC: Self = Self::new(60);
    /// Strict posture floor (score 90). Requires nearly
    /// every posture signal on; the spelling for
    /// high-sensitivity apps.
    pub const STRICT: Self = Self::new(90);

    /// Construct a requirement with an explicit score
    /// floor and no hard gates. Scores above 100 are clamped
    /// to 100 (the maximum [`DevicePosture::risk_score`] can
    /// return), so an out-of-range bundle value can never
    /// make the requirement permanently unsatisfiable.
    #[must_use]
    pub const fn new(min_score: u8) -> Self {
        Self {
            min_score: if min_score > 100 { 100 } else { min_score },
            require_edr: false,
            min_patch_days: None,
            max_av_definition_age_hours: None,
        }
    }

    /// Builder: require a healthy EDR sensor.
    #[must_use]
    pub const fn with_require_edr(mut self, require: bool) -> Self {
        self.require_edr = require;
        self
    }

    /// Builder: require the OS to have been patched within
    /// `days` days.
    #[must_use]
    pub const fn with_min_patch_days(mut self, days: u32) -> Self {
        self.min_patch_days = Some(days);
        self
    }

    /// Builder: require antivirus enabled with definitions
    /// no older than `hours`.
    #[must_use]
    pub const fn with_max_av_definition_age_hours(mut self, hours: u32) -> Self {
        self.max_av_definition_age_hours = Some(hours);
        self
    }

    /// True iff `posture` meets this requirement: its
    /// [`DevicePosture::risk_score`] is at least
    /// [`Self::min_score`] **and** every declared hard gate
    /// (EDR / patch recency / AV freshness) is satisfied.
    #[must_use]
    pub const fn satisfied_by(self, posture: &DevicePosture) -> bool {
        if posture.risk_score() < self.min_score {
            return false;
        }
        if self.require_edr && !posture.edr_healthy {
            return false;
        }
        if let Some(max_days) = self.min_patch_days
            && posture.os_patch_days_since > max_days
        {
            return false;
        }
        if let Some(max_age) = self.max_av_definition_age_hours
            && (!posture.antivirus_enabled || posture.antivirus_definitions_age_hours > max_age)
        {
            return false;
        }
        true
    }
}

/// Orders requirements least-to-most strict via
/// [`PostureRequirement::strictness_key`] (a linear
/// extension of the partial strictness order). Manual rather
/// than derived so the `Option<u32>` gate caps order by
/// *strictness* (smaller cap = stricter) instead of by raw
/// numeric value, while staying consistent with the derived
/// `Eq`.
impl Ord for PostureRequirement {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.strictness_key().cmp(&other.strictness_key())
    }
}

impl PartialOrd for PostureRequirement {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Operator over a single tag in a tag map.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TagOp {
    /// The tag exists and its value equals
    /// [`TagCondition::value`].
    Equals,
    /// The tag is absent, or present with a value
    /// different from [`TagCondition::value`].
    NotEquals,
    /// The tag key exists (any value). [`TagCondition::value`]
    /// is ignored.
    Exists,
    /// The tag key is absent. [`TagCondition::value`] is
    /// ignored.
    NotExists,
}

/// One predicate over a tag map (the `tags` field on
/// [`App`], [`crate::device::DeviceTrust`], or
/// [`crate::identity::UserIdentity`]).
///
/// Tags arrive in the signed policy bundle from the
/// control plane; this is the foundation for
/// attribute-based access (e.g. device `managed=true`,
/// user `risk_tier=elevated`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagCondition {
    /// Tag key the condition tests.
    pub key: String,
    /// Comparison operator.
    pub op: TagOp,
    /// Comparison value. Required for [`TagOp::Equals`] /
    /// [`TagOp::NotEquals`]; ignored for [`TagOp::Exists`] /
    /// [`TagOp::NotExists`] (conventionally `None` there).
    #[serde(default)]
    pub value: Option<String>,
}

impl TagCondition {
    /// True iff `tags` satisfies this condition.
    ///
    /// For [`TagOp::Equals`] a `None` [`Self::value`] can
    /// never match (there is nothing to equal); for
    /// [`TagOp::NotEquals`] a `None` value means "any
    /// value other than absent", i.e. it matches whenever
    /// the key is present.
    #[must_use]
    pub fn matches(&self, tags: &HashMap<String, String>) -> bool {
        let current = tags.get(&self.key).map(String::as_str);
        match self.op {
            TagOp::Equals => current.is_some() && current == self.value.as_deref(),
            TagOp::NotEquals => current != self.value.as_deref(),
            TagOp::Exists => current.is_some(),
            TagOp::NotExists => current.is_none(),
        }
    }
}

/// A daily UTC access window. Carried by
/// [`AccessConditions::allowed_hours`].
///
/// The window is `[start_hour, end_hour)` on a 24-hour
/// clock. When `start_hour <= end_hour` it is a normal
/// same-day window (e.g. 09→17 = 9am–5pm). When
/// `start_hour > end_hour` it wraps past midnight (e.g.
/// 22→06 = 10pm–6am). `start_hour == end_hour` is an
/// empty window that admits no hour — an operator who
/// means "all day" should leave
/// [`AccessConditions::allowed_hours`] as `None`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Inclusive start hour, 0–23 UTC.
    pub start_hour: u8,
    /// Exclusive end hour, 0–23 UTC.
    pub end_hour: u8,
    /// Days of week the window applies to, `0`=Sunday …
    /// `6`=Saturday. An empty set means "every day".
    #[serde(default)]
    pub days: HashSet<u8>,
}

impl TimeWindow {
    /// True iff `now_ms` (Unix epoch milliseconds, UTC)
    /// falls inside this window — both the day-of-week
    /// set (when non-empty) and the hour range must match.
    #[must_use]
    pub fn contains(&self, now_ms: u64) -> bool {
        // Days since the Unix epoch (1970-01-01, a
        // Thursday). 0=Sunday, so the epoch's weekday is
        // 4 and we offset by that before taking mod 7.
        let days_since_epoch = now_ms / 86_400_000;
        let weekday = ((days_since_epoch + 4) % 7) as u8;
        if !self.days.is_empty() && !self.days.contains(&weekday) {
            return false;
        }
        let hour = ((now_ms / 3_600_000) % 24) as u8;
        if self.start_hour <= self.end_hour {
            hour >= self.start_hour && hour < self.end_hour
        } else {
            // Wrapping window: admit the late-evening tail
            // and the early-morning head.
            hour >= self.start_hour || hour < self.end_hour
        }
    }
}

/// Per-app contextual access conditions, evaluated after
/// the tenant guard but before group entitlement. Every
/// field is "unset = no constraint", so a default
/// [`AccessConditions`] admits any request and existing
/// catalog entries keep their current behaviour.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessConditions {
    /// ISO 3166-1 alpha-2 countries the request may
    /// originate from. `None` = any country. Compared
    /// case-insensitively. A request whose
    /// `source_country` is absent fails a non-`None`
    /// allow-list (the evaluator cannot prove it is
    /// allowed).
    #[serde(default)]
    pub allowed_countries: Option<HashSet<String>>,
    /// ISO 3166-1 alpha-2 countries that are always
    /// denied, checked before [`Self::allowed_countries`].
    /// `None` = no deny-list.
    #[serde(default)]
    pub blocked_countries: Option<HashSet<String>>,
    /// Network classes the request may arrive on. `None`
    /// = any. A request with no `network_type` is treated
    /// as [`NetworkType::Unknown`] for this check.
    #[serde(default)]
    pub allowed_network_types: Option<HashSet<NetworkType>>,
    /// Daily UTC window access is permitted in. `None` =
    /// always.
    #[serde(default)]
    pub allowed_hours: Option<TimeWindow>,
    /// Conditions evaluated against the *device's* tag
    /// map. All must hold (logical AND).
    #[serde(default)]
    pub device_tag_conditions: Vec<TagCondition>,
    /// Conditions evaluated against the *user's* tag map.
    /// All must hold (logical AND).
    #[serde(default)]
    pub user_tag_conditions: Vec<TagCondition>,
}

impl AccessConditions {
    /// True iff `country` is denied — either on the
    /// blocked list, or absent / outside a non-`None`
    /// allow list. Comparison is ASCII-case-insensitive.
    #[must_use]
    fn country_denied(&self, country: Option<&str>) -> bool {
        let upper = country.map(str::to_ascii_uppercase);
        if let (Some(blocked), Some(c)) = (self.blocked_countries.as_ref(), upper.as_ref())
            && blocked.iter().any(|b| b.eq_ignore_ascii_case(c))
        {
            return true;
        }
        if let Some(allowed) = self.allowed_countries.as_ref() {
            match upper.as_ref() {
                Some(c) => !allowed.iter().any(|a| a.eq_ignore_ascii_case(c)),
                // Allow-list set but the request carries no
                // country: cannot prove it is allowed.
                None => true,
            }
        } else {
            false
        }
    }

    /// True iff `network` is not in a non-`None` allowed
    /// set.
    #[must_use]
    fn network_denied(&self, network: NetworkType) -> bool {
        self.allowed_network_types
            .as_ref()
            .is_some_and(|set| !set.contains(&network))
    }

    /// True iff `now_ms` is outside a non-`None` window.
    #[must_use]
    fn outside_hours(&self, now_ms: u64) -> bool {
        self.allowed_hours
            .as_ref()
            .is_some_and(|w| !w.contains(now_ms))
    }
}

/// Source of device / user revocations. Production wires
/// a control-plane-backed implementation that NATS
/// pushes revocation events into; the in-memory
/// [`StaticRevocationList`] is the test / single-process
/// default.
pub trait RevocationProvider: Send + Sync + 'static {
    /// True iff `device_id` has been revoked (device
    /// compromise / de-enrollment).
    fn is_revoked(&self, device_id: &str) -> bool;
    /// True iff `user_id` has been revoked (off-boarding
    /// / forced re-auth).
    fn is_user_revoked(&self, user_id: &str) -> bool;
}

/// In-memory [`RevocationProvider`]. Two
/// `ArcSwap<HashSet<String>>` sets — one for device ids,
/// one for user ids — so the bundle adapter can swap a
/// whole revocation set atomically while the data path
/// reads without a lock (same pattern as the other
/// providers).
#[derive(Debug, Default)]
pub struct StaticRevocationList {
    devices: ArcSwap<HashSet<String>>,
    users: ArcSwap<HashSet<String>>,
}

impl StaticRevocationList {
    /// Construct from initial device + user revocation
    /// sets.
    #[must_use]
    pub fn new(devices: HashSet<String>, users: HashSet<String>) -> Self {
        Self {
            devices: ArcSwap::new(Arc::new(devices)),
            users: ArcSwap::new(Arc::new(users)),
        }
    }

    /// Atomically replace the revoked-device set.
    pub fn replace_devices(&self, devices: HashSet<String>) {
        self.devices.store(Arc::new(devices));
    }

    /// Atomically replace the revoked-user set.
    pub fn replace_users(&self, users: HashSet<String>) {
        self.users.store(Arc::new(users));
    }
}

impl RevocationProvider for StaticRevocationList {
    fn is_revoked(&self, device_id: &str) -> bool {
        self.devices.load().contains(device_id)
    }

    fn is_user_revoked(&self, user_id: &str) -> bool {
        self.users.load().contains(user_id)
    }
}

/// The reason an evaluator denied (or allowed) a
/// request. Every reason maps to a stable wire string
/// for downstream dashboards and the
/// [`sng_core::events::ZtnaEvent::reason`] field (the
/// sibling [`sng_core::events::ZtnaEvent::decision`]
/// field carries the binary `allow`/`deny` outcome).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZtnaDecisionReason {
    /// Allow. The user was in the app's group set, the
    /// device posture met the floor, MFA was fresh, and
    /// the device's attestation was fresh.
    Allow,
    /// Deny — request referenced an `app_id` not present
    /// in the active app catalog.
    UnknownApp,
    /// Deny — device_id was not enrolled in the device
    /// trust provider.
    DeviceNotEnrolled,
    /// Deny — device's latest posture attestation is
    /// older than `policy.device_posture_max_age_ms`.
    DevicePostureStale,
    /// Deny — device's posture does not meet the app's
    /// [`PostureRequirement`].
    DevicePostureInsufficient,
    /// Deny — identity not registered with the identity
    /// provider.
    IdentityNotFound,
    /// Deny — identity's MFA timestamp is older than
    /// `policy.mfa_max_age_ms`.
    MfaStale,
    /// Deny — user is not a member of any of the app's
    /// `required_groups`.
    NotEntitled,
    /// Deny — request's tenant does not match the
    /// device's or identity's tenant. Cross-tenant
    /// requests are never allowed.
    TenantMismatch,
    /// Deny — the device or user is on the active
    /// revocation list. Checked before any other signal
    /// so a compromised device / off-boarded user is cut
    /// off immediately, without waiting for posture or
    /// MFA TTLs to expire.
    Revoked,
    /// Deny — the request's `source_country` is on the
    /// app's blocked-country list, or is absent / outside
    /// its allowed-country list.
    GeoBlocked,
    /// Deny — the request's `network_type` is not in the
    /// app's allowed-network-type set.
    NetworkTypeBlocked,
    /// Deny — the request arrived outside the app's
    /// allowed access hours / days.
    OutsideAllowedHours,
    /// Deny — a device or user tag condition declared on
    /// the app's [`AccessConditions`] was not satisfied.
    TagMismatch,
}

impl ZtnaDecisionReason {
    /// Stable wire string for the
    /// [`sng_core::events::ZtnaEvent::reason`] field —
    /// `allow` on the allow path, or the dashboards'
    /// deny bucket label on a deny.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::UnknownApp => "unknown_app",
            Self::DeviceNotEnrolled => "device_not_enrolled",
            Self::DevicePostureStale => "device_posture_stale",
            Self::DevicePostureInsufficient => "device_posture_insufficient",
            Self::IdentityNotFound => "identity_not_found",
            Self::MfaStale => "mfa_stale",
            Self::NotEntitled => "not_entitled",
            Self::TenantMismatch => "tenant_mismatch",
            Self::Revoked => "revoked",
            Self::GeoBlocked => "geo_blocked",
            Self::NetworkTypeBlocked => "network_type_blocked",
            Self::OutsideAllowedHours => "outside_allowed_hours",
            Self::TagMismatch => "tag_mismatch",
        }
    }

    /// True iff this reason represents an allow.
    #[must_use]
    pub const fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// True iff this reason represents a deny.
    #[must_use]
    pub const fn is_deny(&self) -> bool {
        !self.is_allow()
    }
}

/// Tri-state outcome of the device posture check.
///
/// Replaces the prior `bool posture_pass` field on
/// [`ZtnaDecision`] so dashboards can distinguish a
/// genuine posture failure ([`Self::Fail`]) from a
/// deny that short-circuited before the posture check
/// ran ([`Self::NotEvaluated`]).
///
/// # Wire form
///
/// Mapped to a stable lowercase string by
/// [`Self::as_str`] and emitted on
/// [`sng_core::events::ZtnaEvent::posture_result`] (Rust
/// side) / `ZTNAEvent.PostureResult` (Go side). The
/// wire alphabet is `"pass" | "fail" | "not_evaluated"`.
/// Older consumers that only know `"pass"` / `"fail"`
/// will see `"not_evaluated"` as an unknown bucket —
/// safer than the previous behavior of stamping
/// `"fail"` on every non-posture deny, which made the
/// field literally lie about whether the device's
/// posture had failed.
///
/// # Why a tri-state and not just two booleans
///
/// A `(posture_evaluated, posture_passed)` pair would
/// encode the same information but invites the
/// `(false, true)` impossible state. The enum makes
/// the invariant unrepresentable at the type level —
/// `Pass` and `Fail` are only reachable after the
/// posture check actually ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PostureResult {
    /// The posture check ran and the device satisfied
    /// the app's [`PostureRequirement`]. Set on the
    /// allow path and on any deny that occurred after
    /// the posture check passed (none today — the
    /// evaluator currently denies immediately when the
    /// posture check fails — but the variant exists so
    /// a future check ordered after posture can produce
    /// a `(deny, Pass)` decision).
    Pass,
    /// The posture check ran and the device failed it
    /// — either because the attestation was stale
    /// ([`ZtnaDecisionReason::DevicePostureStale`]) or
    /// the requirement was unsatisfied
    /// ([`ZtnaDecisionReason::DevicePostureInsufficient`]).
    Fail,
    /// The decision short-circuited before the posture
    /// check ran. Set on
    /// [`ZtnaDecisionReason::TenantMismatch`],
    /// [`ZtnaDecisionReason::NotEntitled`],
    /// [`ZtnaDecisionReason::MfaStale`], and any other
    /// pre-posture deny added in the future. Dashboards
    /// that bucket on "device-related" denies should
    /// treat this as orthogonal to the
    /// posture-pass / posture-fail axis.
    NotEvaluated,
}

impl PostureResult {
    /// Stable wire-form string used in the
    /// [`sng_core::events::ZtnaEvent::posture_result`]
    /// field (and the Go-side `ZTNAEvent.PostureResult`
    /// peer).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::NotEvaluated => "not_evaluated",
        }
    }
}

/// The decision the evaluator returns. The brain
/// converts this into a wire
/// [`sng_core::envelope::Verdict`] and a
/// [`sng_core::events::ZtnaEvent`] for telemetry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZtnaDecision {
    /// Allow / deny.
    pub allow: bool,
    /// Structured reason — for both allows (= `Allow`)
    /// and denies (= a specific failure cause).
    pub reason: ZtnaDecisionReason,
    /// Tri-state outcome of the device posture check.
    /// Surfaced to the
    /// [`sng_core::events::ZtnaEvent::posture_result`]
    /// field so dashboards can distinguish a genuine
    /// posture failure from a deny that short-circuited
    /// before the posture check ran (e.g. a tenant
    /// mismatch or a stale MFA assertion).
    ///
    /// The previous shape (`posture_pass: bool`)
    /// collapsed these two cases into `false`, which
    /// made `posture_result = "fail"` ambiguous on the
    /// wire — it could mean either "the device's
    /// posture failed" or "this deny short-circuited
    /// before posture was even checked." Splitting them
    /// out via [`PostureResult`] keeps the field name's
    /// promise.
    pub posture_result: PostureResult,
}

impl ZtnaDecision {
    /// Convenience: allow with
    /// `posture_result=PostureResult::Pass`. The allow
    /// path always traverses the posture check, so
    /// `Pass` is the only valid spelling for the
    /// posture outcome on an allow.
    #[must_use]
    pub const fn allow() -> Self {
        Self {
            allow: true,
            reason: ZtnaDecisionReason::Allow,
            posture_result: PostureResult::Pass,
        }
    }

    /// Convenience: deny with the given reason and
    /// posture result. The caller is responsible for
    /// supplying the correct posture-check outcome:
    /// [`PostureResult::Fail`] for posture-related
    /// denies, [`PostureResult::NotEvaluated`] for
    /// pre-posture short-circuits.
    #[must_use]
    pub const fn deny(reason: ZtnaDecisionReason, posture_result: PostureResult) -> Self {
        Self {
            allow: false,
            reason,
            posture_result,
        }
    }
}

/// The policy knobs the brain consults while joining the
/// per-app catalog with the live identity / device
/// signals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZtnaPolicy {
    /// Maximum age of a device's posture attestation
    /// before it is considered stale. Sourced from the
    /// tenant policy bundle.
    pub device_posture_max_age_ms: u64,
    /// Maximum age of a user's MFA completion before it
    /// must be re-prompted. Sourced from the tenant
    /// policy bundle.
    pub mfa_max_age_ms: u64,
    /// Tenant ID this policy belongs to. The evaluator
    /// rejects cross-tenant requests (where the user or
    /// device belongs to a different tenant than the
    /// policy is configured for).
    ///
    /// **Empty string disables the cross-tenant guard.**
    /// This is the intentional shape for single-tenant
    /// deployments where every device and user belong
    /// to the same implicit tenant and the bundle
    /// adapter has no tenant claim to install. Multi-
    /// tenant deployments MUST reject an empty
    /// `tenant_id` at the bundle adapter — the
    /// evaluator can't tell single-tenant-by-design
    /// apart from multi-tenant-misconfiguration, only
    /// the bundle source knows. [`Self::validate`] is
    /// intentionally silent on emptiness for this
    /// reason; the multi-tenant bundle adapter layers
    /// its own non-empty check on top.
    pub tenant_id: String,
    /// Cadence, in milliseconds, of the continuous
    /// re-evaluation loop ([`crate::reeval::ReevalLoop`])
    /// that re-runs [`evaluate_policy`] over every active
    /// session and revokes the ones whose verdict has
    /// flipped to deny (posture decayed, MFA expired,
    /// device/user revoked, app de-listed, …).
    ///
    /// Sourced from the tenant policy bundle alongside the
    /// freshness budgets so an operator can trade
    /// revocation latency against re-evaluation cost: a
    /// tighter interval cuts the window between a posture
    /// regression and the session being torn down, at the
    /// price of more frequent provider lookups. The loop
    /// reads this value once per tick, so a bundle reload
    /// that changes it takes effect on the next cycle
    /// without restarting the loop.
    ///
    /// Defaults to 60_000 ms (60 s). [`Self::validate`]
    /// rejects a zero value — a zero interval would spin
    /// the loop with no delay and is never a valid
    /// operational choice; an operator wanting to disable
    /// continuous re-evaluation simply does not spawn the
    /// loop.
    pub reeval_interval_ms: u64,
}

impl Default for ZtnaPolicy {
    fn default() -> Self {
        Self {
            // 12 hours of posture freshness aligns with
            // the agent's default re-attestation cadence
            // (every hour) leaving a comfortable margin
            // for agents that miss a few cycles.
            device_posture_max_age_ms: 12 * 60 * 60 * 1_000,
            // 8 hours of MFA freshness covers a working
            // day; sensitive apps can drop this with a
            // per-app override (out of scope for the
            // initial bundle schema, but the policy
            // already supports refreshing the whole
            // policy on every bundle reload).
            mfa_max_age_ms: 8 * 60 * 60 * 1_000,
            tenant_id: String::new(),
            // 60 s between re-evaluation sweeps: fast
            // enough that a revoked device / expired MFA
            // is torn down within a minute, slow enough
            // that the per-session provider lookups stay
            // cheap even at thousands of sessions per
            // tenant. Operators tighten or relax it via
            // the bundle.
            reeval_interval_ms: 60 * 1_000,
        }
    }
}

impl ZtnaPolicy {
    /// Validate the value-domain invariants on this
    /// policy. Called from
    /// [`ZtnaPolicyHolder::try_replace`] (and indirectly
    /// from [`crate::service::ZtnaService::reload_policy`])
    /// so a misconfigured bundle is rejected at load
    /// time and the previously-active ruleset stays in
    /// force.
    ///
    /// The current checks reject:
    ///
    /// - `mfa_max_age_ms == 0` — a zero freshness budget
    ///   marks every MFA assertion stale, making the
    ///   evaluator a uniform deny.
    /// - `device_posture_max_age_ms == 0` — same reason
    ///   for posture freshness.
    /// - `reeval_interval_ms == 0` — a zero interval
    ///   would busy-spin the re-evaluation loop with no
    ///   delay between sweeps; disabling continuous
    ///   re-evaluation is expressed by not spawning the
    ///   loop, never by a zero cadence.
    ///
    /// `tenant_id` is *not* checked here — the empty
    /// string is the intentional spelling for single-
    /// tenant deployments (see the doc on
    /// [`Self::tenant_id`]). Multi-tenant deployments
    /// add a non-empty check at the bundle adapter
    /// layer where the bundle's claim on a tenant is
    /// known.
    ///
    /// # Errors
    ///
    /// - [`ZtnaError::InvalidPolicy`] when any of the
    ///   above invariants fail.
    pub fn validate(&self) -> Result<(), ZtnaError> {
        if self.mfa_max_age_ms == 0 {
            return Err(ZtnaError::InvalidPolicy(
                "mfa_max_age_ms must be > 0 (a zero budget marks every MFA assertion stale)"
                    .to_owned(),
            ));
        }
        if self.device_posture_max_age_ms == 0 {
            return Err(ZtnaError::InvalidPolicy(
                "device_posture_max_age_ms must be > 0 (a zero budget marks every posture attestation stale)"
                    .to_owned(),
            ));
        }
        if self.reeval_interval_ms == 0 {
            return Err(ZtnaError::InvalidPolicy(
                "reeval_interval_ms must be > 0 (a zero interval would busy-spin the re-evaluation loop)"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

/// `ArcSwap`-backed holder for the active
/// [`ZtnaPolicy`]. The data path snapshots a cheap
/// `Arc<ZtnaPolicy>` per evaluation; the bundle adapter
/// swaps the policy atomically when a new bundle is
/// pushed.
#[derive(Debug, Default)]
pub struct ZtnaPolicyHolder {
    inner: ArcSwap<ZtnaPolicy>,
}

impl ZtnaPolicyHolder {
    /// Construct a holder around `policy` *without*
    /// validating it. Reserved for callers that already
    /// own a known-good policy — primarily
    /// [`ZtnaPolicy::default`] and unit tests. Bundle
    /// adapters and any externally-sourced policy should
    /// use [`try_new`](Self::try_new) instead so a
    /// misconfigured bundle is rejected at load time
    /// rather than silently replacing the working
    /// ruleset with one that denies every request.
    #[must_use]
    pub fn new(policy: ZtnaPolicy) -> Self {
        Self {
            inner: ArcSwap::new(Arc::new(policy)),
        }
    }

    /// Construct a holder around `policy`, returning an
    /// error if the policy fails [`ZtnaPolicy::validate`].
    /// The intended call site is the bundle adapter that
    /// converts a decoded policy bundle into the in-memory
    /// ZTNA snapshot — a misconfigured bundle is rejected
    /// at load time and the supervisor keeps the
    /// previously-active policy.
    ///
    /// # Errors
    ///
    /// - [`ZtnaError::InvalidPolicy`] when `policy`
    ///   fails [`ZtnaPolicy::validate`].
    pub fn try_new(policy: ZtnaPolicy) -> Result<Self, ZtnaError> {
        policy.validate()?;
        Ok(Self::new(policy))
    }

    /// Replace the active policy *without* validating
    /// it. Reserved for known-good policies; bundle
    /// adapters should use
    /// [`try_replace`](Self::try_replace) so a
    /// misconfigured candidate cannot clobber the live
    /// ruleset. In-flight evaluations see the old policy
    /// until they finish.
    pub fn replace(&self, policy: ZtnaPolicy) {
        self.inner.store(Arc::new(policy));
    }

    /// Validate and atomically replace the policy. On
    /// validation failure the previously-loaded policy
    /// is preserved and the data path keeps running
    /// against the last known-good ruleset.
    ///
    /// # Errors
    ///
    /// - [`ZtnaError::InvalidPolicy`] when `policy`
    ///   fails [`ZtnaPolicy::validate`].
    pub fn try_replace(&self, policy: ZtnaPolicy) -> Result<(), ZtnaError> {
        policy.validate()?;
        self.replace(policy);
        Ok(())
    }

    /// Cheap snapshot of the active policy — clones the
    /// `Arc`, never copies the policy body.
    #[must_use]
    pub fn snapshot(&self) -> Arc<ZtnaPolicy> {
        self.inner.load_full()
    }
}

/// Inputs to [`evaluate_policy`]. Bundles the per-
/// request facts the orchestrator has resolved by the
/// time it calls the evaluator.
#[derive(Clone, Debug)]
pub struct EvaluationInputs<'a> {
    /// The app the request is targeting. The orchestrator
    /// resolves this via the
    /// [`crate::app::AppCatalogProvider`]; if not found,
    /// the orchestrator builds a deny directly without
    /// calling the evaluator.
    pub app: &'a App,
    /// The device's trust + posture record. The
    /// orchestrator resolves this via the
    /// [`crate::device::DeviceTrustProvider`]; if not
    /// found, the orchestrator builds a deny directly.
    pub device: &'a DeviceTrust,
    /// The user's identity record. The orchestrator
    /// resolves this via the
    /// [`crate::identity::IdentityProvider`]; if not
    /// found, the orchestrator builds a deny directly.
    pub identity: &'a UserIdentity,
    /// Monotonic millisecond timestamp the orchestrator
    /// captured when the request arrived. Used for the
    /// MFA + posture freshness checks (and, interpreted
    /// as Unix epoch ms, the [`AccessConditions::allowed_hours`]
    /// gate).
    pub now_ms: u64,
    /// ISO 3166-1 alpha-2 country the proxy resolved for
    /// the request's source IP, copied from
    /// [`crate::request::AccessRequest::source_country`].
    /// `None` when unknown — see
    /// [`AccessConditions::allowed_countries`] for how an
    /// absent country interacts with an allow-list.
    pub source_country: Option<&'a str>,
    /// Network class the request arrived on, copied from
    /// [`crate::request::AccessRequest::network_type`].
    /// An absent network type is normalized to
    /// [`NetworkType::Unknown`] by the orchestrator.
    pub network_type: NetworkType,
}

/// Run the policy. **Order matters** — the evaluator
/// checks the cheapest signals first so the most common
/// deny paths short-circuit without computing later
/// signals.
///
/// Steps:
///
/// 1. **Tenant match.** The policy belongs to one
///    tenant; the device and the identity must both
///    belong to the same tenant. Cross-tenant requests
///    are denied without further checks.
/// 2. **Access conditions.** The app's
///    [`AccessConditions`] gate the request on
///    geography ([`ZtnaDecisionReason::GeoBlocked`]),
///    network class
///    ([`ZtnaDecisionReason::NetworkTypeBlocked`]), time
///    of day ([`ZtnaDecisionReason::OutsideAllowedHours`]),
///    and device / user tags
///    ([`ZtnaDecisionReason::TagMismatch`]). Runs after
///    the tenant guard but before entitlement so a
///    context failure short-circuits the group lookup.
/// 3. **Identity entitlement.** If the app has a non-
///    empty `required_groups` set, the user's groups
///    must intersect it. Otherwise the user is
///    `not_entitled`.
/// 4. **MFA freshness.** The user's `mfa_at_ms` must
///    be within the effective MFA budget of `now_ms` —
///    the app's
///    [`App::mfa_max_age_override_ms`] when set, else
///    `policy.mfa_max_age_ms`.
/// 5. **Device posture freshness.** The device's
///    `attested_at_ms` must be within
///    `policy.device_posture_max_age_ms` of `now_ms`.
/// 6. **Device posture sufficiency.** The device's
///    posture must satisfy the app's
///    [`PostureRequirement`].
///
/// On every deny the [`ZtnaDecision::posture_result`]
/// field reflects whether the posture check ran and
/// what it found:
///
/// - [`PostureResult::Pass`] — only on the allow path
///   (the evaluator currently denies immediately on a
///   posture failure, so a `(deny, Pass)` decision is
///   unreachable today but the variant is reserved for
///   future checks ordered after posture).
/// - [`PostureResult::Fail`] — on denies in steps 5-6
///   ([`ZtnaDecisionReason::DevicePostureStale`] and
///   [`ZtnaDecisionReason::DevicePostureInsufficient`]),
///   i.e. the posture check ran and failed.
/// - [`PostureResult::NotEvaluated`] — on denies in
///   steps 1-4 ([`ZtnaDecisionReason::TenantMismatch`],
///   the access-condition reasons,
///   [`ZtnaDecisionReason::NotEntitled`],
///   [`ZtnaDecisionReason::MfaStale`]), i.e. the
///   evaluator short-circuited before the posture check
///   ran. The prior shape collapsed this case into
///   `posture_pass=false`, which made the wire field
///   ambiguous — a dashboard couldn't tell whether a
///   `posture_result=fail` row meant "device posture
///   failed" or "deny landed before posture was even
///   checked."
//
// `EvaluationInputs` holds three references plus a `u64`,
// so passing by value is essentially the same cost as
// passing by reference — but it lets the function
// destructure the inputs (`let EvaluationInputs { app, .. } = inputs;`)
// instead of writing `inputs.app` / `inputs.device` /
// `inputs.identity` at every use site. The
// `needless_pass_by_value` lint cannot see this trade-off,
// so we allow it explicitly.
#[allow(clippy::needless_pass_by_value)]
#[must_use]
pub fn evaluate_policy(policy: &ZtnaPolicy, inputs: EvaluationInputs<'_>) -> ZtnaDecision {
    let EvaluationInputs {
        app,
        device,
        identity,
        now_ms,
        source_country,
        network_type,
    } = inputs;

    // 1. Tenant guard. Cross-tenant requests never
    // proceed past this gate.
    if !policy.tenant_id.is_empty()
        && (device.tenant_id != policy.tenant_id || identity.tenant_id != policy.tenant_id)
    {
        return ZtnaDecision::deny(
            ZtnaDecisionReason::TenantMismatch,
            PostureResult::NotEvaluated,
        );
    }

    // 2. Access conditions (geo / network / time /
    // tags). All are "unset = no constraint", so an app
    // with default conditions falls straight through.
    let conditions = &app.conditions;
    if conditions.country_denied(source_country) {
        return ZtnaDecision::deny(ZtnaDecisionReason::GeoBlocked, PostureResult::NotEvaluated);
    }
    if conditions.network_denied(network_type) {
        return ZtnaDecision::deny(
            ZtnaDecisionReason::NetworkTypeBlocked,
            PostureResult::NotEvaluated,
        );
    }
    if conditions.outside_hours(now_ms) {
        return ZtnaDecision::deny(
            ZtnaDecisionReason::OutsideAllowedHours,
            PostureResult::NotEvaluated,
        );
    }
    let tags_ok = conditions
        .device_tag_conditions
        .iter()
        .all(|c| c.matches(&device.tags))
        && conditions
            .user_tag_conditions
            .iter()
            .all(|c| c.matches(&identity.tags));
    if !tags_ok {
        return ZtnaDecision::deny(ZtnaDecisionReason::TagMismatch, PostureResult::NotEvaluated);
    }

    // 3. Group entitlement. Empty `required_groups`
    // means "any authenticated user", consistent with
    // the catalog's documented semantics.
    if !app.required_groups.is_empty() {
        let entitled = app
            .required_groups
            .iter()
            .any(|g| identity.groups.contains(g));
        if !entitled {
            return ZtnaDecision::deny(
                ZtnaDecisionReason::NotEntitled,
                PostureResult::NotEvaluated,
            );
        }
    }

    // 4. MFA freshness. A per-app override tightens (or
    // loosens) the policy-global budget for this app.
    let mfa_max_age_ms = app.mfa_max_age_override_ms.unwrap_or(policy.mfa_max_age_ms);
    if !identity.mfa_fresh(now_ms, mfa_max_age_ms) {
        return ZtnaDecision::deny(ZtnaDecisionReason::MfaStale, PostureResult::NotEvaluated);
    }

    // 5. Device posture freshness.
    if !device.posture_fresh(now_ms, policy.device_posture_max_age_ms) {
        return ZtnaDecision::deny(ZtnaDecisionReason::DevicePostureStale, PostureResult::Fail);
    }

    // 6. Device posture sufficiency.
    if !app.posture_requirement.satisfied_by(&device.posture) {
        return ZtnaDecision::deny(
            ZtnaDecisionReason::DevicePostureInsufficient,
            PostureResult::Fail,
        );
    }

    ZtnaDecision::allow()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    fn app(name: &str, posture: PostureRequirement, groups: &[&str]) -> App {
        let mut a = App::new(name, name);
        a.required_groups = groups.iter().map(|s| (*s).to_string()).collect();
        a.posture_requirement = posture;
        a
    }

    fn device(tenant: &str, posture: DevicePosture) -> DeviceTrust {
        DeviceTrust {
            device_id: "dev-1".into(),
            tenant_id: tenant.into(),
            posture,
            tags: HashMap::new(),
        }
    }

    fn user(tenant: &str, groups: &[&str], mfa_at_ms: u64) -> UserIdentity {
        UserIdentity {
            user_id: "alice".into(),
            tenant_id: tenant.into(),
            groups: groups.iter().map(|s| (*s).to_string()).collect(),
            mfa_at_ms,
            tags: HashMap::new(),
        }
    }

    fn policy(tenant: &str) -> ZtnaPolicy {
        ZtnaPolicy {
            tenant_id: tenant.into(),
            ..Default::default()
        }
    }

    fn now() -> u64 {
        // Pick a round number well above the policy's
        // max-age windows so we can roll it back to
        // produce stale-MFA / stale-posture cases.
        1_000_000_000
    }

    fn inputs<'a>(
        a: &'a App,
        d: &'a DeviceTrust,
        u: &'a UserIdentity,
        now_ms: u64,
    ) -> EvaluationInputs<'a> {
        EvaluationInputs {
            app: a,
            device: d,
            identity: u,
            now_ms,
            source_country: None,
            network_type: NetworkType::Unknown,
        }
    }

    /// Like [`inputs`] but carries an explicit
    /// `source_country` / `network_type` so the
    /// access-condition branch can be exercised.
    fn inputs_ctx<'a>(
        a: &'a App,
        d: &'a DeviceTrust,
        u: &'a UserIdentity,
        now_ms: u64,
        source_country: Option<&'a str>,
        network_type: NetworkType,
    ) -> EvaluationInputs<'a> {
        EvaluationInputs {
            app: a,
            device: d,
            identity: u,
            now_ms,
            source_country,
            network_type,
        }
    }

    fn set<const N: usize>(items: [&str; N]) -> HashSet<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn posture_none_satisfied_by_unmanaged() {
        assert!(PostureRequirement::NONE.satisfied_by(&DevicePosture::unmanaged()));
    }

    #[test]
    fn risk_score_sums_signal_weights() {
        assert_eq!(DevicePosture::unmanaged().risk_score(), 0);
        let mut p = DevicePosture::unmanaged();
        p.disk_encrypted = true; // 25
        assert_eq!(p.risk_score(), 25);
        p.os_patched = true; // +25
        assert_eq!(p.risk_score(), 50);
        p.antimalware_running = true; // +20
        assert_eq!(p.risk_score(), 70);
        p.firewall_enabled = true; // +15
        p.screen_lock_configured = true; // +15
        assert_eq!(p.risk_score(), 100);
    }

    #[test]
    fn posture_basic_floor_is_score_60() {
        // disk + os alone = 50, below the Basic floor of
        // 60; adding any third signal clears it.
        let mut p = DevicePosture::unmanaged();
        p.disk_encrypted = true;
        p.os_patched = true;
        assert_eq!(p.risk_score(), 50);
        assert!(!PostureRequirement::BASIC.satisfied_by(&p));
        p.firewall_enabled = true; // +15 -> 65
        assert!(PostureRequirement::BASIC.satisfied_by(&p));
    }

    #[test]
    fn posture_strict_requires_every_signal() {
        assert!(!PostureRequirement::STRICT.satisfied_by(&DevicePosture::unmanaged()));
        assert!(PostureRequirement::STRICT.satisfied_by(&DevicePosture::pristine(now())));
    }

    #[test]
    fn posture_requirement_ord_matches_satisfied_by_strictness() {
        // None is least strict (always passes), Strict is
        // most strict — the score axis orders first.
        assert!(PostureRequirement::NONE < PostureRequirement::BASIC);
        assert!(PostureRequirement::BASIC < PostureRequirement::STRICT);

        // Hard gates linearise least-to-most strict too:
        // declaring a gate is stricter than not, and a
        // smaller cap (tighter window) is stricter than a
        // larger one — never inverted.
        let base = PostureRequirement::BASIC;
        assert!(base < base.with_require_edr(true));
        assert!(base < base.with_min_patch_days(30));
        assert!(base.with_min_patch_days(30) < base.with_min_patch_days(7));
        assert!(base < base.with_max_av_definition_age_hours(72));
        assert!(
            base.with_max_av_definition_age_hours(72) < base.with_max_av_definition_age_hours(24)
        );

        // A requirement that dominates another on every axis
        // is strictly greater; the order is a linear
        // extension of the (partial) strictness order.
        let looser = base.with_min_patch_days(30);
        let stricter = base.with_require_edr(true).with_min_patch_days(7);
        assert!(looser < stricter);
    }

    #[test]
    fn posture_requirement_sugar_maps_to_scores() {
        assert_eq!(PostureRequirement::NONE.min_score, 0);
        assert_eq!(PostureRequirement::BASIC.min_score, 60);
        assert_eq!(PostureRequirement::STRICT.min_score, 90);
        // `new` clamps out-of-range scores to 100 so a bad
        // bundle value can't make a requirement
        // permanently unsatisfiable.
        assert_eq!(PostureRequirement::new(200).min_score, 100);
        assert_eq!(PostureRequirement::new(75).min_score, 75);
    }

    #[test]
    fn decision_reason_wire_strings_cover_every_variant() {
        assert_eq!(ZtnaDecisionReason::Allow.as_str(), "allow");
        assert_eq!(ZtnaDecisionReason::UnknownApp.as_str(), "unknown_app");
        assert_eq!(
            ZtnaDecisionReason::DeviceNotEnrolled.as_str(),
            "device_not_enrolled"
        );
        assert_eq!(
            ZtnaDecisionReason::DevicePostureStale.as_str(),
            "device_posture_stale"
        );
        assert_eq!(
            ZtnaDecisionReason::DevicePostureInsufficient.as_str(),
            "device_posture_insufficient"
        );
        assert_eq!(
            ZtnaDecisionReason::IdentityNotFound.as_str(),
            "identity_not_found"
        );
        assert_eq!(ZtnaDecisionReason::MfaStale.as_str(), "mfa_stale");
        assert_eq!(ZtnaDecisionReason::NotEntitled.as_str(), "not_entitled");
        assert_eq!(
            ZtnaDecisionReason::TenantMismatch.as_str(),
            "tenant_mismatch"
        );
        assert_eq!(ZtnaDecisionReason::Revoked.as_str(), "revoked");
        assert_eq!(ZtnaDecisionReason::GeoBlocked.as_str(), "geo_blocked");
        assert_eq!(
            ZtnaDecisionReason::NetworkTypeBlocked.as_str(),
            "network_type_blocked"
        );
        assert_eq!(
            ZtnaDecisionReason::OutsideAllowedHours.as_str(),
            "outside_allowed_hours"
        );
        assert_eq!(ZtnaDecisionReason::TagMismatch.as_str(), "tag_mismatch");
    }

    #[test]
    fn decision_reason_is_allow_only_for_allow() {
        assert!(ZtnaDecisionReason::Allow.is_allow());
        assert!(!ZtnaDecisionReason::Allow.is_deny());
        for r in [
            ZtnaDecisionReason::UnknownApp,
            ZtnaDecisionReason::DeviceNotEnrolled,
            ZtnaDecisionReason::DevicePostureStale,
            ZtnaDecisionReason::DevicePostureInsufficient,
            ZtnaDecisionReason::IdentityNotFound,
            ZtnaDecisionReason::MfaStale,
            ZtnaDecisionReason::NotEntitled,
            ZtnaDecisionReason::TenantMismatch,
            ZtnaDecisionReason::Revoked,
            ZtnaDecisionReason::GeoBlocked,
            ZtnaDecisionReason::NetworkTypeBlocked,
            ZtnaDecisionReason::OutsideAllowedHours,
            ZtnaDecisionReason::TagMismatch,
        ] {
            assert!(r.is_deny(), "expected deny: {r:?}");
            assert!(!r.is_allow(), "expected !allow: {r:?}");
        }
    }

    #[test]
    fn allow_when_all_signals_pass() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::BASIC, &["eng"]);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &["eng"], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::Allow);
        assert_eq!(dec.posture_result, PostureResult::Pass);
    }

    #[test]
    fn deny_when_user_not_in_required_groups() {
        let p = policy("t1");
        let a = app("payroll", PostureRequirement::BASIC, &["finance"]);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &["eng"], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::NotEntitled);
        // Short-circuited before the posture check ran
        // — not_evaluated, not fail.
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);
    }

    #[test]
    fn allow_when_required_groups_empty() {
        let p = policy("t1");
        let a = app("public", PostureRequirement::NONE, &[]);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(dec.allow);
    }

    #[test]
    fn deny_on_stale_mfa() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::NONE, &[]);
        let d = device("t1", DevicePosture::pristine(now()));
        // MFA was completed 10 hours ago; default
        // mfa_max_age_ms is 8 hours.
        let u = user("t1", &[], now() - 10 * 60 * 60 * 1_000);
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::MfaStale);
    }

    #[test]
    fn deny_on_stale_posture() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::NONE, &[]);
        let mut posture = DevicePosture::pristine(now());
        // Posture attested 13 hours ago; default
        // device_posture_max_age_ms is 12 hours.
        posture.attested_at_ms = now() - 13 * 60 * 60 * 1_000;
        let d = device("t1", posture);
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::DevicePostureStale);
    }

    #[test]
    fn deny_on_posture_insufficient() {
        let p = policy("t1");
        let a = app("admin", PostureRequirement::STRICT, &[]);
        let mut posture = DevicePosture::pristine(now());
        // Strict requires every signal; drop one.
        posture.antimalware_running = false;
        let d = device("t1", posture);
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::DevicePostureInsufficient);
    }

    #[test]
    fn deny_on_cross_tenant_device() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::NONE, &[]);
        let d = device("t-other", DevicePosture::pristine(now()));
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::TenantMismatch);
    }

    #[test]
    fn deny_on_cross_tenant_identity() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::NONE, &[]);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t-other", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(!dec.allow);
        assert_eq!(dec.reason, ZtnaDecisionReason::TenantMismatch);
    }

    #[test]
    fn empty_tenant_disables_tenant_guard() {
        // Tenant guard is skipped when the policy itself
        // has no tenant — useful for single-tenant
        // deployments where the bundle adapter does not
        // bother setting the tenant string.
        let p = ZtnaPolicy::default();
        let a = app("wiki", PostureRequirement::NONE, &[]);
        let d = device("anything", DevicePosture::pristine(now()));
        let u = user("anything-else", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(dec.allow);
    }

    #[test]
    fn tenant_check_runs_before_group_check() {
        // A user lacking the required group AND in the
        // wrong tenant should deny on tenant first — the
        // tenant signal is structurally cheaper and more
        // informative.
        let p = policy("t1");
        let a = app("payroll", PostureRequirement::BASIC, &["finance"]);
        let d = device("t-other", DevicePosture::pristine(now()));
        let u = user("t-other", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::TenantMismatch);
    }

    #[test]
    fn group_check_runs_before_mfa_check() {
        // If both group and MFA fail, group check fires
        // first (preserves the order in the doc above).
        let p = policy("t1");
        let a = app("payroll", PostureRequirement::NONE, &["finance"]);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &["eng"], now() - 10 * 60 * 60 * 1_000);
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::NotEntitled);
    }

    #[test]
    fn mfa_check_runs_before_posture_freshness() {
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::NONE, &[]);
        let mut posture = DevicePosture::pristine(now());
        posture.attested_at_ms = now() - 13 * 60 * 60 * 1_000;
        let d = device("t1", posture);
        let u = user("t1", &[], now() - 10 * 60 * 60 * 1_000);
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        // MFA is checked before posture freshness.
        assert_eq!(dec.reason, ZtnaDecisionReason::MfaStale);
    }

    #[test]
    fn posture_freshness_runs_before_sufficiency() {
        let p = policy("t1");
        let a = app("admin", PostureRequirement::STRICT, &[]);
        let mut posture = DevicePosture::unmanaged();
        posture.attested_at_ms = now() - 13 * 60 * 60 * 1_000;
        let d = device("t1", posture);
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        // Freshness fires before sufficiency.
        assert_eq!(dec.reason, ZtnaDecisionReason::DevicePostureStale);
    }

    #[test]
    fn decision_serde_roundtrips_via_json() {
        let dec = ZtnaDecision::deny(ZtnaDecisionReason::MfaStale, PostureResult::NotEvaluated);
        let json = serde_json::to_string(&dec).unwrap();
        let back: ZtnaDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(dec, back);
    }

    #[test]
    fn policy_holder_swaps_atomically() {
        let h = ZtnaPolicyHolder::new(policy("t1"));
        assert_eq!(h.snapshot().tenant_id, "t1");
        h.replace(policy("t2"));
        assert_eq!(h.snapshot().tenant_id, "t2");
    }

    #[test]
    fn policy_holder_default_is_empty_tenant() {
        let h = ZtnaPolicyHolder::default();
        assert!(h.snapshot().tenant_id.is_empty());
    }

    #[test]
    fn required_groups_use_set_semantics() {
        // Single intersect element is enough — verify
        // with a larger set so the test does more than
        // exercise the empty-set short circuit.
        let p = policy("t1");
        let mut groups = HashSet::new();
        groups.insert("eng".to_string());
        groups.insert("admin".to_string());
        groups.insert("finance".to_string());
        let a = App {
            app_id: "x".into(),
            display_name: "x".into(),
            host_patterns: Vec::new(),
            required_groups: groups,
            posture_requirement: PostureRequirement::NONE,
            mfa_max_age_override_ms: None,
            conditions: AccessConditions::default(),
            tags: HashMap::new(),
        };
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &["admin"], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(dec.allow);
    }

    #[test]
    fn allow_decision_constructor_sets_posture_result_pass() {
        let dec = ZtnaDecision::allow();
        assert!(dec.allow);
        assert_eq!(dec.posture_result, PostureResult::Pass);
        assert_eq!(dec.reason, ZtnaDecisionReason::Allow);
    }

    #[test]
    fn deny_decision_constructor_preserves_posture_result() {
        // Pre-posture short-circuit deny (e.g. UnknownApp)
        // emits NotEvaluated so dashboards can distinguish
        // it from a posture failure.
        let dec = ZtnaDecision::deny(ZtnaDecisionReason::UnknownApp, PostureResult::NotEvaluated);
        assert!(!dec.allow);
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);
        // A posture-related deny carries Fail; verify the
        // constructor preserves whatever the caller passes
        // (the right variant is chosen by the call site,
        // not the constructor).
        let dec2 = ZtnaDecision::deny(
            ZtnaDecisionReason::DevicePostureInsufficient,
            PostureResult::Fail,
        );
        assert_eq!(dec2.posture_result, PostureResult::Fail);
        // And the constructor also accepts Pass on a deny
        // — the variant is reserved for future checks
        // ordered after the posture check (today the
        // evaluator denies immediately on posture fail,
        // but a future `(deny, Pass)` is structurally
        // valid).
        let dec3 = ZtnaDecision::deny(ZtnaDecisionReason::MfaStale, PostureResult::Pass);
        assert_eq!(dec3.posture_result, PostureResult::Pass);
    }

    #[test]
    fn posture_result_wire_alphabet_is_stable() {
        // The wire form is contract-stable across
        // releases; pin every variant so a renamed
        // serde tag (or a refactor to a different
        // string) fails the build.
        assert_eq!(PostureResult::Pass.as_str(), "pass");
        assert_eq!(PostureResult::Fail.as_str(), "fail");
        assert_eq!(PostureResult::NotEvaluated.as_str(), "not_evaluated");
    }

    #[test]
    fn posture_result_per_deny_branch_matches_contract() {
        // Steps 1–3 (pre-posture short-circuits) emit
        // NotEvaluated; steps 4–5 (posture-related)
        // emit Fail; allow emits Pass. This pins the
        // doc on evaluate_policy as executable contract.
        let p = policy("t1");
        let a = app("wiki", PostureRequirement::BASIC, &["eng"]);

        // Step 1: tenant mismatch — NotEvaluated.
        let d_wrong = device("t2", DevicePosture::pristine(now()));
        let u_ok = user("t1", &["eng"], now());
        let dec = evaluate_policy(&p, inputs(&a, &d_wrong, &u_ok, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::TenantMismatch);
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);

        // Step 2: not entitled — NotEvaluated.
        let d = device("t1", DevicePosture::pristine(now()));
        let u_wrong_group = user("t1", &["sales"], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u_wrong_group, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::NotEntitled);
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);

        // Step 3: MFA stale — NotEvaluated.
        let u_stale_mfa = user("t1", &["eng"], now() - 10 * 60 * 60 * 1_000);
        let dec = evaluate_policy(&p, inputs(&a, &d, &u_stale_mfa, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::MfaStale);
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);

        // Step 4: posture stale — Fail.
        let mut stale_posture = DevicePosture::pristine(now());
        stale_posture.attested_at_ms = now() - 13 * 60 * 60 * 1_000;
        let d_stale = device("t1", stale_posture);
        let dec = evaluate_policy(&p, inputs(&a, &d_stale, &u_ok, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::DevicePostureStale);
        assert_eq!(dec.posture_result, PostureResult::Fail);

        // Step 5: posture insufficient — Fail. Build a
        // *fresh-attested* unmanaged posture so the
        // staleness check (step 4) doesn't fire first.
        let a_strict = app("admin", PostureRequirement::STRICT, &["eng"]);
        let mut unmanaged_fresh = DevicePosture::unmanaged();
        unmanaged_fresh.attested_at_ms = now();
        let d_unmanaged = device("t1", unmanaged_fresh);
        let dec = evaluate_policy(&p, inputs(&a_strict, &d_unmanaged, &u_ok, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::DevicePostureInsufficient);
        assert_eq!(dec.posture_result, PostureResult::Fail);

        // Allow path — Pass.
        let dec = evaluate_policy(&p, inputs(&a, &d, &u_ok, now()));
        assert!(dec.allow);
        assert_eq!(dec.posture_result, PostureResult::Pass);
    }

    // ----- WS2C: access conditions (geo / network / time) -----

    #[test]
    fn tag_condition_matches_every_operator() {
        let mut tags = HashMap::new();
        tags.insert("managed".to_string(), "true".to_string());

        let eq_true = TagCondition {
            key: "managed".into(),
            op: TagOp::Equals,
            value: Some("true".into()),
        };
        assert!(eq_true.matches(&tags));

        let eq_false = TagCondition {
            key: "managed".into(),
            op: TagOp::Equals,
            value: Some("false".into()),
        };
        assert!(!eq_false.matches(&tags));

        // Equals with no value can never match.
        let eq_none = TagCondition {
            key: "managed".into(),
            op: TagOp::Equals,
            value: None,
        };
        assert!(!eq_none.matches(&tags));

        let ne = TagCondition {
            key: "managed".into(),
            op: TagOp::NotEquals,
            value: Some("false".into()),
        };
        assert!(ne.matches(&tags));

        let exists = TagCondition {
            key: "managed".into(),
            op: TagOp::Exists,
            value: None,
        };
        assert!(exists.matches(&tags));

        let exists_missing = TagCondition {
            key: "absent".into(),
            op: TagOp::Exists,
            value: None,
        };
        assert!(!exists_missing.matches(&tags));

        let not_exists = TagCondition {
            key: "absent".into(),
            op: TagOp::NotExists,
            value: None,
        };
        assert!(not_exists.matches(&tags));
    }

    #[test]
    fn time_window_same_day_and_day_filter() {
        // now() is Monday (weekday 1) 13:00 UTC.
        let w = TimeWindow {
            start_hour: 9,
            end_hour: 17,
            days: HashSet::new(),
        };
        assert!(w.contains(now()));

        // End is exclusive: 13:00 is out of a 9→13 window.
        let w_excl = TimeWindow {
            start_hour: 9,
            end_hour: 13,
            days: HashSet::new(),
        };
        assert!(!w_excl.contains(now()));

        // Day filter that excludes Monday rejects even an
        // in-hours request.
        let w_days = TimeWindow {
            start_hour: 9,
            end_hour: 17,
            days: [2u8, 3u8].into_iter().collect(),
        };
        assert!(!w_days.contains(now()));
    }

    #[test]
    fn time_window_wraps_midnight() {
        // 22→06 admits the late tail and early head but not
        // mid-afternoon.
        let w = TimeWindow {
            start_hour: 22,
            end_hour: 6,
            days: HashSet::new(),
        };
        let h = |hour: u64| hour * 3_600_000;
        assert!(w.contains(h(23)));
        assert!(w.contains(h(2)));
        assert!(!w.contains(h(13)));
    }

    #[test]
    fn geo_blocked_when_country_not_in_allow_list() {
        let p = policy("t1");
        let mut a = app("crm", PostureRequirement::NONE, &[]);
        a.conditions.allowed_countries = Some(set(["US", "GB"]));
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &[], now());
        let dec = evaluate_policy(
            &p,
            inputs_ctx(&a, &d, &u, now(), Some("CN"), NetworkType::Unknown),
        );
        assert_eq!(dec.reason, ZtnaDecisionReason::GeoBlocked);
        assert_eq!(dec.posture_result, PostureResult::NotEvaluated);

        // Case-insensitive match on an allowed country
        // passes the geo gate.
        let dec = evaluate_policy(
            &p,
            inputs_ctx(&a, &d, &u, now(), Some("us"), NetworkType::Unknown),
        );
        assert!(dec.allow);
    }

    #[test]
    fn geo_blocked_takes_precedence_over_allow_list() {
        let p = policy("t1");
        let mut a = app("crm", PostureRequirement::NONE, &[]);
        a.conditions.allowed_countries = Some(set(["US", "RU"]));
        a.conditions.blocked_countries = Some(set(["RU"]));
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &[], now());
        let dec = evaluate_policy(
            &p,
            inputs_ctx(&a, &d, &u, now(), Some("RU"), NetworkType::Unknown),
        );
        assert_eq!(dec.reason, ZtnaDecisionReason::GeoBlocked);
    }

    #[test]
    fn geo_blocked_when_country_absent_but_allow_list_set() {
        let p = policy("t1");
        let mut a = app("crm", PostureRequirement::NONE, &[]);
        a.conditions.allowed_countries = Some(set(["US"]));
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &[], now());
        let dec = evaluate_policy(
            &p,
            inputs_ctx(&a, &d, &u, now(), None, NetworkType::Unknown),
        );
        assert_eq!(dec.reason, ZtnaDecisionReason::GeoBlocked);
    }

    #[test]
    fn network_type_blocked_when_not_in_allowed_set() {
        let p = policy("t1");
        let mut a = app("crm", PostureRequirement::NONE, &[]);
        a.conditions.allowed_network_types = Some([NetworkType::Corporate].into_iter().collect());
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs_ctx(&a, &d, &u, now(), None, NetworkType::Public));
        assert_eq!(dec.reason, ZtnaDecisionReason::NetworkTypeBlocked);

        let dec = evaluate_policy(
            &p,
            inputs_ctx(&a, &d, &u, now(), None, NetworkType::Corporate),
        );
        assert!(dec.allow);
    }

    #[test]
    fn outside_allowed_hours_denied() {
        let p = policy("t1");
        let mut a = app("crm", PostureRequirement::NONE, &[]);
        // now() is 13:00 UTC; a 9→12 window excludes it.
        a.conditions.allowed_hours = Some(TimeWindow {
            start_hour: 9,
            end_hour: 12,
            days: HashSet::new(),
        });
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::OutsideAllowedHours);
    }

    #[test]
    fn tag_mismatch_denied_for_device_and_user_conditions() {
        let p = policy("t1");
        let mut a = app("crm", PostureRequirement::NONE, &[]);
        a.conditions.device_tag_conditions = vec![TagCondition {
            key: "managed".into(),
            op: TagOp::Equals,
            value: Some("true".into()),
        }];

        // Device without the required tag is denied.
        let d_bad = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &[], now());
        let dec = evaluate_policy(&p, inputs(&a, &d_bad, &u, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::TagMismatch);

        // Device carrying the tag clears the gate.
        let mut d_ok = device("t1", DevicePosture::pristine(now()));
        d_ok.tags.insert("managed".into(), "true".into());
        let dec = evaluate_policy(&p, inputs(&a, &d_ok, &u, now()));
        assert!(dec.allow);

        // A user tag condition is enforced independently.
        a.conditions.user_tag_conditions = vec![TagCondition {
            key: "risk_tier".into(),
            op: TagOp::NotEquals,
            value: Some("elevated".into()),
        }];
        let mut u_bad = user("t1", &[], now());
        u_bad.tags.insert("risk_tier".into(), "elevated".into());
        let dec = evaluate_policy(&p, inputs(&a, &d_ok, &u_bad, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::TagMismatch);
    }

    #[test]
    fn access_conditions_run_before_group_entitlement() {
        // A geo-blocked request must deny with GeoBlocked,
        // not NotEntitled, even when the user also lacks the
        // group — i.e. step 1.5 precedes step 2.
        let p = policy("t1");
        let mut a = app("crm", PostureRequirement::NONE, &["eng"]);
        a.conditions.blocked_countries = Some(set(["CN"]));
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &["sales"], now()); // wrong group
        let dec = evaluate_policy(
            &p,
            inputs_ctx(&a, &d, &u, now(), Some("CN"), NetworkType::Unknown),
        );
        assert_eq!(dec.reason, ZtnaDecisionReason::GeoBlocked);
    }

    // ----- WS2B: per-app MFA override -----

    #[test]
    fn per_app_mfa_override_tightens_freshness_budget() {
        // Policy default MFA budget is 8h; the app tightens
        // it to 30 minutes. An MFA 1h old is fresh under the
        // policy default but stale under the override.
        let p = policy("t1");
        let mut a = app("crm", PostureRequirement::NONE, &[]);
        a.mfa_max_age_override_ms = Some(30 * 60 * 1_000);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &[], now() - 60 * 60 * 1_000); // 1h old
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert_eq!(dec.reason, ZtnaDecisionReason::MfaStale);

        // Without the override the same request is allowed.
        let mut a_default = app("crm", PostureRequirement::NONE, &[]);
        a_default.mfa_max_age_override_ms = None;
        let dec = evaluate_policy(&p, inputs(&a_default, &d, &u, now()));
        assert!(dec.allow);
    }

    #[test]
    fn per_app_mfa_override_can_loosen_budget() {
        // Policy default is 8h; an MFA 10h old is stale by
        // default but fresh under a 12h override.
        let p = policy("t1");
        let mut a = app("crm", PostureRequirement::NONE, &[]);
        a.mfa_max_age_override_ms = Some(12 * 60 * 60 * 1_000);
        let d = device("t1", DevicePosture::pristine(now()));
        let u = user("t1", &[], now() - 10 * 60 * 60 * 1_000);
        let dec = evaluate_policy(&p, inputs(&a, &d, &u, now()));
        assert!(dec.allow);
    }

    // ----- WS2D: revocation provider -----

    #[test]
    fn static_revocation_list_reports_and_swaps() {
        let rl = StaticRevocationList::new(set(["dev-x"]), set(["user-y"]));
        assert!(rl.is_revoked("dev-x"));
        assert!(!rl.is_revoked("dev-z"));
        assert!(rl.is_user_revoked("user-y"));
        assert!(!rl.is_user_revoked("user-z"));

        rl.replace_devices(set(["dev-z"]));
        assert!(!rl.is_revoked("dev-x"));
        assert!(rl.is_revoked("dev-z"));

        rl.replace_users(HashSet::new());
        assert!(!rl.is_user_revoked("user-y"));
    }

    #[test]
    fn validate_accepts_default_policy() {
        ZtnaPolicy::default()
            .validate()
            .expect("default policy must be valid");
    }

    #[test]
    fn validate_accepts_empty_tenant_id() {
        // Empty tenant_id is the intentional spelling
        // for single-tenant deployments — the multi-
        // tenant bundle-adapter layer adds its own
        // non-empty check. The policy itself must not
        // reject it.
        let p = ZtnaPolicy {
            tenant_id: String::new(),
            ..ZtnaPolicy::default()
        };
        p.validate().expect("empty tenant_id is intentional");
    }

    #[test]
    fn validate_rejects_zero_mfa_freshness() {
        // A zero MFA budget marks every assertion stale
        // — every request becomes a uniform deny. That
        // is almost certainly a misconfigured bundle,
        // not an operator intent, so the policy holder
        // rejects it at load time.
        let p = ZtnaPolicy {
            mfa_max_age_ms: 0,
            ..ZtnaPolicy::default()
        };
        let err = p.validate().expect_err("zero MFA budget must be rejected");
        assert!(matches!(err, ZtnaError::InvalidPolicy(ref m) if m.contains("mfa_max_age_ms")));
    }

    #[test]
    fn validate_rejects_zero_device_posture_freshness() {
        let p = ZtnaPolicy {
            device_posture_max_age_ms: 0,
            ..ZtnaPolicy::default()
        };
        let err = p
            .validate()
            .expect_err("zero posture budget must be rejected");
        assert!(
            matches!(err, ZtnaError::InvalidPolicy(ref m) if m.contains("device_posture_max_age_ms"))
        );
    }

    #[test]
    fn validate_rejects_zero_reeval_interval() {
        // A zero re-evaluation interval would spin the
        // continuous-reeval loop with no delay between
        // sweeps. Disabling continuous re-evaluation is
        // expressed by not spawning the loop, not by a
        // zero cadence, so the policy rejects it.
        let p = ZtnaPolicy {
            reeval_interval_ms: 0,
            ..ZtnaPolicy::default()
        };
        let err = p
            .validate()
            .expect_err("zero reeval interval must be rejected");
        assert!(matches!(err, ZtnaError::InvalidPolicy(ref m) if m.contains("reeval_interval_ms")));
    }

    #[test]
    fn validate_accepts_default_reeval_interval() {
        // The shipped default (60 s) must pass validation
        // unchanged.
        assert_eq!(ZtnaPolicy::default().reeval_interval_ms, 60_000);
        ZtnaPolicy::default()
            .validate()
            .expect("default reeval interval is valid");
    }

    #[test]
    fn policy_holder_try_new_rejects_invalid_policy() {
        let bad = ZtnaPolicy {
            mfa_max_age_ms: 0,
            ..ZtnaPolicy::default()
        };
        let err = ZtnaPolicyHolder::try_new(bad).expect_err("zero MFA budget must be rejected");
        assert!(matches!(err, ZtnaError::InvalidPolicy(_)));
    }

    #[test]
    fn policy_holder_try_replace_preserves_previous_policy_on_invalid_input() {
        // Critical safety property: a bundle adapter
        // that feeds a malformed policy must NOT clobber
        // the last-known-good policy. The data path
        // keeps running with whatever was loaded before.
        let h = ZtnaPolicyHolder::new(policy("t1"));
        let baseline = h.snapshot();
        let bad = ZtnaPolicy {
            mfa_max_age_ms: 0,
            ..ZtnaPolicy::default()
        };
        let err = h
            .try_replace(bad)
            .expect_err("zero MFA budget must be rejected");
        assert!(matches!(err, ZtnaError::InvalidPolicy(_)));
        // Old policy still present (Arc-identity check).
        assert!(Arc::ptr_eq(&baseline, &h.snapshot()));
    }

    #[test]
    fn policy_holder_try_replace_swaps_on_valid_policy() {
        let h = ZtnaPolicyHolder::new(policy("t1"));
        h.try_replace(policy("t2"))
            .expect("valid policy must install");
        assert_eq!(h.snapshot().tenant_id, "t2");
    }
}
