//! Configuration loading and validation.
//!
//! Both binary crates in the workspace (`sng-edge` and
//! `sng-agent`) load their startup configuration through this
//! module. The single entry point is [`Config::load`], which:
//!
//! 1. Reads an optional TOML file at the path supplied (or at
//!    a platform default) for the static parts of the config.
//! 2. Layers environment variables on top — env wins over file
//!    so an operator can override a baked-in value at
//!    deployment time without re-rolling the config file.
//! 3. Validates the resulting struct against an explicit set of
//!    invariants and produces a stable [`ConfigError`] on
//!    failure.
//!
//! The loader is sync because startup blocks on it anyway and
//! `figment` is sync. Hot-reload of config is a separate
//! concern (see `sng-pal`'s SIGHUP / `notify`-based file
//! watcher) that uses the same struct.

use crate::error::ErrorCode;
use crate::ids::{DeviceId, SiteId, TenantId};
use crate::policy::BundleTarget;
use figment::Figment;
use figment::providers::{Env, Format, Toml};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

/// Which binary is consuming this config.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    /// Edge VM appliance.
    Edge,
    /// Endpoint agent.
    Endpoint,
}

impl AgentMode {
    /// The matching [`BundleTarget`] for this mode. Bundles
    /// produced for `Edge` mode are intended for `BundleTarget::Edge`
    /// and so on.
    #[must_use]
    pub const fn bundle_target(self) -> BundleTarget {
        match self {
            Self::Edge => BundleTarget::Edge,
            Self::Endpoint => BundleTarget::Endpoint,
        }
    }
}

/// Top-level configuration struct. Every field has either a
/// safe default or is validated as required at load time —
/// callers never see `None` for a required field.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Whether this process is running as an edge appliance or
    /// an endpoint agent.
    pub mode: AgentMode,
    /// Tenant scope. Required.
    pub tenant_id: TenantId,
    /// Device identifier. Required.
    pub device_id: DeviceId,
    /// Optional site binding.
    #[serde(default)]
    pub site_id: Option<SiteId>,
    /// Control-plane base URL — `sng-comms` joins paths onto
    /// this for policy pull, telemetry push, enrolment, etc.
    pub control_plane_url: String,
    /// Resource budget hints (RAM ceiling, CPU idle ceiling).
    /// Defaults are the production targets — sub-15 MB resident,
    /// sub-0.1% idle CPU for the endpoint agent.
    #[serde(default)]
    pub resource_budget: ResourceBudget,
    /// Telemetry configuration.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// Policy configuration.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Logging configuration.
    #[serde(default)]
    pub logging: LoggingConfig,
}

/// Resource budget hints. Each subsystem reads these and
/// proactively trims when its share of the budget is close to
/// exhausted — the budgets are advisory, not hard limits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceBudget {
    /// Maximum resident memory in megabytes. Default 15.
    pub max_memory_mb: u32,
    /// Maximum idle CPU percentage. Default 0.1.
    pub max_cpu_idle_pct: f32,
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self {
            max_memory_mb: 15,
            max_cpu_idle_pct: 0.1,
        }
    }
}

/// Telemetry pipeline configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Batch size threshold (events) before a synchronous flush.
    pub batch_size: usize,
    /// Maximum age of a buffered batch before a forced flush.
    #[serde(with = "humantime_serde")]
    pub flush_interval: Duration,
    /// Bounded local spool size in bytes. Oldest events are
    /// dropped when full.
    pub spool_size_bytes: u64,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            batch_size: 256,
            flush_interval: Duration::from_secs(2),
            spool_size_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Policy pull configuration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Background poll interval for new bundles.
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
    /// Optional explicit signing key directory path. Defaults
    /// to the platform-specific config path.
    #[serde(default)]
    pub trust_store_path: Option<String>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(30),
            trust_store_path: None,
        }
    }
}

/// Logging configuration. Honours `RUST_LOG` env var (handled
/// by `tracing_subscriber::EnvFilter`) so dynamic verbosity
/// changes don't require a config reload.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// JSON output (true) or human-readable (false). Default
    /// JSON — production deployments ship logs to an aggregator
    /// that wants structured input.
    pub json: bool,
    /// Optional override of the `RUST_LOG` filter string.
    #[serde(default)]
    pub filter: Option<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            json: true,
            filter: None,
        }
    }
}

/// Configuration loading / validation error.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// A required field is missing from both the file and the
    /// environment.
    #[error("missing required config: {0}")]
    Missing(String),
    /// A field is present but invalid (URL parse, range check,
    /// etc.).
    #[error("invalid config field {field}: {reason}")]
    Invalid { field: String, reason: String },
    /// Underlying figment / IO failure.
    #[error("{0}")]
    Source(#[from] figment::Error),
}

impl ConfigError {
    /// Map to the stable workspace error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Missing(_) => ErrorCode::ConfigMissing,
            Self::Invalid { .. } | Self::Source(_) => ErrorCode::ConfigInvalid,
        }
    }
}

impl Config {
    /// Environment-variable prefix. `SNG_TENANT_ID=…` overrides
    /// `tenant_id`, `SNG_TELEMETRY__BATCH_SIZE=…` overrides
    /// `telemetry.batch_size`, etc. The double-underscore
    /// separator between the section name and the leaf field
    /// (`TELEMETRY__BATCH_SIZE`, not `TELEMETRY_BATCH_SIZE`)
    /// matches the `__` convention figment recognises for
    /// nested struct fields. With a single underscore figment
    /// would look for a top-level `telemetry_batch_size` field
    /// that does not exist and the override would silently
    /// fall back to the default.
    pub const ENV_PREFIX: &'static str = "SNG_";

    /// Load configuration. If `path` is `Some` and the file
    /// exists, read it. Then layer env vars on top, then
    /// validate.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut figment = Figment::new();
        if let Some(p) = path
            && p.exists()
        {
            figment = figment.merge(Toml::file(p));
        }
        figment = figment.merge(Env::prefixed(Self::ENV_PREFIX).split("__"));
        let mut cfg: Self = figment.extract()?;
        // The loader is the canonical place where normalisation +
        // validation are sequenced; programmatic callers (tests,
        // hot-reload, etc.) get the same guarantee by calling
        // [`Config::normalize`] then [`Config::validate`]
        // themselves, and the validator enforces the post-
        // condition so a caller that forgets to normalise gets a
        // clear error rather than a silently malformed URL going
        // into the HTTP layer.
        cfg.normalize();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Canonicalise whitespace-sensitive fields on the config.
    /// `Config::load` calls this automatically; programmatic
    /// callers that build a [`Config`] from scratch must call it
    /// themselves before [`Config::validate`] (the validator
    /// rejects un-normalised values rather than silently letting
    /// them through, so the API surface is unambiguous about
    /// which step owns the rewrite vs. the check).
    ///
    /// Today's transforms cover the `control_plane_url`; future
    /// fields can be added here without touching call sites.
    pub fn normalize(&mut self) {
        self.control_plane_url = normalise_control_plane_url(&self.control_plane_url);
    }

    /// Validate invariants on a `Config`.
    ///
    /// `Config::load` runs [`Config::normalize`] before this; a
    /// programmatic caller that bypasses `load` (e.g. test
    /// fixtures, the future SIGHUP hot-reload path) MUST also
    /// normalise first — this method takes `&self` so it cannot
    /// silently mutate the URL on the caller's behalf. The check
    /// at the bottom of this function rejects un-normalised
    /// values with a clear `ConfigError::Invalid` so the
    /// programmer error surfaces immediately, not as a confusing
    /// 404 from the HTTP layer.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.tenant_id.is_nil() {
            return Err(ConfigError::Missing("tenant_id".into()));
        }
        if self.device_id.is_nil() {
            return Err(ConfigError::Missing("device_id".into()));
        }
        // Trim once so the emptiness check and the structural
        // prefix check are evaluated against the same string. If
        // we trimmed only one side, an operator who pasted
        // " https://cp.example.com" would survive the emptiness
        // check (trimmed) and then trip the prefix check
        // (untrimmed), producing the confusing error "must start
        // with http:// or https://" against a value that visibly
        // does.
        let url = self.control_plane_url.trim();
        if url.is_empty() {
            return Err(ConfigError::Missing("control_plane_url".into()));
        }
        // Cheap structural URL check — full URL parsing is the
        // `sng-comms` layer's concern, but rejecting obvious
        // garbage at load time produces a much better operator
        // error than waiting for the first HTTP attempt.
        //
        // We strip the scheme prefix and verify there is at
        // least one character of host after it. Without this the
        // bare-scheme strings `http://` / `https://` survive the
        // prefix check above and the canonicality check below
        // (normalisation is idempotent on them), then fail at
        // `sng-comms` connect time with an opaque resolver
        // error. Catching it at the config layer surfaces the
        // typo with a clear field reference for the operator.
        let after_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"));
        match after_scheme {
            None => {
                return Err(ConfigError::Invalid {
                    field: "control_plane_url".into(),
                    reason: "must start with http:// or https://".into(),
                });
            }
            Some("") => {
                return Err(ConfigError::Invalid {
                    field: "control_plane_url".into(),
                    reason: "missing host after scheme (got bare scheme like `https://`)".into(),
                });
            }
            Some(_) => {}
        }
        // Defence-in-depth: refuse to silently accept an
        // un-normalised URL even though it would still resolve.
        // Programmatic callers that build a `Config` and call
        // `validate()` without `normalize()` get a precise
        // pointer to the missing step instead of a confusing
        // double-slashed request appearing in `sng-comms` logs.
        let canonical = normalise_control_plane_url(&self.control_plane_url);
        if canonical != self.control_plane_url {
            return Err(ConfigError::Invalid {
                field: "control_plane_url".into(),
                reason: "must be normalised (call Config::normalize before validate)".into(),
            });
        }
        if self.resource_budget.max_memory_mb == 0 {
            return Err(ConfigError::Invalid {
                field: "resource_budget.max_memory_mb".into(),
                reason: "must be > 0".into(),
            });
        }
        if !(0.0..=100.0).contains(&self.resource_budget.max_cpu_idle_pct) {
            return Err(ConfigError::Invalid {
                field: "resource_budget.max_cpu_idle_pct".into(),
                reason: "must be within [0, 100]".into(),
            });
        }
        if self.telemetry.batch_size == 0 {
            return Err(ConfigError::Invalid {
                field: "telemetry.batch_size".into(),
                reason: "must be > 0".into(),
            });
        }
        if self.telemetry.flush_interval.is_zero() {
            return Err(ConfigError::Invalid {
                field: "telemetry.flush_interval".into(),
                reason: "must be > 0".into(),
            });
        }
        if self.telemetry.spool_size_bytes == 0 {
            return Err(ConfigError::Invalid {
                field: "telemetry.spool_size_bytes".into(),
                reason: "must be > 0".into(),
            });
        }
        if self.policy.poll_interval.is_zero() {
            return Err(ConfigError::Invalid {
                field: "policy.poll_interval".into(),
                reason: "must be > 0".into(),
            });
        }
        Ok(())
    }
}

/// `humantime`-style Duration serde helper. Lets the config
/// file say `flush_interval = "2s"` rather than `2_000_000_000`
/// nanoseconds.
mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub(super) fn serialize<S: Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format_duration(*d))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
        // Accept either an integer (seconds, matching the env
        // var case where everything is a string) or a string
        // like "2s" / "500ms" / "1m".
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Either {
            Str(String),
            Secs(u64),
        }
        match Either::deserialize(d)? {
            Either::Secs(n) => Ok(Duration::from_secs(n)),
            Either::Str(s) => parse_duration(&s).map_err(serde::de::Error::custom),
        }
    }

    fn format_duration(d: Duration) -> String {
        let total_ms = d.as_millis();
        if total_ms.is_multiple_of(1_000) {
            format!("{}s", total_ms / 1_000)
        } else {
            format!("{total_ms}ms")
        }
    }

    fn parse_duration(s: &str) -> Result<Duration, String> {
        let s = s.trim();
        // Suffix-aware fast path. `checked_mul` keeps the
        // hours/days variants safe from a configured value
        // close to `u64::MAX`: a release build would otherwise
        // wrap silently and produce a wildly short duration,
        // and a debug build would panic. Both modes now surface
        // a stable parse error string that propagates through
        // figment as a config-load failure.
        if let Some(stripped) = s.strip_suffix("ms") {
            stripped
                .parse::<u64>()
                .map(Duration::from_millis)
                .map_err(|e| format!("{e}"))
        } else if let Some(stripped) = s.strip_suffix('s') {
            stripped
                .parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|e| format!("{e}"))
        } else if let Some(stripped) = s.strip_suffix('m') {
            let n: u64 = stripped
                .parse()
                .map_err(|e: std::num::ParseIntError| e.to_string())?;
            n.checked_mul(60)
                .map(Duration::from_secs)
                .ok_or_else(|| format!("duration overflow: {n} minutes exceeds u64 seconds range"))
        } else if let Some(stripped) = s.strip_suffix('h') {
            let n: u64 = stripped
                .parse()
                .map_err(|e: std::num::ParseIntError| e.to_string())?;
            n.checked_mul(3_600)
                .map(Duration::from_secs)
                .ok_or_else(|| format!("duration overflow: {n} hours exceeds u64 seconds range"))
        } else if let Some(stripped) = s.strip_suffix('d') {
            let n: u64 = stripped
                .parse()
                .map_err(|e: std::num::ParseIntError| e.to_string())?;
            n.checked_mul(86_400)
                .map(Duration::from_secs)
                .ok_or_else(|| format!("duration overflow: {n} days exceeds u64 seconds range"))
        } else {
            // Bare number = seconds.
            s.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|e| format!("{e}"))
        }
    }
}

/// Normalise the operator-supplied control-plane URL. Cheap,
/// deterministic transforms only — full URL parsing is
/// `sng-comms`' concern.
///
/// Two transforms today:
///   1. trim surrounding whitespace (operator pasted a newline);
///   2. strip *all* trailing `/` characters. The `sng-comms` HTTP
///      layer builds request paths with explicit leading slashes
///      (`format!("{base}/api/v1/tenants/...")`), so any trailing
///      slash on `base` produces double-slashed URLs that some
///      proxies normalise and others reject. Strip them all here
///      so a copy-paste mistake like `https://cp.example.com//`
///      (two slashes) is reduced to the canonical form — the
///      previous single-slash strip would leave that case with
///      one remaining slash and produce the very double-slashed
///      requests this function exists to prevent.
///
/// The function is intentionally NOT exposed: callers must go
/// through [`Config::load`] / [`Config::normalize`] /
/// [`Config::validate`] so the invariants stay enforced in one
/// place.
fn normalise_control_plane_url(raw: &str) -> String {
    let trimmed = raw.trim();
    // Strip every trailing slash, but only down to the authority
    // boundary. Bare-scheme values like `"https://"` shrink to
    // `"https:/"` if naively trimmed, which `validate()` would
    // then reject with a confusing "must start with http:// or
    // https://" error against a value that visibly does. Detect
    // that case by checking whether the trimmed result still
    // contains an authority component (anything past the
    // `<scheme>://` prefix).
    let stripped = trimmed.trim_end_matches('/');
    // Canonicalise the bare-scheme inputs to exactly `"http://"` /
    // `"https://"`. An earlier version returned `trimmed` here,
    // which let an operator paste like `"https:////"` survive as-is
    // (it passes the validator's prefix check because it still
    // starts with `"https://"` and the normaliser is idempotent on
    // it, so the canonicality check at the end of `validate` does
    // not flag it either). The strip-all-trailing-slashes invariant
    // matters even for bare-scheme values, so rewrite the operator-
    // visible form to its single canonical spelling. The previous
    // suffix-based guard (`stripped.ends_with(':')`) was even more
    // over-broad — it incorrectly matched `"https://host:/"` (an
    // authority with an open port-separator) and left the trailing
    // slash on `"https://host:"`, leaking into `sng-comms`'
    // double-slashed requests. Match the bare scheme exactly so
    // every authority-carrying URL falls through the canonical
    // strip path.
    if stripped == "http:" {
        "http://".to_owned()
    } else if stripped == "https:" {
        "https://".to_owned()
    } else {
        stripped.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::NamedTempFile;
    use uuid::Uuid;

    fn valid_config() -> Config {
        Config {
            mode: AgentMode::Endpoint,
            tenant_id: TenantId::from_uuid(Uuid::new_v4()),
            device_id: DeviceId::from_uuid(Uuid::new_v4()),
            site_id: None,
            control_plane_url: "https://cp.example.com".into(),
            resource_budget: ResourceBudget::default(),
            telemetry: TelemetryConfig::default(),
            policy: PolicyConfig::default(),
            logging: LoggingConfig::default(),
        }
    }

    #[test]
    fn validate_accepts_a_well_formed_config() {
        valid_config().validate().expect("valid");
    }

    #[test]
    fn validate_rejects_nil_tenant() {
        let mut c = valid_config();
        c.tenant_id = TenantId::nil();
        let err = c.validate().expect_err("nil tenant");
        assert_eq!(err.code(), ErrorCode::ConfigMissing);
    }

    #[test]
    fn validate_rejects_nil_device() {
        let mut c = valid_config();
        c.device_id = DeviceId::nil();
        assert!(matches!(c.validate(), Err(ConfigError::Missing(f)) if f == "device_id"));
    }

    #[test]
    fn validate_rejects_empty_control_plane_url() {
        let mut c = valid_config();
        c.control_plane_url = String::new();
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_non_http_url() {
        let mut c = valid_config();
        c.control_plane_url = "ftp://cp.example.com".into();
        assert!(matches!(
            c.validate(),
            Err(ConfigError::Invalid { field, .. }) if field == "control_plane_url"
        ));
    }

    #[test]
    fn validate_rejects_bare_scheme_url() {
        // `https://` (and `http://`) survive the scheme-prefix
        // check and `normalise_control_plane_url` is idempotent
        // on them, so without the post-scheme host check both
        // bare schemes would silently validate and only fail at
        // `sng-comms` connect time with an opaque resolver error.
        // The defence-in-depth check at the config layer catches
        // the typo with a clear `control_plane_url` field tag.
        for bare in ["https://", "http://"] {
            let mut c = valid_config();
            c.control_plane_url = bare.into();
            let err = c.validate().expect_err("bare scheme rejected");
            match err {
                ConfigError::Invalid { field, reason } => {
                    assert_eq!(field, "control_plane_url");
                    assert!(
                        reason.contains("host") || reason.contains("bare scheme"),
                        "reason should mention missing host: {reason}"
                    );
                }
                other => panic!("unexpected error for {bare:?}: {other:?}"),
            }
        }
    }

    #[test]
    fn validate_rejects_un_normalised_url_until_normalize_runs() {
        // The new API contract: `validate()` rejects un-normalised
        // URLs so a programmatic caller that forgets to call
        // `normalize()` gets a precise error pointing at the missing
        // step, not a confusing 404 from `sng-comms` later. Padding
        // the URL with whitespace surfaces this: the structural
        // prefix check still passes (it trims internally), but the
        // post-condition check at the bottom of `validate()` fails
        // because the stored value isn't yet canonical.
        let mut c = valid_config();
        c.control_plane_url = "  https://cp.example.com\n".into();
        let err = c.validate().expect_err("un-normalised URL rejected");
        assert!(
            matches!(&err, ConfigError::Invalid { field, reason } if field == "control_plane_url" && reason.contains("normali"))
        );
        // After `normalize()` the same config validates cleanly.
        c.normalize();
        assert_eq!(c.control_plane_url, "https://cp.example.com");
        c.validate().expect("normalised URL is valid");
    }

    #[test]
    fn validate_rejects_un_normalised_url_with_trailing_slash() {
        // Same contract, different failure mode: a stored value
        // with a trailing slash is what `load()` would strip but
        // a programmatic caller might not. Confirming the
        // post-condition fires here too proves the check is on the
        // canonical form, not on a specific whitespace pattern.
        let mut c = valid_config();
        c.control_plane_url = "https://cp.example.com/".into();
        assert!(matches!(
            c.validate(),
            Err(ConfigError::Invalid { field, .. }) if field == "control_plane_url"
        ));
    }

    #[test]
    fn normalize_is_idempotent() {
        // Calling `normalize()` twice must produce the same value
        // as calling it once — `validate()` depends on this to
        // detect un-normalised inputs by comparing against a
        // single round of normalisation.
        let mut c = valid_config();
        c.control_plane_url = "  https://cp.example.com///  ".into();
        c.normalize();
        let first = c.control_plane_url.clone();
        c.normalize();
        assert_eq!(first, c.control_plane_url);
        assert_eq!(c.control_plane_url, "https://cp.example.com");
    }

    #[test]
    fn validate_rejects_whitespace_only_url() {
        // Inverse of the above: trimmed-empty must still fail
        // the emptiness check, not silently fall through to the
        // structural check.
        let mut c = valid_config();
        c.control_plane_url = "   \n\t".into();
        assert!(matches!(
            c.validate(),
            Err(ConfigError::Missing(f)) if f == "control_plane_url"
        ));
    }

    #[test]
    fn validate_rejects_zero_memory_budget() {
        let mut c = valid_config();
        c.resource_budget.max_memory_mb = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_out_of_range_cpu_budget() {
        let mut c = valid_config();
        c.resource_budget.max_cpu_idle_pct = -1.0;
        assert!(c.validate().is_err());
        c.resource_budget.max_cpu_idle_pct = 101.0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_batch_size() {
        let mut c = valid_config();
        c.telemetry.batch_size = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_durations() {
        let mut c = valid_config();
        c.telemetry.flush_interval = Duration::from_secs(0);
        assert!(c.validate().is_err());
        let mut c = valid_config();
        c.policy.poll_interval = Duration::from_secs(0);
        assert!(c.validate().is_err());
    }

    #[test]
    fn agent_mode_maps_to_matching_bundle_target() {
        assert_eq!(AgentMode::Edge.bundle_target(), BundleTarget::Edge);
        assert_eq!(AgentMode::Endpoint.bundle_target(), BundleTarget::Endpoint);
    }

    #[test]
    fn load_reads_a_toml_file() {
        let tenant = Uuid::new_v4();
        let device = Uuid::new_v4();
        let toml_body = format!(
            r#"
mode = "endpoint"
tenant_id = "{tenant}"
device_id = "{device}"
control_plane_url = "https://cp.example.com"

[resource_budget]
max_memory_mb = 32
max_cpu_idle_pct = 0.5

[telemetry]
batch_size = 512
flush_interval = "3s"
spool_size_bytes = 1048576

[policy]
poll_interval = "60s"

[logging]
json = false
"#
        );
        // figment::Jail clears any `SNG_*` env vars another
        // parallel test may have set; without it, the
        // `load_env_overrides_file` test running concurrently
        // can leak a `SNG_TELEMETRY__BATCH_SIZE=999` into this
        // process's env and break the file-only assertion.
        figment::Jail::expect_with(|jail| {
            let mut file =
                NamedTempFile::new().map_err(|e| figment::Error::from(format!("{e}")))?;
            std::io::Write::write_all(&mut file, toml_body.as_bytes())
                .map_err(|e| figment::Error::from(format!("{e}")))?;
            // Persist the file outside the Jail's temp dir so
            // it doesn't get yanked when Jail drops.
            let path = file.path().to_owned();
            let _ = jail; // unused after env reset
            let cfg =
                Config::load(Some(&path)).map_err(|e| figment::Error::from(format!("{e}")))?;
            assert_eq!(cfg.tenant_id.into_uuid(), tenant);
            assert_eq!(cfg.resource_budget.max_memory_mb, 32);
            assert_eq!(cfg.telemetry.batch_size, 512);
            assert_eq!(cfg.telemetry.flush_interval, Duration::from_secs(3));
            assert_eq!(cfg.policy.poll_interval, Duration::from_secs(60));
            assert!(!cfg.logging.json);
            Ok(())
        });
    }

    #[test]
    fn load_env_overrides_file() {
        // env var wins — figment's last-merged provider wins.
        let tenant = Uuid::new_v4();
        let device = Uuid::new_v4();
        let toml_body = format!(
            r#"
mode = "endpoint"
tenant_id = "{tenant}"
device_id = "{device}"
control_plane_url = "https://cp.example.com"

[telemetry]
batch_size = 1
flush_interval = "1s"
spool_size_bytes = 1024

[policy]
poll_interval = "1s"
"#
        );
        figment::Jail::expect_with(|jail| {
            let mut file =
                NamedTempFile::new().map_err(|e| figment::Error::from(format!("{e}")))?;
            std::io::Write::write_all(&mut file, toml_body.as_bytes())
                .map_err(|e| figment::Error::from(format!("{e}")))?;
            jail.set_env("SNG_TELEMETRY__BATCH_SIZE", "999");
            let cfg = Config::load(Some(file.path()))
                .map_err(|e| figment::Error::from(format!("{e}")))?;
            assert_eq!(cfg.telemetry.batch_size, 999);
            Ok(())
        });
    }

    #[test]
    fn load_missing_required_field_errors() {
        // No file, no env → tenant_id missing.
        figment::Jail::expect_with(|_jail| {
            let err = Config::load(None).expect_err("must error");
            // Either the source error (figment couldn't extract
            // a required field) or our explicit Missing variant
            // is acceptable — both surface as `config.invalid`
            // or `config.missing` to dashboards.
            let code = err.code();
            assert!(matches!(
                code,
                ErrorCode::ConfigMissing | ErrorCode::ConfigInvalid
            ));
            Ok(())
        });
    }

    #[test]
    fn load_normalises_control_plane_url() {
        // Regression test for the case where an operator pastes
        // a URL with stray whitespace into a config file or env
        // var: validation must accept it AND the stored value
        // must be the trimmed form so downstream consumers
        // (sng-comms) feed a clean URL into their HTTP client.
        let tenant = Uuid::new_v4();
        let device = Uuid::new_v4();
        let toml_body = format!(
            r#"
mode = "endpoint"
tenant_id = "{tenant}"
device_id = "{device}"
control_plane_url = "  https://cp.example.com\n"

[telemetry]
batch_size = 1
flush_interval = "1s"
spool_size_bytes = 1024

[policy]
poll_interval = "1s"
"#
        );
        figment::Jail::expect_with(|_jail| {
            let mut file =
                NamedTempFile::new().map_err(|e| figment::Error::from(format!("{e}")))?;
            std::io::Write::write_all(&mut file, toml_body.as_bytes())
                .map_err(|e| figment::Error::from(format!("{e}")))?;
            let cfg = Config::load(Some(file.path()))
                .map_err(|e| figment::Error::from(format!("{e}")))?;
            assert_eq!(cfg.control_plane_url, "https://cp.example.com");
            Ok(())
        });
    }

    /// Regression test: a single trailing slash on the
    /// control-plane URL must be stripped on load so the
    /// canonical form is what downstream consumers see.
    /// `sng-comms` builds request paths like
    /// `format!("{base}/api/v1/...")` — a trailing slash on
    /// `base` would otherwise produce `https://cp//api/v1/...`,
    /// which some proxies normalise and others 404 on.
    #[test]
    fn load_strips_trailing_slash_on_control_plane_url() {
        let tenant = Uuid::new_v4();
        let device = Uuid::new_v4();
        let toml_body = format!(
            r#"
mode = "endpoint"
tenant_id = "{tenant}"
device_id = "{device}"
control_plane_url = "https://cp.example.com/"

[telemetry]
batch_size = 1
flush_interval = "1s"
spool_size_bytes = 1024

[policy]
poll_interval = "1s"
"#
        );
        figment::Jail::expect_with(|_jail| {
            let mut file =
                NamedTempFile::new().map_err(|e| figment::Error::from(format!("{e}")))?;
            std::io::Write::write_all(&mut file, toml_body.as_bytes())
                .map_err(|e| figment::Error::from(format!("{e}")))?;
            let cfg = Config::load(Some(file.path()))
                .map_err(|e| figment::Error::from(format!("{e}")))?;
            assert_eq!(cfg.control_plane_url, "https://cp.example.com");
            Ok(())
        });
    }

    /// A bare scheme (`https://`) — which lacks a host — must
    /// NOT have its trailing slash stripped, because that would
    /// reduce it to `https:`, which the prefix check in
    /// `validate()` would then reject with a confusing error.
    /// Operator-supplied URLs of this shape are still nonsense
    /// (no host) but the failure mode should be the existing
    /// "must start with http:// or https://" path, not a
    /// shape-mangled empty-host string.
    #[test]
    fn url_normalisation_preserves_bare_scheme() {
        // White-box test the helper directly so we exercise the
        // edge case without depending on validate() ordering.
        assert_eq!(super::normalise_control_plane_url("https://"), "https://");
        assert_eq!(super::normalise_control_plane_url("http://"), "http://");
        assert_eq!(
            super::normalise_control_plane_url("https://cp.example.com"),
            "https://cp.example.com",
        );
        assert_eq!(
            super::normalise_control_plane_url("https://cp.example.com/"),
            "https://cp.example.com",
        );
    }

    #[test]
    fn url_normalisation_strips_multiple_trailing_slashes() {
        // An operator paste like `https://cp.example.com//` (a
        // common shape when joining a base URL with a leading
        // slash in some templating systems) must reduce all the
        // way to the canonical no-slash form. The previous
        // single-slash strip left this case with one remaining
        // slash, which then produced the double-slashed request
        // the helper exists to prevent. The bare-scheme guard
        // still applies: `https:////` would otherwise collapse
        // to `https:` and trip the prefix check with a confusing
        // error against a value the operator can see is wrong.
        assert_eq!(
            super::normalise_control_plane_url("https://cp.example.com//"),
            "https://cp.example.com",
        );
        assert_eq!(
            super::normalise_control_plane_url("https://cp.example.com////"),
            "https://cp.example.com",
        );
        // Bare scheme with many slashes is canonicalised to the
        // single spelling, not preserved verbatim — `"https:////"`
        // would otherwise survive the prefix check in `validate`
        // (still starts with `"https://"`) and the canonicality
        // post-condition (idempotent under the normaliser) and
        // leak through to `sng-comms` as a double-slashed request.
        assert_eq!(super::normalise_control_plane_url("https:////"), "https://");
        assert_eq!(super::normalise_control_plane_url("http:////"), "http://");
    }

    /// Regression for the port-separator-colon edge case. A value
    /// like `"https://host:/"` is a typo, not a bare scheme — the
    /// trailing slash must still be stripped so `sng-comms` does
    /// not get a double-slashed request. The previous
    /// `stripped.ends_with(':')` guard over-matched this case and
    /// returned the un-stripped form; the exact bare-scheme match
    /// keeps the strip path firing here.
    #[test]
    fn url_normalisation_strips_slash_after_port_colon() {
        assert_eq!(
            super::normalise_control_plane_url("https://host:/"),
            "https://host:",
        );
        assert_eq!(
            super::normalise_control_plane_url("https://host://"),
            "https://host:",
        );
        assert_eq!(
            super::normalise_control_plane_url("http://host:8080/"),
            "http://host:8080",
        );
        assert_eq!(
            super::normalise_control_plane_url("http://host:8080//"),
            "http://host:8080",
        );
    }

    /// Regression test for the duration parser's overflow
    /// branches: `n * (60 | 3_600 | 86_400)` would silently
    /// wrap in a release build and panic in debug for `n`
    /// close to `u64::MAX`. The `checked_mul` rewrite surfaces
    /// a stable parse-error string that propagates through
    /// figment as a config-load failure regardless of build
    /// mode. We deliberately pick the smallest `n` that
    /// overflows each multiplier so the test does not depend
    /// on the exact wrapping behaviour.
    #[test]
    fn parse_duration_rejects_overflow_in_minutes_hours_days() {
        for (suffix, divisor) in [("m", 60_u64), ("h", 3_600), ("d", 86_400)] {
            let smallest_overflow = (u64::MAX / divisor) + 1;
            let raw = format!("{smallest_overflow}{suffix}");
            // Deserialise via the same path Config::load uses,
            // through humantime_serde, by hand-building a JSON
            // string and routing it through serde_json.
            let r: Result<std::time::Duration, _> =
                serde_json::from_str(&format!("\"{raw}\"")).map(|d: Wrap| d.0);
            let err = r.expect_err(&format!("{raw} must overflow"));
            let msg = err.to_string();
            assert!(
                msg.contains("overflow"),
                "{raw} expected overflow error, got: {msg}",
            );
        }
    }

    /// Test-only wrapper that routes through `humantime_serde`
    /// so the overflow test exercises the same deserialisation
    /// path Config::load uses.
    #[derive(serde::Deserialize)]
    struct Wrap(#[serde(with = "humantime_serde")] std::time::Duration);
}
