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
    /// `tenant_id`, `SNG_TELEMETRY_BATCH_SIZE=…` overrides
    /// `telemetry.batch_size`, etc. The double-underscore
    /// separator matches the `__` convention figment recognises
    /// for nested struct fields.
    pub const ENV_PREFIX: &'static str = "SNG_";

    /// Load configuration. If `path` is `Some` and the file
    /// exists, read it. Then layer env vars on top, then
    /// validate.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        let mut figment = Figment::new();
        if let Some(p) = path {
            if p.exists() {
                figment = figment.merge(Toml::file(p));
            }
        }
        figment = figment.merge(Env::prefixed(Self::ENV_PREFIX).split("__"));
        let cfg: Self = figment.extract()?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Validate invariants on an already-deserialised config.
    /// Public so callers that build a config programmatically
    /// (e.g. tests) can run the same validation as the
    /// production loader.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.tenant_id.is_nil() {
            return Err(ConfigError::Missing("tenant_id".into()));
        }
        if self.device_id.is_nil() {
            return Err(ConfigError::Missing("device_id".into()));
        }
        if self.control_plane_url.trim().is_empty() {
            return Err(ConfigError::Missing("control_plane_url".into()));
        }
        // Cheap structural URL check — full URL parsing is the
        // `sng-comms` layer's concern, but rejecting obvious
        // garbage at load time produces a much better operator
        // error than waiting for the first HTTP attempt.
        if !self.control_plane_url.starts_with("http://")
            && !self.control_plane_url.starts_with("https://")
        {
            return Err(ConfigError::Invalid {
                field: "control_plane_url".into(),
                reason: "must start with http:// or https://".into(),
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
        if total_ms % 1_000 == 0 {
            format!("{}s", total_ms / 1_000)
        } else {
            format!("{total_ms}ms")
        }
    }

    fn parse_duration(s: &str) -> Result<Duration, String> {
        let s = s.trim();
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
            stripped
                .parse::<u64>()
                .map(|n| Duration::from_secs(n * 60))
                .map_err(|e| format!("{e}"))
        } else {
            // Bare number = seconds.
            s.parse::<u64>()
                .map(Duration::from_secs)
                .map_err(|e| format!("{e}"))
        }
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
}
