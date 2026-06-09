// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! `sng-agent` TOML config schema.
//!
//! Each subsystem's settings map onto a dedicated `[section]`.
//! Defaults are deliberately conservative — the binary refuses
//! to boot with a default-only config because the operator must
//! at minimum specify a control-plane endpoint + tenant + device
//! identity.
//!
//! Schema mirrors the relevant subset of
//! [`sng_edge::EdgeConfig`] but drops every subsystem the
//! endpoint agent does not run (DNS / FW / IPS / SWG / SD-WAN /
//! updater) and adds the PAL-specific knobs (capture / posture
//! / tunnel cadence + optional native-backend tuning).

use sng_core::ids::{DeviceId, SiteId, TenantId};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

/// Top-level agent config. One TOML file per endpoint.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// Device identity binding (tenant / device / optional
    /// site). Used by every subsystem that emits telemetry so
    /// the envelopes carry the right routing keys.
    pub identity: IdentityConfig,
    /// Control-plane endpoint and authentication material.
    pub comms: CommsConfig,
    /// Policy bundle pull cadence + cache override.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Telemetry pipeline tuning.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// ZTNA settings.
    #[serde(default)]
    pub ztna: ZtnaConfig,
    /// PAL traffic-capture loop tuning.
    #[serde(default)]
    pub capture: CaptureConfig,
    /// PAL posture-collector cadence.
    #[serde(default)]
    pub posture: PostureConfig,
    /// PAL tunnel-provider cadence.
    #[serde(default)]
    pub tunnel: TunnelConfig,
    /// Endpoint DLP (sng-dlp) channel-monitoring settings.
    #[serde(default)]
    pub dlp: DlpConfig,
    /// Per-subsystem drain budget overrides. Subsystems not
    /// listed here use the supervisor's default (30s).
    #[serde(default)]
    pub supervisor: SupervisorConfig,
}

/// Device-identity binding shared across every subsystem.
///
/// The endpoint agent's `site_id` is optional — a roaming
/// laptop's "site" is implicit (the user's home / the office
/// they're connected from), and the control plane derives it
/// from the tunnel egress IP when needed. The field stays in
/// the schema so an operator can pin a fixed-location endpoint
/// (e.g. a kiosk machine) when desired.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Tenant the agent is enrolled into.
    pub tenant_id: TenantId,
    /// Stable device id (also used as the agent id on the
    /// control-plane side).
    pub device_id: DeviceId,
    /// Optional site binding. Omitted for roaming endpoints.
    #[serde(default)]
    pub site_id: Option<SiteId>,
}

/// Control-plane endpoint + identity material.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommsConfig {
    /// `host:port` of the control-plane HTTP/2 endpoint.
    pub endpoint: String,
    /// SNI / server-cert hostname. Defaults to the host
    /// portion of `endpoint` when not specified.
    #[serde(default)]
    pub server_name: Option<String>,
    /// Path to the agent's client certificate (PEM chain).
    pub client_cert: PathBuf,
    /// Path to the agent's client private key (Ed25519 PEM).
    pub client_key: PathBuf,
    /// Optional path to a trust roots bundle. When omitted,
    /// the binary uses the webpki built-in roots
    /// ([`sng_comms::build_client_config_with_webpki_roots`]).
    #[serde(default)]
    pub trust_roots: Option<PathBuf>,
    /// Initial reconnect backoff. Default: 250ms.
    #[serde(default = "default_backoff_initial")]
    #[serde(with = "humantime_serde")]
    pub backoff_initial: Duration,
    /// Maximum reconnect backoff. Default: 30s.
    #[serde(default = "default_backoff_max")]
    #[serde(with = "humantime_serde")]
    pub backoff_max: Duration,
}

/// Policy bundle pull settings.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Path override for the bundle pull endpoint. When
    /// omitted the puller uses the canonical
    /// `/api/v1/tenants/{tid}/policy/bundles/{target}/payload`
    /// path.
    #[serde(default)]
    pub path_override: Option<String>,
    /// How often to poll for new bundles. Default: 60s.
    #[serde(default = "default_policy_pull_interval")]
    #[serde(with = "humantime_serde")]
    pub pull_interval: Duration,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            path_override: None,
            pull_interval: default_policy_pull_interval(),
        }
    }
}

/// Telemetry pipeline tuning. Shape matches the relevant
/// subset of [`sng_telemetry::PipelineConfig`] one-for-one.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Producer → pipeline channel capacity.
    #[serde(default = "default_event_channel_capacity")]
    pub event_channel_capacity: usize,
    /// Rolling dedup window.
    #[serde(default = "default_dedup_window")]
    #[serde(with = "humantime_serde")]
    pub dedup_window: Duration,
    /// Max dedup entries before forced eviction.
    #[serde(default = "default_dedup_max_entries")]
    pub dedup_max_entries: usize,
    /// Pipeline tick interval.
    #[serde(default = "default_tick_interval")]
    #[serde(with = "humantime_serde")]
    pub tick_interval: Duration,
    /// Local egress spool capacity (number of batches).
    #[serde(default = "default_spool_capacity")]
    pub spool_capacity: usize,
    /// Telemetry endpoint path on the control plane. Defaults
    /// to `/api/v1/agents/telemetry/batches`.
    #[serde(default = "default_telemetry_path")]
    pub egress_path: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            event_channel_capacity: default_event_channel_capacity(),
            dedup_window: default_dedup_window(),
            dedup_max_entries: default_dedup_max_entries(),
            tick_interval: default_tick_interval(),
            spool_capacity: default_spool_capacity(),
            egress_path: default_telemetry_path(),
        }
    }
}

/// ZTNA service settings.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZtnaConfig {
    /// Producer-enforced ceiling on the number of concurrent
    /// ZTNA evaluations the brain advertises it can handle.
    /// Default: 256 (endpoints typically have a much smaller
    /// in-flight footprint than the edge).
    #[serde(default = "default_ztna_max_inflight")]
    pub max_inflight: usize,
}

impl Default for ZtnaConfig {
    fn default() -> Self {
        Self {
            max_inflight: default_ztna_max_inflight(),
        }
    }
}

/// PAL capture-loop tuning.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    /// Polling cadence for the capture-loop yield-or-sleep
    /// path. The loop drains the capture buffer as fast as
    /// the OS produces packets; this knob only kicks in when
    /// the buffer reports empty.
    #[serde(default = "default_capture_idle_sleep", with = "humantime_serde")]
    pub idle_sleep: Duration,
    /// Per-batch capture-channel capacity. Mirrors the
    /// `event_channel_capacity` of the telemetry pipeline so
    /// a saturated egress doesn't wedge the capture loop.
    #[serde(default = "default_capture_channel_capacity")]
    pub channel_capacity: usize,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            idle_sleep: default_capture_idle_sleep(),
            channel_capacity: default_capture_channel_capacity(),
        }
    }
}

/// PAL posture-collector cadence.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PostureConfig {
    /// How often to invoke
    /// [`sng_pal::posture::PostureCollector::collect`]. The
    /// snapshot is fan-outed onto every active ZTNA session
    /// at the configured cadence so a posture
    /// regression (e.g. firewall flipped off) triggers a
    /// re-eval inside the next interval.
    ///
    /// Default: 30s — matches the conservative end of the
    /// posture-eval cadence the control plane expects from
    /// the agent.
    #[serde(default = "default_posture_interval", with = "humantime_serde")]
    pub collect_interval: Duration,
}

impl Default for PostureConfig {
    fn default() -> Self {
        Self {
            collect_interval: default_posture_interval(),
        }
    }
}

/// PAL tunnel-provider cadence + reconcile knobs.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    /// How often to reconcile the tunnel set against the
    /// in-effect policy verdicts. Default: 5s — slow enough
    /// that policy churn doesn't thrash the WireGuard
    /// peer list, fast enough that a policy add takes effect
    /// within an interactive operator's attention span.
    #[serde(
        default = "default_tunnel_reconcile_interval",
        with = "humantime_serde"
    )]
    pub reconcile_interval: Duration,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            reconcile_interval: default_tunnel_reconcile_interval(),
        }
    }
}

/// Endpoint DLP channel-monitoring settings.
///
/// Drives the [`crate::subsystems::DlpSubsystem`], which runs the
/// `sng-dlp` engine over the `sng-pal` channel interceptors
/// (clipboard / file-write / USB / print / browser-upload). The
/// portable polling backends run everywhere (including headless
/// CI); the edge-triggered native hooks (USN journal / FSEvents /
/// inotify) are upgrades on top with identical observable
/// behaviour, so this config is OS-agnostic.
///
/// `disabled` is the safe default: with no DLP policy delivered
/// the engine evaluates every event as `Allow`, so a deployment
/// that hasn't authored endpoint DLP rules pays no monitoring cost
/// until an operator opts in.
// The bool fields are independent operator on/off toggles for distinct
// DLP channels (subsystem master switch + clipboard / USB / print), not
// a state machine, so the `struct_excessive_bools` "use an enum"
// suggestion does not apply.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DlpConfig {
    /// Whether the DLP subsystem runs at all. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Directories watched for sensitive file writes / USB copies.
    /// Empty (the default) means the file-write and USB channels
    /// have nothing to watch and stay idle.
    #[serde(default)]
    pub watch_dirs: Vec<PathBuf>,
    /// Poll cadence for the portable directory watcher.
    /// Default: 2s — matches `sng_pal::dlp::DEFAULT_POLL_INTERVAL`.
    #[serde(default = "default_dlp_poll_interval", with = "humantime_serde")]
    pub poll_interval: Duration,
    /// Per-file read ceiling for content events. Default: 1 MiB —
    /// matches `sng_pal::dlp::DEFAULT_MAX_FILE_BYTES`.
    #[serde(default = "default_dlp_max_file_bytes")]
    pub max_file_bytes: usize,
    /// Idle backoff applied when every channel reports closed, so a
    /// fully torn-down interceptor set doesn't spin. Default: 1s.
    #[serde(default = "default_dlp_idle_sleep", with = "humantime_serde")]
    pub idle_sleep: Duration,
    /// Monitor the clipboard channel (native edge-triggered hook with a
    /// portable fallback). Default: true once DLP is enabled.
    #[serde(default = "default_true")]
    pub clipboard: bool,
    /// Monitor removable-storage (USB) writes. Default: true.
    #[serde(default = "default_true")]
    pub usb: bool,
    /// Monitor the print channel (local spooler). Default: true.
    #[serde(default = "default_true")]
    pub print: bool,
    /// Print-spool directory override. `None` (the default) uses the
    /// per-OS standard location (e.g. `/var/spool/cups`).
    #[serde(default)]
    pub print_spool_dir: Option<PathBuf>,
}

impl Default for DlpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            watch_dirs: Vec::new(),
            poll_interval: default_dlp_poll_interval(),
            max_file_bytes: default_dlp_max_file_bytes(),
            idle_sleep: default_dlp_idle_sleep(),
            clipboard: true,
            usb: true,
            print: true,
            print_spool_dir: None,
        }
    }
}

/// Supervisor lifecycle settings.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorConfig {
    /// Per-subsystem drain budget override. Map of subsystem
    /// name (matching [`sng_core::Subsystem::name`]) → drain
    /// budget. Unlisted subsystems fall back on
    /// [`sng_core::DEFAULT_DRAIN_BUDGET`] (30s).
    #[serde(default)]
    pub drain_budgets: std::collections::BTreeMap<String, DurationCfg>,
    /// Cadence at which the supervisor polls every
    /// subsystem's `HealthCheck`. Default: 2s.
    #[serde(default = "default_health_interval")]
    #[serde(with = "humantime_serde")]
    pub health_interval: Duration,
    /// Per-probe budget on health checks. Default: 1s.
    #[serde(default = "default_health_probe_budget")]
    #[serde(with = "humantime_serde")]
    pub health_probe_budget: Duration,
}

impl Default for SupervisorConfig {
    fn default() -> Self {
        Self {
            drain_budgets: std::collections::BTreeMap::new(),
            health_interval: default_health_interval(),
            health_probe_budget: default_health_probe_budget(),
        }
    }
}

/// Newtype around [`Duration`] so the operator can write
/// `"15s"` / `"500ms"` literals.
#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(transparent)]
pub struct DurationCfg(#[serde(with = "humantime_serde")] pub Duration);

/// Errors raised by [`load_from_path`].
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Could not read the file at the given path.
    #[error("read config {path}: {source}")]
    Read {
        /// Path the binary was asked to read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// TOML decode error.
    #[error("parse config {path}: {source}")]
    Parse {
        /// Path the binary was asked to read.
        path: PathBuf,
        /// Underlying serde-toml error.
        #[source]
        source: toml::de::Error,
    },
    /// Config decoded cleanly but a cross-field invariant is
    /// violated. We surface these at load-time so a
    /// misconfigured file fails fast at `--config` parse.
    #[error("invalid config {path}: {message}")]
    Invariant {
        /// Path the binary was asked to read.
        path: PathBuf,
        /// Human-readable description of the violated
        /// invariant.
        message: String,
    },
}

/// Read + parse the TOML file at `path` and validate
/// cross-field invariants.
///
/// # Errors
///
/// Returns [`ConfigError::Read`] for I/O failures,
/// [`ConfigError::Parse`] for TOML decode errors, and
/// [`ConfigError::Invariant`] when a cross-field check fails.
pub fn load_from_path(path: &std::path::Path) -> Result<AgentConfig, ConfigError> {
    let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;
    let cfg: AgentConfig = toml::from_str(&raw).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        source: e,
    })?;
    validate(&cfg).map_err(|message| ConfigError::Invariant {
        path: path.to_path_buf(),
        message,
    })?;
    Ok(cfg)
}

fn validate(cfg: &AgentConfig) -> Result<(), String> {
    if cfg.comms.backoff_initial > cfg.comms.backoff_max {
        return Err(format!(
            "comms.backoff_initial ({:?}) > comms.backoff_max ({:?})",
            cfg.comms.backoff_initial, cfg.comms.backoff_max
        ));
    }
    if cfg.comms.endpoint.is_empty() {
        return Err("comms.endpoint must be a non-empty host:port".into());
    }
    if cfg.ztna.max_inflight == 0 {
        return Err("ztna.max_inflight must be > 0".into());
    }
    if cfg.capture.channel_capacity == 0 {
        return Err("capture.channel_capacity must be > 0".into());
    }
    if cfg.posture.collect_interval.is_zero() {
        return Err("posture.collect_interval must be > 0".into());
    }
    if cfg.tunnel.reconcile_interval.is_zero() {
        return Err("tunnel.reconcile_interval must be > 0".into());
    }
    // The telemetry capacity is fed straight into `mpsc::channel(N)` /
    // `broadcast::channel(N)`, both of which panic on `N == 0`. Catching
    // it here turns an operator typo into a clean `ConfigError::Invariant`
    // at load time instead of a thread-panic at first subsystem startup.
    if cfg.telemetry.event_channel_capacity == 0 {
        return Err("telemetry.event_channel_capacity must be > 0".into());
    }
    Ok(())
}

// --- defaults ----------------------------------------------------

const fn default_backoff_initial() -> Duration {
    Duration::from_millis(250)
}
const fn default_backoff_max() -> Duration {
    Duration::from_secs(30)
}
const fn default_policy_pull_interval() -> Duration {
    Duration::from_secs(60)
}
const fn default_event_channel_capacity() -> usize {
    1024
}
const fn default_dedup_window() -> Duration {
    Duration::from_secs(30)
}
const fn default_dedup_max_entries() -> usize {
    32_768
}
const fn default_tick_interval() -> Duration {
    Duration::from_secs(1)
}
const fn default_spool_capacity() -> usize {
    256
}
fn default_telemetry_path() -> String {
    "/api/v1/agents/telemetry/batches".into()
}
const fn default_ztna_max_inflight() -> usize {
    256
}
const fn default_capture_idle_sleep() -> Duration {
    Duration::from_millis(50)
}
const fn default_capture_channel_capacity() -> usize {
    1024
}
const fn default_posture_interval() -> Duration {
    Duration::from_secs(30)
}
const fn default_tunnel_reconcile_interval() -> Duration {
    Duration::from_secs(5)
}
const fn default_dlp_poll_interval() -> Duration {
    Duration::from_secs(2)
}
const fn default_dlp_max_file_bytes() -> usize {
    1024 * 1024
}
const fn default_dlp_idle_sleep() -> Duration {
    Duration::from_secs(1)
}
const fn default_true() -> bool {
    true
}
const fn default_health_interval() -> Duration {
    Duration::from_secs(2)
}
const fn default_health_probe_budget() -> Duration {
    Duration::from_secs(1)
}

// --- humantime_serde fallback -----------------------------------
// Same shape as the sister `sng-edge::config::humantime_serde`
// adapter; kept local so the agent crate does not pick up an
// extra workspace dep purely for one helper.

mod humantime_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        parse(&raw).map_err(serde::de::Error::custom)
    }

    #[allow(dead_code)] // exposed for symmetry; not used yet
    pub(super) fn serialize<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let secs = value.as_secs();
        let nanos = value.subsec_nanos();
        if nanos == 0 {
            serializer.serialize_str(&format!("{secs}s"))
        } else {
            let millis = value.as_millis();
            serializer.serialize_str(&format!("{millis}ms"))
        }
    }

    fn parse(raw: &str) -> Result<Duration, String> {
        let raw = raw.trim();
        if let Some(rest) = raw.strip_suffix("ms") {
            let n: u64 = rest
                .parse()
                .map_err(|e| format!("invalid duration `{raw}`: {e}"))?;
            return Ok(Duration::from_millis(n));
        }
        if let Some(rest) = raw.strip_suffix('s') {
            let n: u64 = rest
                .parse()
                .map_err(|e| format!("invalid duration `{raw}`: {e}"))?;
            return Ok(Duration::from_secs(n));
        }
        if let Some(rest) = raw.strip_suffix('m') {
            let n: u64 = rest
                .parse()
                .map_err(|e| format!("invalid duration `{raw}`: {e}"))?;
            return Ok(Duration::from_secs(n * 60));
        }
        if let Some(rest) = raw.strip_suffix('h') {
            let n: u64 = rest
                .parse()
                .map_err(|e| format!("invalid duration `{raw}`: {e}"))?;
            return Ok(Duration::from_secs(n * 3600));
        }
        Err(format!(
            "invalid duration `{raw}`: expected ms / s / m / h suffix"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use tempfile::NamedTempFile;

    fn minimal_toml() -> String {
        r#"
[identity]
tenant_id = "11111111-1111-1111-1111-111111111111"
device_id = "22222222-2222-2222-2222-222222222222"

[comms]
endpoint    = "control.example.com:443"
client_cert = "/etc/sng/client.pem"
client_key  = "/etc/sng/client.key"
"#
        .into()
    }

    #[test]
    fn minimal_config_parses_with_defaults() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), minimal_toml()).unwrap();
        let cfg = load_from_path(f.path()).unwrap();
        assert_eq!(cfg.comms.endpoint, "control.example.com:443");
        assert_eq!(cfg.comms.backoff_initial, Duration::from_millis(250));
        assert_eq!(cfg.comms.backoff_max, Duration::from_secs(30));
        assert_eq!(cfg.telemetry.event_channel_capacity, 1024);
        assert_eq!(cfg.policy.pull_interval, Duration::from_secs(60));
        assert_eq!(cfg.supervisor.health_interval, Duration::from_secs(2));
        assert_eq!(cfg.identity.site_id, None);
        assert_eq!(cfg.capture.idle_sleep, Duration::from_millis(50));
        assert_eq!(cfg.posture.collect_interval, Duration::from_secs(30));
        assert_eq!(cfg.tunnel.reconcile_interval, Duration::from_secs(5));
    }

    #[test]
    fn humantime_durations_parse_in_subsystem_config() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            r#"
[identity]
tenant_id = "11111111-1111-1111-1111-111111111111"
device_id = "22222222-2222-2222-2222-222222222222"
site_id   = "33333333-3333-3333-3333-333333333333"

[comms]
endpoint        = "control.example.com:443"
client_cert     = "/etc/sng/client.pem"
client_key      = "/etc/sng/client.key"
backoff_initial = "500ms"
backoff_max     = "1m"

[posture]
collect_interval = "10s"

[tunnel]
reconcile_interval = "2s"
"#,
        )
        .unwrap();
        let cfg = load_from_path(f.path()).unwrap();
        assert_eq!(cfg.comms.backoff_initial, Duration::from_millis(500));
        assert_eq!(cfg.comms.backoff_max, Duration::from_secs(60));
        assert_eq!(cfg.posture.collect_interval, Duration::from_secs(10));
        assert_eq!(cfg.tunnel.reconcile_interval, Duration::from_secs(2));
        assert!(cfg.identity.site_id.is_some());
    }

    #[test]
    fn parse_rejects_backoff_inversion() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            r#"
[identity]
tenant_id = "11111111-1111-1111-1111-111111111111"
device_id = "22222222-2222-2222-2222-222222222222"

[comms]
endpoint        = "control.example.com:443"
client_cert     = "/etc/sng/client.pem"
client_key      = "/etc/sng/client.key"
backoff_initial = "5s"
backoff_max     = "1s"
"#,
        )
        .unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Invariant { .. }));
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            r#"
[identity]
tenant_id = "11111111-1111-1111-1111-111111111111"
device_id = "22222222-2222-2222-2222-222222222222"
banana    = true

[comms]
endpoint    = "control.example.com:443"
client_cert = "/etc/sng/client.pem"
client_key  = "/etc/sng/client.key"
"#,
        )
        .unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
    }

    #[test]
    fn parse_rejects_missing_path() {
        let err = load_from_path(std::path::Path::new("/nonexistent/sng-agent.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Read { .. }));
    }

    /// Regression: zero-capacity `telemetry.event_channel_capacity`
    /// would have panicked at runtime when `mpsc::channel(0)` ran
    /// during subsystem startup. The validator must reject it up
    /// front so the operator gets a `ConfigError::Invariant` at
    /// load time instead.
    #[test]
    fn validate_rejects_zero_telemetry_event_channel_capacity() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            r#"
[identity]
tenant_id = "11111111-1111-1111-1111-111111111111"
device_id = "22222222-2222-2222-2222-222222222222"

[comms]
endpoint    = "control.example.com:443"
client_cert = "/etc/sng/client.pem"
client_key  = "/etc/sng/client.key"

[telemetry]
event_channel_capacity = 0
"#,
        )
        .unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        let ConfigError::Invariant { message, .. } = err else {
            panic!("expected Invariant error, got {err:?}");
        };
        assert!(
            message.contains("telemetry.event_channel_capacity"),
            "message did not name the bad field: {message}"
        );
    }
}
