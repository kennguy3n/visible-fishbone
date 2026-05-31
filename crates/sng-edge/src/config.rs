// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

//! `sng-edge` TOML config schema.
//!
//! Each subsystem's settings map onto a dedicated `[section]`.
//! Defaults are deliberately conservative — the binary refuses
//! to boot with a default-only config because the operator must
//! at minimum specify a control-plane endpoint + tenant + device
//! identity.

use sng_core::ids::{DeviceId, SiteId, TenantId};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;

/// Top-level edge config. One TOML file per appliance.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeConfig {
    /// Device identity binding (tenant / device / site). Used
    /// by every subsystem that emits telemetry so the
    /// envelopes carry the right routing keys.
    pub identity: IdentityConfig,
    /// Control-plane endpoint and authentication material.
    pub comms: CommsConfig,
    /// Policy bundle pull cadence + cache override.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Telemetry pipeline tuning.
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// DNS service filter chain settings.
    #[serde(default)]
    pub dns: DnsConfig,
    /// L3/L4/L7 firewall settings.
    #[serde(default)]
    pub fw: FwConfig,
    /// IPS (Suricata) subprocess management.
    #[serde(default)]
    pub ips: IpsConfig,
    /// SWG (Envoy) subprocess management.
    #[serde(default)]
    pub swg: SwgConfig,
    /// ZTNA settings.
    #[serde(default)]
    pub ztna: ZtnaConfig,
    /// SD-WAN settings.
    #[serde(default)]
    pub sdwan: SdwanConfig,
    /// Self-update engine tuning.
    #[serde(default)]
    pub updater: UpdaterConfig,
    /// Per-subsystem drain budget overrides. Subsystems not
    /// listed here use the supervisor's default (30s).
    #[serde(default)]
    pub supervisor: SupervisorConfig,
}

/// Device-identity binding shared across every subsystem.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// Tenant the appliance is enrolled into.
    pub tenant_id: TenantId,
    /// Stable device id (also used as the agent id on the
    /// control-plane side).
    pub device_id: DeviceId,
    /// Site this edge VM serves. Required at the edge tier —
    /// endpoints (sng-agent) optionally omit it.
    pub site_id: SiteId,
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
    /// Path override for the bundle pull endpoint. When omitted
    /// the puller uses the canonical
    /// `/api/v1/tenants/{tid}/policy/bundles/{target}/payload`
    /// path. Operators with a non-standard control-plane
    /// routing prefix (e.g. behind an API gateway) set this.
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

/// Telemetry pipeline tuning. Shape matches
/// [`sng_telemetry::PipelineConfig`] one-for-one so the operator
/// can copy / paste from the library docs.
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

/// DNS service settings. Filter chain is fixed (reputation →
/// category → sinkhole) at the edge; the operator tunes the
/// per-filter knobs here.
///
/// Manual `Default` impl because the
/// `reputation_refresh_interval` field needs the
/// [`default_dns_reputation_interval`] value, not
/// `Duration::default()` (0s, which would tight-loop the
/// refresh task). Serde's per-field `default` attribute
/// covers the wire path; the manual impl covers the in-Rust
/// `DnsConfig::default()` path.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsConfig {
    /// IP literal for the sinkhole response. Defaults to
    /// `0.0.0.0` for IPv4 and `::` for IPv6, both of which
    /// are RFC 5737 / RFC 6666 reserved sinks.
    #[serde(default = "default_sinkhole_ipv4")]
    pub sinkhole_ipv4: std::net::Ipv4Addr,
    #[serde(default = "default_sinkhole_ipv6")]
    pub sinkhole_ipv6: std::net::Ipv6Addr,
    /// Optional path to a newline-separated reputation deny
    /// list. When set, the DNS subsystem reloads the
    /// [`sng_dns::Reputation`] filter on every interval tick
    /// where the file's mtime has advanced. Lines starting
    /// with `#` are comments; empty lines are skipped. When
    /// omitted, the reputation filter stays empty for the
    /// process lifetime (and the operator relies on the
    /// category / sinkhole filters only).
    #[serde(default)]
    pub reputation_file: Option<PathBuf>,
    /// Polling interval for the reputation file mtime watcher.
    /// Defaults to 30s — short enough that operator changes
    /// land within a sysadmin's typical attention span and
    /// long enough that the per-tick `stat()` cost is
    /// negligible.
    #[serde(default = "default_dns_reputation_interval", with = "humantime_serde")]
    pub reputation_refresh_interval: std::time::Duration,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            sinkhole_ipv4: default_sinkhole_ipv4(),
            sinkhole_ipv6: default_sinkhole_ipv6(),
            reputation_file: None,
            reputation_refresh_interval: default_dns_reputation_interval(),
        }
    }
}

/// Firewall settings. Real nftables backend is wired through
/// [`sng_fw::ShellNftables`] at boot — no operator-visible
/// switch here because the edge VM has no other path: the
/// supervisor refuses to boot if `nft` is not reachable.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FwConfig {
    /// Override the `nft` binary path. Defaults to the system
    /// `nft` on `$PATH` (resolved by `ShellNftables`).
    #[serde(default)]
    pub nft_binary: Option<PathBuf>,
}

/// IPS subprocess management settings. Mirrors the shape of
/// [`sng_ips::IpsManagerConfig`].
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpsConfig {
    /// Where the rendered `suricata.yaml` lands.
    #[serde(default = "default_suricata_config_path")]
    pub config_path: PathBuf,
    /// Where EVE JSON output is written.
    #[serde(default = "default_suricata_eve_log_path")]
    pub eve_log_path: PathBuf,
    /// `suricata` binary path. Defaults to the system
    /// `suricata` on `$PATH`.
    #[serde(default)]
    pub suricata_binary: Option<PathBuf>,
    /// Whether to actually start Suricata. Edge appliances
    /// where the operator has not yet provisioned the IPS
    /// rules can boot with `enable = false` to skip starting
    /// the process while still wiring the manager into the
    /// supervisor for future operator action.
    #[serde(default = "default_true")]
    pub enable: bool,
    /// AF_PACKET / pcap interface Suricata binds to. Defaults
    /// to `eth0` (the canonical first data-plane NIC on the
    /// shipped edge VM image); operators with a different NIC
    /// layout must override.
    #[serde(default = "default_ips_interface")]
    pub interface: String,
    /// Where the staged rules file lives. The stager renders
    /// to this path; `suricata -T` validates it; the running
    /// binary re-reads it on `SIGHUP`.
    #[serde(default = "default_ips_rule_file_path")]
    pub rule_file_path: PathBuf,
    /// Staging directory for in-flight rule bundles. Must be
    /// on the same filesystem as `rule_file_path` so the
    /// stager's `rename` is atomic.
    #[serde(default = "default_ips_staging_dir")]
    pub staging_dir: PathBuf,
    /// Unix-socket path Suricata's stats reader polls.
    #[serde(default = "default_ips_stats_socket_path")]
    pub stats_socket_path: PathBuf,
    /// HOME_NET CIDRs — Suricata's "trusted" set. Maps to the
    /// branch.lan / dc.dmz networks from the policy bundle.
    /// Defaults to the RFC-1918 trio so the agent boots with
    /// a useful posture on greenfield deployments.
    #[serde(default = "default_ips_home_net")]
    pub home_net: Vec<String>,
    /// EXTERNAL_NET CIDRs. Defaults to `!$HOME_NET`.
    #[serde(default = "default_ips_external_net")]
    pub external_net: Vec<String>,
    /// IDS vs IPS mode toggle. Defaults to `ids` so a fresh
    /// install never blocks production traffic until the
    /// operator opts into inline mode explicitly.
    #[serde(default = "default_ips_runtime")]
    pub runtime: IpsRuntimeSetting,
    /// Capacity of the EVE event channel into the telemetry
    /// pipeline. Defaults to 1024 — sufficient for a quiet
    /// branch and small enough that a wedged consumer surfaces
    /// back-pressure within seconds.
    #[serde(default = "default_ips_event_channel_capacity")]
    pub event_channel_capacity: usize,
}

impl Default for IpsConfig {
    fn default() -> Self {
        Self {
            config_path: default_suricata_config_path(),
            eve_log_path: default_suricata_eve_log_path(),
            suricata_binary: None,
            // Must match the field-level `#[serde(default = "default_true")]`
            // above. Diverging here means a TOML containing `[ips]` with any
            // custom field but no `enable` boots the IPS subsystem (and
            // launches Suricata), while omitting `[ips]` entirely does not
            // — a split-brain operator footgun. Keep them in lockstep.
            enable: default_true(),
            interface: default_ips_interface(),
            rule_file_path: default_ips_rule_file_path(),
            staging_dir: default_ips_staging_dir(),
            stats_socket_path: default_ips_stats_socket_path(),
            home_net: default_ips_home_net(),
            external_net: default_ips_external_net(),
            runtime: default_ips_runtime(),
            event_channel_capacity: default_ips_event_channel_capacity(),
        }
    }
}

/// Wire-friendly mirror of [`sng_ips::IpsRuntime`]. We don't
/// derive `Deserialize` directly on `sng_ips::IpsRuntime`
/// because it's a foreign type; this enum sits at the config
/// boundary and is converted by [`Self::into_lib`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpsRuntimeSetting {
    /// Detection-only (alerts but never drops). Production-safe
    /// default for greenfield deployments.
    Ids,
    /// Inline mode (alerts AND drops). Operator must opt in.
    Inline,
}

impl IpsRuntimeSetting {
    /// Convert to the library enum the IPS manager expects.
    #[must_use]
    pub const fn into_lib(self) -> sng_ips::IpsRuntime {
        match self {
            Self::Ids => sng_ips::IpsRuntime::Ids,
            Self::Inline => sng_ips::IpsRuntime::Inline,
        }
    }
}

/// SWG subprocess management settings. Mirrors
/// [`sng_swg::SwgManagerConfig`].
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwgConfig {
    /// Where the rendered Envoy YAML lands.
    #[serde(default = "default_envoy_config_path")]
    pub config_path: PathBuf,
    /// `envoy` binary path. Defaults to the system `envoy`.
    #[serde(default)]
    pub envoy_binary: Option<PathBuf>,
    /// Whether to actually start Envoy.
    #[serde(default = "default_true")]
    pub enable: bool,
}

impl Default for SwgConfig {
    fn default() -> Self {
        Self {
            config_path: default_envoy_config_path(),
            envoy_binary: None,
            // Must match the field-level `#[serde(default = "default_true")]`
            // above. See the matching note on `IpsConfig::default` for the
            // operator-footgun rationale.
            enable: default_true(),
        }
    }
}

/// ZTNA service settings. All providers are seeded empty at
/// boot — the policy bundle pull populates the catalog /
/// identity / device-trust tables.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZtnaConfig {
    /// Cap on the number of in-flight `AccessRequest`
    /// evaluations. Default: 1024.
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

/// SD-WAN settings. The probe ingest is wired through the
/// telemetry bridge; the operator tunes the sticky-window /
/// cache capacity here.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdwanConfig {
    /// Cap on the sticky-pin cache.
    #[serde(default = "default_sdwan_sticky_capacity")]
    pub sticky_cache_capacity: usize,
}

impl Default for SdwanConfig {
    fn default() -> Self {
        Self {
            sticky_cache_capacity: default_sdwan_sticky_capacity(),
        }
    }
}

/// Self-update settings.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdaterConfig {
    /// How often to poll [`sng_updater::ManifestSource::latest`].
    #[serde(default = "default_updater_poll_interval")]
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
    /// Maximum acceptable image size, in bytes. Mapped onto
    /// [`sng_updater::UpdaterPolicy::max_image_bytes`].
    #[serde(default = "default_updater_max_image_bytes")]
    pub max_image_bytes: u64,
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            poll_interval: default_updater_poll_interval(),
            max_image_bytes: default_updater_max_image_bytes(),
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
    /// Cadence at which the supervisor polls every subsystem's
    /// `HealthCheck`. Default: 2s.
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
/// `"15s"` / `"500ms"` literals without paying the deserialize
/// cost on every parser invocation. (toml's `value` form would
/// require an integer / float of seconds; the humantime string
/// form is much friendlier in operator-facing configs.)
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
    /// violated (e.g. `backoff_initial > backoff_max`). We
    /// surface these at load-time so a misconfigured file
    /// fails fast at `--config` parse rather than at first
    /// reconnect attempt.
    #[error("invalid config {path}: {message}")]
    Invariant {
        /// Path the binary was asked to read.
        path: PathBuf,
        /// Human-readable description of the violated invariant.
        message: String,
    },
}

/// Read + parse the TOML file at `path` and validate cross-field
/// invariants.
///
/// # Errors
///
/// Returns [`ConfigError::Read`] for I/O failures,
/// [`ConfigError::Parse`] for TOML decode errors, and
/// [`ConfigError::Invariant`] when a cross-field check fails.
pub fn load_from_path(path: &std::path::Path) -> Result<EdgeConfig, ConfigError> {
    let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Read {
        path: path.to_path_buf(),
        source: e,
    })?;
    let cfg: EdgeConfig = toml::from_str(&raw).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        source: e,
    })?;
    validate(&cfg).map_err(|message| ConfigError::Invariant {
        path: path.to_path_buf(),
        message,
    })?;
    Ok(cfg)
}

fn validate(cfg: &EdgeConfig) -> Result<(), String> {
    if cfg.comms.backoff_initial > cfg.comms.backoff_max {
        return Err(format!(
            "comms.backoff_initial ({:?}) > comms.backoff_max ({:?})",
            cfg.comms.backoff_initial, cfg.comms.backoff_max
        ));
    }
    if cfg.comms.endpoint.is_empty() {
        return Err("comms.endpoint must be a non-empty host:port".into());
    }
    if cfg.updater.max_image_bytes == 0 {
        return Err("updater.max_image_bytes must be > 0".into());
    }
    if cfg.ztna.max_inflight == 0 {
        return Err("ztna.max_inflight must be > 0".into());
    }
    // Every channel capacity is fed straight into `mpsc::channel(N)` /
    // `broadcast::channel(N)`, both of which panic on `N == 0`. Catching
    // it here turns an operator typo into a clean `ConfigError::Invariant`
    // at load time instead of a thread-panic at first subsystem startup.
    if cfg.telemetry.event_channel_capacity == 0 {
        return Err("telemetry.event_channel_capacity must be > 0".into());
    }
    if cfg.ips.event_channel_capacity == 0 {
        return Err("ips.event_channel_capacity must be > 0".into());
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
    4096
}
const fn default_dedup_window() -> Duration {
    Duration::from_secs(30)
}
const fn default_dedup_max_entries() -> usize {
    100_000
}
const fn default_tick_interval() -> Duration {
    Duration::from_secs(1)
}
const fn default_spool_capacity() -> usize {
    1024
}
fn default_telemetry_path() -> String {
    "/api/v1/agents/telemetry/batches".into()
}
const fn default_sinkhole_ipv4() -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::UNSPECIFIED
}
const fn default_sinkhole_ipv6() -> std::net::Ipv6Addr {
    std::net::Ipv6Addr::UNSPECIFIED
}
const fn default_dns_reputation_interval() -> std::time::Duration {
    std::time::Duration::from_secs(30)
}
fn default_suricata_config_path() -> PathBuf {
    PathBuf::from("/var/lib/sng/ips/suricata.yaml")
}
fn default_suricata_eve_log_path() -> PathBuf {
    PathBuf::from("/var/lib/sng/ips/eve.json")
}
fn default_ips_interface() -> String {
    "eth0".into()
}
fn default_ips_rule_file_path() -> PathBuf {
    PathBuf::from("/var/lib/sng/ips/sng.rules")
}
fn default_ips_staging_dir() -> PathBuf {
    PathBuf::from("/var/lib/sng/ips/staging")
}
fn default_ips_stats_socket_path() -> PathBuf {
    PathBuf::from("/run/sng/suricata-command.socket")
}
fn default_ips_home_net() -> Vec<String> {
    vec![
        "10.0.0.0/8".into(),
        "172.16.0.0/12".into(),
        "192.168.0.0/16".into(),
    ]
}
fn default_ips_external_net() -> Vec<String> {
    vec!["!$HOME_NET".into()]
}
const fn default_ips_runtime() -> IpsRuntimeSetting {
    IpsRuntimeSetting::Ids
}
const fn default_ips_event_channel_capacity() -> usize {
    1024
}
fn default_envoy_config_path() -> PathBuf {
    PathBuf::from("/var/lib/sng/swg/envoy.yaml")
}
const fn default_true() -> bool {
    true
}
const fn default_ztna_max_inflight() -> usize {
    1024
}
const fn default_sdwan_sticky_capacity() -> usize {
    1024
}
const fn default_updater_poll_interval() -> Duration {
    Duration::from_secs(300)
}
const fn default_updater_max_image_bytes() -> u64 {
    // 2 GiB — generous upper bound; the operator typically
    // tightens this further in their per-fleet config.
    2 * 1024 * 1024 * 1024
}
const fn default_health_interval() -> Duration {
    Duration::from_secs(2)
}
const fn default_health_probe_budget() -> Duration {
    Duration::from_secs(1)
}

// --- humantime_serde fallback -----------------------------------
// We don't pull `humantime-serde` as a workspace dep; the
// in-crate adapter below covers the only shape we need (a
// `Duration` field that can be written as "250ms" / "30s" /
// "5m" by the operator). Keeping this local avoids pulling
// another crate purely for one helper.

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
        // Stable lossless round-trip: emit milliseconds when
        // sub-second precision is needed, seconds otherwise.
        let secs = value.as_secs();
        let nanos = value.subsec_nanos();
        if nanos == 0 {
            serializer.serialize_str(&format!("{secs}s"))
        } else {
            // Express as fractional seconds with millisecond
            // precision — enough for every config knob we expose.
            let millis = value.as_millis();
            serializer.serialize_str(&format!("{millis}ms"))
        }
    }

    fn parse(raw: &str) -> Result<Duration, String> {
        // Accept the operator-friendly forms: "250ms", "5s",
        // "10m", "1h". Reject everything else with a clear
        // message so a typo doesn't silently degrade to 0.
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
site_id   = "33333333-3333-3333-3333-333333333333"

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
        assert_eq!(cfg.telemetry.event_channel_capacity, 4096);
        assert_eq!(cfg.policy.pull_interval, Duration::from_secs(60));
        assert_eq!(cfg.supervisor.health_interval, Duration::from_secs(2));
    }

    #[test]
    fn humantime_durations_parse_in_subsystem_config() {
        let mut raw = minimal_toml();
        raw.push_str(
            r#"
[comms]
endpoint        = "control.example.com:443"
client_cert     = "/etc/sng/client.pem"
client_key      = "/etc/sng/client.key"
backoff_initial = "500ms"
backoff_max     = "1m"
"#,
        );
        // re-parsing the file: only the LAST [comms] block wins
        // in TOML, so we have to write a single-comms-block file
        // for this assertion. The point is to prove the
        // humantime adapter accepts the operator-friendly forms.
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
"#,
        )
        .unwrap();
        let cfg = load_from_path(f.path()).unwrap();
        assert_eq!(cfg.comms.backoff_initial, Duration::from_millis(500));
        assert_eq!(cfg.comms.backoff_max, Duration::from_secs(60));
    }

    #[test]
    fn invariant_violation_surfaces_at_load_time() {
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
backoff_initial = "1m"
backoff_max     = "10s"
"#,
        )
        .unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        let ConfigError::Invariant { message, .. } = err else {
            panic!("expected Invariant error, got {err:?}");
        };
        assert!(message.contains("backoff_initial"));
    }

    /// Regression: `IpsConfig::default()` previously returned
    /// `enable = false` while the field-level
    /// `#[serde(default = "default_true")]` made `enable` default
    /// to `true` whenever `[ips]` was present but the `enable` key
    /// was omitted. The two must agree so an operator who customises
    /// any IPS field without naming `enable` doesn't accidentally
    /// launch Suricata. This test fails before the fix and passes
    /// after.
    #[test]
    fn ips_default_matches_field_level_serde_default() {
        let f = NamedTempFile::new().unwrap();
        // `[ips]` with one non-`enable` field forces serde to fill
        // `enable` from the field-level default (`default_true`).
        std::fs::write(
            f.path(),
            r#"
[identity]
tenant_id = "11111111-1111-1111-1111-111111111111"
device_id = "22222222-2222-2222-2222-222222222222"
site_id   = "33333333-3333-3333-3333-333333333333"

[comms]
endpoint    = "control.example.com:443"
client_cert = "/etc/sng/client.pem"
client_key  = "/etc/sng/client.key"

[ips]
interface = "eth1"
"#,
        )
        .unwrap();
        let cfg = load_from_path(f.path()).unwrap();
        assert!(
            cfg.ips.enable,
            "[ips] with a custom field should default `enable = true` via serde"
        );
        assert!(
            IpsConfig::default().enable,
            "IpsConfig::default() must match the field-level serde default"
        );
    }

    /// Regression: same shape as
    /// [`ips_default_matches_field_level_serde_default`] for the SWG
    /// section. `SwgConfig::default()` returned `enable = false`
    /// while the per-field serde default was `true`.
    #[test]
    fn swg_default_matches_field_level_serde_default() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            r#"
[identity]
tenant_id = "11111111-1111-1111-1111-111111111111"
device_id = "22222222-2222-2222-2222-222222222222"
site_id   = "33333333-3333-3333-3333-333333333333"

[comms]
endpoint    = "control.example.com:443"
client_cert = "/etc/sng/client.pem"
client_key  = "/etc/sng/client.key"

[swg]
config_path = "/etc/envoy/envoy.yaml"
"#,
        )
        .unwrap();
        let cfg = load_from_path(f.path()).unwrap();
        assert!(
            cfg.swg.enable,
            "[swg] with a custom field should default `enable = true` via serde"
        );
        assert!(
            SwgConfig::default().enable,
            "SwgConfig::default() must match the field-level serde default"
        );
    }

    /// Regression: zero-capacity channel sizes were previously
    /// accepted at load time and would panic at runtime when
    /// `mpsc::channel(0)` ran during subsystem startup. The
    /// validator must reject them up front.
    #[test]
    fn validate_rejects_zero_telemetry_event_channel_capacity() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            r#"
[identity]
tenant_id = "11111111-1111-1111-1111-111111111111"
device_id = "22222222-2222-2222-2222-222222222222"
site_id   = "33333333-3333-3333-3333-333333333333"

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

    /// Same shape as
    /// [`validate_rejects_zero_telemetry_event_channel_capacity`]
    /// for the IPS event channel. The Suricata wrapper similarly
    /// panics on `mpsc::channel(0)` during boot.
    #[test]
    fn validate_rejects_zero_ips_event_channel_capacity() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            r#"
[identity]
tenant_id = "11111111-1111-1111-1111-111111111111"
device_id = "22222222-2222-2222-2222-222222222222"
site_id   = "33333333-3333-3333-3333-333333333333"

[comms]
endpoint    = "control.example.com:443"
client_cert = "/etc/sng/client.pem"
client_key  = "/etc/sng/client.key"

[ips]
event_channel_capacity = 0
"#,
        )
        .unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        let ConfigError::Invariant { message, .. } = err else {
            panic!("expected Invariant error, got {err:?}");
        };
        assert!(
            message.contains("ips.event_channel_capacity"),
            "message did not name the bad field: {message}"
        );
    }

    #[test]
    fn missing_required_field_is_a_parse_error() {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            r#"
[identity]
tenant_id = "11111111-1111-1111-1111-111111111111"
device_id = "22222222-2222-2222-2222-222222222222"
site_id   = "33333333-3333-3333-3333-333333333333"

[comms]
endpoint = "control.example.com:443"
# missing client_cert / client_key
"#,
        )
        .unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }), "{err:?}");
    }
}
