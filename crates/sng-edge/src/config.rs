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
    /// Root of the edge's on-disk state — the filesystem that holds
    /// the policy-bundle cache, telemetry spool, and the per-subsystem
    /// working dirs (IPS staging, SWG config, …), all of which default
    /// under it. The commodity-hardware preflight measures this path's
    /// free space against the documented 8 GiB micro-branch minimum, so
    /// it must name the data partition rather than any one subsystem's
    /// subdir. Default: `/var/lib/sng`.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
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
    /// Active/passive HA (VRRP-class failover) settings. Disabled
    /// by default — a single-edge deployment leaves `[ha]` out of
    /// the file entirely and the subsystem installs a no-op.
    #[serde(default)]
    pub ha: HaConfig,
    /// Self-update engine tuning.
    #[serde(default)]
    pub updater: UpdaterConfig,
    /// Per-subsystem drain budget overrides. Subsystems not
    /// listed here use the supervisor's default (30s).
    #[serde(default)]
    pub supervisor: SupervisorConfig,
    /// Edge operating mode. `site` (the default) is the existing
    /// single-tenant branch/site appliance: every subsystem is
    /// bound to the one tenant in `[identity]`. `pop` turns the
    /// same binary into a shared, multi-tenant cloud
    /// Point-of-Presence that loads policy bundles for ALL
    /// assigned tenants and routes each incoming connection to the
    /// owning tenant's evaluator (see [`crate::pop`]).
    #[serde(default)]
    pub mode: EdgeMode,
    /// Cloud-PoP tuning. Only consulted when `mode = "pop"`; a
    /// `site`-mode appliance leaves `[pop]` out of the file
    /// entirely and the defaults are never read.
    #[serde(default)]
    pub pop: PopConfig,
}

/// Edge operating mode — selects single-tenant (`site`) versus
/// multi-tenant cloud (`pop`) behaviour. Defaults to `site` so an
/// existing appliance config (which has no `mode` key) keeps its
/// current single-tenant semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EdgeMode {
    /// Single-tenant branch/site appliance (the historical
    /// default). Bound to the one tenant in `[identity]`.
    #[default]
    Site,
    /// Multi-tenant cloud inspection point. Serves many tenants
    /// from one deployment; connections are demultiplexed to the
    /// correct tenant's policy evaluator by [`crate::pop::PoPRouter`].
    Pop,
}

impl EdgeMode {
    /// Wire/string form (`"site"` / `"pop"`), matching the
    /// kebab-case serde representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Site => "site",
            Self::Pop => "pop",
        }
    }

    /// True iff this is the multi-tenant cloud PoP mode.
    #[must_use]
    pub const fn is_pop(self) -> bool {
        matches!(self, Self::Pop)
    }
}

/// Cloud-PoP capacity tuning. A PoP is shared infrastructure, so
/// it shields itself from resource exhaustion two ways: a hard
/// admission ceiling (`max_connections`) past which new
/// connections are shed, and a soft high-water mark
/// (`high_water_fraction`) at which it reports itself overloaded
/// so the control-plane rebalancer drains non-pinned tenants
/// away. The fraction mirrors the control plane's
/// `POP_HIGH_WATER_FRACTION` default so both ends agree on what
/// "overloaded" means.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PopConfig {
    /// Hard ceiling on concurrent tenant connections this PoP
    /// admits. Connections beyond it are refused so one PoP
    /// cannot be driven past its sizing. Default: 50000.
    #[serde(default = "default_pop_max_connections")]
    pub max_connections: u64,
    /// Fraction `(0, 1]` of `max_connections` at or above which
    /// the PoP reports itself overloaded and asks the control
    /// plane to rebalance tenants away. Default: 0.85.
    #[serde(default = "default_pop_high_water_fraction")]
    pub high_water_fraction: f64,
}

impl Default for PopConfig {
    fn default() -> Self {
        Self {
            max_connections: default_pop_max_connections(),
            high_water_fraction: default_pop_high_water_fraction(),
        }
    }
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
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FwConfig {
    /// Override the `nft` binary path. Defaults to the system
    /// `nft` on `$PATH` (resolved by `ShellNftables`).
    #[serde(default)]
    pub nft_binary: Option<PathBuf>,
    /// Ingress NIC the XDP fast-path program attaches to when the
    /// eBPF data path is selected AND the binary was built with the
    /// `xdp` feature. Defaults to `eth0` (the canonical first
    /// data-plane NIC on the shipped edge VM image). Ignored when the
    /// nftables slow path is selected or when the `xdp` feature is
    /// compiled out — attach is fail-soft, so an interface mismatch
    /// degrades to the slow path rather than failing boot.
    #[serde(default = "default_xdp_interface")]
    pub xdp_interface: String,
}

impl Default for FwConfig {
    fn default() -> Self {
        Self {
            nft_binary: None,
            xdp_interface: default_xdp_interface(),
        }
    }
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
    /// Multi-queue (RSS) fan-out of Suricata's `af-packet` capture
    /// path. Accepts `"auto"` (the default — match the NIC's RSS
    /// queues, fail safe to one thread on a single-queue NIC) or a
    /// positive integer to pin an explicit thread count. This is what
    /// lets the inspection data path scale across cores toward line
    /// rate instead of being capped by a single capture thread.
    #[serde(default)]
    pub capture_threads: CaptureThreadsSetting,
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
            capture_threads: CaptureThreadsSetting::default(),
        }
    }
}

/// Wire-friendly mirror of [`sng_ips::CaptureThreads`]. Deserializes
/// ergonomically from TOML as either the bareword/string `"auto"` or a
/// positive integer, e.g. `capture_threads = "auto"` or
/// `capture_threads = 4`. Converted at the config boundary by
/// [`Self::into_lib`].
///
/// `auto` is the multi-queue default; it fails safe to a single capture
/// thread when the NIC exposes one RSS queue, so making it the default
/// never sheds traffic — it only adds parallelism where the hardware
/// allows it.
///
/// Variant order is load-bearing: `#[serde(untagged)]` tries variants top to
/// bottom and takes the first that deserializes. `Keyword` must stay first so
/// the string `"auto"` is matched as the keyword before serde would attempt
/// to read it as a `Count(u16)`. Do not reorder these variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(untagged)]
pub enum CaptureThreadsSetting {
    /// The `"auto"` keyword — match the NIC's RSS-queue count.
    Keyword(CaptureThreadsKeyword),
    /// An explicit thread count.
    Count(u16),
}

/// The only accepted string form for [`CaptureThreadsSetting`]. A
/// dedicated unit enum (rather than a free `String`) means serde
/// rejects a typo like `"atuo"` at parse time instead of silently
/// accepting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureThreadsKeyword {
    /// Match the capture-thread count to the NIC's RSS queues.
    Auto,
}

impl Default for CaptureThreadsSetting {
    fn default() -> Self {
        Self::Keyword(CaptureThreadsKeyword::Auto)
    }
}

impl CaptureThreadsSetting {
    /// Convert to the library enum the IPS config generator expects.
    #[must_use]
    pub const fn into_lib(self) -> sng_ips::CaptureThreads {
        match self {
            Self::Keyword(CaptureThreadsKeyword::Auto) => sng_ips::CaptureThreads::Auto,
            Self::Count(n) => sng_ips::CaptureThreads::Fixed(n),
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
/// [`sng_swg::SwgManagerConfig`] plus the ext-authz listener +
/// ClamAV content-scan knobs.
//
// `struct_excessive_bools`: this is an operator-facing config
// mirror, not a state machine — each bool is an independent
// on/off knob (`enable`, `ext_authz_enabled`, `clamav_enabled`,
// `clamav_fail_open`) deserialised straight from TOML, so folding
// them into an enum would only obscure the 1:1 mapping to config
// keys.
#[allow(clippy::struct_excessive_bools)]
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
    /// Master switch for the ext-authz verdict listener — the
    /// in-process server that answers Envoy's ext-authz filter on
    /// [`Self::ext_authz_socket`]. Default **off**: until an
    /// operator opts in, Envoy's ext-authz cluster dials a socket
    /// nobody serves and (per its fail-open config) waves traffic
    /// through, exactly as before this subsystem existed. Turning
    /// it on stands up the verdict engine (safe-browsing category
    /// deny + optional ClamAV content scan).
    #[serde(default)]
    pub ext_authz_enabled: bool,
    /// Unix socket the ext-authz listener binds. Must match the
    /// `ext_authz` cluster address baked into the rendered
    /// `envoy.yaml` (`unix:///var/run/sng/ext_authz.sock`).
    #[serde(default = "default_ext_authz_socket")]
    pub ext_authz_socket: PathBuf,
    /// Master switch for the ClamAV streaming content scanner.
    /// Default **off**: when off the verdict engine runs the
    /// malware chain with the hash check + YARA scan only and never
    /// dials `clamd`. Only consulted when [`Self::ext_authz_enabled`]
    /// is also true (the scanner is a stage inside the listener's
    /// handler).
    #[serde(default)]
    pub clamav_enabled: bool,
    /// `clamd` endpoint. Either `tcp://host:port` or, on Unix,
    /// `unix:///path/to/clamd.sock`. Only consulted when
    /// [`Self::clamav_enabled`] is true.
    #[serde(default = "default_clamav_endpoint")]
    pub clamav_endpoint: String,
    /// Largest response body (bytes) the scanner streams to
    /// `clamd`. Bodies larger than this are skipped (allowed) rather
    /// than scanned. Default 32 MiB.
    #[serde(default = "default_clamav_max_bytes")]
    pub clamav_max_bytes: usize,
    /// INSTREAM chunk size (bytes). Default 64 KiB.
    #[serde(default = "default_clamav_chunk_size")]
    pub clamav_chunk_size: usize,
    /// Per-scan wall-clock ceiling. On expiry the scan resolves to
    /// the configured fail posture ([`Self::clamav_fail_open`]).
    /// Default 5s.
    #[serde(default = "default_clamav_timeout", with = "humantime_serde")]
    pub clamav_timeout: Duration,
    /// Fail posture when `clamd` is unreachable / errors / times
    /// out. `true` (default) fails **open** — an unavailable scanner
    /// allows the body (availability over strictness); `false` fails
    /// **closed** — an unavailable scanner denies with the
    /// `scanner.unavailable` sentinel.
    #[serde(default = "default_true")]
    pub clamav_fail_open: bool,
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
            // The ext-authz + ClamAV surface is opt-in: both master
            // switches default off so an upgrade is behaviourally inert
            // until an operator turns them on.
            ext_authz_enabled: false,
            ext_authz_socket: default_ext_authz_socket(),
            clamav_enabled: false,
            clamav_endpoint: default_clamav_endpoint(),
            clamav_max_bytes: default_clamav_max_bytes(),
            clamav_chunk_size: default_clamav_chunk_size(),
            clamav_timeout: default_clamav_timeout(),
            clamav_fail_open: default_true(),
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
    /// Master gate for the continuous re-evaluation loop
    /// (`sng_ztna::ReevalLoop`). When **false** (the default) the
    /// re-eval subsystem is inert: it never spawns the sweep, never
    /// touches the session tracker, and the appliance behaves
    /// byte-for-byte as it did before the loop was wired in. An
    /// operator opts in by setting this true, mirroring the
    /// default-off discipline of `swg.ext_authz_enabled`.
    #[serde(default)]
    pub reeval_enabled: bool,
    /// Optional edge-local override of the sweep cadence, in
    /// milliseconds. **0** (the default) means follow the
    /// control-plane bundle's `ZtnaPolicy::reeval_interval_ms`,
    /// re-read live each cycle so a bundle reload retunes the
    /// cadence without a restart — the recommended posture. A
    /// non-zero value pins the cadence to the operator's edge
    /// config instead, independent of the bundle. Only consulted
    /// when [`Self::reeval_enabled`] is true.
    #[serde(default)]
    pub reeval_interval_ms: u64,
    /// Master gate for **full user-subject evaluation**. When
    /// **false** (the default) the appliance behaves
    /// byte-for-byte as before: the edge does not register
    /// verified user subjects with the brain's identity cache,
    /// and an access request whose subject cannot be resolved
    /// is denied with `identity_not_found` (a deny-by-default
    /// provider miss).
    ///
    /// When **true** the operator opts in to threading the
    /// verified user subject (groups / MFA freshness / tenant /
    /// tags — resolved from the IdP / mTLS chain) through the
    /// evaluator and the continuous re-evaluation loop:
    ///
    ///  - the ZTNA subsystem exposes a per-subject identity
    ///    cache the producer feeds via
    ///    [`ZtnaSubsystem::open_session_with_subject`](crate::subsystems::ztna::ZtnaSubsystem::open_session_with_subject),
    ///    so a real user's groups / MFA timestamp drive the
    ///    verdict (group-gated allow / deny, stale-MFA deny,
    ///    revoked-user deny) instead of degrading;
    ///  - a request that genuinely has no subject is denied
    ///    with the explicit `identity_absent` reason rather
    ///    than masquerading as a provider miss.
    ///
    /// Inert when disabled, mirroring the default-off
    /// discipline of [`Self::reeval_enabled`] and
    /// `swg.ext_authz_enabled` — never fails closed on an
    /// upgrade, never makes a subjectless request more
    /// permissive.
    #[serde(default)]
    pub user_subject_eval_enabled: bool,
}

impl Default for ZtnaConfig {
    fn default() -> Self {
        Self {
            max_inflight: default_ztna_max_inflight(),
            // Default OFF / inert: continuous re-evaluation is an
            // explicit operator opt-in (see field docs).
            reeval_enabled: false,
            reeval_interval_ms: 0,
            // Default OFF / inert: full user-subject evaluation is
            // an explicit operator opt-in (see field docs).
            user_subject_eval_enabled: false,
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

/// Active/passive HA (VRRP-class failover) settings.
///
/// The five operator-facing knobs the spec calls out map onto
/// the fields below: `ha_enabled` → [`enabled`](Self::enabled),
/// `ha_peer_address` → [`peer_address`](Self::peer_address),
/// `ha_virtual_ip` → [`virtual_ip`](Self::virtual_ip),
/// `ha_priority` → [`priority`](Self::priority), and
/// `ha_interface` → [`interface`](Self::interface). The
/// remaining fields are protocol parameters with RFC-default
/// values so a minimal `[ha]` block only needs the five.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HaConfig {
    /// Master switch. When `false` the subsystem is a no-op and
    /// none of the other fields are consulted.
    #[serde(default)]
    pub enabled: bool,
    /// L2 interface the VIP and the VRRP multicast socket live
    /// on (e.g. `eth0`).
    #[serde(default = "default_ha_interface")]
    pub interface: String,
    /// This node's own IPv4 on [`interface`](Self::interface).
    /// Used to bind the VRRP multicast socket and as the
    /// advertisement source for the tie-break. Required (and
    /// must be IPv4) when [`enabled`](Self::enabled).
    #[serde(default)]
    pub local_address: Option<std::net::IpAddr>,
    /// The peer edge's address — the far end of the state-sync
    /// channel. Required when [`enabled`](Self::enabled).
    #[serde(default)]
    pub peer_address: Option<std::net::IpAddr>,
    /// The virtual IP this pair fails over. Required when
    /// [`enabled`](Self::enabled).
    #[serde(default)]
    pub virtual_ip: Option<std::net::IpAddr>,
    /// CIDR prefix length the VIP is configured with. Default 24.
    #[serde(default = "default_ha_vip_prefix_len")]
    pub virtual_ip_prefix_len: u8,
    /// VRRP virtual router id — both peers share it. Default 1.
    #[serde(default = "default_ha_virtual_router_id")]
    pub virtual_router_id: u8,
    /// VRRP priority in `1..=255`; higher wins. Default 100.
    #[serde(default = "default_ha_priority")]
    pub priority: u8,
    /// Advertisement cadence (Master) / master-down unit
    /// (Backup). Default 1s.
    #[serde(default = "default_ha_advertisement_interval")]
    #[serde(with = "humantime_serde")]
    pub advertisement_interval: Duration,
    /// When `true`, a higher-priority node preempts a
    /// lower-priority Master. Default `true`.
    #[serde(default = "default_true")]
    pub preempt_mode: bool,
    /// How often the controller re-polls its health registry.
    /// Default 1s.
    #[serde(default = "default_ha_health_interval")]
    #[serde(with = "humantime_serde")]
    pub health_interval: Duration,
    /// Bounded state-sync queue depth. Default 1024.
    #[serde(default = "default_ha_sync_queue_capacity")]
    pub sync_queue_capacity: usize,
    /// Maximum records drained from the sync queue per flush.
    /// Default 256.
    #[serde(default = "default_ha_sync_batch")]
    pub sync_batch: usize,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: default_ha_interface(),
            local_address: None,
            peer_address: None,
            virtual_ip: None,
            virtual_ip_prefix_len: default_ha_vip_prefix_len(),
            virtual_router_id: default_ha_virtual_router_id(),
            priority: default_ha_priority(),
            advertisement_interval: default_ha_advertisement_interval(),
            preempt_mode: true,
            health_interval: default_ha_health_interval(),
            sync_queue_capacity: default_ha_sync_queue_capacity(),
            sync_batch: default_ha_sync_batch(),
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
    // PoP capacity invariants only bite in pop mode — a site-mode
    // appliance never reads `[pop]`, so a stray/defaulted value
    // there must not fail an otherwise-valid site config.
    if cfg.mode.is_pop() {
        if cfg.pop.max_connections == 0 {
            return Err("pop.max_connections must be > 0 in pop mode".into());
        }
        // Feeds `PoPRouter`'s overload predicate; a fraction outside
        // (0, 1] would make the high-water mark either unreachable
        // or permanently tripped, so reject it at load time.
        if !(cfg.pop.high_water_fraction > 0.0 && cfg.pop.high_water_fraction <= 1.0) {
            return Err(format!(
                "pop.high_water_fraction must be in (0, 1], got {}",
                cfg.pop.high_water_fraction
            ));
        }
    }
    validate_ha(&cfg.ha)?;
    validate_swg(&cfg.swg)?;
    Ok(())
}

/// SWG content-scan invariants. Only enforced when the ext-authz
/// listener *and* the ClamAV scanner are both enabled — the scanner
/// is a stage inside the listener's handler, so its knobs are inert
/// (and a defaulted/stray value must not fail an otherwise-valid
/// config) until both master switches are on. The defaults are all
/// non-zero, so these only bite an operator who explicitly zeroed a
/// field. Mirrors the HA pattern: each zero here is well-defined
/// downstream (chunk clamps to 1, max-bytes scans nothing, a zero
/// timeout expires every scan into the fail posture) but silently
/// neuters scanning, so we turn the typo into a load-time error
/// rather than a scanner that quietly never inspects anything.
fn validate_swg(swg: &SwgConfig) -> Result<(), String> {
    if !(swg.ext_authz_enabled && swg.clamav_enabled) {
        return Ok(());
    }
    // An empty endpoint is never a valid `clamd` target — guard it
    // the same way `comms.endpoint` is guarded above. (A non-empty
    // but unreachable / unparseable endpoint is intentionally left to
    // surface as a fail-posture scan result with telemetry, per the
    // `ClamdScanner` design, rather than a load-time error.)
    if swg.clamav_endpoint.trim().is_empty() {
        return Err(
            "swg.clamav_endpoint must be non-empty when clamav_enabled (e.g. tcp://127.0.0.1:3310)"
                .into(),
        );
    }
    if swg.clamav_max_bytes == 0 {
        return Err(
            "swg.clamav_max_bytes must be > 0 when clamav_enabled (0 scans nothing)".into(),
        );
    }
    if swg.clamav_chunk_size == 0 {
        return Err(
            "swg.clamav_chunk_size must be > 0 when clamav_enabled (0 streams no bytes)".into(),
        );
    }
    if swg.clamav_timeout.is_zero() {
        return Err(
            "swg.clamav_timeout must be > 0 when clamav_enabled (0 expires every scan immediately)"
                .into(),
        );
    }
    Ok(())
}

/// HA cross-field invariants. Only enforced when the subsystem
/// is enabled — a disabled `[ha]` block (the default) leaves the
/// optional addresses `None` and is always valid. The protocol
/// invariants (`priority != 0`, non-zero intervals, VIP prefix
/// in range) are re-checked at build time by
/// [`sng_ha::HaSettings::validate`]; mirroring the cheap ones
/// here turns an operator typo into a load-time error rather
/// than a boot-time one.
fn validate_ha(ha: &HaConfig) -> Result<(), String> {
    if !ha.enabled {
        return Ok(());
    }
    match ha.local_address {
        Some(std::net::IpAddr::V4(_)) => {}
        Some(std::net::IpAddr::V6(_)) => {
            return Err(
                "ha.local_address must be IPv4 (the VRRP multicast group 224.0.0.18 is IPv4)"
                    .into(),
            );
        }
        None => return Err("ha.local_address is required when ha.enabled".into()),
    }
    match ha.peer_address {
        // The peer shares the L2 segment and the IPv4-only VRRP group,
        // so its address family must match `local_address`.
        Some(std::net::IpAddr::V4(_)) => {}
        Some(std::net::IpAddr::V6(_)) => {
            return Err(
                "ha.peer_address must be IPv4 (the HA pair shares the IPv4 VRRP segment)".into(),
            );
        }
        None => return Err("ha.peer_address is required when ha.enabled".into()),
    }
    match ha.virtual_ip {
        Some(vip) => {
            // Match the family-aware bound in `sng_ha::VipSpec::validate`
            // so the operator gets a ConfigError at load time rather
            // than an HaError at subsystem build time.
            let max = if vip.is_ipv4() { 32 } else { 128 };
            if ha.virtual_ip_prefix_len > max {
                return Err(format!(
                    "ha.virtual_ip_prefix_len /{} is out of range for the VIP address family (max /{max})",
                    ha.virtual_ip_prefix_len
                ));
            }
        }
        None => return Err("ha.virtual_ip is required when ha.enabled".into()),
    }
    if ha.priority == 0 {
        return Err("ha.priority must be in 1..=255 (0 is the VRRP release signal)".into());
    }
    if ha.virtual_router_id == 0 {
        return Err("ha.virtual_router_id must be in 1..=255".into());
    }
    if ha.advertisement_interval.is_zero() {
        return Err("ha.advertisement_interval must be > 0".into());
    }
    if ha.health_interval.is_zero() {
        return Err("ha.health_interval must be > 0".into());
    }
    if ha.sync_queue_capacity == 0 {
        return Err("ha.sync_queue_capacity must be > 0".into());
    }
    if ha.sync_batch == 0 {
        return Err("ha.sync_batch must be > 0".into());
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
fn default_xdp_interface() -> String {
    "eth0".into()
}
fn default_ips_rule_file_path() -> PathBuf {
    PathBuf::from("/var/lib/sng/ips/sng.rules")
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/sng")
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
fn default_ext_authz_socket() -> PathBuf {
    PathBuf::from(sng_swg::DEFAULT_SOCKET_PATH)
}
fn default_clamav_endpoint() -> String {
    "tcp://127.0.0.1:3310".to_string()
}
const fn default_clamav_max_bytes() -> usize {
    32 * 1024 * 1024
}
const fn default_clamav_chunk_size() -> usize {
    64 * 1024
}
const fn default_clamav_timeout() -> Duration {
    Duration::from_secs(5)
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
const fn default_pop_max_connections() -> u64 {
    50_000
}
const fn default_pop_high_water_fraction() -> f64 {
    0.85
}
fn default_ha_interface() -> String {
    "eth0".into()
}
const fn default_ha_vip_prefix_len() -> u8 {
    24
}
const fn default_ha_virtual_router_id() -> u8 {
    1
}
const fn default_ha_priority() -> u8 {
    100
}
const fn default_ha_advertisement_interval() -> Duration {
    Duration::from_secs(1)
}
const fn default_ha_health_interval() -> Duration {
    Duration::from_secs(1)
}
const fn default_ha_sync_queue_capacity() -> usize {
    1024
}
const fn default_ha_sync_batch() -> usize {
    256
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
        // The data root defaults to the canonical SNG state dir when no
        // `data_dir` key is present (the commodity preflight probes it).
        assert_eq!(cfg.data_dir, PathBuf::from("/var/lib/sng"));
        assert_eq!(cfg.telemetry.event_channel_capacity, 4096);
        assert_eq!(cfg.policy.pull_interval, Duration::from_secs(60));
        assert_eq!(cfg.supervisor.health_interval, Duration::from_secs(2));
        // A config with no `[pop]` / `mode` key defaults to the
        // historical single-tenant site behaviour.
        assert_eq!(cfg.mode, EdgeMode::Site);
        assert!(!cfg.mode.is_pop());
        assert_eq!(cfg.pop.max_connections, 50_000);
        assert!((cfg.pop.high_water_fraction - 0.85).abs() < f64::EPSILON);
    }

    #[test]
    fn pop_mode_parses_with_overrides() {
        // `mode` is a top-level key, so it must precede any table
        // header; `[pop]` is appended as its own table.
        let mut raw = String::from("mode = \"pop\"\n");
        raw.push_str(&minimal_toml());
        raw.push_str(
            r"
[pop]
max_connections = 12000
high_water_fraction = 0.7
",
        );
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), raw).unwrap();
        let cfg = load_from_path(f.path()).unwrap();
        assert_eq!(cfg.mode, EdgeMode::Pop);
        assert!(cfg.mode.is_pop());
        assert_eq!(cfg.mode.as_str(), "pop");
        assert_eq!(cfg.pop.max_connections, 12_000);
        assert!((cfg.pop.high_water_fraction - 0.7).abs() < f64::EPSILON);
    }

    #[test]
    fn pop_mode_uses_pop_defaults_when_section_omitted() {
        let mut raw = String::from("mode = \"pop\"\n");
        raw.push_str(&minimal_toml());
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), raw).unwrap();
        let cfg = load_from_path(f.path()).unwrap();
        assert_eq!(cfg.mode, EdgeMode::Pop);
        assert_eq!(cfg.pop.max_connections, 50_000);
    }

    #[test]
    fn pop_mode_rejects_zero_max_connections() {
        let mut raw = String::from("mode = \"pop\"\n");
        raw.push_str(&minimal_toml());
        raw.push_str(
            r"
[pop]
max_connections = 0
",
        );
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), raw).unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invariant { message, .. } if message.contains("pop.max_connections")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn pop_mode_rejects_out_of_range_high_water_fraction() {
        for bad in ["0.0", "1.5", "-0.2"] {
            let mut raw = String::from("mode = \"pop\"\n");
            raw.push_str(&minimal_toml());
            raw.push_str("\n[pop]\nhigh_water_fraction = ");
            raw.push_str(bad);
            raw.push('\n');
            let f = NamedTempFile::new().unwrap();
            std::fs::write(f.path(), raw).unwrap();
            let err = load_from_path(f.path()).unwrap_err();
            assert!(
                matches!(&err, ConfigError::Invariant { message, .. } if message.contains("high_water_fraction")),
                "fraction {bad}: unexpected error: {err:?}"
            );
        }
    }

    #[test]
    fn site_mode_ignores_pop_invariants() {
        // A bogus `[pop]` block is harmless in site mode — the PoP
        // knobs are never read, so the config still loads.
        let mut raw = minimal_toml();
        raw.push_str(
            r"
[pop]
max_connections = 0
high_water_fraction = 9.0
",
        );
        let f = NamedTempFile::new().unwrap();
        std::fs::write(f.path(), raw).unwrap();
        let cfg = load_from_path(f.path()).unwrap();
        assert_eq!(cfg.mode, EdgeMode::Site);
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

    fn config_with_ips_block(ips_body: &str) -> Result<EdgeConfig, ConfigError> {
        let f = NamedTempFile::new().unwrap();
        std::fs::write(
            f.path(),
            format!(
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
{ips_body}
"#
            ),
        )
        .unwrap();
        load_from_path(f.path())
    }

    #[test]
    fn ips_capture_threads_defaults_to_auto_multiqueue() {
        // The whole point of the WS-8 change: an operator who sets
        // nothing gets multi-queue (`auto`), not the single-thread floor.
        let cfg = config_with_ips_block("interface = \"eth1\"").unwrap();
        assert_eq!(cfg.ips.capture_threads, CaptureThreadsSetting::default());
        assert_eq!(
            cfg.ips.capture_threads.into_lib(),
            sng_ips::CaptureThreads::Auto
        );
    }

    #[test]
    fn ips_capture_threads_accepts_auto_keyword_and_integer() {
        let auto = config_with_ips_block("capture_threads = \"auto\"").unwrap();
        assert_eq!(
            auto.ips.capture_threads,
            CaptureThreadsSetting::Keyword(CaptureThreadsKeyword::Auto)
        );

        let fixed = config_with_ips_block("capture_threads = 6").unwrap();
        assert_eq!(fixed.ips.capture_threads, CaptureThreadsSetting::Count(6));
        assert_eq!(
            fixed.ips.capture_threads.into_lib(),
            sng_ips::CaptureThreads::Fixed(6)
        );
    }

    #[test]
    fn ips_capture_threads_rejects_unknown_keyword() {
        // A typo'd keyword must be a hard parse error, never a silent
        // fall-through to single-threaded capture.
        let err = config_with_ips_block("capture_threads = \"atuo\"").unwrap_err();
        assert!(
            matches!(err, ConfigError::Parse { .. }),
            "expected a parse error, got {err:?}"
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

    /// A zeroed ClamAV knob is rejected at load time once both the
    /// listener and the scanner are enabled — otherwise the scanner
    /// would silently never inspect anything (here `clamav_timeout =
    /// 0` expires every scan into the fail posture).
    #[test]
    fn validate_rejects_zero_clamav_timeout_when_scanner_enabled() {
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
ext_authz_enabled = true
clamav_enabled    = true
clamav_timeout    = "0s"
"#,
        )
        .unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        let ConfigError::Invariant { message, .. } = err else {
            panic!("expected Invariant error, got {err:?}");
        };
        assert!(
            message.contains("swg.clamav_timeout"),
            "message did not name the bad field: {message}"
        );
    }

    /// The same zeroed knob is inert (and so accepted) while the
    /// scanner is off — the surface is opt-in, so a defaulted/stray
    /// value must not fail an otherwise-valid config.
    #[test]
    fn validate_allows_zero_clamav_timeout_when_scanner_disabled() {
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
clamav_timeout = "0s"
"#,
        )
        .unwrap();
        assert!(
            load_from_path(f.path()).is_ok(),
            "a zero clamav_timeout must be inert while the scanner is disabled"
        );
    }

    /// An empty `clamav_endpoint` is rejected once the scanner is
    /// enabled — it is never a valid `clamd` target, mirroring the
    /// existing non-empty guard on `comms.endpoint`.
    #[test]
    fn validate_rejects_empty_clamav_endpoint_when_scanner_enabled() {
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
ext_authz_enabled = true
clamav_enabled    = true
clamav_endpoint   = ""
"#,
        )
        .unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        let ConfigError::Invariant { message, .. } = err else {
            panic!("expected Invariant error, got {err:?}");
        };
        assert!(
            message.contains("swg.clamav_endpoint"),
            "message did not name the bad field: {message}"
        );
    }

    #[test]
    fn validate_rejects_out_of_range_ha_vip_prefix_len() {
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

[ha]
enabled               = true
local_address         = "192.168.9.2"
peer_address          = "192.168.9.3"
virtual_ip            = "192.168.9.1"
virtual_ip_prefix_len = 33
"#,
        )
        .unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        let ConfigError::Invariant { message, .. } = err else {
            panic!("expected Invariant error, got {err:?}");
        };
        assert!(
            message.contains("ha.virtual_ip_prefix_len"),
            "message did not name the bad field: {message}"
        );
    }

    #[test]
    fn validate_rejects_ipv6_ha_peer_address() {
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

[ha]
enabled       = true
local_address = "192.168.9.2"
peer_address  = "fd00::3"
virtual_ip    = "192.168.9.1"
"#,
        )
        .unwrap();
        let err = load_from_path(f.path()).unwrap_err();
        let ConfigError::Invariant { message, .. } = err else {
            panic!("expected Invariant error, got {err:?}");
        };
        assert!(
            message.contains("ha.peer_address must be IPv4"),
            "message did not reject the IPv6 peer: {message}"
        );
    }

    #[test]
    fn enabled_ha_block_with_valid_fields_loads() {
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

[ha]
enabled       = true
local_address = "192.168.9.2"
peer_address  = "192.168.9.3"
virtual_ip    = "192.168.9.1"
priority      = 150
"#,
        )
        .unwrap();
        let cfg = load_from_path(f.path()).expect("valid HA config should load");
        assert!(cfg.ha.enabled);
        assert_eq!(cfg.ha.priority, 150);
        assert_eq!(cfg.ha.virtual_ip_prefix_len, 24);
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
