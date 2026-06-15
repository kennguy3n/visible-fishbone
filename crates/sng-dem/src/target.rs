//! Probe target configuration and the bounded engine budget.
//!
//! A [`Target`] is one thing the edge probes — a SaaS host or URL —
//! plus the probe kind and a hard per-probe timeout. The
//! [`EngineConfig`] carries the *cost model* knobs that keep a fleet
//! of 5,000 SME tenants from generating a probe storm: a concurrency
//! ceiling, a startup-jitter fraction, and a hard cap on the number
//! of targets evaluated per sweep.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::DemError;

/// The lowest per-probe timeout the engine accepts, in milliseconds.
/// Mirrors the `timeout_ms` CHECK on the `dem_targets` table.
pub const MIN_TIMEOUT_MS: u32 = 100;
/// The highest per-probe timeout the engine accepts, in milliseconds.
pub const MAX_TIMEOUT_MS: u32 = 30_000;

/// What the engine measures for a target.
///
/// Serialised as a lowercase token (`dns`, `tcp`, `http`, `https`)
/// so the wire form lines up byte-for-byte with the `probe_kind`
/// CHECK constraint on the control-plane `dem_probe_results` table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    /// DNS resolution latency only.
    Dns,
    /// DNS resolution plus TCP-connect latency.
    Tcp,
    /// DNS + TCP + HTTP TTFB / total latency + status (cleartext).
    Http,
    /// DNS + TCP + TLS + HTTP TTFB / total latency + status.
    Https,
}

impl ProbeKind {
    /// The lowercase wire token for this kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    /// Whether this kind issues an HTTP request (and therefore needs
    /// the shared [`reqwest::Client`]).
    #[must_use]
    pub fn is_http(self) -> bool {
        matches!(self, Self::Http | Self::Https)
    }
}

/// One probe target: a SaaS host or URL plus its probe kind and a
/// hard per-probe timeout.
///
/// * For [`ProbeKind::Dns`] / [`ProbeKind::Tcp`], `address` is a bare
///   host name and `port` is required for TCP.
/// * For [`ProbeKind::Http`] / [`ProbeKind::Https`], `address` is a
///   full URL (`https://login.microsoftonline.com/`) and `port` is
///   ignored (the scheme/host/port come from the URL).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    /// Stable identity used as the scoring dimension on the control
    /// plane (e.g. `m365`, or a tenant custom-target slug). Never
    /// reused across distinct targets.
    pub key: String,
    /// Human-readable label surfaced in the UI.
    pub name: String,
    /// What to measure.
    pub kind: ProbeKind,
    /// Host (DNS/TCP) or URL (HTTP/HTTPS).
    pub address: String,
    /// TCP port. Required for [`ProbeKind::Tcp`]; ignored for HTTP.
    pub port: Option<u16>,
    /// Hard wall-clock budget for the whole probe, in milliseconds.
    /// All phases (DNS, TCP, TTFB, body) draw from this single budget,
    /// so one slow target costs at most `timeout_ms` end-to-end.
    pub timeout_ms: u32,
}

impl Target {
    /// Validate the target's value domain.
    ///
    /// Returns [`DemError::Config`] when the target could never
    /// produce a meaningful probe — an empty key/name/address, a TCP
    /// target without a port, an HTTP target whose URL does not parse
    /// or carries no host, or a timeout outside
    /// `[MIN_TIMEOUT_MS, MAX_TIMEOUT_MS]`.
    pub fn validate(&self) -> Result<(), DemError> {
        if self.key.trim().is_empty() {
            return Err(DemError::Config("target key is empty".into()));
        }
        if self.name.trim().is_empty() {
            return Err(DemError::Config("target name is empty".into()));
        }
        if self.address.trim().is_empty() {
            return Err(DemError::Config("target address is empty".into()));
        }
        if self.timeout_ms < MIN_TIMEOUT_MS || self.timeout_ms > MAX_TIMEOUT_MS {
            return Err(DemError::Config(format!(
                "timeout_ms {} out of range [{MIN_TIMEOUT_MS}, {MAX_TIMEOUT_MS}]",
                self.timeout_ms
            )));
        }
        match self.kind {
            ProbeKind::Tcp if self.port.is_none() => {
                Err(DemError::Config("tcp target requires a port".into()))
            }
            ProbeKind::Http | ProbeKind::Https => {
                let url = self.parsed_url()?;
                let scheme = url.scheme();
                let scheme_ok = match self.kind {
                    ProbeKind::Http => scheme == "http",
                    ProbeKind::Https => scheme == "https",
                    _ => unreachable!(),
                };
                if !scheme_ok {
                    return Err(DemError::Config(format!(
                        "url scheme {scheme:?} does not match probe kind {}",
                        self.kind.as_str()
                    )));
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// The hard per-probe wall-clock budget as a [`Duration`], shared
    /// across all phases.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        Duration::from_millis(u64::from(self.timeout_ms))
    }

    /// Parse `address` as a URL (HTTP/HTTPS targets only), rejecting a
    /// URL with no host.
    pub(crate) fn parsed_url(&self) -> Result<Url, DemError> {
        let url = Url::parse(&self.address)
            .map_err(|e| DemError::Config(format!("invalid url {:?}: {e}", self.address)))?;
        if url.host_str().is_none() {
            return Err(DemError::Config(format!(
                "url {:?} has no host",
                self.address
            )));
        }
        Ok(url)
    }
}

/// The bounded cost model for a probe sweep.
///
/// Defaults are tuned for a no-ops SME fleet: at most 8 in-flight
/// probes, a 5 s default timeout, 50 % startup jitter to smear
/// connection bursts across the sweep, and a hard 64-target ceiling
/// per sweep so a misconfigured tenant cannot enqueue an unbounded
/// amount of work.
#[derive(Clone, Copy, Debug)]
pub struct EngineConfig {
    /// Maximum number of probes in flight at once.
    pub max_concurrency: usize,
    /// Default timeout for the shared HTTP client and connect phase.
    pub default_timeout: Duration,
    /// Fraction of a target's timeout used as the upper bound of a
    /// uniform random startup delay (`0.0` disables jitter). Clamped
    /// to `[0.0, 1.0]` at use.
    pub jitter: f64,
    /// Hard ceiling on targets evaluated per [`crate::ProbeEngine::probe_all`]
    /// call. Extra targets are dropped (and logged) rather than run.
    pub max_targets: usize,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 8,
            default_timeout: Duration::from_secs(5),
            jitter: 0.5,
            max_targets: 64,
        }
    }
}

impl EngineConfig {
    /// Validate the budget. Returns [`DemError::Config`] for a zero
    /// concurrency/target ceiling or a zero default timeout — any of
    /// which would make the engine unable to make progress.
    pub fn validate(&self) -> Result<(), DemError> {
        if self.max_concurrency == 0 {
            return Err(DemError::Config("max_concurrency must be > 0".into()));
        }
        if self.max_targets == 0 {
            return Err(DemError::Config("max_targets must be > 0".into()));
        }
        if self.default_timeout.is_zero() {
            return Err(DemError::Config("default_timeout must be > 0".into()));
        }
        Ok(())
    }

    /// The jitter fraction clamped to `[0.0, 1.0]`.
    #[must_use]
    pub fn jitter_clamped(&self) -> f64 {
        self.jitter.clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn http_target() -> Target {
        Target {
            key: "m365".into(),
            name: "Microsoft 365".into(),
            kind: ProbeKind::Https,
            address: "https://login.microsoftonline.com/".into(),
            port: None,
            timeout_ms: 5_000,
        }
    }

    #[test]
    fn probe_kind_round_trips_through_serde() {
        for (k, tok) in [
            (ProbeKind::Dns, "\"dns\""),
            (ProbeKind::Tcp, "\"tcp\""),
            (ProbeKind::Http, "\"http\""),
            (ProbeKind::Https, "\"https\""),
        ] {
            let s = serde_json::to_string(&k).unwrap();
            assert_eq!(s, tok);
            let back: ProbeKind = serde_json::from_str(&s).unwrap();
            assert_eq!(back, k);
            assert_eq!(k.as_str(), tok.trim_matches('"'));
        }
    }

    #[test]
    fn valid_https_target_passes() {
        assert!(http_target().validate().is_ok());
    }

    #[test]
    fn tcp_without_port_is_rejected() {
        let t = Target {
            key: "smtp".into(),
            name: "SMTP".into(),
            kind: ProbeKind::Tcp,
            address: "smtp.example.com".into(),
            port: None,
            timeout_ms: 2_000,
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn scheme_mismatch_is_rejected() {
        let mut t = http_target();
        t.kind = ProbeKind::Http; // address is https://
        assert!(t.validate().is_err());
    }

    #[test]
    fn out_of_range_timeout_is_rejected() {
        let mut t = http_target();
        t.timeout_ms = 1; // below MIN_TIMEOUT_MS
        assert!(t.validate().is_err());
        t.timeout_ms = MAX_TIMEOUT_MS + 1;
        assert!(t.validate().is_err());
    }

    #[test]
    fn empty_fields_are_rejected() {
        let mut t = http_target();
        t.key = "  ".into();
        assert!(t.validate().is_err());
    }

    #[test]
    fn unparseable_url_is_rejected() {
        let t = Target {
            key: "bad".into(),
            name: "Bad".into(),
            kind: ProbeKind::Https,
            address: "not a url".into(),
            port: None,
            timeout_ms: 2_000,
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn engine_config_default_validates() {
        assert!(EngineConfig::default().validate().is_ok());
    }

    #[test]
    fn engine_config_zero_concurrency_rejected() {
        let cfg = EngineConfig {
            max_concurrency: 0,
            ..EngineConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn jitter_is_clamped() {
        let cfg = EngineConfig {
            jitter: 5.0,
            ..EngineConfig::default()
        };
        assert_eq!(cfg.jitter_clamped(), 1.0);
        let cfg = EngineConfig {
            jitter: -1.0,
            ..EngineConfig::default()
        };
        assert_eq!(cfg.jitter_clamped(), 0.0);
    }
}
