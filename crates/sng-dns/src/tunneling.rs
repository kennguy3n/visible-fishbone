//! DNS tunneling detection.
//!
//! DNS tunneling smuggles a non-DNS protocol inside DNS queries and
//! answers to bypass egress controls: the client encodes payload
//! bytes into the QNAME labels (`<base32-chunk>.tunnel.evil.com`)
//! and the server returns data in `TXT` / `NULL` answers. Because
//! the recursive resolver forwards these like any other lookup,
//! tunneling is a favourite C2 / exfiltration channel for malware
//! on networks that otherwise block direct egress.
//!
//! This module is a *detector*, not a filter: it observes the query
//! stream the [`crate::filter::FilterChain`] already canonicalised
//! and emits typed [`TunnelingAlert`]s that the service layer routes
//! into the alert pipeline. Keeping it out of the short-circuit path
//! means a noisy detector can never accidentally NXDOMAIN a tenant's
//! legitimate traffic; the operator decides whether an alert escalates
//! to a block.
//!
//! Three orthogonal signals, any of which fires independently:
//!
//! 1. **Encoded-payload QNAMEs** — abnormally long names whose label
//!    bytes carry high Shannon entropy (base32/base64 payload looks
//!    random; English-ish domains do not).
//! 2. **Query-volume burst** — many lookups to one registrable
//!    domain inside a sliding window (each tunnel packet is a fresh
//!    unique subdomain, so volume to the *parent* spikes).
//! 3. **TXT-record abuse** — a disproportionate run of `TXT` lookups
//!    to one domain (the tunnel's downstream channel).
//!
//! Thresholds live in [`TunnelingConfig`] so the existing per-tenant
//! feedback loop can tune sensitivity without code changes.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use crate::qtype::QType;
use crate::query::DnsQuery;

/// Sink the service forwards [`TunnelingAlert`]s to.
///
/// Tunneling alerts are deliberately kept off the one-DnsEvent-per-query
/// telemetry path (see [`crate::service`]): a detector signal is an
/// out-of-band security alert, not a per-query verdict, so it routes
/// through this sink into the alert pipeline instead of inflating the
/// DNS event stream. The default [`TracingTunnelingSink`] just logs;
/// production wires a sink that forwards into the alert router.
pub trait TunnelingSink: Send + Sync + 'static {
    /// Called once per detected alert. Implementations MUST be cheap
    /// and non-blocking — this runs on the DNS hot path.
    fn record(&self, alert: &TunnelingAlert, client_id: Option<&str>);
}

/// Default sink: emit a structured WARN trace per alert.
#[derive(Debug, Default, Clone, Copy)]
pub struct TracingTunnelingSink;

impl TunnelingSink for TracingTunnelingSink {
    fn record(&self, alert: &TunnelingAlert, client_id: Option<&str>) {
        tracing::warn!(
            target: "sng_dns::tunneling",
            kind = alert.kind.as_str(),
            domain = %alert.domain,
            score = alert.score,
            client_id = client_id.unwrap_or("-"),
            detail = %alert.detail,
            "DNS tunneling indicator"
        );
    }
}

/// Which tunneling signal an alert represents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelingKind {
    /// QNAME is long and high-entropy — an encoded payload.
    EncodedQname,
    /// Query volume to one registrable domain exceeded the window cap.
    QueryVolume,
    /// TXT-query volume to one registrable domain exceeded the cap.
    TxtAbuse,
}

impl TunnelingKind {
    /// Stable dotted-lowercase id used as the alert kind on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EncodedQname => "dns.tunneling.encoded_qname",
            Self::QueryVolume => "dns.tunneling.query_volume",
            Self::TxtAbuse => "dns.tunneling.txt_abuse",
        }
    }
}

/// A single detected tunneling indicator.
#[derive(Clone, Debug, PartialEq)]
pub struct TunnelingAlert {
    /// Which signal fired.
    pub kind: TunnelingKind,
    /// The registrable domain (volume / TXT signals) or the full
    /// QNAME (encoded-qname signal) the alert is about.
    pub domain: String,
    /// Human-readable detail for the analyst (entropy value, count
    /// vs threshold, …).
    pub detail: String,
    /// Normalised severity in `[0, 1]`: how far past the threshold
    /// the observation is, saturating at 1.0. Feeds alert ranking.
    pub score: f64,
}

/// Tunable detector thresholds. Defaults are tuned for a corporate
/// resolver: legitimate names rarely exceed ~52 chars or ~3.5
/// bits/char, and a single parent domain rarely sees >100 lookups in
/// 10s from one client.
#[derive(Clone, Copy, Debug)]
pub struct TunnelingConfig {
    /// Sliding window the volume / TXT counters accumulate over.
    pub window: Duration,
    /// QNAME length (bytes, excluding dots) at/above which the
    /// encoded-payload check engages.
    pub min_qname_len: usize,
    /// Shannon entropy (bits/char) at/above which a long QNAME is
    /// considered an encoded payload.
    pub min_entropy_bits: f64,
    /// Query count to one registrable domain within `window` that
    /// trips the volume alarm.
    pub max_queries_per_window: u32,
    /// TXT-query count to one registrable domain within `window`
    /// that trips the TXT-abuse alarm.
    pub max_txt_per_window: u32,
}

impl Default for TunnelingConfig {
    fn default() -> Self {
        Self {
            window: Duration::from_secs(10),
            min_qname_len: 52,
            min_entropy_bits: 3.5,
            max_queries_per_window: 100,
            max_txt_per_window: 40,
        }
    }
}

/// Per-registrable-domain rolling counters.
#[derive(Debug, Default)]
struct DomainWindow {
    /// Timestamps of recent queries (all qtypes), oldest first.
    queries: VecDeque<Instant>,
    /// Timestamps of recent TXT queries, oldest first.
    txt: VecDeque<Instant>,
}

impl DomainWindow {
    /// Drop entries older than `now - window` from both rings.
    fn evict(&mut self, now: Instant, window: Duration) {
        let cutoff = now.checked_sub(window);
        let drop_old = |q: &mut VecDeque<Instant>| {
            if let Some(cutoff) = cutoff {
                while let Some(&front) = q.front() {
                    if front < cutoff {
                        q.pop_front();
                    } else {
                        break;
                    }
                }
            }
        };
        drop_old(&mut self.queries);
        drop_old(&mut self.txt);
    }

    fn is_empty(&self) -> bool {
        self.queries.is_empty() && self.txt.is_empty()
    }
}

/// Sliding-window DNS tunneling detector. Cheap, lock-guarded
/// in-memory state keyed by registrable domain; one instance per
/// tenant (the service owns the per-tenant map).
#[derive(Debug)]
pub struct TunnelingDetector {
    config: TunnelingConfig,
    windows: Mutex<HashMap<String, DomainWindow>>,
}

impl TunnelingDetector {
    /// Construct with explicit thresholds.
    #[must_use]
    pub fn new(config: TunnelingConfig) -> Self {
        Self {
            config,
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Construct with [`TunnelingConfig::default`].
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(TunnelingConfig::default())
    }

    /// Observe one query at time `now`, returning any alerts it
    /// trips. `now` is injected (rather than read from the clock)
    /// so the detector is deterministic under test and so the
    /// caller can replay historical streams.
    pub fn observe(&self, query: &DnsQuery, now: Instant) -> Vec<TunnelingAlert> {
        let mut alerts = Vec::new();

        // Signal 1: encoded-payload QNAME (stateless).
        if let Some(alert) = self.check_encoded_qname(&query.name) {
            alerts.push(alert);
        }

        // Signals 2 & 3: per-domain volume + TXT abuse (stateful).
        let domain = registrable_domain(&query.name);
        let mut windows = self.windows.lock();
        let w = windows.entry(domain.clone()).or_default();
        w.evict(now, self.config.window);
        w.queries.push_back(now);
        if query.qtype == QType::Txt {
            w.txt.push_back(now);
        }
        let qcount = u32::try_from(w.queries.len()).unwrap_or(u32::MAX);
        let txtcount = u32::try_from(w.txt.len()).unwrap_or(u32::MAX);
        drop(windows);

        if qcount > self.config.max_queries_per_window {
            alerts.push(TunnelingAlert {
                kind: TunnelingKind::QueryVolume,
                domain: domain.clone(),
                detail: format!(
                    "{qcount} queries in {:?} (threshold {})",
                    self.config.window, self.config.max_queries_per_window
                ),
                score: ratio_score(qcount, self.config.max_queries_per_window),
            });
        }
        if txtcount > self.config.max_txt_per_window {
            alerts.push(TunnelingAlert {
                kind: TunnelingKind::TxtAbuse,
                domain,
                detail: format!(
                    "{txtcount} TXT queries in {:?} (threshold {})",
                    self.config.window, self.config.max_txt_per_window
                ),
                score: ratio_score(txtcount, self.config.max_txt_per_window),
            });
        }
        alerts
    }

    fn check_encoded_qname(&self, name: &str) -> Option<TunnelingAlert> {
        let payload: String = name.chars().filter(|&c| c != '.').collect();
        if payload.len() < self.config.min_qname_len {
            return None;
        }
        let entropy = shannon_entropy_bits(&payload);
        if entropy < self.config.min_entropy_bits {
            return None;
        }
        // Score blends how far past both thresholds we are. Lengths
        // are tiny (≤ 255-byte names) so the f64 casts are exact.
        #[allow(clippy::cast_precision_loss)]
        let len_factor = payload.len() as f64 / self.config.min_qname_len as f64;
        let ent_factor = entropy / self.config.min_entropy_bits;
        let score = (f64::midpoint(len_factor, ent_factor) - 1.0).clamp(0.0, 1.0);
        Some(TunnelingAlert {
            kind: TunnelingKind::EncodedQname,
            domain: name.to_string(),
            detail: format!(
                "len {} entropy {entropy:.2} bits/char (thresholds {} / {:.2})",
                payload.len(),
                self.config.min_qname_len,
                self.config.min_entropy_bits
            ),
            score,
        })
    }

    /// Evict fully-expired domain windows. Callers should run this
    /// periodically (e.g. once per window) so the map does not grow
    /// unbounded for domains that went quiet. Returns the number of
    /// domains evicted.
    pub fn gc(&self, now: Instant) -> usize {
        let mut windows = self.windows.lock();
        let before = windows.len();
        windows.retain(|_, w| {
            w.evict(now, self.config.window);
            !w.is_empty()
        });
        before - windows.len()
    }

    /// Number of domains currently tracked (telemetry / tests).
    #[must_use]
    pub fn tracked_domains(&self) -> usize {
        self.windows.lock().len()
    }
}

/// Normalised "how far past threshold" score in `[0, 1]`.
fn ratio_score(observed: u32, threshold: u32) -> f64 {
    if threshold == 0 {
        return 1.0;
    }
    let over = f64::from(observed) / f64::from(threshold) - 1.0;
    over.clamp(0.0, 1.0)
}

/// Shannon entropy of `s` in bits per character. An empty string is
/// zero entropy. Pure ASCII-aware byte frequency is sufficient — DNS
/// labels are bytes and tunnel payloads are base32/base64 ASCII.
#[must_use]
pub fn shannon_entropy_bits(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    let mut total = 0u32;
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
        total += 1;
    }
    // `total` is a byte count of a single DNS name (≤ 255), well
    // within f64's exact-integer range.
    let total_f = f64::from(total);
    let mut entropy = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = f64::from(c) / total_f;
        entropy -= p * p.log2();
    }
    entropy
}

/// Best-effort registrable domain: the last two labels of `name`
/// (an eTLD+1 approximation). DNS tunnels mint a fresh unique
/// subdomain per packet, so collapsing to the registered parent is
/// what makes the volume / TXT counters meaningful. This is a
/// deliberate heuristic — it over-aggregates multi-label public
/// suffixes (e.g. `foo.co.uk` groups under `co.uk`), which is the
/// safe direction for a *detector* (it raises sensitivity, never
/// hides a tunnel) and avoids shipping a megabyte Public Suffix List
/// to every constrained edge.
#[must_use]
pub fn registrable_domain(name: &str) -> String {
    let labels: Vec<&str> = name.split('.').filter(|l| !l.is_empty()).collect();
    let n = labels.len();
    if n <= 2 {
        return labels.join(".");
    }
    labels[n - 2..].join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn entropy_low_for_english_high_for_random() {
        let low = shannon_entropy_bits("wwwgooglecom");
        let high = shannon_entropy_bits("mfrggzdfmztwq2lknnwg23tpobyxe43uov3ho");
        assert!(low < high, "english {low} should be < base32 {high}");
        assert!(
            high > 4.0,
            "base32 entropy {high} should exceed 4 bits/char"
        );
    }

    #[test]
    fn entropy_empty_is_zero() {
        assert!(shannon_entropy_bits("").abs() < f64::EPSILON);
    }

    #[test]
    fn registrable_domain_takes_last_two_labels() {
        assert_eq!(registrable_domain("a.b.c.evil.com"), "evil.com");
        assert_eq!(registrable_domain("evil.com"), "evil.com");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain("x.tunnel.evil.com"), "evil.com");
    }

    #[test]
    fn detects_encoded_qname() {
        let d = TunnelingDetector::with_defaults();
        // ~60-char base32 payload subdomain.
        let payload = "mfrggzdfmztwq2lknnwg23tpobyxe43uov3homfrggzdfmztwq2lk";
        let name = format!("{payload}.tunnel.evil.com");
        let alerts = d.observe(&DnsQuery::new(&name, QType::A), Instant::now());
        assert!(
            alerts.iter().any(|a| a.kind == TunnelingKind::EncodedQname),
            "expected encoded-qname alert, got {alerts:?}"
        );
    }

    #[test]
    fn ignores_short_or_lowentropy_names() {
        let d = TunnelingDetector::with_defaults();
        // Short, normal name.
        assert!(
            d.observe(&DnsQuery::new("www.example.com", QType::A), Instant::now())
                .is_empty()
        );
        // Long but low-entropy (repeated label) name should not trip
        // the encoded-payload signal.
        let repetitive = format!("{}.example.com", "aaaaaaaaaa".repeat(6));
        let alerts = d.observe(&DnsQuery::new(&repetitive, QType::A), Instant::now());
        assert!(
            !alerts.iter().any(|a| a.kind == TunnelingKind::EncodedQname),
            "low-entropy long name should not be an encoded-qname tunnel: {alerts:?}"
        );
    }

    #[test]
    fn detects_query_volume_burst() {
        let cfg = TunnelingConfig {
            max_queries_per_window: 10,
            ..TunnelingConfig::default()
        };
        let d = TunnelingDetector::new(cfg);
        let base = Instant::now();
        let mut fired = false;
        for i in 0..15 {
            // Fresh unique subdomain each time, same registrable parent.
            let q = DnsQuery::new(&format!("p{i}.tunnel.evil.com"), QType::A);
            let alerts = d.observe(&q, at(base, 0));
            if alerts.iter().any(|a| a.kind == TunnelingKind::QueryVolume) {
                fired = true;
            }
        }
        assert!(fired, "volume burst to one parent should alert");
    }

    #[test]
    fn volume_resets_after_window() {
        let cfg = TunnelingConfig {
            max_queries_per_window: 5,
            window: Duration::from_secs(10),
            ..TunnelingConfig::default()
        };
        let d = TunnelingDetector::new(cfg);
        let base = Instant::now();
        // 5 within the window: no alert (strictly greater trips it).
        for i in 0..5 {
            let q = DnsQuery::new(&format!("p{i}.a.evil.com"), QType::A);
            assert!(d.observe(&q, at(base, 1)).is_empty());
        }
        // Far in the future: old entries evicted, counter resets, so a
        // single query does not trip.
        let q = DnsQuery::new("late.a.evil.com", QType::A);
        let alerts = d.observe(&q, at(base, 100));
        assert!(
            alerts.is_empty(),
            "counter should reset after window: {alerts:?}"
        );
    }

    #[test]
    fn detects_txt_abuse() {
        let cfg = TunnelingConfig {
            max_txt_per_window: 3,
            // Keep the plain volume threshold high so only TXT trips.
            max_queries_per_window: 10_000,
            ..TunnelingConfig::default()
        };
        let d = TunnelingDetector::new(cfg);
        let base = Instant::now();
        let mut fired = false;
        for i in 0..6 {
            let q = DnsQuery::new(&format!("c{i}.dl.evil.com"), QType::Txt);
            if d.observe(&q, at(base, 0))
                .iter()
                .any(|a| a.kind == TunnelingKind::TxtAbuse)
            {
                fired = true;
            }
        }
        assert!(fired, "TXT abuse should alert");
    }

    #[test]
    fn gc_drops_quiet_domains() {
        let d = TunnelingDetector::with_defaults();
        let base = Instant::now();
        d.observe(&DnsQuery::new("x.quiet.com", QType::A), at(base, 0));
        assert_eq!(d.tracked_domains(), 1);
        // Long after the window, gc reaps it.
        let reaped = d.gc(at(base, 1000));
        assert_eq!(reaped, 1);
        assert_eq!(d.tracked_domains(), 0);
    }

    #[test]
    fn alert_kind_strings_stable() {
        assert_eq!(
            TunnelingKind::EncodedQname.as_str(),
            "dns.tunneling.encoded_qname"
        );
        assert_eq!(
            TunnelingKind::QueryVolume.as_str(),
            "dns.tunneling.query_volume"
        );
        assert_eq!(TunnelingKind::TxtAbuse.as_str(), "dns.tunneling.txt_abuse");
    }
}
