//! DNS threat-intelligence efficacy: drive the *real* sng-dns
//! [`ThreatIntelSinkhole`] (Bloom-filter known-bad domain matcher) and
//! [`TunnelingDetector`] (encoded-QNAME / query-volume / TXT-abuse
//! signals) over a corpus of known-bad and known-good DNS activity.
//!
//! Two confusion matrices are produced and merged into one report:
//!
//! * **Sinkhole**: a bad case is a known-bad (or sub-domain of a
//!   known-bad) name that MUST match the Bloom feed; a good case is a
//!   benign name (incl. an allowlisted name that collides with the
//!   feed) that MUST NOT be sinkholed.
//! * **Tunneling**: a bad case is an exfiltration pattern (long
//!   high-entropy QNAME, query flood, or TXT flood) that MUST raise an
//!   alert; a good case is ordinary resolver traffic that MUST stay
//!   silent.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use sng_dns::{
    canonicalize_name, DnsQuery, QType, ThreatIntelSinkhole, TunnelingConfig, TunnelingDetector,
};

use crate::report::{Case, Feature, FunctionReport, Kind, Targets};

/// Known-bad feed (threat-intel domains). Small, but the Bloom filter
/// is sized for it so the false-positive rate stays well under target.
const BAD_DOMAINS: &[&str] = &[
    "malware-c2.example",
    "evil-tracker.example",
    "ransom-pay.example",
    "phish-login.example",
    "botnet-node.example",
    "exfil-sink.example",
];

/// Allowlisted names that must never be sinkholed even on a Bloom hit.
const ALLOW_DOMAINS: &[&str] = &["safe.example"];

/// A long, high-entropy QNAME label (base32-ish encoded payload) that
/// should trip the encoded-QNAME signal: >= 52 chars, >= 3.5 bits/char.
fn encoded_qname() -> String {
    // 60 chars of mixed-case + digits → high per-char entropy.
    format!(
        "{}.{}",
        "k7n2p9q4r8s3t6v1w5x0y2z8a4b7c9d3e6f1g5h0j2k4m7n9p3q6", "tunnel.example"
    )
}

fn sinkhole_cases() -> Vec<Case> {
    let sink = ThreatIntelSinkhole::build(
        BAD_DOMAINS.iter().map(|s| s.to_string()),
        ALLOW_DOMAINS.iter().map(|s| s.to_string()),
        BAD_DOMAINS.len(),
        0.001,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv6Addr::LOCALHOST,
    );

    struct DnsCase {
        desc: &'static str,
        bad: bool,
        name: &'static str,
    }
    let corpus = [
        // ---- known-bad: MUST be sinkholed ----
        DnsCase {
            desc: "known-bad C2 domain",
            bad: true,
            name: "malware-c2.example",
        },
        DnsCase {
            desc: "known-bad tracker",
            bad: true,
            name: "evil-tracker.example",
        },
        DnsCase {
            desc: "known-bad ransom-pay",
            bad: true,
            name: "ransom-pay.example",
        },
        DnsCase {
            desc: "known-bad phishing",
            bad: true,
            name: "phish-login.example",
        },
        DnsCase {
            desc: "known-bad botnet node",
            bad: true,
            name: "botnet-node.example",
        },
        DnsCase {
            desc: "sub-domain of known-bad (suffix match)",
            bad: true,
            name: "beacon.malware-c2.example",
        },
        DnsCase {
            desc: "deep sub-domain of known-bad",
            bad: true,
            name: "a.b.c.exfil-sink.example",
        },
        // ---- known-good: MUST resolve normally ----
        DnsCase {
            desc: "popular CDN",
            bad: false,
            name: "cdn.cloudflare.com",
        },
        DnsCase {
            desc: "SaaS app",
            bad: false,
            name: "app.salesforce.com",
        },
        DnsCase {
            desc: "search engine",
            bad: false,
            name: "www.google.com",
        },
        DnsCase {
            desc: "OS update service",
            bad: false,
            name: "update.microsoft.com",
        },
        DnsCase {
            desc: "package registry",
            bad: false,
            name: "registry.npmjs.org",
        },
        DnsCase {
            desc: "corporate intranet",
            bad: false,
            name: "intranet.corp.example",
        },
        DnsCase {
            desc: "allowlisted name (must override feed)",
            bad: false,
            name: "safe.example",
        },
    ];

    corpus
        .iter()
        .map(|c| {
            let canonical = canonicalize_name(c.name);
            // Allowlist takes precedence over a Bloom hit, exactly as
            // the resolver path enforces; model that here so an
            // allowlisted collision counts as a correct allow.
            let allow = ALLOW_DOMAINS
                .iter()
                .any(|a| canonical == *a || canonical.ends_with(&format!(".{a}")));
            let sinkholed = !allow && sink.matches(&canonical);
            let correct = if c.bad { sinkholed } else { !sinkholed };
            Case {
                description: format!("sinkhole: {}", c.desc),
                bad: c.bad,
                expected: if c.bad { "deny" } else { "allow" }.into(),
                actual: if sinkholed { "deny" } else { "allow" }.into(),
                correct,
            }
        })
        .collect()
}

fn tunneling_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    let base = Instant::now();

    // Signal 1: encoded-QNAME payload (stateless) — fresh detector so
    // volume counters do not interfere.
    {
        let det = TunnelingDetector::with_defaults();
        let q = DnsQuery::new(&encoded_qname(), QType::A);
        let alerts = det.observe(&q, base);
        let detected = !alerts.is_empty();
        cases.push(Case {
            description: "tunneling: long high-entropy encoded QNAME".into(),
            bad: true,
            expected: "detect".into(),
            actual: if detected { "detect" } else { "pass" }.into(),
            correct: detected,
        });
    }

    // Signal 2: query-volume flood to one registrable domain.
    {
        let cfg = TunnelingConfig::default();
        let det = TunnelingDetector::new(cfg);
        let mut detected = false;
        for i in 0..(cfg.max_queries_per_window + 5) {
            let q = DnsQuery::new(&format!("h{i}.flood-domain.example"), QType::A);
            let alerts = det.observe(&q, base + Duration::from_millis(u64::from(i)));
            if alerts
                .iter()
                .any(|a| a.kind.as_str() == "dns.tunneling.query_volume")
            {
                detected = true;
            }
        }
        cases.push(Case {
            description: "tunneling: query-volume flood to one domain".into(),
            bad: true,
            expected: "detect".into(),
            actual: if detected { "detect" } else { "pass" }.into(),
            correct: detected,
        });
    }

    // Signal 3: TXT-record abuse flood.
    {
        let cfg = TunnelingConfig::default();
        let det = TunnelingDetector::new(cfg);
        let mut detected = false;
        for i in 0..(cfg.max_txt_per_window + 5) {
            let q = DnsQuery::new(&format!("seg{i}.txt-tunnel.example"), QType::Txt);
            let alerts = det.observe(&q, base + Duration::from_millis(u64::from(i)));
            if alerts
                .iter()
                .any(|a| a.kind.as_str() == "dns.tunneling.txt_abuse")
            {
                detected = true;
            }
        }
        cases.push(Case {
            description: "tunneling: TXT-record abuse flood".into(),
            bad: true,
            expected: "detect".into(),
            actual: if detected { "detect" } else { "pass" }.into(),
            correct: detected,
        });
    }

    // ---- known-good: ordinary traffic MUST stay silent ----
    struct GoodCase {
        desc: &'static str,
        name: &'static str,
        qtype: QType,
    }
    let good = [
        GoodCase {
            desc: "short A query",
            name: "www.example.com",
            qtype: QType::A,
        },
        GoodCase {
            desc: "AAAA query",
            name: "api.service.example",
            qtype: QType::Aaaa,
        },
        GoodCase {
            desc: "CNAME lookup",
            name: "cdn.assets.example",
            qtype: QType::Cname,
        },
        GoodCase {
            desc: "MX lookup",
            name: "mail.example.org",
            qtype: QType::Mx,
        },
        GoodCase {
            desc: "moderately long but low-entropy name",
            name: "very-long-but-human-readable-subdomain.example.com",
            qtype: QType::A,
        },
        GoodCase {
            desc: "single TXT (SPF) lookup",
            name: "example.com",
            qtype: QType::Txt,
        },
    ];
    for g in good {
        // Each benign case gets a fresh detector: a single ordinary
        // query must never alert on its own.
        let det = TunnelingDetector::with_defaults();
        let q = DnsQuery::new(g.name, g.qtype);
        let alerts = det.observe(&q, base);
        let detected = !alerts.is_empty();
        cases.push(Case {
            description: format!("tunneling: {}", g.desc),
            bad: false,
            expected: "pass".into(),
            actual: if detected { "detect" } else { "pass" }.into(),
            correct: !detected,
        });
    }

    cases
}

pub async fn run() -> FunctionReport {
    let mut cases = sinkhole_cases();
    cases.extend(tunneling_cases());

    FunctionReport::from_cases(
        "dns",
        "sng-dns",
        Kind::Detection,
        Targets::default(),
        cases,
        Some(
            "Real ThreatIntelSinkhole Bloom matcher + TunnelingDetector. Known-bad \
             feed domains (and their sub-domains) sinkholed with allowlist override; \
             encoded-QNAME / query-volume / TXT-abuse tunneling flagged; ordinary \
             resolver traffic resolves and stays silent."
                .into(),
        ),
    )
    .with_features(vec![
        Feature {
            name: "Bloom-filter sinkhole".into(),
            how: "known-bad threat-feed domains are inserted into a sized Bloom filter; \
                  a query (and each parent suffix) is probed and sinkholed on a hit, \
                  with an allowlist override for business-critical infra."
                .into(),
            coverage: "suffix-matched domain feed + allowlist".into(),
        },
        Feature {
            name: "Tunneling detection".into(),
            how: "stateless encoded-QNAME entropy/length check plus per-registrable-domain \
                  sliding-window query-volume and TXT-abuse counters."
                .into(),
            coverage: "encoded_qname + query_volume + txt_abuse signals".into(),
        },
    ])
}
