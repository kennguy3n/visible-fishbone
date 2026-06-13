# Threat Intelligence & IOC Management (WORKSTREAM 8)

The threat-intel aggregator pulls Indicators of Compromise (IOCs) from
external feeds, normalizes/deduplicates them with a TTL + confidence
score, and wires matches into the existing enforcement planes:

- **Domain IOCs** → DNS sinkhole + app-registry demotion (via the
  `appdb` demotion engine, `threat_feed` signal).
- **IP IOCs** → firewall deny rules compiled into the next signed
  policy bundle (NGFW target slice).
- **URL IOCs** → SWG deny rules in the bundle (SWG target slice).
- **Hash IOCs** → malware verdict set in the bundle's `mw` section,
  hot-swapped into the `sng-swg` `StaticMalwareList`.

All of it lives in `internal/service/ai` (feed parsers, IOC store,
feed manager, enforcement compiler) and folds into the control plane
in `cmd/sng-control`.

## Components

| File | Role |
|------|------|
| `ioc.go` | `IOC` type, type normalization (`domain`/`ip`/`url`/`hash`), validation |
| `ioc_store.go` | In-memory dedup store (TTL, confidence floor, `Sweep`), implements `ThreatFeedProvider` for live matching |
| `feed.go` | `FeedParser`/`FeedFetcher` seams, `HTTPFetcher` (the only network IO), `StaticFetcher` (tests) |
| `feed_stix_taxii.go` | STIX 2.1 / TAXII 2.1 pattern extraction |
| `feed_csvjson.go` | Generic CSV (header- or index-addressed) + JSON (bare/wrapped array) parsers |
| `feed_otx.go` | AlienVault OTX pulses |
| `feed_abusech.go` | abuse.ch URLhaus / MalwareBazaar / Feodo Tracker |
| `feed_misp.go` | MISP events/attributes export (nested Event→Attribute, composite types, `to_ids` filter) |
| `feed_manager.go` | Per-feed scheduler (default hourly), warm-up refresh, TTL sweeper, `OnUpdate` hook, per-feed telemetry |
| `ioc_enforcement.go` | `IOCEnforcementCompiler` (IOC→`policy.Rule` + malware hashes) and `DemotionBridge` (domain IOC → demotion engine) |

The parsers are pure functions (no network IO) and are unit-tested
against realistic sample payloads in `feed_parsers_test.go`. The
end-to-end path (seed IOCs → compiled bundle carries deny rules +
malware section → evaluator blocks matching traffic) is proven in
`internal/service/policy/ioc_integration_test.go`.

## Configuration

Every feed is gated behind its URL — with nothing configured the
aggregator still runs (in-memory store + sweeper) but pulls nothing,
so the IOC→enforcement path is a safe no-op. Network calls happen
only for configured feeds.

| Env var | Default | Meaning |
|---------|---------|---------|
| `THREATINTEL_REFRESH_INTERVAL` | `1h` | Default per-feed refresh cadence |
| `THREATINTEL_DEFAULT_TTL` | `0` (permanent) | TTL applied to undated indicators |
| `THREATINTEL_MIN_CONFIDENCE` | `0` | Store-wide confidence floor `[0,1]` |
| `THREATINTEL_TAXII_URL` / `THREATINTEL_TAXII_TOKEN` | — | STIX/TAXII 2.1 collection (token → `Authorization: Bearer`) |
| `THREATINTEL_OTX_URL` / `THREATINTEL_OTX_API_KEY` | — | AlienVault OTX (key → `X-OTX-API-KEY`) |
| `THREATINTEL_URLHAUS_URL` | — | abuse.ch URLhaus (malware URLs) |
| `THREATINTEL_MALWAREBAZAAR_URL` | — | abuse.ch MalwareBazaar (malware hashes) |
| `THREATINTEL_FEODOTRACKER_URL` | — | abuse.ch Feodo Tracker (C2 IPs) |
| `THREATINTEL_CSV_URL` | — | Generic CERT CSV (indicator/type/confidence columns) |
| `THREATINTEL_JSON_URL` | — | Generic CERT JSON (array of objects) |
| `THREATINTEL_MISP_URL` / `THREATINTEL_MISP_AUTH_KEY` | — | MISP feed (events/attributes export; key → `Authorization`) |
| `THREATINTEL_MISP_INCLUDE_NON_IDS` | `false` | Ingest MISP attributes not flagged `to_ids` (default: `to_ids:true` only) |

## Data flow

```
feeds ── HTTPFetcher ──▶ FeedParser ──▶ IOCStore (dedup/TTL/confidence)
                                              │
                  ┌───────────────────────────┼───────────────────────────┐
                  ▼                            ▼                            ▼
        ThreatIntelEngine            IOCEnforcementCompiler         DemotionBridge
        (live traffic match)         (policy bundle compile)        (domain → demotion engine)
                                       │            │
                                  deny rules     malware "mw"
                                  (IP/domain/URL)  section → StaticMalwareList
```

The IOC store is the shared spine: the live-traffic matcher reads it
alongside the regional catalogs, the enforcement compiler reads a
point-in-time snapshot at bundle-compile time, and the demotion bridge
fires on every feed refresh via the manager's `OnUpdate` hook.

## Evaluation precedence

The IOC deny rules are appended to the typed policy graph **after** the
operator's own rules and the inline-CASB rules, and the policy
evaluator is first-match-wins (`Graph.CompileTarget`). IOC rules are
therefore the **lowest-priority** rules in a bundle: an explicit
operator *allow* for a domain/IP/URL shadows a threat-intel *deny* for
the same indicator. This is intentional and mirrors the inline-CASB
ordering — an operator's deliberate allow-list entry (e.g. a known
false-positive or a sanctioned-but-flagged host) is a stronger signal
than an automated feed, so the operator stays in control of automated
blocks without having to mute the feed. The malware-hash (`mw`) set is
a separate verdict plane (SWG malware inspector), not a graph rule, so
it is not subject to this rule ordering.
