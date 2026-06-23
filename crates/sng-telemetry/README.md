# sng-telemetry

Local telemetry collector for the ShieldNet Gateway edge VM and
endpoint client. Implements the five-stage pipeline described in
[`ARCHITECTURE.md`](../../ARCHITECTURE.md) §4.8.

```
collect → dedup → redact → enrich → egress (sng-comms)
```

1. **Collect** — typed `TelemetryEvent`s arrive from every
   subsystem (DNS filter, firewall, IPS, SWG, ZTNA, SD-WAN,
   DEM, updater, agent lifecycle). Subsystems implement
   `EventSource` or push directly into a `PipelineHandle`.
2. **Dedup** — a rolling window (`Dedup`) drops fingerprint-
   equal events observed within the configured TTL. The
   fingerprint is computed over producer-relevant fields only
   (byte counters and other observation-dependent fields are
   excluded) so a retry path emitting the same flow twice
   collapses to one record.
3. **Redact** — metadata-first (`RedactionPolicy`): payload
   only when the tenant policy explicitly opts in for that flow
   class. Redaction happens at source.
4. **Enrich** — site / tenant / time / identity context applied
   on the egress path so the bytes that leave always carry the
   producer's authoritative view.
5. **Egress** — handoff to [`sng-comms`](../sng-comms) for the
   bounded-spool + batched native-protocol upload to the
   control plane.

A short `PcapRing` gives operators bounded forensic re-hydration
on demand. The ring is local-only — bytes never leave the edge /
endpoint unless the operator explicitly pulls a slice.

## Module layout

* `source` — `EventSource` trait, `ChannelSource` impl,
  `TelemetryEvent` shape.
* `dedup` — rolling-window deduplicator and `Fingerprint`
  hasher.
* `redaction` — `RedactionPolicy` per-flow-class opt-in
  matrix.
* `enrichment` — site / tenant / time / identity binder.
* `pcap` — `PcapRing`, `PcapRingConfig`, `PcapStats`.
* `pipeline` — `Pipeline` / `PipelineHandle` /
  `PipelineStats` — the supervisor surface the edge / agent
  drive from their subsystem composition.
* `error` — `TelemetryError` mapped to
  `sng_core::error::ErrorCode`.

## Shutdown contract

`Pipeline::drain` cooperates with the supervisor drain path: it
exits as soon as every producer-side mpsc clone is dropped and
the in-flight `try_recv` returns `Disconnected`. The supervisor
drains the health aggregator before per-subsystem drain so the
aggregator's `Arc<dyn HealthCheck>` clones release their
producer-side handles in time. See
[`sng-edge`](../sng-edge) `tests/edge_e2e.rs` for the
regression test.

## Local verification

```sh
cargo +1.91 test  -p sng-telemetry
cargo +1.91 clippy -p sng-telemetry --all-targets -- -D warnings
cargo +1.91 fmt    --all -- --check
```
