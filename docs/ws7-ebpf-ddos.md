# XDP DDoS mitigation & connection-tracking enhancements

This page documents Workstream 7: the XDP-level DDoS mitigations and the
per-flow connection-tracking enhancements added to
[`crates/sng-ebpf`](../crates/sng-ebpf). It is the userspace authority and
in-memory model for behaviour that the appliance image's kernel BPF
objects enforce at the NIC ring buffer; see
[`crates/sng-ebpf/README.md`](../crates/sng-ebpf/README.md) for the
kernel/userspace split and how the crate is tested without a live NIC.

## DDoS mitigation ([`ddos.rs`](../crates/sng-ebpf/src/ddos.rs))

The [`DdosMitigator`] runs the cheapest check first and short-circuits on
the first drop:

1. **GeoIP country block** — a single longest-prefix lookup in the
   per-tenant [`GeoIpTable`] (IP → ISO-3166 country) followed by a
   [`GeoIpBlocklist`] membership test. The database is shared; the
   blocklist is per tenant, so the same `DdosMitigator` config can block
   `CN`/`RU` for one tenant and nothing for another.
2. **SYN-flood rate limit** — only TCP SYNs (no ACK) consume the
   per-source SYN budget.
3. **UDP-flood rate limit** — every UDP datagram consumes the per-source
   UDP budget. The SYN and UDP buckets are independent, so draining one
   never affects the other for the same source.

### Token bucket

[`TokenBucket`] uses **integer, remainder-preserving** refill — there is
no floating point in the kernel data path. A naive integer rate limiter
floors the fractional tokens accrued between two closely-spaced packets
to zero on every poll and so never refills under high-frequency traffic;
carrying the sub-token remainder forward fixes that starvation bug. Burst
size is the bucket capacity; the sustained rate is `refill_per_sec`.

### Per-source tracking & eviction

[`SourceRateLimiter`] bounds memory by tracking at most `max_tracked`
sources (mirroring the kernel `LRU_HASH`). Under insert pressure it
evicts a *fully-refilled* (idle) source; if every tracked source is
active it **fails open** — a new source is admitted rather than
mis-attributed to another source's bucket. Monotonic-clock anomalies are
clamped (timestamps never move backwards).

## Connection tracking ([`maps.rs`](../crates/sng-ebpf/src/maps.rs))

[`FlowState`] gained, alongside `last_seen_ns`/`packets`:

* `first_seen_ns` + `duration_ns()` / `is_long_lived()` — long-lived
  connection detection.
* `bytes` + `bytes_per_sec()` — per-flow bandwidth monitoring.
* `l4_protocol` + `anomaly_flags` — `observe()` sets the
  `anomaly::PROTOCOL_CHANGE` bit (a `|=`, a single-instruction kernel
  update) when a packet arrives on an existing 5-tuple slot carrying a
  different IANA protocol than the flow was first seen with, without
  overwriting the baseline protocol. `last_seen_ns` is monotonic, so a
  reordered/late packet cannot rewind a flow's duration.

`FlowState::new()` takes the creating packet's `bpf_ktime_get_ns`
timestamp (nanoseconds since boot, never zero at runtime); the all-zero
`Default` value is the map's uninitialised sentinel.

## Control-plane integration

[`XdpControlPlane::install_ddos`] validates a [`DdosConfig`] and pushes it
through the [`ProgramLoader::update_ddos`] map-marshalling hook, exactly
like rules/classification/steering. [`XdpStats`] surfaces
`ddos_installed` and `geoip_entries` for telemetry.

## Verification

All logic is exercised by the in-memory model — no NIC, no root, no
kernel required:

* `cargo test -p sng-ebpf` — unit tests in `ddos.rs`/`maps.rs` plus the
  end-to-end `tests/ddos.rs` and `tests/conntrack.rs` integration suites
  (SYN/UDP flood drop-after-burst, sustained refill, per-tenant GeoIP,
  distributed sources, bandwidth, long-lived, protocol anomaly,
  reordering).
* `cargo build -p sng-ebpf --features xdp` — compiles the `aya` kernel
  loader, including the `update_ddos` marshalling stub the appliance
  image fills in.
* `bench/src/datapath.rs::bench_syn_flood_drop_rate` + the
  `sng-bench-datapath` binary measure the SYN-flood **drop-decision**
  throughput. On the development box this model sustains **> 30M
  decisions/s**, comfortably clearing the 10M pps target; the kernel XDP
  path is strictly faster because it also skips `sk_buff` allocation and
  the entire network-stack traversal.

**Environment-limited:** this session cannot attach an XDP program to a
live NIC, so the kernel-side map marshalling in
[`AyaLoader::update_ddos`](../crates/sng-ebpf/src/loader.rs) returns
`Unsupported` (as the sibling rule/classification/steering hooks already
do) — that wiring lands with the BPF object crate in the appliance image
pipeline. Everything above is real, compiling, and unit-tested against
the same verdict functions the kernel path drives.
