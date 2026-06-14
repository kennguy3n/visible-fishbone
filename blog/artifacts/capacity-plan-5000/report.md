## SNG control-plane scale benchmark — capacity-plan

- run (unix): `1781437282`

### Verdict

| Metric | Theoretical | Actual | Fortinet | Zscaler | Palo Alto | Verdict |
|--------|-------------|--------|----------|---------|-----------|---------|

> Fortinet (FortiManager) and Palo Alto (Panorama) numbers are management-plane / ASIC-appliance figures, NOT apples-to-apples with a multi-tenant SaaS control plane. Zscaler (cloud-native) is the most directly comparable. Treat the cross-vendor column as directional only.

### Capacity plan @ 5000 tenants × 7 telemetry classes

Telemetry classes: `agent`, `dns`, `flow`, `http`, `ips`, `sdwan`, `ztna`

**Postgres connection-pool pressure**

- replicas × PG_MAX_OPEN_CONNS = 3 × 20 = 60 app conns
- peak concurrent queries (Little's law): 10.0 → recommended pool/replica 5
- PgBouncer: true → backend conns required 15 / max_connections 200 (within: true)
- pool sized comfortably for the modelled load.

**ClickHouse write throughput**

- 26500.0 rows/s total across 2 shard(s) = 13250.0 rows/s/shard
- 12.94 inserts/s/shard @ batch 1024 (recommended: batch 13250 across 2 shard(s))
- 68688000000 rows/month (13737600/tenant), ~2198.0 GB/month compressed hot storage
- 12.94 inserts/s/shard exceeds the ~1/s target; raise CLICKHOUSE_BATCH_SIZE to 13250 (more rows per part, same shard count).

**NATS subject cardinality**

- 35000 distinct subjects across 16 partition(s) = 2187.5 avg (busiest ~2516)
- 26500.0 msgs/s, 24h retention → ~732672000000 bytes hot JetStream storage
- recommended NATS_PARTITIONS: 16 — subject cardinality per partition within the healthy envelope.

**AI inference footprint (WS-9 shared pool)**

- 250 active tenants → 0.42 avg calls/s, 1.25 peak calls/s (burst)
- offered concurrency (Little's law): 4.38 vs pool slots 4 → 109% utilization (recommended slots 7)
- shared pool 4.6 GB vs per-tenant residency 17000.0 GB → ~3696× less memory
- peak demand needs ~4.38 parallel slots; raise AI_INFERENCE_POOL_MAX_CONCURRENT to 7 (bursts above the cap queue fairly up to MaxWait, then degrade to the template path).

**Periodic per-tenant sweep cost (dormancy dividend, WS-1)**

- activity mix: 400 active / 600 idle / 4000 dormant (idle every 10 cycles, dormant every 100)
- tiered jobs (`idp_directory_sync`, `casb_noops_reconcile`, `alert_feedback_tuning`)
- per job: 5000 tenants/cycle (untiered) → 500.0 tenants/cycle (tiered) = **10.0x** fewer
- tiered breakdown/cycle: 400.0 active + 60.0 idle + 40.0 dormant
- tail dividend: idle **10.0x**, dormant **100.0x** fewer visits/cycle
- aggregate across 3 job(s): 15000 → 1500.0 tenants/cycle
- 3 job(s) tiered: 5000 tenants/cycle/job → 500.0 (10.0x); idle tail 10.0x, dormant tail 100.0x.

