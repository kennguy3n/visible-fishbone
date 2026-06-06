# Commodity-hardware edge (micro-branch)

`sng-edge` is a software appliance: it must run acceptably on the cheap,
heterogeneous hardware an SME branch already owns (a mini-PC, a spare
1U, an ARM SBC) rather than requiring a purpose-built box. Session 2B
adds the host-awareness layer that lets one binary adapt to whatever it
lands on, in [`crates/sng-edge/src/commodity.rs`](../crates/sng-edge/src/commodity.rs).

## Minimum spec

The documented micro-branch floor (`COMMODITY_BASELINE`):

| Resource | Minimum | Class |
|----------|--------:|-------|
| CPU      | **2 cores** (ARM64 or x86-64) | hard |
| RAM      | **2 GiB** | hard |
| Storage  | **8 GiB** free on the spool filesystem | soft |

CPU and RAM are *hard* bounds — below them the edge boots but logs a
`FAIL` preflight, because the inspection pipeline cannot be expected to
keep up. Storage is a *soft* bound (`Warn`): a small disk only limits
spool depth / update staging, which degrades gracefully. The edge never
*refuses* to boot on under-spec hardware — a refusing security appliance
is worse than a degraded one — but it makes the condition unmissable in
the boot log.

## What the host probe does

`CommodityProfile::detect(data_dir, workers, datapath)` assembles four
things at boot:

1. **`HostTopology`** — best-effort, never fails. On Linux it reads
   logical CPUs (`available_parallelism`), NUMA nodes
   (`/sys/devices/system/node/node*/cpulist`), total RAM
   (`/proc/meminfo`), and free spool space (`statvfs`, walking up to the
   nearest existing parent so a not-yet-created spool dir still probes
   the right filesystem). On non-Linux / masked `/sys` (containers) it
   falls back to a single NUMA node owning all CPUs and zeroes the
   unprobed metrics.
2. **`MinSpec::assess`** → `Pass` / `Warn(reasons)` / `Fail(reasons)`
   against the baseline above.
3. **`AffinityPlan`** — a NUMA-aware worker→CPU pinning plan
   (round-robin workers across nodes, then CPUs within a node).
   `pin_current_thread(worker)` applies it via `sched_setaffinity` on
   Linux and is a no-op elsewhere, so keeping packet workers on cores
   local to their memory avoids cross-node traffic on multi-socket
   hosts without breaking single-node ones.
4. **`DataPathProfile`** — see below.

The boot preflight in `supervisor::run_edge` logs a one-line
`CommodityProfile::summary()` (`cpus=… numa_nodes=… mem=… storage_free=…
workers=… datapath=… xdp=… pool_frames=… min_spec=…`) at `info` / `warn`
/ `error` matching the assessment.

## Zero-copy packet buffers

`MmapBufferPool` pre-allocates a fixed pool of page-aligned frames from a
single anonymous `mmap`, handed out as RAII `Frame`s (returned to the
free list on drop). This keeps the forwarding hot path allocation-free —
critical on a 2-core box where allocator contention shows up directly as
latency. The pool's mutex recovers from poisoning (`PoisonError::into_inner`)
instead of panicking, since each critical section is a panic-free
push/pop and a leaked frame must never wedge the data path.

## eBPF fast-path flag (owned by 2D)

The optional XDP/eBPF fast-path itself is **Session 2D's** work; Session
2B only *consumes* the resolved feature flag. `DataPathProfile::from_selection`
takes the already-resolved `DataPathSelection` and records whether the
fast path is active, then sizes the buffer pool accordingly:

| Backend | Frames | Frame size |
|---------|-------:|-----------:|
| slow path (userspace) | `SLOW_PATH_FRAMES` = 1024 | `FRAME_BYTES` = 2048 |
| XDP fast path         | `FAST_PATH_FRAMES` = 4096 | `FRAME_BYTES` = 2048 |

The fast path gets a deeper pool because it drains NIC queues in larger
bursts. Session 2B does **not** implement XDP, attach any BPF program, or
duplicate the `sng-ebpf` crate — it only reads the flag and provisions
host resources to match.
