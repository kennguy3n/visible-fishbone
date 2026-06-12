# High Availability & Failover of the Leader-Gated Loops

The SNG control plane (`sng-control`) is deployed as **2–3 horizontally
scaled replicas** behind a load balancer. Every replica serves API
traffic and consumes NATS, but a handful of background jobs are
**singletons**: they must run on exactly one replica at a time, or
replicas would duplicate vendor fetches, race on certificate rotation,
and emit duplicate scheduled reports.

This document describes how that singleton guarantee is enforced
([`internal/service/leader`](../internal/service/leader)), how failover
behaves when the leader replica crashes, and the **measured recovery
time objective (RTO)** from the reproducible harness in
[`bench/ha-failover`](../bench/ha-failover).

> The RTO numbers in §5 were measured on this dev VM. Read §6 before
> quoting them: this is a single-host, multi-process test, not a true
> multi-node cluster, and the *clean-crash* RTO it measures is very
> different from the *network-partition* RTO.

---

## 1. Election mechanism

Leadership is a **Postgres session-level advisory lock**
(`pg_try_advisory_lock` / `pg_advisory_unlock`). The lock is held for
the lifetime of a dedicated database session and is released
automatically by Postgres the moment that session ends — whether the
replica unlocks gracefully or simply dies. That auto-release on session
death is the entire basis for automatic failover.

Each replica runs a `LeaderElector` (`internal/service/leader/election.go`):

```
Run(ctx):
  tick(ctx)                       // immediate attempt at boot
  every interval (DefaultCheckInterval = 30s):
    tick(ctx)

tick(ctx):
  if we hold a session:
    if session.Ping() fails -> step down, drop the session   // leader path
  else:
    open a session; if TryLock(lockID) succeeds -> become leader  // follower path
```

- **Follower → leader.** A follower opens a session and calls
  `TryLock`. Exactly one replica can hold a given lock key
  (`DefaultLockID`), so at most one leader exists at a time —
  **split-brain is prevented by Postgres's lock mutual-exclusion**, not
  by any timing assumption.
- **Leader → follower.** On every tick the leader `Ping`s the
  lock-holding session. If the ping fails (connection dropped, backend
  gone), the leader steps down and releases its in-process leadership
  flag so a follower can take over.
- **Clean handoff.** On graceful shutdown (`ctx` cancelled, e.g. a
  rolling deploy draining a pod) the leader explicitly relinquishes:
  it unlocks and closes the session, so a follower acquires on its next
  tick without waiting for any timeout.

### Fencing tokens

There is an unavoidable window during an ungraceful crash: the lock is
already free (Postgres reclaimed it) and a new leader has acquired it,
but the *old* leader has not yet run the tick that pings its dead
session — so for a few milliseconds two replicas both believe they are
leader. Advisory locks alone do not make a stale leader's in-flight
writes safe.

`internal/service/leader/fencing.go` closes this with a **fencing
token** = `{LockID, Epoch}`. The epoch is globally monotonic: in
production it is the Postgres transaction id at acquisition
(`pg_current_xact_id()`, see `pgsession.go`), so a new leader's token is
always strictly greater than any prior leader's. Downstream singleton
work obtained via `RunIfLeaderFenced` receives the live token and can
stamp it on writes; a stale leader's lower-epoch writes are rejected.
This is the standard fencing pattern (Kleppmann) and is what makes the
brief two-leader window *safe* rather than merely *short*.

---

## 2. The leader-gated loops

Singleton jobs are wrapped in `elector.RunIfLeader(ctx, name, fn)` in
[`cmd/sng-control/main.go`](../cmd/sng-control/main.go). `RunIfLeader`
runs `fn` with a leadership-scoped context **only while this replica is
the leader**, cancels that context the instant leadership is lost (or
flaps to a new term), and re-invokes `fn` on the replica that takes
over. The currently gated loops:

| Job name (`RunIfLeader`)  | Purpose                                            | Issue |
|---------------------------|----------------------------------------------------|-------|
| `app-registry-sync`       | Vendor app-registry catalog sync                   |       |
| `idp-directory-sync`      | IdP directory (users/groups) sync                  | #177  |
| `casb-noops-reconcile`    | Shadow-IT / CASB NoOps reconciliation              | #172  |
| `pop-rebalance`           | PoP capacity rebalance                             |       |
| `compliance-evidence`     | Scheduled compliance evidence collection           |       |
| `threatintel-feed-sync`   | Threat-intel feed ingestion                        |       |
| `ws11-migration-resume`   | Resumable migration driver                         |       |

Running any of these on more than one replica would double vendor API
calls, duplicate scheduled compliance reports, and race on shared
state — exactly what leader-gating prevents.

---

## 3. Failover behavior

1. **Leader replica crashes** (OOM, segfault, `kill -9`, node loss).
   Its Postgres session ends, so the advisory lock is released.
2. **A follower's next election tick** opens a session and wins
   `TryLock`. It establishes a new fencing epoch *before* flipping its
   leadership flag, then starts the gated loops.
3. **The old leader (if still alive but partitioned)** fails its next
   `Ping`, steps down, and stops its gated loops. Its fencing token is
   now stale and any late writes are rejected.

The **failover RTO** is therefore bounded by **one election check
interval** (the follower's worst-case wait until its next tick) plus the
time for Postgres to release the dead session's lock and for the new
leader to start work.

---

## 4. Reproducing the measurement

The harness [`bench/ha-failover`](../bench/ha-failover) is deliberately
**multi-process**: each replica is a separate OS process running the
real `LeaderElector` against a shared Postgres database — the same
coordination primitive used in production. The orchestrator launches N
replica processes, waits for one to win the lock and for the cluster to
reach steady state, **SIGKILLs the leader process** (an ungraceful
crash — no graceful unlock), and measures the wall-clock time until a
*different, already-running* replica acquires leadership.

Two design points make the numbers honest rather than artifacts:

- **Steady-state only.** A crashed replica is relaunched between
  trials, but the next kill is delayed until that replica is past its
  boot-time election and polling normally. Otherwise a freshly booting
  replica could grab the just-freed lock via its *startup* election,
  measuring process boot time instead of a real follower takeover.
- **Randomized crash phase.** A real crash happens at an arbitrary
  instant relative to each follower's election ticker. The harness
  sleeps a uniform random `[0, interval)` before each kill so the
  measured RTO is a fair draw from the true failover distribution, not
  an artifact of synchronized ticker phases.

```bash
# Postgres reachable over TCP; advisory locks + pg_current_xact_id() only.
export DATABASE_URL='postgres://USER:PASS@HOST:5432/DB?sslmode=disable'

go run ./bench/ha-failover -replicas=3 -trials=20 -interval=250ms
```

`-interval` is the per-replica election check interval. The harness uses
a **short** interval so a run completes in seconds; production uses
`leader.DefaultCheckInterval = 30s` (see §6).

---

## 5. Measured RTO on this dev VM

Measured with the harness above on this single dev VM (Postgres 14,
loopback TCP). The crash is a local `SIGKILL`, so the killed process's
socket is closed by the kernel and Postgres releases the advisory lock
promptly; the RTO is then dominated by the surviving follower's wait
until its next election tick.

| Run | replicas | check interval | trials | min | median | mean | max |
|-----|----------|----------------|--------|-----|--------|------|-----|
| A   | 3        | 250 ms         | 20     | 8 ms  | 122 ms | 126 ms | 249 ms |
| B   | 3        | 1 s            | 10     | 9 ms  | 474 ms | 403 ms | 983 ms |
| C   | 5        | 100 ms         | 15     | 9 ms  | 36 ms  | 42 ms  | 87 ms  |

Observations, all consistent with the model in §3:

- **RTO is bounded by ~one check interval** (max ≈ 1× interval in every
  run) and the mean lands near `interval/2` — exactly the expected wait
  for a follower polling at a random phase.
- **RTO scales linearly with the check interval** (compare A vs B).
- **More replicas lower the median** (run C, 4 followers): the takeover
  is decided by the *soonest*-ticking follower, so more followers means
  a shorter expected wait.
- **The floor (~8–9 ms)** is the residual: Postgres releasing the lock
  after the socket closes, plus the harness's ~1 ms observation poll and
  pipe latency. The election mechanism itself adds no fixed delay beyond
  the poll interval.

**Extrapolated production RTO:** with the default 30 s check interval,
the same model puts the clean-crash failover RTO at **up to ~30 s, mean
~15 s** — dominated entirely by the check interval, not by Postgres or
the election code. If a tighter RTO is required, lower
`DefaultCheckInterval`; the harness is the tool to re-measure any chosen
value. **These 30 s figures are an extrapolation of the measured
per-interval behavior, not a directly measured number.**

---

## 6. Honest caveats

This harness exercises the **real** election code path and **real**
Postgres advisory-lock session semantics, but it is **not** a true
multi-node cluster. Read these before quoting any number:

1. **Single host, multi-process — not multi-node.** All replicas and
   Postgres run on one VM over loopback. There is no inter-node network,
   no load balancer, no separate Postgres primary/standby, and no real
   host failure. Scheduling, disk, and network contention of a real
   cluster are absent.

2. **`SIGKILL` measures *clean-crash* RTO, not *partition* RTO — this is
   the big one.** Killing a local process closes its TCP sockets, so
   Postgres sees the connection drop and releases the advisory lock
   within milliseconds. A real **network partition** (node silently
   unreachable) sends no FIN/RST: Postgres keeps the backend — and the
   advisory lock — alive until it notices the dead connection via TCP
   keepalive. With stock settings (`tcp_keepalives_idle` ≈ 2 h) that can
   be **far longer than the election interval**, so partition-induced
   failover RTO is governed by Postgres/OS keepalive tuning
   (`tcp_keepalives_idle/_interval/_count`, `tcp_user_timeout`), **not**
   by `DefaultCheckInterval`. The measured numbers in §5 do **not**
   cover this case. Production HA must tune keepalives to bound it.

3. **Short intervals for measurability.** Runs use 100 ms–1 s intervals
   so a run finishes in seconds. Production runs at 30 s. RTO scales
   with the interval (§5), so divide/multiply accordingly rather than
   quoting the dev numbers directly.

4. **Wall-clock timing.** RTO is measured on the orchestrator's wall
   clock from kill instant to observing the new leader, including a
   ~1 ms observation poll and OS pipe latency. This slightly *over*states
   true election latency (a conservative direction), and is negligible
   beside the interval-dominated term.

5. **Clock assumptions.** Fencing epoch monotonicity relies on Postgres
   transaction ids being globally monotonic on a single primary. With
   multi-primary / logical-replication topologies that assumption needs
   revisiting.

In short: the election logic and its failover behavior are validated and
deterministic; the **clean-crash** RTO is real and bounded by the check
interval; the **partition** RTO is a separate, keepalive-bound quantity
this single-host harness intentionally does not measure.
```

