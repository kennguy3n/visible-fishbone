// Package workshard is an active/active tenant-shard work distributor.
//
// Per-tenant background jobs in SNG historically ran on a single elected
// leader (internal/service/leader), which serialises all 5,000 tenants'
// compute onto one replica — the scaling ceiling this package removes.
// Here every control-plane replica registers in a Postgres-backed worker
// registry and heartbeats its liveness; tenants are hashed to a fixed
// set of shards (the same FNV-1a hash the telemetry store shards on), and
// each shard is assigned to exactly one live worker by rendezvous (HRW)
// hashing. A Postgres lease per shard makes the assignment authoritative:
// a worker processes a tenant only while it holds a non-expired lease on
// that tenant's shard, so each tenant is handled by exactly one worker
// per cycle. Adding a replica reshuffles ~1/N of shards; losing one lets
// its leases lapse and survivors reclaim them — no operator action, no
// manual shard configuration.
//
// Exactly-once-per-tenant safety. Acquisition is a single atomic upsert
// that only succeeds when the shard is unowned, expired, or already the
// caller's. Locally a worker stops treating itself as a shard's owner a
// safety margin BEFORE the database lease expires, so the previous owner
// has yielded before any successor can acquire — the ownership windows
// never overlap. If a worker cannot refresh its leases (DB blip, network
// partition) its local window lapses and it fails closed: it processes no
// tenants until it re-establishes ownership.
//
// Single-replica deployments cost almost nothing: the one worker is the
// HRW winner for every shard, owns them all, and runs identically to the
// old leader path — one heartbeat plus a handful of set-based queries per
// cycle, independent of tenant count.
package workshard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/errgroup"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Distributor owns this replica's participation in the work-shard
// scheme: it heartbeats, computes and leases the shards it should own,
// and answers ownership queries the background jobs gate on.
type Distributor struct {
	repo     repository.WorkShardRepository
	workerID uuid.UUID
	instance string

	shardCount      int
	leaseTTL        time.Duration
	cycleInterval   time.Duration
	safetyMargin    time.Duration
	concurrency     int
	gcEvery         int
	gcGrace         time.Duration
	shutdownTimeout time.Duration

	clock  func() time.Time
	logger *slog.Logger

	starting atomic.Bool
	stopOnce sync.Once
	cancel   context.CancelFunc // cancels the loop's own derived context
	wg       sync.WaitGroup
	cycles   uint64 // cycle counter, only touched on the loop goroutine

	mu              sync.RWMutex
	owned           map[int]int64 // shard -> fence token; replaced wholesale each cycle
	validUntil      time.Time     // local ownership is valid only while clock() < validUntil
	started         bool          // set true after the first successful cycle
	liveWorkerCount int
	lastCycleAt     time.Time
}

// New constructs a Distributor backed by repo. Without options it uses a
// fresh per-process worker identity, the package defaults, the wall
// clock, and slog.Default().
func New(repo repository.WorkShardRepository, opts ...Option) *Distributor {
	d := &Distributor{
		repo:            repo,
		workerID:        uuid.New(),
		instance:        defaultInstance(),
		shardCount:      DefaultShardCount,
		leaseTTL:        DefaultLeaseTTL,
		cycleInterval:   DefaultCycleInterval,
		safetyMargin:    DefaultSafetyMargin,
		concurrency:     DefaultConcurrency,
		gcEvery:         DefaultGCEvery,
		gcGrace:         DefaultGCGrace,
		shutdownTimeout: DefaultShutdownTimeout,
		clock:           time.Now,
		logger:          slog.Default(),
		owned:           map[int]int64{},
	}
	for _, o := range opts {
		o(d)
	}
	// Clamp to safe invariants so misconfiguration cannot defeat the
	// exactly-once guarantee or divide by zero.
	if d.shardCount < 1 {
		d.shardCount = 1
	}
	if d.concurrency < 1 {
		d.concurrency = 1
	}
	if d.leaseTTL <= 0 {
		d.leaseTTL = DefaultLeaseTTL
	}
	if d.cycleInterval <= 0 {
		d.cycleInterval = DefaultCycleInterval
	}
	// The safety margin must leave a positive local validity window
	// (LeaseTTL-SafetyMargin); if it does not, fall back to half the TTL.
	if d.safetyMargin <= 0 || d.safetyMargin >= d.leaseTTL {
		d.safetyMargin = d.leaseTTL / 2
	}
	return d
}

// WorkerID returns this replica's work-shard identity.
func (d *Distributor) WorkerID() uuid.UUID { return d.workerID }

// ShardCount returns the configured shard count.
func (d *Distributor) ShardCount() int { return d.shardCount }

// Start runs one assignment cycle synchronously so ownership is
// established before any caller consults it, then launches the
// background heartbeat/renewal loop bound to ctx. It returns the first
// cycle's error (if any) for visibility; the loop keeps retrying
// regardless, and ownership simply stays empty (fail-closed) until a
// cycle succeeds. Start is single-shot.
func (d *Distributor) Start(ctx context.Context) error {
	if !d.starting.CompareAndSwap(false, true) {
		return errors.New("workshard: distributor already started")
	}
	// Derive the loop's own cancellable context so Stop can wind the
	// loop down independently of the parent. This matters on early
	// error-return paths in main(): the parent (rootCtx) is only
	// cancelled by an OS signal, so a Wait that depended on it would
	// hang forever if boot fails after Start. Stop cancels this derived
	// context instead, so lease release runs and Wait returns on every
	// shutdown path.
	runCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel
	firstErr := d.runCycle(runCtx)
	if firstErr != nil {
		d.logger.Warn("workshard: initial assignment cycle failed; will retry in background",
			"worker_id", d.workerID, "error", firstErr)
	}
	d.wg.Add(1)
	go d.loop(runCtx)
	return firstErr
}

// Stop winds the distributor down: it cancels the loop (releasing this
// worker's leases for a clean handoff) and blocks until the loop has
// exited. It is safe to call on any shutdown path and idempotent; a
// Distributor that was never started is a no-op.
func (d *Distributor) Stop() {
	d.stopOnce.Do(func() {
		if d.cancel != nil {
			d.cancel()
		}
	})
	d.wg.Wait()
}

// Wait blocks until the background loop has exited (after the context is
// cancelled) and the shutdown lease release has run. Prefer Stop, which
// also triggers the wind-down; Wait alone assumes the caller cancels the
// context it passed to Start.
func (d *Distributor) Wait() { d.wg.Wait() }

func (d *Distributor) loop(ctx context.Context) {
	defer d.wg.Done()
	ticker := time.NewTicker(d.cycleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.releaseAll()
			return
		case <-ticker.C:
			if err := d.runCycle(ctx); err != nil {
				d.logger.Warn("workshard: assignment cycle failed",
					"worker_id", d.workerID, "error", err)
			}
		}
	}
}

// runCycle performs one heartbeat + reassignment + lease renewal. It is
// the single place ownership is recomputed. Errors leave the previously
// published ownership in place; once its local validity window lapses,
// ownership queries fail closed.
func (d *Distributor) runCycle(ctx context.Context) error {
	cycleStart := d.clock()

	if err := d.repo.Heartbeat(ctx, d.workerID, d.instance, d.leaseTTL); err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}

	workers, err := d.repo.ListLiveWorkers(ctx)
	if err != nil {
		return fmt.Errorf("list live workers: %w", err)
	}
	ids := ensureContains(workerIDs(workers), d.workerID)

	desired := ownedShards(d.shardCount, ids, d.workerID)

	held, err := d.repo.AcquireShards(ctx, d.workerID, desired, d.leaseTTL)
	if err != nil {
		return fmt.Errorf("acquire shards: %w", err)
	}

	// Yield any lease this worker still holds for a shard it no longer
	// wants (graceful handoff), so a successor need not wait out the TTL.
	if err := d.repo.ReleaseShardsExcept(ctx, d.workerID, desired); err != nil {
		return fmt.Errorf("release shards: %w", err)
	}

	owned := make(map[int]int64, len(held))
	for _, l := range held {
		owned[l.Shard] = l.FenceToken
	}

	d.mu.Lock()
	d.owned = owned
	d.validUntil = cycleStart.Add(d.leaseTTL - d.safetyMargin)
	d.started = true
	d.liveWorkerCount = len(ids)
	d.lastCycleAt = cycleStart
	d.mu.Unlock()

	d.cycles++
	if d.gcEvery > 0 && d.cycles%uint64(d.gcEvery) == 0 {
		if _, err := d.repo.DeleteExpiredWorkers(ctx, d.gcGrace); err != nil {
			d.logger.Warn("workshard: expired-worker sweep failed",
				"worker_id", d.workerID, "error", err)
		}
	}
	return nil
}

// releaseAll yields every lease this worker holds during shutdown, using
// a fresh bounded context because the parent is already cancelled.
func (d *Distributor) releaseAll() {
	ctx, cancel := context.WithTimeout(context.Background(), d.shutdownTimeout)
	defer cancel()
	if err := d.repo.ReleaseShardsExcept(ctx, d.workerID, nil); err != nil {
		d.logger.Warn("workshard: releasing leases on shutdown failed",
			"worker_id", d.workerID, "error", err)
	}
	d.mu.Lock()
	d.owned = map[int]int64{}
	d.validUntil = time.Time{}
	d.mu.Unlock()
}

// Owns reports whether this worker currently owns the shard tenantID
// hashes to. It fails closed: false before the first successful cycle
// and false once the local lease-validity window lapses, so two replicas
// never both believe they own the same tenant.
func (d *Distributor) Owns(tenantID uuid.UUID) bool {
	shard := shardIndex(tenantID, d.shardCount)
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.ownershipValidLocked() {
		return false
	}
	_, ok := d.owned[shard]
	return ok
}

// FilterOwned returns the subset of tenants this worker currently owns,
// preserving input order. It snapshots ownership once, so it is cheaper
// than calling Owns per tenant for large tenant sets.
func (d *Distributor) FilterOwned(tenants []uuid.UUID) []uuid.UUID {
	if len(tenants) == 0 {
		return nil
	}
	owned, ok := d.ownershipView()
	if !ok {
		return nil
	}
	out := make([]uuid.UUID, 0, len(tenants))
	for _, t := range tenants {
		if _, has := owned[shardIndex(t, d.shardCount)]; has {
			out = append(out, t)
		}
	}
	return out
}

// ForEachOwned runs fn for each tenant this worker owns, with bounded
// parallelism (the configured concurrency) for backpressure. It returns
// the first error from any invocation (cancelling the rest), matching
// errgroup semantics.
func (d *Distributor) ForEachOwned(ctx context.Context, tenants []uuid.UUID, fn func(context.Context, uuid.UUID) error) error {
	owned := d.FilterOwned(tenants)
	if len(owned) == 0 {
		return nil
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(d.concurrency)
	for _, t := range owned {
		t := t
		g.Go(func() error { return fn(gctx, t) })
	}
	return g.Wait()
}

// ownershipView returns the current owned-shard set if ownership is
// locally valid. The returned map is the live snapshot, which runCycle
// only ever replaces wholesale (never mutates in place), so reading it
// after releasing the lock is safe.
func (d *Distributor) ownershipView() (map[int]int64, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if !d.ownershipValidLocked() {
		return nil, false
	}
	return d.owned, true
}

// ownershipValidLocked reports whether ownership has been established
// and its local validity window has not lapsed. Callers must hold mu.
func (d *Distributor) ownershipValidLocked() bool {
	return d.started && d.clock().Before(d.validUntil)
}

// defaultInstance builds a best-effort human-facing label for the
// registry row.
func defaultInstance() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	return fmt.Sprintf("%s:%d", host, os.Getpid())
}

// workerIDs projects the registry rows to their worker IDs.
func workerIDs(workers []repository.WorkshardWorker) []uuid.UUID {
	out := make([]uuid.UUID, len(workers))
	for i, w := range workers {
		out[i] = w.WorkerID
	}
	return out
}

// ensureContains appends id to ids if absent. ListLiveWorkers should
// already include this worker (it just heartbeated), but a clock skew
// between the heartbeat write and the read could in principle omit it;
// including ourselves keeps the HRW input consistent with reality.
func ensureContains(ids []uuid.UUID, id uuid.UUID) []uuid.UUID {
	for _, x := range ids {
		if x == id {
			return ids
		}
	}
	return append(ids, id)
}
