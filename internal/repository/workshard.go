package repository

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// WorkshardWorker is a row in the workshard_workers registry: one
// running control-plane replica and its heartbeat-extended liveness
// window. A worker is live while now() < ExpiresAt.
//
// The fields are primitive / standard-library types only (no domain
// imports), matching the neutral-row convention of the other
// repository structs (see ThreatIOC) so the storage interface stays
// decoupled from the workshard service's own types.
type WorkshardWorker struct {
	WorkerID        uuid.UUID
	Instance        string
	StartedAt       time.Time
	LastHeartbeatAt time.Time
	ExpiresAt       time.Time
}

// ShardLease is a row in the workshard_shard_leases ledger: the
// current owner of one shard, its fencing token, and its lease
// deadline. The holder owns the shard while now() < ExpiresAt.
type ShardLease struct {
	Shard      int
	WorkerID   uuid.UUID
	FenceToken int64
	AcquiredAt time.Time
	RenewedAt  time.Time
	ExpiresAt  time.Time
}

// WorkShardRepository is the persistence boundary for the tenant-shard
// work distributor (internal/service/workshard). It backs an
// active/active ownership scheme: replicas register and heartbeat in
// the worker registry, and each shard is leased to exactly one live
// worker so per-tenant background jobs run exactly once per cycle
// across the fleet.
//
// All deadlines are computed from the database clock (now() + ttl) so
// every replica races against a single, consistent time source rather
// than its own wall clock. Callers pass the TTL/grace as durations;
// implementations translate them to that single clock.
type WorkShardRepository interface {
	// Heartbeat upserts this worker's registry row, (re)setting its
	// liveness window to now()+ttl. started_at is preserved across
	// heartbeats; instance is refreshed.
	Heartbeat(ctx context.Context, workerID uuid.UUID, instance string, ttl time.Duration) error

	// ListLiveWorkers returns every worker whose lease window has not
	// expired (now() < expires_at), ordered by worker_id for a stable
	// rendezvous-hash input across replicas.
	ListLiveWorkers(ctx context.Context) ([]WorkshardWorker, error)

	// DeleteExpiredWorkers removes registry rows that expired more than
	// grace ago and returns the number deleted. The grace period keeps
	// a just-expired worker visible briefly so its lease hand-off is
	// observable; the sweep is idempotent and safe to run from any
	// replica. Bounded by the (tiny) worker count.
	DeleteExpiredWorkers(ctx context.Context, grace time.Duration) (int64, error)

	// AcquireShards atomically acquires or renews the given shards for
	// workerID, each with a fresh now()+ttl deadline, and returns the
	// leases the worker holds as a result. A shard is taken when it is
	// unowned, when its current lease has expired, or when workerID
	// already holds it (a renewal). A shard still held by a different,
	// live worker is left untouched and omitted from the result, so the
	// returned set is exactly what this worker may process. The fencing
	// token is incremented on a change of ownership and left unchanged
	// on a same-owner renewal.
	AcquireShards(ctx context.Context, workerID uuid.UUID, shards []int, ttl time.Duration) ([]ShardLease, error)

	// ReleaseShardsExcept releases every shard currently held by
	// workerID whose number is not in keep. It is the graceful-handoff
	// path: a rebalancing or shutting-down worker yields shards it no
	// longer should own immediately, rather than forcing successors to
	// wait out the lease TTL. Passing an empty keep releases all of the
	// worker's shards.
	ReleaseShardsExcept(ctx context.Context, workerID uuid.UUID, keep []int) error

	// ListHeldShards returns the non-expired leases currently held by
	// workerID.
	ListHeldShards(ctx context.Context, workerID uuid.UUID) ([]ShardLease, error)

	// ListLeases returns every non-expired lease across all workers,
	// ordered by shard. It backs read-only ownership/status reporting.
	ListLeases(ctx context.Context) ([]ShardLease, error)
}
