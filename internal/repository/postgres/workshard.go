package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// WorkShardRepository persists the tenant-shard work distributor's
// worker registry (workshard_workers) and shard-ownership ledger
// (workshard_shard_leases). Neither table is tenant-scoped — they hold
// fleet-wide infrastructure state with no tenant data — so every
// operation runs in a system-role transaction, matching the global
// app_registry / threat-intel pattern.
//
// All lease/heartbeat deadlines are derived from the database clock
// (now() + ttl) inside a single statement, so every replica races
// against one consistent time source. now() is stable within a
// transaction, so the repeated now() references in each statement all
// observe the same instant.
type WorkShardRepository struct{ s *Store }

// NewWorkShardRepository constructs the Postgres-backed work-shard
// repository. It lives here (not in repos.go) so WP2 adds only new
// files and never co-edits the shared repository wiring.
func (s *Store) NewWorkShardRepository() *WorkShardRepository {
	return &WorkShardRepository{s: s}
}

var _ repository.WorkShardRepository = (*WorkShardRepository)(nil)

const workerCols = `worker_id, instance, started_at, last_heartbeat_at, expires_at`

const leaseCols = `shard, worker_id, fence_token, acquired_at, renewed_at, expires_at`

// Heartbeat upserts the worker's registry row, pushing its liveness
// window to now()+ttl. started_at is preserved across heartbeats so it
// records the replica's first registration.
func (r *WorkShardRepository) Heartbeat(ctx context.Context, workerID uuid.UUID, instance string, ttl time.Duration) error {
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO workshard_workers AS w (worker_id, instance, started_at, last_heartbeat_at, expires_at)
VALUES ($1, $2, now(), now(), now() + make_interval(secs => $3))
ON CONFLICT (worker_id) DO UPDATE
SET instance          = $2,
    last_heartbeat_at = now(),
    expires_at        = now() + make_interval(secs => $3)`,
			workerID, instance, ttl.Seconds())
		return err
	})
}

// ListLiveWorkers returns every worker whose liveness window is still
// open, ordered by worker_id so the rendezvous hash sees an identical,
// stable input on every replica.
func (r *WorkShardRepository) ListLiveWorkers(ctx context.Context) ([]repository.WorkshardWorker, error) {
	var out []repository.WorkshardWorker
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT `+workerCols+`
FROM workshard_workers
WHERE expires_at > now()
ORDER BY worker_id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var w repository.WorkshardWorker
			if err := rows.Scan(&w.WorkerID, &w.Instance, &w.StartedAt, &w.LastHeartbeatAt, &w.ExpiresAt); err != nil {
				return err
			}
			out = append(out, w)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteExpiredWorkers removes registry rows that lapsed more than
// grace ago and returns the count deleted.
func (r *WorkShardRepository) DeleteExpiredWorkers(ctx context.Context, grace time.Duration) (int64, error) {
	var deleted int64
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
DELETE FROM workshard_workers
WHERE expires_at < now() - make_interval(secs => $1)`,
			grace.Seconds())
		if err != nil {
			return err
		}
		deleted = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

// AcquireShards atomically takes or renews the requested shards for
// workerID and returns the leases held as a result. The single upsert
// takes a shard when it is unowned, expired, or already this worker's,
// bumping the fence token only on a change of ownership; a shard held
// by a different live worker is skipped (its row is locked for the
// UPDATE, so racing acquirers serialise and exactly one wins) and
// therefore absent from the returned set.
func (r *WorkShardRepository) AcquireShards(ctx context.Context, workerID uuid.UUID, shards []int, ttl time.Duration) ([]repository.ShardLease, error) {
	if len(shards) == 0 {
		return nil, nil
	}
	var out []repository.ShardLease
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
INSERT INTO workshard_shard_leases AS l (shard, worker_id, fence_token, acquired_at, renewed_at, expires_at)
SELECT s, $1, 1, now(), now(), now() + make_interval(secs => $3)
FROM unnest($2::int[]) AS s
ON CONFLICT (shard) DO UPDATE
SET worker_id   = $1,
    fence_token = CASE
        WHEN l.worker_id = $1 AND l.expires_at > now() THEN l.fence_token
        ELSE l.fence_token + 1
    END,
    acquired_at = CASE
        WHEN l.worker_id = $1 AND l.expires_at > now() THEN l.acquired_at
        ELSE now()
    END,
    renewed_at  = now(),
    expires_at  = now() + make_interval(secs => $3)
WHERE l.worker_id = $1 OR l.expires_at <= now()
RETURNING `+leaseCols,
			workerID, int32s(shards), ttl.Seconds())
		if err != nil {
			return err
		}
		defer rows.Close()
		out, err = scanLeases(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ReleaseShardsExcept releases every lease held by workerID whose shard
// is not in keep. An empty keep releases all of the worker's shards
// (the graceful-shutdown path). `shard <> ALL('{}')` is vacuously true,
// so an empty array deletes all the worker's rows as intended.
func (r *WorkShardRepository) ReleaseShardsExcept(ctx context.Context, workerID uuid.UUID, keep []int) error {
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
DELETE FROM workshard_shard_leases
WHERE worker_id = $1 AND shard <> ALL($2::int[])`,
			workerID, int32s(keep))
		return err
	})
}

// ListHeldShards returns the non-expired leases currently held by
// workerID, ordered by shard.
func (r *WorkShardRepository) ListHeldShards(ctx context.Context, workerID uuid.UUID) ([]repository.ShardLease, error) {
	var out []repository.ShardLease
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT `+leaseCols+`
FROM workshard_shard_leases
WHERE worker_id = $1 AND expires_at > now()
ORDER BY shard`, workerID)
		if err != nil {
			return err
		}
		defer rows.Close()
		out, err = scanLeases(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListLeases returns every non-expired lease across the fleet, ordered
// by shard, for read-only ownership/status reporting.
func (r *WorkShardRepository) ListLeases(ctx context.Context) ([]repository.ShardLease, error) {
	var out []repository.ShardLease
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT `+leaseCols+`
FROM workshard_shard_leases
WHERE expires_at > now()
ORDER BY shard`)
		if err != nil {
			return err
		}
		defer rows.Close()
		out, err = scanLeases(rows)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// scanLeases drains a lease result set. Callers must invoke it before
// their withSystem callback returns (the transaction — and connection —
// is released on commit).
func scanLeases(rows pgx.Rows) ([]repository.ShardLease, error) {
	var out []repository.ShardLease
	for rows.Next() {
		var l repository.ShardLease
		if err := rows.Scan(&l.Shard, &l.WorkerID, &l.FenceToken, &l.AcquiredAt, &l.RenewedAt, &l.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// int32s narrows a []int shard list to the []int32 the pgx driver
// encodes as a Postgres int4[] (matching the int[] casts in the
// queries above). Shard numbers are small and bounded by the shard
// count, so the narrowing never overflows.
func int32s(xs []int) []int32 {
	if len(xs) == 0 {
		return []int32{}
	}
	out := make([]int32, len(xs))
	for i, x := range xs {
		out[i] = int32(x)
	}
	return out
}
