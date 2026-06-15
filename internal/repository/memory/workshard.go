package memory

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// WorkShardRepository is an in-memory WorkShardRepository for tests and
// single-process use. Unlike the other memory repositories it does NOT
// hang its state off the shared memory.Store: WP2 may only add new
// files, and threading new fields through memory/store.go would co-edit
// a shared file. It therefore owns its maps and mutex outright, which
// also keeps each instance's state independent.
//
// The clock is injectable (WithClock) so tests can drive lease/heartbeat
// expiry deterministically. Semantics mirror the Postgres implementation
// exactly — same acquisition/renewal/takeover and fencing rules — so the
// service layer behaves identically against either backend.
type WorkShardRepository struct {
	mu      sync.Mutex
	now     func() time.Time
	workers map[uuid.UUID]repository.WorkshardWorker
	leases  map[int]repository.ShardLease
}

// NewWorkShardRepository returns an empty in-memory work-shard
// repository using the wall clock.
func NewWorkShardRepository() *WorkShardRepository {
	return &WorkShardRepository{
		now:     time.Now,
		workers: make(map[uuid.UUID]repository.WorkshardWorker),
		leases:  make(map[int]repository.ShardLease),
	}
}

// WithClock overrides the clock used to stamp and compare deadlines and
// returns the receiver for chaining. Intended for deterministic tests.
func (r *WorkShardRepository) WithClock(now func() time.Time) *WorkShardRepository {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
	return r
}

var _ repository.WorkShardRepository = (*WorkShardRepository)(nil)

func (r *WorkShardRepository) Heartbeat(_ context.Context, workerID uuid.UUID, instance string, ttl time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	w, ok := r.workers[workerID]
	if !ok {
		w = repository.WorkshardWorker{WorkerID: workerID, StartedAt: now}
	}
	w.Instance = instance
	w.LastHeartbeatAt = now
	w.ExpiresAt = now.Add(ttl)
	r.workers[workerID] = w
	return nil
}

func (r *WorkShardRepository) ListLiveWorkers(_ context.Context) ([]repository.WorkshardWorker, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var out []repository.WorkshardWorker
	for _, w := range r.workers {
		if w.ExpiresAt.After(now) {
			out = append(out, w)
		}
	}
	// Order by worker_id, byte-wise, matching the Postgres uuid sort so
	// the rendezvous hash sees an identical input on every backend.
	sort.Slice(out, func(i, j int) bool {
		return bytes.Compare(out[i].WorkerID[:], out[j].WorkerID[:]) < 0
	})
	return out, nil
}

func (r *WorkShardRepository) DeleteExpiredWorkers(_ context.Context, grace time.Duration) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cutoff := r.now().Add(-grace)
	var deleted int64
	for id, w := range r.workers {
		if w.ExpiresAt.Before(cutoff) {
			delete(r.workers, id)
			deleted++
		}
	}
	return deleted, nil
}

func (r *WorkShardRepository) AcquireShards(_ context.Context, workerID uuid.UUID, shards []int, ttl time.Duration) ([]repository.ShardLease, error) {
	if len(shards) == 0 {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	exp := now.Add(ttl)
	var out []repository.ShardLease
	for _, shard := range shards {
		cur, ok := r.leases[shard]
		if !ok {
			l := repository.ShardLease{
				Shard: shard, WorkerID: workerID, FenceToken: 1,
				AcquiredAt: now, RenewedAt: now, ExpiresAt: exp,
			}
			r.leases[shard] = l
			out = append(out, l)
			continue
		}
		isMine := cur.WorkerID == workerID
		valid := cur.ExpiresAt.After(now)
		// Update only when the lease is already mine or has expired —
		// the Postgres `WHERE l.worker_id = $1 OR l.expires_at <= now()`.
		if !isMine && valid {
			continue // held by a different live worker
		}
		if !isMine || !valid {
			// Change of ownership (takeover of expired, or my own
			// lapsed lease): bump the fence token and reset acquired_at.
			cur.FenceToken++
			cur.AcquiredAt = now
		}
		cur.WorkerID = workerID
		cur.RenewedAt = now
		cur.ExpiresAt = exp
		r.leases[shard] = cur
		out = append(out, cur)
	}
	return out, nil
}

func (r *WorkShardRepository) ReleaseShardsExcept(_ context.Context, workerID uuid.UUID, keep []int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	keepSet := make(map[int]struct{}, len(keep))
	for _, s := range keep {
		keepSet[s] = struct{}{}
	}
	for shard, l := range r.leases {
		if l.WorkerID != workerID {
			continue
		}
		if _, ok := keepSet[shard]; ok {
			continue
		}
		delete(r.leases, shard)
	}
	return nil
}

func (r *WorkShardRepository) ListHeldShards(_ context.Context, workerID uuid.UUID) ([]repository.ShardLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var out []repository.ShardLease
	for _, l := range r.leases {
		if l.WorkerID == workerID && l.ExpiresAt.After(now) {
			out = append(out, l)
		}
	}
	sortLeases(out)
	return out, nil
}

func (r *WorkShardRepository) ListLeases(_ context.Context) ([]repository.ShardLease, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	var out []repository.ShardLease
	for _, l := range r.leases {
		if l.ExpiresAt.After(now) {
			out = append(out, l)
		}
	}
	sortLeases(out)
	return out, nil
}

func sortLeases(ls []repository.ShardLease) {
	sort.Slice(ls, func(i, j int) bool { return ls[i].Shard < ls[j].Shard })
}
