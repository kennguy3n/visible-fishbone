package workshard

import (
	"context"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Status is a point-in-time view of this replica's distributor state,
// for logging and read-only observability. It reflects local state only
// (no database round trip).
type Status struct {
	WorkerID     string
	Instance     string
	ShardCount   int
	OwnedShards  int
	LiveWorkers  int
	Started      bool
	Healthy      bool
	ValidUntil   time.Time
	LastCycleAt  time.Time
	LeaseTTL     time.Duration
	CycleEvery   time.Duration
	SafetyMargin time.Duration
}

// Status returns the current local distributor status.
func (d *Distributor) Status() Status {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return Status{
		WorkerID:     d.workerID.String(),
		Instance:     d.instance,
		ShardCount:   d.shardCount,
		OwnedShards:  len(d.owned),
		LiveWorkers:  d.liveWorkerCount,
		Started:      d.started,
		Healthy:      d.ownershipValidLocked(),
		ValidUntil:   d.validUntil,
		LastCycleAt:  d.lastCycleAt,
		LeaseTTL:     d.leaseTTL,
		CycleEvery:   d.cycleInterval,
		SafetyMargin: d.safetyMargin,
	}
}

// Ownership is a fleet-wide view assembled from the registry and lease
// ledger, for a read-only admin/status endpoint. It performs database
// reads and so takes a context.
type Ownership struct {
	Workers []repository.WorkshardWorker
	Leases  []repository.ShardLease
}

// OwnershipSnapshot reads the live workers and active leases from the
// store. It is intended for low-frequency admin/status queries, not the
// hot path.
func (d *Distributor) OwnershipSnapshot(ctx context.Context) (Ownership, error) {
	workers, err := d.repo.ListLiveWorkers(ctx)
	if err != nil {
		return Ownership{}, err
	}
	leases, err := d.repo.ListLeases(ctx)
	if err != nil {
		return Ownership{}, err
	}
	return Ownership{Workers: workers, Leases: leases}, nil
}
