package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// newLazyPool builds a pgxpool that does not eagerly connect (pgx
// connects on first use), so routing logic can be exercised without
// a live Postgres. The DSN host is distinct per pool so Replica()
// pointer identity is unambiguous.
func newLazyPool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New(%q): %v", dsn, err)
	}
	t.Cleanup(p.Close)
	return p
}

func TestReadWritePool_NoReplicasFallsBackToPrimary(t *testing.T) {
	primary := newLazyPool(t, "postgres://u:p@127.0.0.1:6000/db")
	p := NewReadWritePool(ReadWritePoolConfig{Primary: primary})

	if p.Primary() != primary {
		t.Fatal("Primary() did not return the configured primary")
	}
	if p.ReplicaCount() != 0 {
		t.Fatalf("ReplicaCount() = %d, want 0", p.ReplicaCount())
	}
	// With no replicas, every read must route to the primary.
	for i := 0; i < 5; i++ {
		if p.Replica() != primary {
			t.Fatal("Replica() did not fall back to primary when no replicas configured")
		}
	}
}

func TestReadWritePool_RoutesToHealthyReplicas(t *testing.T) {
	primary := newLazyPool(t, "postgres://u:p@127.0.0.1:6000/db")
	ra := newLazyPool(t, "postgres://u:p@127.0.0.1:6001/db")
	rb := newLazyPool(t, "postgres://u:p@127.0.0.1:6002/db")

	p := NewReadWritePool(ReadWritePoolConfig{
		Primary:  primary,
		Replicas: []*pgxpool.Pool{ra, rb},
	})
	if p.ReplicaCount() != 2 || p.HealthyReplicaCount() != 2 {
		t.Fatalf("counts: replicas=%d healthy=%d, want 2/2", p.ReplicaCount(), p.HealthyReplicaCount())
	}

	// Round-robin over the two healthy replicas; the primary must
	// never be selected while a replica is healthy.
	seen := map[*pgxpool.Pool]int{}
	for i := 0; i < 20; i++ {
		got := p.Replica()
		if got == primary {
			t.Fatal("Replica() returned primary while replicas were healthy")
		}
		seen[got]++
	}
	if seen[ra] == 0 || seen[rb] == 0 {
		t.Errorf("round-robin did not cover both replicas: %v", seen)
	}
}

func TestReadWritePool_UnhealthyReplicaEvicted(t *testing.T) {
	primary := newLazyPool(t, "postgres://u:p@127.0.0.1:6000/db")
	ra := newLazyPool(t, "postgres://u:p@127.0.0.1:6001/db")
	rb := newLazyPool(t, "postgres://u:p@127.0.0.1:6002/db")

	p := NewReadWritePool(ReadWritePoolConfig{
		Primary:  primary,
		Replicas: []*pgxpool.Pool{ra, rb},
	})

	// Mark ra unhealthy: all reads must land on rb, never ra, never
	// primary (one replica is still healthy).
	p.replicas[0].healthy.Store(false)
	if p.HealthyReplicaCount() != 1 {
		t.Fatalf("HealthyReplicaCount() = %d, want 1", p.HealthyReplicaCount())
	}
	for i := 0; i < 20; i++ {
		got := p.Replica()
		if got == ra {
			t.Fatal("Replica() returned an unhealthy replica")
		}
		if got == primary {
			t.Fatal("Replica() fell back to primary while a healthy replica remained")
		}
	}

	// Now mark rb unhealthy too: total replica outage degrades to
	// the primary rather than failing reads.
	p.replicas[1].healthy.Store(false)
	if p.HealthyReplicaCount() != 0 {
		t.Fatalf("HealthyReplicaCount() = %d, want 0", p.HealthyReplicaCount())
	}
	for i := 0; i < 5; i++ {
		if p.Replica() != primary {
			t.Fatal("Replica() did not degrade to primary on total replica outage")
		}
	}
}

func TestReadWritePool_PgBouncerPosture(t *testing.T) {
	primary := newLazyPool(t, "postgres://u:p@127.0.0.1:6000/db")
	p := NewReadWritePool(ReadWritePoolConfig{
		Primary:       primary,
		AppRole:       "sng_app",
		PgBouncerMode: true,
	})
	if !p.PgBouncerMode() {
		t.Error("PgBouncerMode() = false, want true")
	}
	if p.AppRole() != "sng_app" {
		t.Errorf("AppRole() = %q, want sng_app", p.AppRole())
	}
}

// TestReadWritePool_StartHealthChecksEvictsUnreachable spins the
// real health loop against replicas pointing at dead ports: the
// immediate probe must evict both and Close must tear the loop down
// cleanly.
func TestReadWritePool_StartHealthChecksEvictsUnreachable(t *testing.T) {
	primary := newLazyPool(t, "postgres://u:p@127.0.0.1:6000/db")
	ra := newLazyPool(t, "postgres://u:p@127.0.0.1:6101/db")
	rb := newLazyPool(t, "postgres://u:p@127.0.0.1:6102/db")

	p := NewReadWritePool(ReadWritePoolConfig{
		Primary:  primary,
		Replicas: []*pgxpool.Pool{ra, rb},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.StartHealthChecks(ctx)

	// The initial probe runs synchronously at loop start, but the
	// goroutine scheduling is async; poll briefly for eviction. The
	// probe dials a dead port bounded by replicaHealthProbeTimeout,
	// so allow a little over that.
	deadline := time.After(2*replicaHealthProbeTimeout + time.Second)
	for p.HealthyReplicaCount() != 0 {
		select {
		case <-deadline:
			t.Fatalf("replicas not evicted; healthy=%d", p.HealthyReplicaCount())
		case <-time.After(10 * time.Millisecond):
		}
	}
	p.Close()
}
