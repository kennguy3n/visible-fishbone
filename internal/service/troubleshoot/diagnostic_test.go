package troubleshoot_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot/checks"
)

// countingCheck records how many times Run was invoked so cache
// behavior can be asserted without depending on wall-clock timestamps.
type countingCheck struct {
	name string
	runs *int64
}

func (c countingCheck) Name() string { return c.name }

func (c countingCheck) Run(_ context.Context, _ uuid.UUID) checks.DiagnosticResult {
	atomic.AddInt64(c.runs, 1)
	return checks.DiagnosticResult{CheckName: c.name, Status: checks.DiagnosticPass}
}

func TestDiagnosticEngine_RunAll_CachesWithinTTL(t *testing.T) {
	var runs int64
	engine := troubleshoot.NewDiagnosticEngine([]checks.DiagnosticCheck{
		countingCheck{name: "counter", runs: &runs},
	})

	current := time.Unix(0, 0).UTC()
	engine.SetClock(func() time.Time { return current })
	engine.SetCacheTTL(30 * time.Second)

	tenantID := uuid.New()

	// First call runs the check.
	engine.RunAll(context.Background(), tenantID)
	if got := atomic.LoadInt64(&runs); got != 1 {
		t.Fatalf("expected 1 run after first call, got %d", got)
	}

	// Within the TTL window: served from cache, no extra run.
	current = current.Add(29 * time.Second)
	engine.RunAll(context.Background(), tenantID)
	if got := atomic.LoadInt64(&runs); got != 1 {
		t.Fatalf("expected cache hit (still 1 run), got %d", got)
	}

	// Past the TTL: re-runs.
	current = current.Add(2 * time.Second) // now 31s since first run
	engine.RunAll(context.Background(), tenantID)
	if got := atomic.LoadInt64(&runs); got != 2 {
		t.Fatalf("expected re-run after TTL expiry (2 runs), got %d", got)
	}

	// A different tenant is cached independently.
	engine.RunAll(context.Background(), uuid.New())
	if got := atomic.LoadInt64(&runs); got != 3 {
		t.Fatalf("expected separate run for new tenant (3 runs), got %d", got)
	}
}

func TestDiagnosticEngine_RunAll_CacheDisabled(t *testing.T) {
	var runs int64
	engine := troubleshoot.NewDiagnosticEngine([]checks.DiagnosticCheck{
		countingCheck{name: "counter", runs: &runs},
	})
	engine.SetCacheTTL(0) // disable caching

	tenantID := uuid.New()
	engine.RunAll(context.Background(), tenantID)
	engine.RunAll(context.Background(), tenantID)
	if got := atomic.LoadInt64(&runs); got != 2 {
		t.Fatalf("expected 2 runs with caching disabled, got %d", got)
	}
}

func TestDiagnosticEngine_RunAll(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	deviceRepo := memory.NewDeviceRepository(store)

	// Seed a device with a recent heartbeat.
	now := time.Now().UTC()
	_, err := deviceRepo.Create(context.Background(), tenantID, repository.Device{
		Name:       "test-device",
		Platform:   "linux",
		LastSeenAt: &now,
	})
	if err != nil {
		t.Fatal(err)
	}

	connCheck := checks.NewConnectivityCheck(deviceRepo, 5*time.Minute)
	perfCheck := checks.NewPerformanceCheck(deviceRepo, 10*time.Minute)

	engine := troubleshoot.NewDiagnosticEngine([]checks.DiagnosticCheck{connCheck, perfCheck})

	results := engine.RunAll(context.Background(), tenantID)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}

	for _, r := range results {
		if r.Status != troubleshoot.DiagnosticPass {
			t.Errorf("expected pass for %s, got %s: %s", r.CheckName, r.Status, r.Message)
		}
	}
}

func TestDiagnosticEngine_RunCheck(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	deviceRepo := memory.NewDeviceRepository(store)

	connCheck := checks.NewConnectivityCheck(deviceRepo, 5*time.Minute)
	engine := troubleshoot.NewDiagnosticEngine([]checks.DiagnosticCheck{connCheck})

	result, err := engine.RunCheck(context.Background(), tenantID, "connectivity")
	if err != nil {
		t.Fatal(err)
	}
	if result.CheckName != "connectivity" {
		t.Fatalf("expected check name 'connectivity', got %q", result.CheckName)
	}
}

func TestDiagnosticEngine_UnknownCheck(t *testing.T) {
	engine := troubleshoot.NewDiagnosticEngine(nil)
	_, err := engine.RunCheck(context.Background(), uuid.New(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for unknown check")
	}
}

func TestDiagnosticEngine_StaleDevice(t *testing.T) {
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	deviceRepo := memory.NewDeviceRepository(store)

	staleTime := time.Now().UTC().Add(-10 * time.Minute)
	_, err := deviceRepo.Create(context.Background(), tenantID, repository.Device{
		Name:       "stale-device",
		Platform:   "linux",
		LastSeenAt: &staleTime,
	})
	if err != nil {
		t.Fatal(err)
	}

	connCheck := checks.NewConnectivityCheck(deviceRepo, 5*time.Minute)
	engine := troubleshoot.NewDiagnosticEngine([]checks.DiagnosticCheck{connCheck})

	result, err := engine.RunCheck(context.Background(), tenantID, "connectivity")
	if err != nil {
		t.Fatal(err)
	}
	if result.Status == troubleshoot.DiagnosticPass {
		t.Fatal("expected non-pass status for stale device")
	}
}
