package activity_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/activity"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

// captureToucher records the last persisted (id -> seen) so a test can
// reconstruct the tenants.last_active_at projection the dormancy
// planner reads, using GREATEST semantics (only the most-recent seen
// per tenant is kept).
type captureToucher struct {
	mu   sync.Mutex
	last map[uuid.UUID]time.Time
}

func (c *captureToucher) TouchLastActive(_ context.Context, id uuid.UUID, seen time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		c.last = make(map[uuid.UUID]time.Time)
	}
	if cur, ok := c.last[id]; !ok || seen.After(cur) {
		c.last[id] = seen
	}
	return nil
}

func (c *captureToucher) activity(id uuid.UUID) repository.TenantActivity {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.last[id]; ok {
		return repository.TenantActivity{ID: id, LastActiveAt: &t}
	}
	return repository.TenantActivity{ID: id, LastActiveAt: nil}
}

func waitFor(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// TestFleetClassification_AfterCoverage is the WS-2 outcome check: it
// feeds a small synthetic fleet through the recorder via the
// newly-instrumented ingress sources and confirms the dormancy planner
// then buckets each tenant by its true most-recent activity — no
// false-active, no false-dormant for a tenant seen on a non-telemetry
// path. This is the behaviour the broadened writer coverage exists to
// produce.
func TestFleetClassification_AfterCoverage(t *testing.T) {
	now := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
	ct := &captureToucher{}
	// MinInterval 0 so each distinct seen lands (we drive event-time
	// directly); clock fixed so the test is deterministic.
	r := activity.NewRecorder(ct, activity.WithMinInterval(0), activity.WithClock(func() time.Time { return now }))
	go r.Run()

	// Four tenants, each active only through a single ingress path at a
	// different recency. The planner defaults: active < 24h, idle < 14d,
	// else dormant.
	active := uuid.New()    // mobile refresh (recurring check-in) just now
	idle := uuid.New()      // device enrolment 2 days ago
	dormByAge := uuid.New() // telemetry, but 20 days ago
	neverSeen := uuid.New() // no ingress at all

	r.From(activity.SourceMobileRefresh).Observe(active, now.Add(-30*time.Minute))
	r.From(activity.SourceEnroll).Observe(idle, now.Add(-2*24*time.Hour))
	r.From(activity.SourceTelemetry).Observe(dormByAge, now.Add(-20*24*time.Hour))

	if !waitFor(time.Second, func() bool {
		ct.mu.Lock()
		defer ct.mu.Unlock()
		return len(ct.last) == 3
	}) {
		t.Fatalf("not all touches persisted")
	}
	r.Stop()

	acts := []repository.TenantActivity{
		ct.activity(active),
		ct.activity(idle),
		ct.activity(dormByAge),
		ct.activity(neverSeen),
	}

	planner := tenancy.DefaultPlanner()
	s := planner.Summarize(now, 1 /* non-zero cycle: not the full startup sweep */, acts)

	if s.Active != 1 {
		t.Errorf("active = %d, want 1", s.Active)
	}
	if s.Idle != 1 {
		t.Errorf("idle = %d, want 1", s.Idle)
	}
	if s.Dormant != 2 {
		t.Errorf("dormant = %d, want 2 (20d-stale + never-seen)", s.Dormant)
	}
	if s.Total != 4 {
		t.Errorf("total = %d, want 4", s.Total)
	}

	// The point of the broadened coverage: the mobile-refresh-only and
	// enrol-only tenants are NOT mis-bucketed as dormant. Confirm each
	// classifies as expected individually.
	c := planner.Classifier
	if got := c.Classify(now, acts[0].LastActiveAt); got != tenancy.TierActive {
		t.Errorf("mobile-refresh tenant tier = %v, want active", got)
	}
	if got := c.Classify(now, acts[1].LastActiveAt); got != tenancy.TierIdle {
		t.Errorf("enroll tenant tier = %v, want idle", got)
	}
	if got := c.Classify(now, acts[3].LastActiveAt); got != tenancy.TierDormant {
		t.Errorf("never-seen tenant tier = %v, want dormant", got)
	}
}
