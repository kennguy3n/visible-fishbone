package policy

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// recordingSamplingObserver captures the most recent ObserveSampling
// call so a test can assert what (if anything) the policy service
// pushed downstream on publish / promote.
type recordingSamplingObserver struct {
	mu       sync.Mutex
	calls    int
	lastTID  uuid.UUID
	lastRate map[string]float64
}

func (o *recordingSamplingObserver) ObserveSampling(tenantID uuid.UUID, classRates map[string]float64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.calls++
	o.lastTID = tenantID
	o.lastRate = classRates
}

func (o *recordingSamplingObserver) snapshot() (int, uuid.UUID, map[string]float64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.calls, o.lastTID, o.lastRate
}

func newSamplingTestService(t *testing.T, obs SamplingObserver) (*Service, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(s)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(s)
	auditRepo := memory.NewAuditLogRepository(s)
	svc := New(policyRepo, auditRepo, nil, WithSamplingObserver(obs))
	return svc, tnt.ID
}

func samplingGraphJSON(t *testing.T, classRates map[string]float64) json.RawMessage {
	t.Helper()
	g := map[string]any{
		"default_action": "deny",
		"sampling":       map[string]any{"class_rates": classRates},
	}
	raw, err := json.Marshal(g)
	if err != nil {
		t.Fatalf("marshal graph: %v", err)
	}
	return raw
}

func TestSamplingObserver_PublishNotifies(t *testing.T) {
	t.Parallel()
	obs := &recordingSamplingObserver{}
	svc, tenantID := newSamplingTestService(t, obs)

	raw := samplingGraphJSON(t, map[string]float64{"trusted_direct": 0.01})
	if _, err := svc.PutGraph(context.Background(), tenantID, nil, raw); err != nil {
		t.Fatalf("put graph: %v", err)
	}

	calls, gotTID, gotRate := obs.snapshot()
	if calls != 1 {
		t.Fatalf("ObserveSampling calls = %d, want 1", calls)
	}
	if gotTID != tenantID {
		t.Fatalf("tenant = %s, want %s", gotTID, tenantID)
	}
	if got := gotRate["trusted_direct"]; got != 0.01 {
		t.Fatalf("trusted_direct rate = %v, want 0.01", got)
	}
}

func TestSamplingObserver_DraftDoesNotNotify(t *testing.T) {
	t.Parallel()
	obs := &recordingSamplingObserver{}
	svc, tenantID := newSamplingTestService(t, obs)

	raw := samplingGraphJSON(t, map[string]float64{"trusted_direct": 0.01})
	if _, err := svc.PutDraftGraph(context.Background(), tenantID, nil, raw); err != nil {
		t.Fatalf("put draft graph: %v", err)
	}

	if calls, _, _ := obs.snapshot(); calls != 0 {
		t.Fatalf("a draft must not notify the sampling observer; calls = %d", calls)
	}
}

func TestSamplingObserver_PromoteNotifies(t *testing.T) {
	t.Parallel()
	obs := &recordingSamplingObserver{}
	svc, tenantID := newSamplingTestService(t, obs)

	raw := samplingGraphJSON(t, map[string]float64{"trusted_media_bypass": 0.02})
	draft, err := svc.PutDraftGraph(context.Background(), tenantID, nil, raw)
	if err != nil {
		t.Fatalf("put draft graph: %v", err)
	}
	if calls, _, _ := obs.snapshot(); calls != 0 {
		t.Fatalf("draft notified unexpectedly; calls = %d", calls)
	}

	if _, err := svc.PromoteGraph(context.Background(), tenantID, nil, draft.ID); err != nil {
		t.Fatalf("promote graph: %v", err)
	}

	calls, gotTID, gotRate := obs.snapshot()
	if calls != 1 {
		t.Fatalf("ObserveSampling calls after promote = %d, want 1", calls)
	}
	if gotTID != tenantID {
		t.Fatalf("tenant = %s, want %s", gotTID, tenantID)
	}
	if got := gotRate["trusted_media_bypass"]; got != 0.02 {
		t.Fatalf("trusted_media_bypass rate = %v, want 0.02", got)
	}
}

func TestSamplingObserver_PublishNoSamplingConfigSendsEmpty(t *testing.T) {
	t.Parallel()
	obs := &recordingSamplingObserver{}
	svc, tenantID := newSamplingTestService(t, obs)

	// A published graph with no sampling section still notifies, with an
	// empty map, so the resolver REMOVES any stale per-tenant override
	// and the tenant reverts to built-in defaults.
	raw := json.RawMessage(`{"default_action":"deny"}`)
	if _, err := svc.PutGraph(context.Background(), tenantID, nil, raw); err != nil {
		t.Fatalf("put graph: %v", err)
	}

	calls, _, gotRate := obs.snapshot()
	if calls != 1 {
		t.Fatalf("ObserveSampling calls = %d, want 1", calls)
	}
	if len(gotRate) != 0 {
		t.Fatalf("expected empty class rates, got %v", gotRate)
	}
}

func TestSamplingObserver_NilObserverIsSafe(t *testing.T) {
	t.Parallel()
	svc, tenantID := newSamplingTestService(t, nil)
	raw := samplingGraphJSON(t, map[string]float64{"trusted_direct": 0.01})
	if _, err := svc.PutGraph(context.Background(), tenantID, nil, raw); err != nil {
		t.Fatalf("put graph with nil observer must not error: %v", err)
	}
}
