package ai

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func TestCorrelationEngine_NoAlerts(t *testing.T) {
	t.Parallel()
	engine := NewCorrelationEngine(nil, CorrelationConfig{})
	result, err := engine.Analyze(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Clusters) != 0 {
		t.Fatalf("expected 0 clusters, got %d", len(result.Clusters))
	}
}

func TestCorrelationEngine_TemporalCluster(t *testing.T) {
	t.Parallel()
	engine := NewCorrelationEngine(nil, CorrelationConfig{
		TimeWindow:     10 * time.Minute,
		MinClusterSize: 2,
	})

	tenantID := uuid.New()
	now := time.Now()
	alerts := []AlertInput{
		{ID: uuid.New(), TenantID: tenantID, Kind: "anomaly", Severity: "medium", DeviceID: "d1", CreatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Kind: "anomaly", Severity: "medium", DeviceID: "d2", CreatedAt: now.Add(5 * time.Minute)},
	}

	result, err := engine.Analyze(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(result.Clusters))
	}
	c := result.Clusters[0]
	if len(c.AlertIDs) != 2 {
		t.Fatalf("expected 2 alert IDs, got %d", len(c.AlertIDs))
	}
	if c.TenantID != tenantID {
		t.Fatalf("tenant mismatch: got %s want %s", c.TenantID, tenantID)
	}
	if c.Status != "open" {
		t.Fatalf("expected status open, got %s", c.Status)
	}
	if result.AIGenerated {
		t.Fatal("template-only mode: ai_generated must be false")
	}
	// The engine must not assign an ID: a cluster is only retrievable
	// once a caller persists it and writes the persisted ID back. A
	// non-nil ID here would be a plausible UUID that a later GET could
	// not resolve.
	if c.ID != nil {
		t.Fatalf("engine must leave cluster ID nil, got %v", *c.ID)
	}
}

func TestCorrelationEngine_TemporalProximityAloneDoesNotCluster(t *testing.T) {
	t.Parallel()
	engine := NewCorrelationEngine(nil, CorrelationConfig{
		TimeWindow:     time.Hour,
		MinClusterSize: 2,
	})

	tenantID := uuid.New()
	now := time.Now()
	// Two alerts close in time but with no shared entity (different
	// device/user/IP) and different kinds. Temporal proximity alone
	// must NOT correlate them, otherwise unrelated alerts that merely
	// occur near each other would form spurious, low-signal incidents.
	alerts := []AlertInput{
		{ID: uuid.New(), TenantID: tenantID, Kind: "anomaly", Severity: "low", DeviceID: "d1", UserID: "u1", IPAddress: "10.0.0.1", CreatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Kind: "policy_violation", Severity: "low", DeviceID: "d2", UserID: "u2", IPAddress: "10.0.0.2", CreatedAt: now.Add(2 * time.Minute)},
	}

	result, err := engine.Analyze(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Clusters) != 0 {
		t.Fatalf("expected 0 clusters (temporal-only must not correlate), got %d", len(result.Clusters))
	}
	if result.CorrelatedAlerts != 0 {
		t.Fatalf("expected 0 correlated alerts, got %d", result.CorrelatedAlerts)
	}
}

func TestCorrelationEngine_EntityCluster(t *testing.T) {
	t.Parallel()
	engine := NewCorrelationEngine(nil, CorrelationConfig{
		TimeWindow:     time.Hour,
		MinClusterSize: 2,
	})

	tenantID := uuid.New()
	now := time.Now()
	alerts := []AlertInput{
		{ID: uuid.New(), TenantID: tenantID, Kind: "brute_force", Severity: "high", UserID: "user1", CreatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Kind: "credential_stuffing", Severity: "high", UserID: "user1", CreatedAt: now.Add(30 * time.Minute)},
	}

	result, err := engine.Analyze(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(result.Clusters))
	}
	c := result.Clusters[0]
	if c.Severity != "high" {
		t.Fatalf("expected severity high, got %s", c.Severity)
	}
}

func TestCorrelationEngine_MultiStageEscalation(t *testing.T) {
	t.Parallel()
	engine := NewCorrelationEngine(nil, CorrelationConfig{
		TimeWindow:     time.Hour,
		MinClusterSize: 2,
	})

	tenantID := uuid.New()
	now := time.Now()
	alerts := []AlertInput{
		{ID: uuid.New(), TenantID: tenantID, Kind: "recon", Severity: "low", DeviceID: "d1", CreatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Kind: "exploit", Severity: "medium", DeviceID: "d1", CreatedAt: now.Add(10 * time.Minute)},
		{ID: uuid.New(), TenantID: tenantID, Kind: "exfiltration", Severity: "high", DeviceID: "d1", CreatedAt: now.Add(20 * time.Minute)},
	}

	result, err := engine.Analyze(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(result.Clusters))
	}
	if result.Clusters[0].Severity != "critical" {
		t.Fatalf("expected critical severity for multi-stage attack, got %s", result.Clusters[0].Severity)
	}
}

func TestCorrelationEngine_SeverityNormalizedToEnum(t *testing.T) {
	t.Parallel()
	engine := NewCorrelationEngine(nil, CorrelationConfig{
		TimeWindow:     time.Hour,
		MinClusterSize: 2,
	})

	tenantID := uuid.New()
	now := time.Now()
	// Same kind so the multi-stage escalation paths don't override the
	// per-alert max; the cluster severity must be the highest input
	// severity, normalized to its canonical lowercase enum form.
	alerts := []AlertInput{
		{ID: uuid.New(), TenantID: tenantID, Kind: "brute_force", Severity: "High", DeviceID: "d1", CreatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Kind: "brute_force", Severity: "MEDIUM", DeviceID: "d1", CreatedAt: now.Add(5 * time.Minute)},
	}

	result, err := engine.Analyze(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(result.Clusters))
	}
	got := result.Clusters[0].Severity
	if got != "high" {
		t.Fatalf("severity = %q, want lowercase enum value \"high\"", got)
	}
	// The persisted value must satisfy the repository enum contract so
	// the cluster is actually stored (and retrievable via GET) rather
	// than silently dropped on a validation error.
	if err := repository.ValidateAICorrelationSeverity(got); err != nil {
		t.Fatalf("severity %q failed enum validation: %v", got, err)
	}
}

func TestCorrelationEngine_CrossTenantIsolation(t *testing.T) {
	t.Parallel()
	engine := NewCorrelationEngine(nil, CorrelationConfig{
		TimeWindow:     time.Hour,
		MinClusterSize: 2,
	})

	now := time.Now()
	alerts := []AlertInput{
		{ID: uuid.New(), TenantID: uuid.New(), Kind: "anomaly", Severity: "medium", DeviceID: "d1", CreatedAt: now},
		{ID: uuid.New(), TenantID: uuid.New(), Kind: "anomaly", Severity: "medium", DeviceID: "d1", CreatedAt: now.Add(1 * time.Minute)},
	}

	result, err := engine.Analyze(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Clusters) != 0 {
		t.Fatalf("expected 0 clusters (cross-tenant), got %d", len(result.Clusters))
	}
}

func TestCorrelationEngine_BelowMinCluster(t *testing.T) {
	t.Parallel()
	engine := NewCorrelationEngine(nil, CorrelationConfig{
		TimeWindow:     time.Hour,
		MinClusterSize: 3,
	})

	tenantID := uuid.New()
	now := time.Now()
	alerts := []AlertInput{
		{ID: uuid.New(), TenantID: tenantID, Kind: "anomaly", Severity: "low", CreatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Kind: "anomaly", Severity: "low", CreatedAt: now.Add(5 * time.Minute)},
	}

	result, err := engine.Analyze(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Clusters) != 0 {
		t.Fatalf("expected 0 clusters (below min), got %d", len(result.Clusters))
	}
}

func TestCorrelationEngine_NilAlertIDsNotDropped(t *testing.T) {
	t.Parallel()
	engine := NewCorrelationEngine(nil, CorrelationConfig{
		TimeWindow:     time.Hour,
		MinClusterSize: 2,
	})

	tenantID := uuid.New()
	now := time.Now()
	// A mix of real-ID and nil-ID alerts sharing a device. Every
	// alert (including the nil-ID ones) must be grouped — none may be
	// silently dropped — but only the real IDs may be persisted into
	// AlertIDs; nil IDs must never appear as dangling references.
	realA := uuid.New()
	realB := uuid.New()
	alerts := []AlertInput{
		{ID: realA, TenantID: tenantID, Kind: "anomaly", Severity: "medium", DeviceID: "d1", CreatedAt: now},
		{TenantID: tenantID, Kind: "anomaly", Severity: "medium", DeviceID: "d1", CreatedAt: now.Add(2 * time.Minute)},
		{ID: realB, TenantID: tenantID, Kind: "anomaly", Severity: "medium", DeviceID: "d1", CreatedAt: now.Add(4 * time.Minute)},
	}

	result, err := engine.Analyze(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(result.Clusters))
	}
	// All three alerts were correlated (nil-ID one not dropped).
	if result.CorrelatedAlerts != 3 {
		t.Fatalf("expected 3 correlated alerts, got %d", result.CorrelatedAlerts)
	}
	// Only the two real IDs are persisted; no nil entries.
	ids := result.Clusters[0].AlertIDs
	if len(ids) != 2 {
		t.Fatalf("expected 2 persisted alert IDs, got %d (%v)", len(ids), ids)
	}
	got := map[uuid.UUID]bool{}
	for _, id := range ids {
		if id == uuid.Nil {
			t.Fatal("persisted alert ID must not be nil")
		}
		got[id] = true
	}
	if !got[realA] || !got[realB] {
		t.Fatalf("expected persisted IDs to be {%s,%s}, got %v", realA, realB, ids)
	}
}

func TestCorrelationEngine_WithLLM(t *testing.T) {
	t.Parallel()
	llm := &correlationStubLLM{text: "AI-polished cluster summary", modelID: "test-model"}
	engine := NewCorrelationEngine(llm, CorrelationConfig{
		TimeWindow:     time.Hour,
		MinClusterSize: 2,
	})

	tenantID := uuid.New()
	now := time.Now()
	alerts := []AlertInput{
		{ID: uuid.New(), TenantID: tenantID, Kind: "anomaly", Severity: "medium", DeviceID: "d1", CreatedAt: now},
		{ID: uuid.New(), TenantID: tenantID, Kind: "anomaly", Severity: "medium", DeviceID: "d1", CreatedAt: now.Add(5 * time.Minute)},
	}

	result, err := engine.Analyze(context.Background(), alerts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.AIGenerated {
		t.Fatal("expected ai_generated=true with LLM")
	}
	if result.Clusters[0].Summary != "AI-polished cluster summary" {
		t.Fatalf("expected LLM summary, got %q", result.Clusters[0].Summary)
	}
}

func TestSeverityRank(t *testing.T) {
	t.Parallel()
	cases := []struct {
		input string
		want  int
	}{
		{"critical", 4},
		{"high", 3},
		{"medium", 2},
		{"low", 1},
		{"info", 0},
		{"unknown", 0},
	}
	for _, tc := range cases {
		if got := severityRank(tc.input); got != tc.want {
			t.Errorf("severityRank(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// --- test stubs ---

type correlationStubLLM struct {
	text    string
	modelID string
	err     error
}

func (s *correlationStubLLM) Complete(_ context.Context, _ LLMRequest) (LLMResponse, error) {
	if s.err != nil {
		return LLMResponse{}, s.err
	}
	return LLMResponse{Text: s.text, ModelID: s.modelID, TokenCount: 50}, nil
}
