package ai

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
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
