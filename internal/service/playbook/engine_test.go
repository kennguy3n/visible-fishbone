package playbook_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/playbook"
)

type mockPublisher struct {
	mu   sync.Mutex
	msgs []struct {
		Subject string
		Data    []byte
	}
}

func (m *mockPublisher) Publish(_ context.Context, subject string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.msgs = append(m.msgs, struct {
		Subject string
		Data    []byte
	}{subject, data})
	return nil
}

type mockRegistry struct{}

func (m *mockRegistry) Get(t playbook.StepType) (playbook.StepExecutor, error) {
	return &mockExecutor{}, nil
}

type mockExecutor struct{}

func (m *mockExecutor) Execute(_ context.Context, _ uuid.UUID, _ json.RawMessage) (json.RawMessage, error) {
	return json.Marshal(map[string]string{"status": "ok"})
}

func newTestEngine() (*playbook.Engine, *memory.Store) {
	store := memory.NewStore()
	pbRepo := memory.NewPlaybookRepository(store)
	execRepo := memory.NewPlaybookExecutionRepository(store)
	pub := &mockPublisher{}
	engine := playbook.NewEngine(pbRepo, execRepo, pub, nil)
	engine.SetExecutors(&mockRegistry{})
	return engine, store
}

func createTestPlaybook(t *testing.T, engine *playbook.Engine, tenantID uuid.UUID) repository.Playbook {
	t.Helper()
	steps, _ := json.Marshal([]playbook.PlaybookStep{
		{Order: 1, Type: playbook.StepNotify, Config: json.RawMessage(`{"message":"test"}`)},
		{Order: 2, Type: playbook.StepCreateTicket, Config: json.RawMessage(`{"title":"incident"}`)},
	})
	pb, err := engine.CreatePlaybook(context.Background(), tenantID, repository.Playbook{
		Name:             "Test Playbook",
		Description:      "A test playbook",
		TriggerCondition: "baseline.anomaly",
		Steps:            steps,
		Enabled:          true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return pb
}

func TestEngine_Execute(t *testing.T) {
	engine, _ := newTestEngine()
	tenantID := uuid.New()
	pb := createTestPlaybook(t, engine, tenantID)

	exec, err := engine.Execute(context.Background(), tenantID, pb.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if exec.Status != string(playbook.StatusCompleted) {
		t.Errorf("expected completed, got %s", exec.Status)
	}
	if exec.PlaybookID != pb.ID {
		t.Error("playbook ID mismatch")
	}
}

type capturingExecutor struct {
	lastConfig json.RawMessage
}

func (c *capturingExecutor) Execute(_ context.Context, _ uuid.UUID, config json.RawMessage) (json.RawMessage, error) {
	c.lastConfig = config
	return json.Marshal(map[string]string{"status": "ok"})
}

type capturingRegistry struct{ exec *capturingExecutor }

func (r *capturingRegistry) Get(_ playbook.StepType) (playbook.StepExecutor, error) {
	return r.exec, nil
}

func TestEngine_Execute_MergesTriggerContext(t *testing.T) {
	store := memory.NewStore()
	engine := playbook.NewEngine(
		memory.NewPlaybookRepository(store),
		memory.NewPlaybookExecutionRepository(store),
		&mockPublisher{}, nil,
	)
	capExec := &capturingExecutor{}
	engine.SetExecutors(&capturingRegistry{exec: capExec})

	tenantID := uuid.New()
	steps, _ := json.Marshal([]playbook.PlaybookStep{
		// no device_id in config; it must be filled from the trigger event,
		// while the explicit reason must win over the trigger's reason.
		{Order: 1, Type: playbook.StepIsolate, Config: json.RawMessage(`{"reason":"explicit"}`)},
	})
	pb, err := engine.CreatePlaybook(context.Background(), tenantID, repository.Playbook{
		Name:             "Isolate",
		TriggerCondition: "device.compromised",
		Steps:            steps,
		Enabled:          true,
	})
	if err != nil {
		t.Fatal(err)
	}

	deviceID := uuid.New()
	trigger := json.RawMessage(`{"device_id":"` + deviceID.String() + `","reason":"from-trigger","severity":"critical"}`)
	if _, err := engine.Execute(context.Background(), tenantID, pb.ID, trigger); err != nil {
		t.Fatal(err)
	}

	var merged map[string]any
	if err := json.Unmarshal(capExec.lastConfig, &merged); err != nil {
		t.Fatalf("merged config not valid JSON: %v", err)
	}
	if merged["device_id"] != deviceID.String() {
		t.Errorf("expected device_id injected from trigger, got %v", merged["device_id"])
	}
	if merged["reason"] != "explicit" {
		t.Errorf("explicit config should win over trigger, got %v", merged["reason"])
	}
	if merged["severity"] != "critical" {
		t.Errorf("expected severity carried from trigger, got %v", merged["severity"])
	}
}

func TestEngine_Concurrency(t *testing.T) {
	engine, _ := newTestEngine()
	tenantID := uuid.New()
	pb := createTestPlaybook(t, engine, tenantID)

	done := make(chan error, 2)
	go func() {
		_, err := engine.Execute(context.Background(), tenantID, pb.ID, nil)
		done <- err
	}()
	go func() {
		_, err := engine.Execute(context.Background(), tenantID, pb.ID, nil)
		done <- err
	}()

	err1 := <-done
	err2 := <-done

	// At least one should succeed, possibly both if the first finishes fast
	if err1 != nil && err2 != nil {
		t.Error("both executions failed, expected at least one to succeed")
	}
}

func TestEngine_DryRun(t *testing.T) {
	engine, _ := newTestEngine()
	tenantID := uuid.New()
	pb := createTestPlaybook(t, engine, tenantID)

	results, err := engine.DryRun(context.Background(), tenantID, pb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 step results, got %d", len(results))
	}
	for _, r := range results {
		if r.Status != "simulated" {
			t.Errorf("expected simulated, got %s", r.Status)
		}
	}
}

func TestEngine_PlaybookNotFound(t *testing.T) {
	engine, _ := newTestEngine()
	_, err := engine.Execute(context.Background(), uuid.New(), uuid.New(), nil)
	if err == nil {
		t.Error("expected error for nonexistent playbook")
	}
}

func TestEngine_CRUD(t *testing.T) {
	engine, _ := newTestEngine()
	tenantID := uuid.New()

	pb := createTestPlaybook(t, engine, tenantID)

	got, err := engine.GetPlaybook(context.Background(), tenantID, pb.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Test Playbook" {
		t.Error("name mismatch")
	}

	newName := "Updated"
	updated, err := engine.UpdatePlaybook(context.Background(), tenantID, pb.ID, repository.PlaybookPatch{
		Name: &newName,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Updated" {
		t.Error("update failed")
	}

	list, err := engine.ListPlaybooks(context.Background(), tenantID, repository.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Errorf("expected 1 playbook, got %d", len(list.Items))
	}

	if err := engine.DeletePlaybook(context.Background(), tenantID, pb.ID); err != nil {
		t.Fatal(err)
	}

	_, err = engine.GetPlaybook(context.Background(), tenantID, pb.ID)
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestEvaluateTrigger(t *testing.T) {
	tests := []struct {
		condition string
		kind      string
		want      bool
	}{
		{"baseline.anomaly", "baseline.anomaly", true},
		{"baseline.anomaly", "other.event", false},
		{"*", "anything", true},
		{"", "anything", false},
	}
	for _, tc := range tests {
		got := playbook.EvaluateTrigger(tc.condition, tc.kind)
		if got != tc.want {
			t.Errorf("EvaluateTrigger(%q, %q) = %v, want %v", tc.condition, tc.kind, got, tc.want)
		}
	}
}
