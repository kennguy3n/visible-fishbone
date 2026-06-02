package executors_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/playbook"
	"github.com/kennguy3n/visible-fishbone/internal/service/playbook/executors"
)

type mockPublisher struct {
	published []struct {
		Subject string
		Data    []byte
	}
}

func (m *mockPublisher) Publish(_ context.Context, subject string, data []byte) error {
	m.published = append(m.published, struct {
		Subject string
		Data    []byte
	}{Subject: subject, Data: data})
	return nil
}

func TestRegistry_AllTypesRegistered(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)

	for st := range playbook.ValidStepTypes {
		if _, err := reg.Get(st); err != nil {
			t.Errorf("missing executor for step type %s: %v", st, err)
		}
	}
}

func TestIsolateExecutor(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)
	exec, _ := reg.Get(playbook.StepIsolate)

	cfg, _ := json.Marshal(map[string]string{
		"device_id": uuid.New().String(),
		"reason":    "compromised",
	})
	out, err := exec.Execute(context.Background(), uuid.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	json.Unmarshal(out, &result)
	if result["status"] != "isolated" {
		t.Errorf("expected status=isolated, got %s", result["status"])
	}
	if len(pub.published) != 1 {
		t.Errorf("expected 1 publish, got %d", len(pub.published))
	}
}

func TestBlockIPExecutor(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)
	exec, _ := reg.Get(playbook.StepBlockIP)

	cfg, _ := json.Marshal(map[string]string{
		"ip_address": "10.0.0.1",
		"duration":   "1h",
	})
	out, err := exec.Execute(context.Background(), uuid.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	json.Unmarshal(out, &result)
	if result["status"] != "blocked" {
		t.Errorf("expected status=blocked, got %s", result["status"])
	}
}

func TestNotifyExecutor(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)
	exec, _ := reg.Get(playbook.StepNotify)

	cfg, _ := json.Marshal(map[string]string{
		"message": "Alert triggered",
		"channel": "webhook",
	})
	out, err := exec.Execute(context.Background(), uuid.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	json.Unmarshal(out, &result)
	if result["status"] != "notified" {
		t.Errorf("expected status=notified, got %s", result["status"])
	}
}

func TestTicketExecutor(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)
	exec, _ := reg.Get(playbook.StepCreateTicket)

	cfg, _ := json.Marshal(map[string]string{
		"title":       "Incident",
		"description": "Security incident detected",
	})
	out, err := exec.Execute(context.Background(), uuid.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	json.Unmarshal(out, &result)
	if result["status"] != "created" {
		t.Errorf("expected status=created, got %s", result["status"])
	}
}

func TestQuarantineExecutor(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)
	exec, _ := reg.Get(playbook.StepQuarantine)

	cfg, _ := json.Marshal(map[string]string{
		"file_id": "f-123",
		"reason":  "DLP violation",
	})
	out, err := exec.Execute(context.Background(), uuid.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	json.Unmarshal(out, &result)
	if result["status"] != "quarantined" {
		t.Errorf("expected status=quarantined, got %s", result["status"])
	}
}

func TestPolicyUpdateExecutor(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)
	exec, _ := reg.Get(playbook.StepPolicyUpdate)

	cfg, _ := json.Marshal(map[string]string{
		"action": "restrict",
		"scope":  "site-level",
	})
	out, err := exec.Execute(context.Background(), uuid.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	json.Unmarshal(out, &result)
	if result["status"] != "updated" {
		t.Errorf("expected status=updated, got %s", result["status"])
	}
}

func TestRevokeAccessExecutor(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)
	exec, _ := reg.Get(playbook.StepRevokeAccess)

	cfg, _ := json.Marshal(map[string]string{
		"user_id": uuid.New().String(),
		"reason":  "compromised credentials",
	})
	out, err := exec.Execute(context.Background(), uuid.New(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	json.Unmarshal(out, &result)
	if result["status"] != "revoked" {
		t.Errorf("expected status=revoked, got %s", result["status"])
	}
}

func TestIsolateExecutor_MissingDeviceID(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)
	exec, _ := reg.Get(playbook.StepIsolate)

	cfg, _ := json.Marshal(map[string]string{"reason": "test"})
	_, err := exec.Execute(context.Background(), uuid.New(), cfg)
	if err == nil {
		t.Error("expected error for missing device_id")
	}
}

func TestBlockIPExecutor_MissingIP(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)
	exec, _ := reg.Get(playbook.StepBlockIP)

	cfg, _ := json.Marshal(map[string]string{})
	_, err := exec.Execute(context.Background(), uuid.New(), cfg)
	if err == nil {
		t.Error("expected error for missing ip_address")
	}
}

func TestRegistry_UnknownType(t *testing.T) {
	pub := &mockPublisher{}
	reg := executors.NewRegistry(pub)
	_, err := reg.Get("unknown_type")
	if err == nil {
		t.Error("expected error for unknown step type")
	}
}
