package playbook_test

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/playbook"
)

func TestGetTemplates(t *testing.T) {
	templates := playbook.GetTemplates()
	if len(templates) == 0 {
		t.Error("expected non-empty templates")
	}
	if len(templates) != 5 {
		t.Errorf("expected 5 templates, got %d", len(templates))
	}
}

func TestGetTemplate_Exists(t *testing.T) {
	tmpl, ok := playbook.GetTemplate("compromised_device")
	if !ok {
		t.Fatal("expected to find compromised_device template")
	}
	if tmpl.Name != "Compromised Device Response" {
		t.Errorf("unexpected name: %s", tmpl.Name)
	}
	if len(tmpl.Steps) != 4 {
		t.Errorf("expected 4 steps, got %d", len(tmpl.Steps))
	}
}

func TestGetTemplate_NotFound(t *testing.T) {
	_, ok := playbook.GetTemplate("nonexistent")
	if ok {
		t.Error("expected not found")
	}
}

func TestCloneTemplate(t *testing.T) {
	tmpl, _ := playbook.GetTemplate("brute_force")
	tenantID := uuid.New()
	pb := playbook.CloneTemplate(tenantID, tmpl)

	if pb.TenantID != tenantID {
		t.Error("tenant ID mismatch")
	}
	if pb.Name != tmpl.Name {
		t.Error("name mismatch")
	}
	if !pb.Enabled {
		t.Error("cloned playbook should be enabled")
	}
	if pb.ID == uuid.Nil {
		t.Error("cloned playbook should have a non-nil ID")
	}

	var steps []playbook.PlaybookStep
	if err := json.Unmarshal(pb.Steps, &steps); err != nil {
		t.Fatal(err)
	}
	if len(steps) != len(tmpl.Steps) {
		t.Errorf("expected %d steps, got %d", len(tmpl.Steps), len(steps))
	}
}

func TestAllTemplates_ValidSteps(t *testing.T) {
	for _, tmpl := range playbook.GetTemplates() {
		for _, step := range tmpl.Steps {
			if !playbook.ValidStepTypes[step.Type] {
				t.Errorf("template %s step %d has invalid type: %s", tmpl.ID, step.Order, step.Type)
			}
			if step.TimeoutSeconds <= 0 {
				t.Errorf("template %s step %d has invalid timeout: %d", tmpl.ID, step.Order, step.TimeoutSeconds)
			}
		}
	}
}

func TestAllTemplates_HaveTriggers(t *testing.T) {
	for _, tmpl := range playbook.GetTemplates() {
		if tmpl.TriggerCondition == "" {
			t.Errorf("template %s has empty trigger condition", tmpl.ID)
		}
	}
}
