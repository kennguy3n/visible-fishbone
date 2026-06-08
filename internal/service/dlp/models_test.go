package dlp_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlp"
)

const (
	// 64 hex chars (SHA-256) and 128 hex chars (Ed25519 signature).
	testSHA256 = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	testSig    = testSHA256 + testSHA256
)

func validModelInput() dlp.ModelInput {
	return dlp.ModelInput{
		Name:          "pii-ner",
		Version:       1,
		EntityClasses: []string{"person_name", "bank_account"},
		ObjectKey:     "tenants/x/models/pii-ner/v1.onnx",
		SizeBytes:     875,
		SHA256:        testSHA256,
	}
}

func TestRegisterModel_Validation(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	cases := map[string]func(*dlp.ModelInput){
		"empty name":   func(in *dlp.ModelInput) { in.Name = "" },
		"zero version": func(in *dlp.ModelInput) { in.Version = 0 },
		"no classes":   func(in *dlp.ModelInput) { in.EntityClasses = nil },
		"bad class":    func(in *dlp.ModelInput) { in.EntityClasses = []string{"not_a_class"} },
		"empty key":    func(in *dlp.ModelInput) { in.ObjectKey = "" },
		"zero size":    func(in *dlp.ModelInput) { in.SizeBytes = 0 },
		"short sha":    func(in *dlp.ModelInput) { in.SHA256 = "abcd" },
		"non-hex sha":  func(in *dlp.ModelInput) { in.SHA256 = strings.Repeat("z", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := validModelInput()
			mutate(&in)
			if _, err := svc.RegisterModel(ctx, tid, in); !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("expected ErrInvalidArgument, got %v", err)
			}
		})
	}
}

func TestModelLifecycle_RegisterValidateAssign(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	m, err := svc.RegisterModel(ctx, tid, validModelInput())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if m.Status != repository.DLPModelStatusDraft {
		t.Fatalf("new model status = %q, want draft", m.Status)
	}

	// A draft model cannot be assigned.
	if _, err := svc.AssignModel(ctx, tid, m.ID); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("assign draft: expected ErrInvalidArgument, got %v", err)
	}

	// Validate promotes it and records the signature.
	v, err := svc.ValidateModel(ctx, tid, m.ID, testSig)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if v.Status != repository.DLPModelStatusValidated || v.Signature != testSig {
		t.Fatalf("validated model = %+v", v)
	}

	if _, err := svc.AssignModel(ctx, tid, m.ID); err != nil {
		t.Fatalf("assign validated: %v", err)
	}
	got, err := svc.AssignedModel(ctx, tid)
	if err != nil || got.ID != m.ID {
		t.Fatalf("assigned = %+v, err=%v", got, err)
	}

	// A model that is the active assignment cannot be deleted.
	if err := svc.DeleteModel(ctx, tid, m.ID); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("delete assigned: expected ErrConflict, got %v", err)
	}
	// Clearing the assignment unblocks deletion.
	if err := svc.ClearModelAssignment(ctx, tid); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if err := svc.DeleteModel(ctx, tid, m.ID); err != nil {
		t.Fatalf("delete after clear: %v", err)
	}
}

func TestValidateModel_RejectsMalformedSignature(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()
	m, err := svc.RegisterModel(ctx, tid, validModelInput())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := svc.ValidateModel(ctx, tid, m.ID, "deadbeef"); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestRegisterModel_DuplicateVersionConflicts(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()
	if _, err := svc.RegisterModel(ctx, tid, validModelInput()); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := svc.RegisterModel(ctx, tid, validModelInput()); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("dup version: expected ErrConflict, got %v", err)
	}
}

// A validated model is embedded in the endpoint bundle only when the
// tenant has an ml_ner rule referencing it.
func TestCompileEndpointBundle_EmbedsModelForMLNerRule(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "PII NER",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeMLNER, Pattern: "person_name,bank_account"}},
		Action:  repository.DLPActionBlock,
		Enabled: true,
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	m, err := svc.RegisterModel(ctx, tid, validModelInput())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := svc.ValidateModel(ctx, tid, m.ID, testSig); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := svc.AssignModel(ctx, tid, m.ID); err != nil {
		t.Fatalf("assign: %v", err)
	}

	blob, err := svc.CompileEndpointBundle(ctx, tid, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var doc struct {
		Rules []map[string]any `json:"rules"`
		Model *struct {
			Version       int      `json:"version"`
			EntityClasses []string `json:"entity_classes"`
			ObjectKey     string   `json:"object_key"`
			SHA256        string   `json:"sha256"`
			Signature     string   `json:"signature"`
		} `json:"model"`
	}
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(doc.Rules) != 1 || doc.Rules[0]["pattern_type"] != "ml_ner" {
		t.Fatalf("rules = %v", doc.Rules)
	}
	if doc.Model == nil {
		t.Fatal("expected model descriptor in bundle")
	}
	if doc.Model.ObjectKey != m.ObjectKey || doc.Model.SHA256 != testSHA256 || doc.Model.Signature != testSig {
		t.Fatalf("model descriptor = %+v", doc.Model)
	}
}

// No model is embedded when the tenant has an assigned model but no
// ml_ner rule to use it.
func TestCompileEndpointBundle_NoModelWithoutMLNerRule(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "Regex",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: `\d{16}`}},
		Action:  repository.DLPActionBlock,
		Enabled: true,
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	m, err := svc.RegisterModel(ctx, tid, validModelInput())
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := svc.ValidateModel(ctx, tid, m.ID, testSig); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := svc.AssignModel(ctx, tid, m.ID); err != nil {
		t.Fatalf("assign: %v", err)
	}

	blob, err := svc.CompileEndpointBundle(ctx, tid, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := doc["model"]; ok {
		t.Fatalf("did not expect a model descriptor, got %v", doc["model"])
	}
}

// An ml_ner rule whose pattern_data lists an unknown entity class is
// dropped from the compiled endpoint rules (it would otherwise poison
// the whole-bundle decode on the agent).
func TestEndpointRules_DropsPoisonMLNerPatternData(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name: "Mixed",
		Rules: []repository.DLPRule{
			{Type: repository.DLPRuleTypeMLNER, Pattern: "person_name"},
			{Type: repository.DLPRuleTypeMLNER, Pattern: "bogus_class"},
		},
		Action:  repository.DLPActionBlock,
		Enabled: true,
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}
	rules, err := svc.EndpointRules(ctx, tid)
	if err != nil {
		t.Fatalf("endpoint rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 valid ml_ner rule, got %d (%v)", len(rules), rules)
	}
	if rules[0].PatternData != "person_name" {
		t.Fatalf("pattern_data = %q, want person_name", rules[0].PatternData)
	}
}

func TestModelMethods_RequireModelRepo(t *testing.T) {
	// A service built without a model repo disables model management.
	svc := dlp.New(nil, nil, nil, nil, nil)
	ctx := context.Background()
	tid := uuid.New()
	if _, err := svc.RegisterModel(ctx, tid, validModelInput()); !errors.Is(err, dlp.ErrModelsUnavailable) {
		t.Fatalf("expected ErrModelsUnavailable, got %v", err)
	}
	if _, err := svc.AssignedModel(ctx, tid); !errors.Is(err, dlp.ErrModelsUnavailable) {
		t.Fatalf("expected ErrModelsUnavailable, got %v", err)
	}
}
