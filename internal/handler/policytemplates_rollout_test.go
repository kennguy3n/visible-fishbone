package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/handler"
)

// stubTemplateAuthorizer is a fixed-answer RBAC seam for exercising the
// roll-out permission gate.
type stubTemplateAuthorizer struct{ allow bool }

func (s stubTemplateAuthorizer) HasPermission(_ context.Context, _ uuid.UUID, _ string) (bool, error) {
	return s.allow, nil
}

func TestPolicyTemplateHandler_Options(t *testing.T) {
	t.Parallel()
	router, _, token := newPolicyTemplateTestRouter(t)

	rec := doJSON(t, router, http.MethodGet, "/api/v1/policy-templates/options", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("options: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Industries []struct {
			Industry   string `json:"industry"`
			Name       string `json:"name"`
			TemplateID string `json:"template_id"`
		} `json:"industries"`
		Countries []struct {
			Country string `json:"country"`
			Regime  string `json:"regime"`
		} `json:"countries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Industries) == 0 || len(body.Countries) == 0 {
		t.Fatalf("expected industries and countries, got %d/%d", len(body.Industries), len(body.Countries))
	}
	// "options" must resolve to the vocabulary endpoint, not the
	// {id...} catch-all template lookup.
	if body.Industries[0].TemplateID == "" {
		t.Error("industry option missing template id")
	}
}

func TestPolicyTemplateHandler_RolloutPreviewAndExecute(t *testing.T) {
	t.Parallel()
	router, seeded, token := newPolicyTemplateTestRouter(t)
	fresh := uuid.New()

	body := map[string]any{
		"industry":   "finance",
		"country":    "DE",
		"tenant_ids": []string{seeded.String(), fresh.String()},
	}

	// Preview classifies each tenant as create (neither has a baseline
	// yet) and writes nothing.
	rec := doJSON(t, router, http.MethodPost, "/api/v1/policy-templates/rollout/preview", token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("preview: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var preview struct {
		Regime  string `json:"regime"`
		Targets []struct {
			TenantID string `json:"tenant_id"`
			Action   string `json:"action"`
		} `json:"targets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &preview); err != nil {
		t.Fatalf("unmarshal preview: %v", err)
	}
	if preview.Regime != "eu-gdpr" {
		t.Errorf("DE should resolve to eu-gdpr, got %q", preview.Regime)
	}
	if len(preview.Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(preview.Targets))
	}
	for _, tgt := range preview.Targets {
		if tgt.Action != "create" {
			t.Errorf("tenant %s: action = %q, want create", tgt.TenantID, tgt.Action)
		}
	}

	// Execute applies to both tenants.
	rec = doJSON(t, router, http.MethodPost, "/api/v1/policy-templates/rollout", token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollout: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var result struct {
		Applied   int `json:"applied"`
		Unchanged int `json:"unchanged"`
		Failed    int `json:"failed"`
		Outcomes  []struct {
			Status string `json:"status"`
		} `json:"outcomes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if result.Applied != 2 || result.Failed != 0 {
		t.Fatalf("counts = applied:%d unchanged:%d failed:%d, want applied:2",
			result.Applied, result.Unchanged, result.Failed)
	}

	// Re-running the same roll-out is idempotent: both tenants report
	// unchanged on the second pass.
	rec = doJSON(t, router, http.MethodPost, "/api/v1/policy-templates/rollout", token, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-rollout: expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &result)
	if result.Unchanged != 2 || result.Applied != 0 {
		t.Errorf("idempotent re-rollout counts = applied:%d unchanged:%d, want unchanged:2",
			result.Applied, result.Unchanged)
	}
}

func TestPolicyTemplateHandler_RolloutInvalidInput(t *testing.T) {
	t.Parallel()
	router, _, token := newPolicyTemplateTestRouter(t)

	cases := []struct {
		name string
		body map[string]any
	}{
		{
			name: "empty tenant list",
			body: map[string]any{"industry": "finance", "country": "DE", "tenant_ids": []string{}},
		},
		{
			name: "malformed tenant id",
			body: map[string]any{"industry": "finance", "country": "DE", "tenant_ids": []string{"not-a-uuid"}},
		},
		{
			name: "unsupported country",
			body: map[string]any{"industry": "finance", "country": "ZZ", "tenant_ids": []string{uuid.NewString()}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := doJSON(t, router, http.MethodPost, "/api/v1/policy-templates/rollout", token, tc.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("%s: expected 400, got %d: %s", tc.name, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestPolicyTemplateHandler_RolloutAuthorization(t *testing.T) {
	t.Parallel()
	body := map[string]any{
		"industry":   "finance",
		"country":    "DE",
		"tenant_ids": []string{uuid.NewString()},
	}

	// A wired authorizer that denies the permission gates both the
	// preview (policy:read) and the execute (policy:write) with 403,
	// before any roll-out work happens.
	denied, _, deniedToken := newPolicyTemplateTestRouter(t, handler.WithPolicyTemplateAuthorizer(stubTemplateAuthorizer{allow: false}))
	for _, path := range []string{"/api/v1/policy-templates/rollout/preview", "/api/v1/policy-templates/rollout"} {
		rec := doJSON(t, denied, http.MethodPost, path, deniedToken, body)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s: expected 403 when permission denied, got %d: %s", path, rec.Code, rec.Body.String())
		}
	}

	// A wired authorizer that grants the permission lets the roll-out
	// proceed (the create fans out to the single fresh tenant).
	allowed, _, allowedToken := newPolicyTemplateTestRouter(t, handler.WithPolicyTemplateAuthorizer(stubTemplateAuthorizer{allow: true}))
	rec := doJSON(t, allowed, http.MethodPost, "/api/v1/policy-templates/rollout", allowedToken, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 when permission granted, got %d: %s", rec.Code, rec.Body.String())
	}
}
