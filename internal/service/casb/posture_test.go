package casb_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

type stubAlertEmitter struct {
	emitted []repository.Alert
}

func (s *stubAlertEmitter) Emit(_ context.Context, _ uuid.UUID, a repository.Alert) (repository.Alert, error) {
	s.emitted = append(s.emitted, a)
	a.ID = uuid.New()
	return a, nil
}

func boolPtr(b bool) *bool    { return &b }
func intPtr(i int) *int       { return &i }
func strPtr(s string) *string { return &s }

func TestPostureAssessor_AllPass(t *testing.T) {
	t.Parallel()
	emitter := &stubAlertEmitter{}
	assessor := casb.NewPostureAssessor(emitter, 70, nil)

	report, err := assessor.Assess(context.Background(), uuid.New(), casb.SaaSSnapshot{
		AppID:                  "slack",
		AppName:                "Slack",
		MFAEnforced:            boolPtr(true),
		SSOFederated:           boolPtr(true),
		AdminAccountCount:      intPtr(2),
		ExternalSharing:        boolPtr(false),
		APIAccessRestricted:    boolPtr(true),
		AuditLoggingEnabled:    boolPtr(true),
		PasswordPolicyStrength: strPtr("strong"),
		SessionTimeout:         intPtr(30),
	})
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if report.RiskScore != 0 {
		t.Fatalf("risk_score = %d, want 0 (all pass)", report.RiskScore)
	}
	if len(emitter.emitted) > 0 {
		t.Fatalf("expected no alerts, got %d", len(emitter.emitted))
	}
}

func TestPostureAssessor_AllFail(t *testing.T) {
	t.Parallel()
	emitter := &stubAlertEmitter{}
	assessor := casb.NewPostureAssessor(emitter, 70, nil)

	report, err := assessor.Assess(context.Background(), uuid.New(), casb.SaaSSnapshot{
		AppID:                  "box",
		AppName:                "Box",
		MFAEnforced:            boolPtr(false),
		SSOFederated:           boolPtr(false),
		AdminAccountCount:      intPtr(20),
		ExternalSharing:        boolPtr(true),
		APIAccessRestricted:    boolPtr(false),
		AuditLoggingEnabled:    boolPtr(false),
		PasswordPolicyStrength: strPtr("weak"),
		SessionTimeout:         intPtr(0),
	})
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	if report.RiskScore != 100 {
		t.Fatalf("risk_score = %d, want 100 (all fail)", report.RiskScore)
	}
	if len(emitter.emitted) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(emitter.emitted))
	}
}

func TestPostureAssessor_PartialFail(t *testing.T) {
	t.Parallel()
	assessor := casb.NewPostureAssessor(nil, 70, nil)

	report, err := assessor.Assess(context.Background(), uuid.New(), casb.SaaSSnapshot{
		AppID:               "github",
		AppName:             "GitHub",
		MFAEnforced:         boolPtr(true),
		SSOFederated:        boolPtr(false),
		AdminAccountCount:   intPtr(2),
		AuditLoggingEnabled: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	// Some checks fail/warn, score should be between 0 and 100.
	if report.RiskScore <= 0 || report.RiskScore >= 100 {
		t.Fatalf("risk_score = %d, expected between 1 and 99", report.RiskScore)
	}
}

func TestPostureAssessor_UnknownFields(t *testing.T) {
	t.Parallel()
	assessor := casb.NewPostureAssessor(nil, 70, nil)

	report, err := assessor.Assess(context.Background(), uuid.New(), casb.SaaSSnapshot{
		AppID:   "unknown",
		AppName: "Unknown App",
	})
	if err != nil {
		t.Fatalf("assess: %v", err)
	}
	// All checks should be warn.
	for _, c := range report.Checks {
		if c.Status != casb.CheckStatusWarn {
			t.Fatalf("check %q status = %q, want warn", c.Name, c.Status)
		}
	}
}
