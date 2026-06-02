// Package casb implements the Cloud Access Security Broker posture
// assessment engine (Phase 4, Task 44).
//
// The PostureAssessor runs a suite of standard posture checks against
// a SaaS application's configuration snapshot, scores each check as
// pass/fail/warn, and aggregates them into a per-app risk score
// (0-100). When the score degrades beyond a configurable threshold
// the assessor routes an alert through the existing alert.Router.
package casb

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// CheckStatus is the outcome of a single posture check.
type CheckStatus string

const (
	CheckStatusPass CheckStatus = "pass"
	CheckStatusFail CheckStatus = "fail"
	CheckStatusWarn CheckStatus = "warn"
)

// PostureCheck is a single check within a posture assessment.
type PostureCheck struct {
	Name     string      `json:"name"`
	Category string      `json:"category"`
	Status   CheckStatus `json:"status"`
	Evidence string      `json:"evidence,omitempty"`
	Weight   int         `json:"weight"`
}

// PostureReport is the aggregate result of running all posture
// checks against a SaaS application snapshot.
type PostureReport struct {
	AppID      string         `json:"app_id"`
	AppName    string         `json:"app_name"`
	TenantID   uuid.UUID      `json:"tenant_id"`
	RiskScore  int            `json:"risk_score"`
	Checks     []PostureCheck `json:"checks"`
	AssessedAt time.Time      `json:"assessed_at"`
}

// SaaSSnapshot is the configuration snapshot from a CASB sync that
// the posture assessor evaluates.
type SaaSSnapshot struct {
	AppID                  string  `json:"app_id"`
	AppName                string  `json:"app_name"`
	MFAEnforced            *bool   `json:"mfa_enforced,omitempty"`
	SSOFederated           *bool   `json:"sso_federated,omitempty"`
	AdminAccountCount      *int    `json:"admin_account_count,omitempty"`
	ExternalSharing        *bool   `json:"external_sharing,omitempty"`
	APIAccessRestricted    *bool   `json:"api_access_restricted,omitempty"`
	AuditLoggingEnabled    *bool   `json:"audit_logging_enabled,omitempty"`
	PasswordPolicyStrength *string `json:"password_policy_strength,omitempty"`
	SessionTimeout         *int    `json:"session_timeout_minutes,omitempty"`
}

// AlertEmitter is the interface the assessor uses to route posture
// degradation alerts. Satisfied by alert.Router.Emit.
type AlertEmitter interface {
	Emit(ctx context.Context, tenantID uuid.UUID, a repository.Alert) (repository.Alert, error)
}

// PostureAssessor scores SaaS application posture.
type PostureAssessor struct {
	alertEmitter AlertEmitter
	threshold    int
	logger       *slog.Logger
}

// NewPostureAssessor returns a ready-to-use assessor. `threshold`
// is the risk score above which an alert is emitted (0-100).
func NewPostureAssessor(emitter AlertEmitter, threshold int, logger *slog.Logger) *PostureAssessor {
	if logger == nil {
		logger = slog.Default()
	}
	if threshold <= 0 {
		threshold = 70
	}
	return &PostureAssessor{alertEmitter: emitter, threshold: threshold, logger: logger}
}

// Assess runs the standard posture checks against the snapshot and
// returns a PostureReport. If the resulting risk score exceeds the
// threshold, an alert is emitted.
func (a *PostureAssessor) Assess(ctx context.Context, tenantID uuid.UUID, snap SaaSSnapshot) (PostureReport, error) {
	checks := a.runChecks(snap)
	score := computeRiskScore(checks)

	report := PostureReport{
		AppID:      snap.AppID,
		AppName:    snap.AppName,
		TenantID:   tenantID,
		RiskScore:  score,
		Checks:     checks,
		AssessedAt: time.Now().UTC(),
	}

	if score >= a.threshold && a.alertEmitter != nil {
		evidence, _ := json.Marshal(report)
		now := time.Now().UTC()
		if _, err := a.alertEmitter.Emit(ctx, tenantID, repository.Alert{
			TenantID:  tenantID,
			Kind:      "posture_degradation",
			Severity:  repository.AlertSeverity(severityForScore(score)),
			Dimension: "casb.posture." + snap.AppID,
			Summary:   fmt.Sprintf("SaaS posture degradation: %s scored %d/100", snap.AppName, score),
			Evidence:  evidence,
			State:     repository.AlertStateOpen,
			CreatedAt: now,
			UpdatedAt: now,
		}); err != nil {
			a.logger.Error("posture alert failed", "app", snap.AppName, "err", err)
		}
	}

	return report, nil
}

func (a *PostureAssessor) runChecks(snap SaaSSnapshot) []PostureCheck {
	var checks []PostureCheck

	checks = append(checks, boolCheck("MFA Enforcement", "authentication", snap.MFAEnforced, true, 15))
	checks = append(checks, boolCheck("SSO Federation", "authentication", snap.SSOFederated, true, 12))
	checks = append(checks, adminCountCheck(snap.AdminAccountCount, 10))
	checks = append(checks, boolCheck("External Sharing Disabled", "data_protection", snap.ExternalSharing, false, 12))
	checks = append(checks, boolCheck("API Access Restricted", "access_control", snap.APIAccessRestricted, true, 10))
	checks = append(checks, boolCheck("Audit Logging Enabled", "compliance", snap.AuditLoggingEnabled, true, 15))
	checks = append(checks, passwordPolicyCheck(snap.PasswordPolicyStrength, 13))
	checks = append(checks, sessionTimeoutCheck(snap.SessionTimeout, 13))

	return checks
}

func boolCheck(name, category string, val *bool, expected bool, weight int) PostureCheck {
	if val == nil {
		return PostureCheck{Name: name, Category: category, Status: CheckStatusWarn, Evidence: "not reported", Weight: weight}
	}
	if *val == expected {
		return PostureCheck{Name: name, Category: category, Status: CheckStatusPass, Evidence: fmt.Sprintf("value=%v", *val), Weight: weight}
	}
	return PostureCheck{Name: name, Category: category, Status: CheckStatusFail, Evidence: fmt.Sprintf("expected=%v got=%v", expected, *val), Weight: weight}
}

func adminCountCheck(count *int, weight int) PostureCheck {
	if count == nil {
		return PostureCheck{Name: "Admin Account Inventory", Category: "access_control", Status: CheckStatusWarn, Evidence: "not reported", Weight: weight}
	}
	if *count <= 3 {
		return PostureCheck{Name: "Admin Account Inventory", Category: "access_control", Status: CheckStatusPass, Evidence: fmt.Sprintf("count=%d", *count), Weight: weight}
	}
	if *count <= 5 {
		return PostureCheck{Name: "Admin Account Inventory", Category: "access_control", Status: CheckStatusWarn, Evidence: fmt.Sprintf("count=%d (elevated)", *count), Weight: weight}
	}
	return PostureCheck{Name: "Admin Account Inventory", Category: "access_control", Status: CheckStatusFail, Evidence: fmt.Sprintf("count=%d (excessive)", *count), Weight: weight}
}

func passwordPolicyCheck(strength *string, weight int) PostureCheck {
	if strength == nil {
		return PostureCheck{Name: "Password Policy Strength", Category: "authentication", Status: CheckStatusWarn, Evidence: "not reported", Weight: weight}
	}
	switch *strength {
	case "strong":
		return PostureCheck{Name: "Password Policy Strength", Category: "authentication", Status: CheckStatusPass, Evidence: "strong", Weight: weight}
	case "medium":
		return PostureCheck{Name: "Password Policy Strength", Category: "authentication", Status: CheckStatusWarn, Evidence: "medium", Weight: weight}
	default:
		return PostureCheck{Name: "Password Policy Strength", Category: "authentication", Status: CheckStatusFail, Evidence: *strength, Weight: weight}
	}
}

func sessionTimeoutCheck(timeout *int, weight int) PostureCheck {
	if timeout == nil {
		return PostureCheck{Name: "Session Management", Category: "access_control", Status: CheckStatusWarn, Evidence: "not reported", Weight: weight}
	}
	if *timeout > 0 && *timeout <= 60 {
		return PostureCheck{Name: "Session Management", Category: "access_control", Status: CheckStatusPass, Evidence: fmt.Sprintf("timeout=%dm", *timeout), Weight: weight}
	}
	if *timeout > 60 && *timeout <= 480 {
		return PostureCheck{Name: "Session Management", Category: "access_control", Status: CheckStatusWarn, Evidence: fmt.Sprintf("timeout=%dm (long)", *timeout), Weight: weight}
	}
	return PostureCheck{Name: "Session Management", Category: "access_control", Status: CheckStatusFail, Evidence: fmt.Sprintf("timeout=%dm", *timeout), Weight: weight}
}

func computeRiskScore(checks []PostureCheck) int {
	totalWeight := 0
	failedWeight := 0
	warnWeight := 0

	for _, c := range checks {
		totalWeight += c.Weight
		switch c.Status {
		case CheckStatusFail:
			failedWeight += c.Weight
		case CheckStatusWarn:
			warnWeight += c.Weight
		}
	}
	if totalWeight == 0 {
		return 0
	}
	// Risk score: full weight for fails, half for warns.
	risk := float64(failedWeight) + float64(warnWeight)*0.5
	score := int((risk / float64(totalWeight)) * 100)
	if score > 100 {
		score = 100
	}
	return score
}

func severityForScore(score int) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "warning"
	default:
		return "info"
	}
}
