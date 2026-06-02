package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// AutomationAction represents a single automated action for reporting.
type AutomationAction struct {
	ID         uuid.UUID       `json:"id"`
	TenantID   uuid.UUID       `json:"tenant_id"`
	ActionType string          `json:"action_type"`
	Actor      string          `json:"actor"`
	Outcome    string          `json:"outcome"`
	Details    json.RawMessage `json:"details,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`
}

// AutomationSummary aggregates automation activity for a period.
type AutomationSummary struct {
	TenantID            uuid.UUID `json:"tenant_id"`
	Period              string    `json:"period"`
	TotalActions        int       `json:"total_actions"`
	PlaybookExecutions  int       `json:"playbook_executions"`
	AISuggestions       int       `json:"ai_suggestions"`
	CertRotations       int       `json:"cert_rotations"`
	PolicyAutoReviews   int       `json:"policy_auto_reviews"`
	SuccessRate         float64   `json:"success_rate"`
}

// AutomationReport is the full compliance-grade automation audit.
type AutomationReport struct {
	TenantID  uuid.UUID          `json:"tenant_id"`
	From      time.Time          `json:"from"`
	To        time.Time          `json:"to"`
	Summary   AutomationSummary  `json:"summary"`
	Actions   []AutomationAction `json:"actions"`
	Generated time.Time          `json:"generated_at"`
}

// AutomationDataProvider abstracts retrieval of automation actions
// from external sources (playbook engine, AI service, cert service).
type AutomationDataProvider interface {
	ListAutomationActions(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]AutomationAction, error)
}

// staticProvider returns a fixed list of actions — used for testing
// or when the real provider is not wired.
type staticProvider struct {
	actions []AutomationAction
}

func (p *staticProvider) ListAutomationActions(_ context.Context, tenantID uuid.UUID, from, to time.Time) ([]AutomationAction, error) {
	var filtered []AutomationAction
	for _, a := range p.actions {
		if a.TenantID != tenantID {
			continue
		}
		if a.Timestamp.Before(from) || a.Timestamp.After(to) {
			continue
		}
		filtered = append(filtered, a)
	}
	return filtered, nil
}

// AutomationReportService generates automation audit reports.
type AutomationReportService struct {
	providers []AutomationDataProvider
	logger    *slog.Logger
	nowFunc   func() time.Time
}

// NewAutomationReportService returns a ready-to-use report service.
func NewAutomationReportService(logger *slog.Logger) *AutomationReportService {
	if logger == nil {
		logger = slog.Default()
	}
	return &AutomationReportService{
		logger:  logger,
		nowFunc: func() time.Time { return time.Now().UTC() },
	}
}

// SetNowFunc overrides the clock for testing.
func (s *AutomationReportService) SetNowFunc(fn func() time.Time) {
	if fn != nil {
		s.nowFunc = fn
	}
}

// AddProvider registers an automation data source.
func (s *AutomationReportService) AddProvider(p AutomationDataProvider) {
	if p != nil {
		s.providers = append(s.providers, p)
	}
}

// AddStaticActions is a convenience for testing — wraps actions in
// a static provider.
func (s *AutomationReportService) AddStaticActions(actions []AutomationAction) {
	s.AddProvider(&staticProvider{actions: actions})
}

// GenerateReport produces a compliance-grade automation audit report
// for the given tenant and time range.
func (s *AutomationReportService) GenerateReport(
	ctx context.Context,
	tenantID uuid.UUID,
	from, to time.Time,
) (AutomationReport, error) {
	var allActions []AutomationAction
	for _, p := range s.providers {
		actions, err := p.ListAutomationActions(ctx, tenantID, from, to)
		if err != nil {
			s.logger.Error("automation report: provider error",
				slog.Any("error", err))
			continue
		}
		allActions = append(allActions, actions...)
	}

	summary := s.summarize(tenantID, from, to, allActions)

	return AutomationReport{
		TenantID:  tenantID,
		From:      from,
		To:        to,
		Summary:   summary,
		Actions:   allActions,
		Generated: s.nowFunc(),
	}, nil
}

// ExportJSON returns the report as indented JSON for compliance export.
func (s *AutomationReportService) ExportJSON(report AutomationReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}

func (s *AutomationReportService) summarize(
	tenantID uuid.UUID,
	from, to time.Time,
	actions []AutomationAction,
) AutomationSummary {
	summary := AutomationSummary{
		TenantID:     tenantID,
		Period:       from.Format(time.DateOnly) + " to " + to.Format(time.DateOnly),
		TotalActions: len(actions),
	}
	succeeded := 0
	for _, a := range actions {
		switch a.ActionType {
		case "playbook_execution":
			summary.PlaybookExecutions++
		case "ai_suggestion":
			summary.AISuggestions++
		case "cert_rotation":
			summary.CertRotations++
		case "policy_auto_review":
			summary.PolicyAutoReviews++
		}
		if a.Outcome == "success" {
			succeeded++
		}
	}
	if summary.TotalActions > 0 {
		summary.SuccessRate = float64(succeeded) / float64(summary.TotalActions) * 100
	}
	return summary
}
