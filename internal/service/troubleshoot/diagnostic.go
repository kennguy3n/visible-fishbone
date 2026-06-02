package troubleshoot

import (
	"context"
	"fmt"
	"sort"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot/checks"
)

// DiagnosticEngine runs diagnostic checks against tenant state.
type DiagnosticEngine struct {
	registry map[string]checks.DiagnosticCheck
}

// NewDiagnosticEngine creates a diagnostic engine with the provided checks.
func NewDiagnosticEngine(diagnosticChecks []checks.DiagnosticCheck) *DiagnosticEngine {
	reg := make(map[string]checks.DiagnosticCheck, len(diagnosticChecks))
	for _, c := range diagnosticChecks {
		reg[c.Name()] = c
	}
	return &DiagnosticEngine{registry: reg}
}

// RunAll executes every registered diagnostic check and returns
// all results sorted by check name for deterministic ordering.
func (e *DiagnosticEngine) RunAll(ctx context.Context, tenantID uuid.UUID) []DiagnosticResult {
	names := make([]string, 0, len(e.registry))
	for name := range e.registry {
		names = append(names, name)
	}
	sort.Strings(names)
	results := make([]DiagnosticResult, 0, len(names))
	for _, name := range names {
		r := e.registry[name].Run(ctx, tenantID)
		results = append(results, toServiceResult(r))
	}
	return results
}

// RunCheck executes a single diagnostic check by name.
func (e *DiagnosticEngine) RunCheck(ctx context.Context, tenantID uuid.UUID, checkName string) (DiagnosticResult, error) {
	c, ok := e.registry[checkName]
	if !ok {
		return DiagnosticResult{}, fmt.Errorf("unknown diagnostic check %q", checkName)
	}
	r := c.Run(ctx, tenantID)
	return toServiceResult(r), nil
}

// ListChecks returns the names of all registered checks.
func (e *DiagnosticEngine) ListChecks() []string {
	names := make([]string, 0, len(e.registry))
	for name := range e.registry {
		names = append(names, name)
	}
	return names
}

func toServiceResult(r checks.DiagnosticResult) DiagnosticResult {
	return DiagnosticResult{
		CheckName:  r.CheckName,
		Status:     DiagnosticStatus(r.Status),
		Message:    r.Message,
		Details:    r.Details,
		ExecutedAt: r.ExecutedAt,
	}
}

