package checks

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// DiagnosticStatus enumerates the outcome of a diagnostic check.
type DiagnosticStatus string

const (
	DiagnosticPass DiagnosticStatus = "pass"
	DiagnosticFail DiagnosticStatus = "fail"
	DiagnosticWarn DiagnosticStatus = "warn"
)

// DiagnosticResult captures the outcome of a single diagnostic check.
type DiagnosticResult struct {
	CheckName  string           `json:"check_name"`
	Status     DiagnosticStatus `json:"status"`
	Message    string           `json:"message"`
	Details    json.RawMessage  `json:"details,omitempty"`
	ExecutedAt time.Time        `json:"executed_at"`
}

// DiagnosticCheck is the interface each check must implement.
type DiagnosticCheck interface {
	Name() string
	Run(ctx context.Context, tenantID uuid.UUID) DiagnosticResult
}
