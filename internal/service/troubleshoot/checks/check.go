package checks

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// maxDiagnosticPages bounds how many pages a diagnostic check will
// walk so a single check can never loop unbounded on a pathological
// tenant or a misbehaving repository cursor.
const maxDiagnosticPages = 10_000

// listAllDevices walks every page of devices for a tenant so checks
// evaluate the full fleet rather than only the first page.
func listAllDevices(ctx context.Context, repo repository.DeviceRepository, tenantID uuid.UUID, filter repository.DeviceListFilter) ([]repository.Device, error) {
	var out []repository.Device
	page := repository.Page{Limit: repository.MaxPageLimit}
	for i := 0; i < maxDiagnosticPages; i++ {
		res, err := repo.List(ctx, tenantID, filter, page)
		if err != nil {
			return nil, err
		}
		out = append(out, res.Items...)
		if res.NextCursor == "" {
			break
		}
		page.After = res.NextCursor
	}
	return out, nil
}

// listAllConnectors walks every page of integration connectors for a
// tenant so the integration-health check sees the full set.
func listAllConnectors(ctx context.Context, repo repository.IntegrationConnectorRepository, tenantID uuid.UUID) ([]repository.IntegrationConnector, error) {
	var out []repository.IntegrationConnector
	page := repository.Page{Limit: repository.MaxPageLimit}
	for i := 0; i < maxDiagnosticPages; i++ {
		res, err := repo.List(ctx, tenantID, page)
		if err != nil {
			return nil, err
		}
		out = append(out, res.Items...)
		if res.NextCursor == "" {
			break
		}
		page.After = res.NextCursor
	}
	return out, nil
}

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
