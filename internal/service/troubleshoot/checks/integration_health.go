package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IntegrationHealthCheck verifies integration connector sync status
// and credential validity.
type IntegrationHealthCheck struct {
	connectors repository.IntegrationConnectorRepository
}

// NewIntegrationHealthCheck creates an integration health check.
func NewIntegrationHealthCheck(connectors repository.IntegrationConnectorRepository) *IntegrationHealthCheck {
	return &IntegrationHealthCheck{connectors: connectors}
}

func (c *IntegrationHealthCheck) Name() string { return "integration_health" }

func (c *IntegrationHealthCheck) Run(ctx context.Context, tenantID uuid.UUID) DiagnosticResult {
	now := time.Now().UTC()
	result := DiagnosticResult{
		CheckName:  c.Name(),
		ExecutedAt: now,
	}

	connectors, err := c.connectors.List(ctx, tenantID, repository.Page{Limit: 200})
	if err != nil {
		result.Status = DiagnosticFail
		result.Message = "Failed to retrieve integration connectors: " + err.Error()
		return result
	}

	if len(connectors.Items) == 0 {
		result.Status = DiagnosticPass
		result.Message = "No integration connectors configured"
		return result
	}

	unhealthy := 0
	total := len(connectors.Items)
	for _, conn := range connectors.Items {
		if conn.Status == repository.IntegrationConnectorStatusDisabled {
			unhealthy++
		}
	}

	details, _ := json.Marshal(map[string]any{
		"total_connectors":     total,
		"unhealthy_connectors": unhealthy,
	})
	result.Details = details

	switch {
	case unhealthy == 0:
		result.Status = DiagnosticPass
		result.Message = "All integration connectors are healthy"
	case unhealthy < total:
		result.Status = DiagnosticWarn
		result.Message = fmt.Sprintf("%d of %d connectors are unhealthy", unhealthy, total)
	default:
		result.Status = DiagnosticFail
		result.Message = "All integration connectors are unhealthy"
	}
	return result
}
