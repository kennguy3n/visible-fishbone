package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PerformanceCheck checks telemetry pipeline lag by comparing
// expected vs actual event flow from device heartbeats.
type PerformanceCheck struct {
	devices      repository.DeviceRepository
	lagThreshold time.Duration
}

// NewPerformanceCheck creates a performance diagnostic check.
func NewPerformanceCheck(devices repository.DeviceRepository, lagThreshold time.Duration) *PerformanceCheck {
	if lagThreshold <= 0 {
		lagThreshold = 10 * time.Minute
	}
	return &PerformanceCheck{devices: devices, lagThreshold: lagThreshold}
}

func (c *PerformanceCheck) Name() string { return "performance" }

func (c *PerformanceCheck) Run(ctx context.Context, tenantID uuid.UUID) DiagnosticResult {
	now := time.Now().UTC()
	result := DiagnosticResult{
		CheckName:  c.Name(),
		ExecutedAt: now,
	}

	devices, err := listAllDevices(ctx, c.devices, tenantID, repository.DeviceListFilter{})
	if err != nil {
		result.Status = DiagnosticFail
		result.Message = "Failed to retrieve device data: " + err.Error()
		return result
	}

	if len(devices) == 0 {
		result.Status = DiagnosticPass
		result.Message = "No devices to measure pipeline lag"
		return result
	}

	lagging := 0
	total := len(devices)
	for _, d := range devices {
		if d.LastSeenAt != nil && now.Sub(*d.LastSeenAt) > c.lagThreshold {
			lagging++
		}
	}

	details, _ := json.Marshal(map[string]any{
		"total_devices":   total,
		"lagging_devices": lagging,
		"lag_threshold":   c.lagThreshold.String(),
	})
	result.Details = details

	switch {
	case lagging == 0:
		result.Status = DiagnosticPass
		result.Message = "Telemetry pipeline within expected latency"
	case lagging < total/2:
		result.Status = DiagnosticWarn
		result.Message = fmt.Sprintf("%d of %d devices showing telemetry lag", lagging, total)
	default:
		result.Status = DiagnosticFail
		result.Message = fmt.Sprintf("%d of %d devices showing significant telemetry lag", lagging, total)
	}
	return result
}
