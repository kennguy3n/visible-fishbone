package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ConnectivityCheck verifies edge/agent connectivity to the control
// plane by checking last heartbeat timestamps.
type ConnectivityCheck struct {
	devices   repository.DeviceRepository
	threshold time.Duration
}

// NewConnectivityCheck creates a connectivity check. The threshold
// determines how long since last heartbeat before flagging an issue.
func NewConnectivityCheck(devices repository.DeviceRepository, threshold time.Duration) *ConnectivityCheck {
	if threshold <= 0 {
		threshold = 5 * time.Minute
	}
	return &ConnectivityCheck{devices: devices, threshold: threshold}
}

func (c *ConnectivityCheck) Name() string { return "connectivity" }

func (c *ConnectivityCheck) Run(ctx context.Context, tenantID uuid.UUID) DiagnosticResult {
	now := time.Now().UTC()
	result := DiagnosticResult{
		CheckName:  c.Name(),
		ExecutedAt: now,
	}

	devices, err := c.devices.List(ctx, tenantID, repository.DeviceListFilter{}, repository.Page{Limit: 200})
	if err != nil {
		result.Status = DiagnosticFail
		result.Message = "Failed to retrieve device list: " + err.Error()
		return result
	}

	if len(devices.Items) == 0 {
		result.Status = DiagnosticPass
		result.Message = "No devices registered"
		return result
	}

	stale := 0
	total := len(devices.Items)
	for _, d := range devices.Items {
		if d.LastSeenAt != nil && now.Sub(*d.LastSeenAt) > c.threshold {
			stale++
		} else if d.LastSeenAt == nil {
			stale++
		}
	}

	details, _ := json.Marshal(map[string]any{
		"total_devices": total,
		"stale_devices": stale,
		"threshold":     c.threshold.String(),
	})
	result.Details = details

	switch {
	case stale == 0:
		result.Status = DiagnosticPass
		result.Message = "All devices have recent heartbeats"
	case stale < total:
		result.Status = DiagnosticWarn
		result.Message = fmt.Sprintf("%d of %d devices have stale heartbeats", stale, total)
	default:
		result.Status = DiagnosticFail
		result.Message = "All devices have stale or missing heartbeats"
	}
	return result
}
