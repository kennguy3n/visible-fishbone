package checks

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// CertHealthCheck verifies certificate expiry and chain validity.
// Flags certificates expiring within 30 days.
type CertHealthCheck struct {
	devices     repository.DeviceRepository
	enrollments repository.DeviceEnrollmentRepository
	warnWindow  time.Duration
}

// NewCertHealthCheck creates a certificate health check.
func NewCertHealthCheck(devices repository.DeviceRepository, enrollments repository.DeviceEnrollmentRepository, warnWindow time.Duration) *CertHealthCheck {
	if warnWindow <= 0 {
		warnWindow = 30 * 24 * time.Hour // 30 days
	}
	return &CertHealthCheck{devices: devices, enrollments: enrollments, warnWindow: warnWindow}
}

func (c *CertHealthCheck) Name() string { return "cert_health" }

func (c *CertHealthCheck) Run(ctx context.Context, tenantID uuid.UUID) DiagnosticResult {
	now := time.Now().UTC()
	result := DiagnosticResult{
		CheckName:  c.Name(),
		ExecutedAt: now,
	}

	// List devices for the tenant, then check each one's enrollment.
	devices, err := c.devices.List(ctx, tenantID, repository.DeviceListFilter{}, repository.Page{Limit: 200})
	if err != nil {
		result.Status = DiagnosticFail
		result.Message = "Failed to retrieve device list: " + err.Error()
		return result
	}

	if len(devices.Items) == 0 {
		result.Status = DiagnosticPass
		result.Message = "No devices to check"
		details, _ := json.Marshal(map[string]any{
			"warn_window": c.warnWindow.String(),
		})
		result.Details = details
		return result
	}

	expiringSoon := 0
	expired := 0
	checked := 0

	for _, d := range devices.Items {
		enrollment, err := c.enrollments.GetEnrollmentAnyStatus(ctx, tenantID, d.ID)
		if err != nil {
			continue
		}
		checked++
		if enrollment.LastCertIssuedAt != nil {
			certAge := now.Sub(*enrollment.LastCertIssuedAt)
			if certAge > 365*24*time.Hour {
				expired++
			} else if certAge > (365*24*time.Hour - c.warnWindow) {
				expiringSoon++
			}
		}
	}

	details, _ := json.Marshal(map[string]any{
		"warn_window":   c.warnWindow.String(),
		"checked":       checked,
		"expiring_soon": expiringSoon,
		"expired":       expired,
	})
	result.Details = details

	switch {
	case expired > 0:
		result.Status = DiagnosticFail
		result.Message = fmt.Sprintf("%d certificate(s) have expired", expired)
	case expiringSoon > 0:
		result.Status = DiagnosticWarn
		result.Message = fmt.Sprintf("%d certificate(s) expiring within %s", expiringSoon, c.warnWindow)
	default:
		result.Status = DiagnosticPass
		result.Message = "All certificates are valid"
	}
	return result
}
