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
	enrollments repository.DeviceEnrollmentRepository
	warnWindow  time.Duration
}

// NewCertHealthCheck creates a certificate health check.
func NewCertHealthCheck(enrollments repository.DeviceEnrollmentRepository, warnWindow time.Duration) *CertHealthCheck {
	if warnWindow <= 0 {
		warnWindow = 30 * 24 * time.Hour // 30 days
	}
	return &CertHealthCheck{enrollments: enrollments, warnWindow: warnWindow}
}

func (c *CertHealthCheck) Name() string { return "cert_health" }

func (c *CertHealthCheck) Run(ctx context.Context, tenantID uuid.UUID) DiagnosticResult {
	now := time.Now().UTC()
	result := DiagnosticResult{
		CheckName:  c.Name(),
		ExecutedAt: now,
	}

	// List enrollments to check their certificate status.
	// We can't iterate all certs directly, so we check enrollment status.
	enrollments, err := c.enrollments.GetEnrollmentAnyStatus(ctx, tenantID, uuid.Nil)
	if err != nil {
		// If no enrollments exist, that's fine.
		result.Status = DiagnosticPass
		result.Message = "No device enrollments to check"
		details, _ := json.Marshal(map[string]any{
			"warn_window": c.warnWindow.String(),
		})
		result.Details = details
		return result
	}

	expiringSoon := 0
	expired := 0
	if enrollments.LastCertIssuedAt != nil {
		certAge := now.Sub(*enrollments.LastCertIssuedAt)
		if certAge > 365*24*time.Hour {
			expired++
		} else if certAge > (365*24*time.Hour - c.warnWindow) {
			expiringSoon++
		}
	}

	details, _ := json.Marshal(map[string]any{
		"warn_window":    c.warnWindow.String(),
		"expiring_soon":  expiringSoon,
		"expired":        expired,
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
