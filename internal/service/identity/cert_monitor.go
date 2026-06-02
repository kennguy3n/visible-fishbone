package identity

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultCertExpiryThreshold is the default window within which
// certificates are flagged as expiring soon.
const DefaultCertExpiryThreshold = 30 * 24 * time.Hour

// CertHealthSummary aggregates certificate health metrics for a tenant.
type CertHealthSummary struct {
	TenantID     uuid.UUID `json:"tenant_id"`
	Total        int       `json:"total"`
	Healthy      int       `json:"healthy"`
	ExpiringSoon int       `json:"expiring_soon"`
	Expired      int       `json:"expired"`
	Revoked      int       `json:"revoked"`
}

// ExpiringCert represents a certificate approaching expiry.
type ExpiringCert struct {
	DeviceID  uuid.UUID `json:"device_id"`
	CertID    uuid.UUID `json:"cert_id"`
	Serial    string    `json:"serial"`
	ExpiresAt time.Time `json:"expires_at"`
	DaysLeft  int       `json:"days_left"`
}

// CertRenewalStatus tracks whether a device has renewed after trigger.
type CertRenewalStatus struct {
	DeviceID       uuid.UUID  `json:"device_id"`
	Triggered      bool       `json:"triggered"`
	RenewedAfter   bool       `json:"renewed_after"`
	LastCertIssued *time.Time `json:"last_cert_issued,omitempty"`
}

// CertificateProvider abstracts read-only access to device certificates.
type CertificateProvider interface {
	ListCertificates(ctx context.Context, tenantID uuid.UUID) ([]repository.DeviceCertificate, error)
}

// EnrollmentProvider abstracts read-only access to device enrollments.
type EnrollmentProvider interface {
	ListEnrollments(ctx context.Context, tenantID uuid.UUID) ([]repository.DeviceEnrollment, error)
}

// CertMonitorService monitors certificate health across devices.
type CertMonitorService struct {
	certs     CertificateProvider
	enrolls   EnrollmentProvider
	logger    *slog.Logger
	nowFunc   func() time.Time
	threshold time.Duration
}

// NewCertMonitorService returns a ready-to-use certificate monitor.
func NewCertMonitorService(
	certs CertificateProvider,
	enrolls EnrollmentProvider,
	logger *slog.Logger,
) *CertMonitorService {
	if logger == nil {
		logger = slog.Default()
	}
	return &CertMonitorService{
		certs:     certs,
		enrolls:   enrolls,
		logger:    logger,
		nowFunc:   func() time.Time { return time.Now().UTC() },
		threshold: DefaultCertExpiryThreshold,
	}
}

// SetThreshold configures the expiry threshold window.
func (s *CertMonitorService) SetThreshold(d time.Duration) {
	if d > 0 {
		s.threshold = d
	}
}

// SetNowFunc overrides the clock for testing.
func (s *CertMonitorService) SetNowFunc(fn func() time.Time) {
	if fn != nil {
		s.nowFunc = fn
	}
}

// HealthSummary computes aggregate certificate health for a tenant.
func (s *CertMonitorService) HealthSummary(
	_ context.Context,
	tenantID uuid.UUID,
	certs []repository.DeviceCertificate,
) CertHealthSummary {
	now := s.nowFunc()
	threshold := now.Add(s.threshold)
	summary := CertHealthSummary{TenantID: tenantID}
	for _, c := range certs {
		if c.TenantID != tenantID {
			continue
		}
		summary.Total++
		if c.RevokedAt != nil {
			summary.Revoked++
			continue
		}
		switch {
		case now.After(c.ExpiresAt):
			summary.Expired++
		case threshold.After(c.ExpiresAt):
			summary.ExpiringSoon++
		default:
			summary.Healthy++
		}
	}
	return summary
}

// FindExpiring returns certificates expiring within the threshold window.
func (s *CertMonitorService) FindExpiring(
	_ context.Context,
	tenantID uuid.UUID,
	certs []repository.DeviceCertificate,
) []ExpiringCert {
	now := s.nowFunc()
	threshold := now.Add(s.threshold)
	var expiring []ExpiringCert
	for _, c := range certs {
		if c.TenantID != tenantID || c.RevokedAt != nil {
			continue
		}
		// threshold = now + window, so threshold.After(ExpiresAt) already
		// covers both already-expired and expiring-soon certificates.
		if threshold.After(c.ExpiresAt) {
			daysLeft := int(c.ExpiresAt.Sub(now).Hours() / 24)
			if daysLeft < 0 {
				daysLeft = 0
			}
			expiring = append(expiring, ExpiringCert{
				DeviceID:  c.DeviceID,
				CertID:    c.ID,
				Serial:    c.Serial,
				ExpiresAt: c.ExpiresAt,
				DaysLeft:  daysLeft,
			})
		}
	}
	return expiring
}

// CheckRenewalStatus checks if a device renewed its certificate
// after an expiry trigger.
func (s *CertMonitorService) CheckRenewalStatus(
	enrollment repository.DeviceEnrollment,
	certs []repository.DeviceCertificate,
) CertRenewalStatus {
	now := s.nowFunc()
	status := CertRenewalStatus{
		DeviceID:       enrollment.DeviceID,
		LastCertIssued: enrollment.LastCertIssuedAt,
	}

	// Check if any cert is expiring soon (trigger condition).
	for _, c := range certs {
		if c.DeviceID != enrollment.DeviceID || c.TenantID != enrollment.TenantID {
			continue
		}
		if c.RevokedAt != nil {
			continue
		}
		threshold := now.Add(s.threshold)
		if threshold.After(c.ExpiresAt) {
			status.Triggered = true
			break
		}
	}

	// Check if there's a recent cert issued after the trigger.
	if status.Triggered && enrollment.LastCertIssuedAt != nil {
		for _, c := range certs {
			if c.DeviceID != enrollment.DeviceID || c.TenantID != enrollment.TenantID {
				continue
			}
			if c.RevokedAt != nil {
				continue
			}
			if c.IssuedAt.After(*enrollment.LastCertIssuedAt) || c.IssuedAt.Equal(*enrollment.LastCertIssuedAt) {
				// A genuine renewal cert must itself be healthy: its expiry
				// is beyond the threshold window. This excludes the cert that
				// triggered the concern (whose expiry is within the window),
				// which would otherwise self-satisfy the check when its
				// IssuedAt equals LastCertIssuedAt (the single-cert case).
				if now.Add(s.threshold).Before(c.ExpiresAt) {
					status.RenewedAfter = true
					break
				}
			}
		}
	}
	return status
}
