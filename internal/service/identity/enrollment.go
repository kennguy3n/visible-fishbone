package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultCertTTL is the default short-lived mTLS certificate
// lifetime. Mirrors the sn360-security-platform mobile-compliance-
// receipt enrollment pattern.
const DefaultCertTTL = 24 * time.Hour

// EnrollmentService implements the claim-token device enrollment
// flow described in PROPOSAL.md §7 and ARCHITECTURE.md §3.4.
type EnrollmentService struct {
	enrollments repository.DeviceEnrollmentRepository
	tokens      repository.ClaimTokenRepository
	audit       repository.AuditLogRepository
	nowFunc     func() time.Time
	certTTL     time.Duration
}

// NewEnrollmentService returns a ready-to-use enrollment service.
func NewEnrollmentService(
	enrollments repository.DeviceEnrollmentRepository,
	tokens repository.ClaimTokenRepository,
	audit repository.AuditLogRepository,
) *EnrollmentService {
	return &EnrollmentService{
		enrollments: enrollments,
		tokens:      tokens,
		audit:       audit,
		nowFunc:     func() time.Time { return time.Now().UTC() },
		certTTL:     DefaultCertTTL,
	}
}

// EnrollmentResult is returned by RedeemClaimToken.
type EnrollmentResult struct {
	Enrollment  repository.DeviceEnrollment
	Certificate repository.DeviceCertificate
}

// RedeemClaimToken validates the claim token (single-use, short TTL),
// binds the Ed25519 public key to the device, registers the device
// enrollment, and returns a short-lived mTLS device certificate.
func (s *EnrollmentService) RedeemClaimToken(
	ctx context.Context,
	tenantID uuid.UUID,
	deviceID uuid.UUID,
	plaintextToken string,
	publicKey []byte,
) (EnrollmentResult, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return EnrollmentResult{}, fmt.Errorf("public key must be %d bytes (Ed25519): %w", ed25519.PublicKeySize, repository.ErrInvalidArgument)
	}

	now := s.nowFunc()

	// Validate and atomically consume the claim token.
	raw, err := base64.RawURLEncoding.DecodeString(plaintextToken)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("invalid claim token encoding: %w", repository.ErrInvalidArgument)
	}
	hash := sha256.Sum256(raw)
	if _, err := s.tokens.Redeem(ctx, tenantID, hash[:], now); err != nil {
		return EnrollmentResult{}, fmt.Errorf("claim token validation failed: %w", err)
	}
	enrollment := repository.DeviceEnrollment{
		DeviceID:   deviceID,
		TenantID:   tenantID,
		PublicKey:  publicKey,
		Status:     repository.EnrollmentStatusEnrolled,
		EnrolledAt: now,
	}

	saved, err := s.enrollments.CreateEnrollment(ctx, tenantID, enrollment)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("create enrollment: %w", err)
	}

	cert, err := s.issueCertificate(ctx, tenantID, deviceID, publicKey, now)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("issue certificate: %w", err)
	}

	return EnrollmentResult{
		Enrollment:  saved,
		Certificate: cert,
	}, nil
}

// RefreshCertificate issues a new short-lived certificate for an
// enrolled device. Validates the device is in active or enrolled state.
func (s *EnrollmentService) RefreshCertificate(
	ctx context.Context,
	tenantID uuid.UUID,
	deviceID uuid.UUID,
) (repository.DeviceCertificate, error) {
	enrollment, err := s.enrollments.GetEnrollment(ctx, tenantID, deviceID)
	if err != nil {
		return repository.DeviceCertificate{}, err
	}
	if enrollment.Status == repository.EnrollmentStatusRevoked {
		return repository.DeviceCertificate{}, fmt.Errorf("device is revoked: %w", repository.ErrForbidden)
	}

	now := s.nowFunc()
	cert, err := s.issueCertificate(ctx, tenantID, deviceID, enrollment.PublicKey, now)
	if err != nil {
		return repository.DeviceCertificate{}, fmt.Errorf("issue certificate: %w", err)
	}

	// Transition to active on first cert refresh if still enrolled.
	if enrollment.Status == repository.EnrollmentStatusEnrolled {
		_ = s.enrollments.UpdateEnrollmentStatus(ctx, tenantID, deviceID, repository.EnrollmentStatusActive)
	}

	return cert, nil
}

// RevokeDevice transitions a device to the revoked state and
// revokes all active certificates.
func (s *EnrollmentService) RevokeDevice(
	ctx context.Context,
	tenantID uuid.UUID,
	deviceID uuid.UUID,
) error {
	if err := s.enrollments.UpdateEnrollmentStatus(ctx, tenantID, deviceID, repository.EnrollmentStatusRevoked); err != nil {
		return fmt.Errorf("revoke enrollment: %w", err)
	}
	if err := s.enrollments.RevokeAllCertificates(ctx, tenantID, deviceID, s.nowFunc()); err != nil {
		return fmt.Errorf("revoke certificates: %w", err)
	}
	return nil
}

// GetEnrollmentStatus returns the current enrollment status for a device.
func (s *EnrollmentService) GetEnrollmentStatus(
	ctx context.Context,
	tenantID uuid.UUID,
	deviceID uuid.UUID,
) (repository.DeviceEnrollment, error) {
	return s.enrollments.GetEnrollment(ctx, tenantID, deviceID)
}

// issueCertificate generates a short-lived self-signed mTLS
// certificate binding the device's Ed25519 public key.
func (s *EnrollmentService) issueCertificate(
	ctx context.Context,
	tenantID uuid.UUID,
	deviceID uuid.UUID,
	publicKey []byte,
	now time.Time,
) (repository.DeviceCertificate, error) {
	// Generate an ephemeral CA key for signing. In production this
	// would be a persistent tenant CA; for the MVP we self-sign.
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return repository.DeviceCertificate{}, fmt.Errorf("generate CA key: %w", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return repository.DeviceCertificate{}, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   deviceID.String(),
			Organization: []string{tenantID.String()},
		},
		NotBefore: now,
		NotAfter:  now.Add(s.certTTL),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	devicePubKey := ed25519.PublicKey(publicKey)
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, devicePubKey, caPriv)
	if err != nil {
		return repository.DeviceCertificate{}, fmt.Errorf("create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	cert := repository.DeviceCertificate{
		ID:        uuid.New(),
		DeviceID:  deviceID,
		TenantID:  tenantID,
		Serial:    serialNumber.Text(16),
		CertPEM:   string(certPEM),
		IssuedAt:  now,
		ExpiresAt: now.Add(s.certTTL),
	}

	saved, err := s.enrollments.CreateCertificate(ctx, tenantID, cert)
	if err != nil {
		return repository.DeviceCertificate{}, err
	}

	// Update last_cert_issued_at on the enrollment record.
	_ = s.enrollments.UpdateLastCertIssuedAt(ctx, tenantID, deviceID, now)

	return saved, nil
}
