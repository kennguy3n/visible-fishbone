package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
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
	logger      *slog.Logger
	nowFunc     func() time.Time
	certTTL     time.Duration
}

// NewEnrollmentService returns a ready-to-use enrollment service.
func NewEnrollmentService(
	enrollments repository.DeviceEnrollmentRepository,
	tokens repository.ClaimTokenRepository,
	audit repository.AuditLogRepository,
	logger *slog.Logger,
) *EnrollmentService {
	if logger == nil {
		logger = slog.Default()
	}
	return &EnrollmentService{
		enrollments: enrollments,
		tokens:      tokens,
		audit:       audit,
		logger:      logger,
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
		if unErr := s.tokens.UnredeemByHash(ctx, tenantID, hash[:]); unErr != nil {
			s.logger.Error("enrollment: failed to un-redeem token after enrollment creation failure",
				slog.Any("unredeemError", unErr),
				slog.Any("enrollmentError", err))
		}
		return EnrollmentResult{}, fmt.Errorf("create enrollment: %w", err)
	}

	cert, err := s.issueCertificate(ctx, tenantID, deviceID, publicKey, now)
	if err != nil {
		// Enrollment succeeded so the token stays consumed — the
		// device can recover via RefreshCertificate. Un-redeeming
		// here would leave an orphaned enrollment that blocks
		// retries with ErrConflict.
		s.logger.Error("enrollment: certificate issuance failed after enrollment created; device should use RefreshCertificate",
			slog.Any("error", err),
			slog.String("deviceID", deviceID.String()))
		return EnrollmentResult{}, fmt.Errorf("issue certificate: %w", err)
	}

	s.logAuditErr(s.appendAudit(ctx, tenantID, "device.enrollment.created", "device_enrollment", &deviceID, nil))

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

	s.logAuditErr(s.appendAudit(ctx, tenantID, "device.certificate.refreshed", "device_enrollment", &deviceID, nil))

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

	s.logAuditErr(s.appendAudit(ctx, tenantID, "device.enrollment.revoked", "device_enrollment", &deviceID, nil))

	return nil
}

// GetEnrollmentStatus returns the current enrollment status for a device,
// including revoked enrollments.
func (s *EnrollmentService) GetEnrollmentStatus(
	ctx context.Context,
	tenantID uuid.UUID,
	deviceID uuid.UUID,
) (repository.DeviceEnrollment, error) {
	return s.enrollments.GetEnrollmentAnyStatus(ctx, tenantID, deviceID)
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
	// Generate an ephemeral CA key pair. In production this would be
	// a persistent tenant CA; for the MVP we create a per-issuance CA
	// so the resulting certificate chain is cryptographically valid.
	caPub, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return repository.DeviceCertificate{}, fmt.Errorf("generate CA key: %w", err)
	}

	caSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return repository.DeviceCertificate{}, fmt.Errorf("generate CA serial: %w", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "SNG Ephemeral CA - " + tenantID.String(),
			Organization: []string{tenantID.String()},
		},
		NotBefore:             now,
		NotAfter:              now.Add(s.certTTL),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	// Self-sign the CA certificate (caPub signs with caPriv).
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caPriv)
	if err != nil {
		return repository.DeviceCertificate{}, fmt.Errorf("create CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return repository.DeviceCertificate{}, fmt.Errorf("parse CA certificate: %w", err)
	}

	deviceSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return repository.DeviceCertificate{}, fmt.Errorf("generate device serial: %w", err)
	}

	deviceTemplate := &x509.Certificate{
		SerialNumber: deviceSerial,
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

	// Sign the device cert with the CA (parent = caCert, signer = caPriv).
	devicePubKey := ed25519.PublicKey(publicKey)
	deviceCertDER, err := x509.CreateCertificate(rand.Reader, deviceTemplate, caCert, devicePubKey, caPriv)
	if err != nil {
		return repository.DeviceCertificate{}, fmt.Errorf("create device certificate: %w", err)
	}

	// PEM chain: device cert followed by CA cert for verification.
	var certChain []byte
	certChain = append(certChain, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: deviceCertDER,
	})...)
	certChain = append(certChain, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCertDER,
	})...)

	cert := repository.DeviceCertificate{
		ID:        uuid.New(),
		DeviceID:  deviceID,
		TenantID:  tenantID,
		Serial:    deviceSerial.Text(16),
		CertPEM:   string(certChain),
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

func (s *EnrollmentService) appendAudit(
	ctx context.Context,
	tenantID uuid.UUID,
	action, resourceType string,
	resourceID *uuid.UUID,
	details json.RawMessage,
) error {
	if details == nil {
		details = json.RawMessage(`{}`)
	}
	details = middleware.EnrichAuditDetails(ctx, details)
	_, err := s.audit.Append(ctx, tenantID, repository.AuditEntry{
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	})
	return err
}

func (s *EnrollmentService) logAuditErr(err error) {
	if err != nil {
		s.logger.Warn("enrollment: audit append failed", slog.Any("error", err))
	}
}
