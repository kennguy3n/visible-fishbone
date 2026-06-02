package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func newEnrollmentService(t *testing.T) (*EnrollmentService, uuid.UUID, repository.ClaimTokenRepository) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "Enrollment Test", Slug: "enroll-test", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tokens := memory.NewClaimTokenRepository(s)
	svc := NewEnrollmentService(
		memory.NewDeviceEnrollmentRepository(s),
		tokens,
		memory.NewAuditLogRepository(s),
	)
	return svc, tn.ID, tokens
}

func seedClaimToken(t *testing.T, tokens repository.ClaimTokenRepository, tenantID uuid.UUID) string {
	t.Helper()
	plainBytes := make([]byte, 32)
	if _, err := rand.Read(plainBytes); err != nil {
		t.Fatalf("generate claim token bytes: %v", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(plainBytes)
	hash := sha256.Sum256(plainBytes)
	_, err := tokens.Create(context.Background(), tenantID, repository.ClaimToken{
		ID:        uuid.New(),
		TenantID:  tenantID,
		TokenHash: hash[:],
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("seed claim token: %v", err)
	}
	return plaintext
}

func generateEd25519PublicKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	return pub
}

func TestRedeemClaimToken(t *testing.T) {
	t.Parallel()
	svc, tid, tokens := newEnrollmentService(t)
	deviceID := uuid.New()
	pubKey := generateEd25519PublicKey(t)
	token := seedClaimToken(t, tokens, tid)

	result, err := svc.RedeemClaimToken(context.Background(), tid, deviceID, token, pubKey)
	if err != nil {
		t.Fatalf("RedeemClaimToken: %v", err)
	}
	if result.Enrollment.DeviceID != deviceID {
		t.Errorf("deviceID = %s, want %s", result.Enrollment.DeviceID, deviceID)
	}
	if result.Enrollment.Status != repository.EnrollmentStatusEnrolled {
		t.Errorf("status = %s, want enrolled", result.Enrollment.Status)
	}
	if result.Certificate.CertPEM == "" {
		t.Error("expected non-empty certificate PEM")
	}
	if result.Certificate.Serial == "" {
		t.Error("expected non-empty serial number")
	}
}

func TestRedeemClaimTokenInvalidKeySize(t *testing.T) {
	t.Parallel()
	svc, tid, tokens := newEnrollmentService(t)
	token := seedClaimToken(t, tokens, tid)
	_, err := svc.RedeemClaimToken(context.Background(), tid, uuid.New(), token, []byte("too-short"))
	if err == nil {
		t.Fatal("expected error for invalid key size")
	}
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("expected ErrInvalidArgument, got %v", err)
	}
}

func TestRedeemClaimTokenDuplicate(t *testing.T) {
	t.Parallel()
	svc, tid, tokens := newEnrollmentService(t)
	deviceID := uuid.New()
	pubKey := generateEd25519PublicKey(t)
	token1 := seedClaimToken(t, tokens, tid)

	_, err := svc.RedeemClaimToken(context.Background(), tid, deviceID, token1, pubKey)
	if err != nil {
		t.Fatalf("first RedeemClaimToken: %v", err)
	}
	token2 := seedClaimToken(t, tokens, tid)
	_, err = svc.RedeemClaimToken(context.Background(), tid, deviceID, token2, pubKey)
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("expected ErrConflict for duplicate enrollment, got %v", err)
	}
}

func TestRefreshCertificate(t *testing.T) {
	t.Parallel()
	svc, tid, tokens := newEnrollmentService(t)
	deviceID := uuid.New()
	pubKey := generateEd25519PublicKey(t)
	token := seedClaimToken(t, tokens, tid)

	_, err := svc.RedeemClaimToken(context.Background(), tid, deviceID, token, pubKey)
	if err != nil {
		t.Fatalf("RedeemClaimToken: %v", err)
	}

	cert, err := svc.RefreshCertificate(context.Background(), tid, deviceID)
	if err != nil {
		t.Fatalf("RefreshCertificate: %v", err)
	}
	if cert.CertPEM == "" {
		t.Error("expected non-empty certificate PEM from refresh")
	}

	// After refresh, enrollment should transition to active.
	e, err := svc.GetEnrollmentStatus(context.Background(), tid, deviceID)
	if err != nil {
		t.Fatalf("GetEnrollmentStatus: %v", err)
	}
	if e.Status != repository.EnrollmentStatusActive {
		t.Errorf("status = %s, want active", e.Status)
	}
}

func TestRevokeDevice(t *testing.T) {
	t.Parallel()
	svc, tid, tokens := newEnrollmentService(t)
	deviceID := uuid.New()
	pubKey := generateEd25519PublicKey(t)
	token := seedClaimToken(t, tokens, tid)

	_, err := svc.RedeemClaimToken(context.Background(), tid, deviceID, token, pubKey)
	if err != nil {
		t.Fatalf("RedeemClaimToken: %v", err)
	}

	if err := svc.RevokeDevice(context.Background(), tid, deviceID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}

	// RefreshCertificate on revoked device should fail.
	_, err = svc.RefreshCertificate(context.Background(), tid, deviceID)
	if err == nil {
		t.Fatal("expected error refreshing cert for revoked device")
	}
}

func TestGetEnrollmentStatus(t *testing.T) {
	t.Parallel()
	svc, tid, tokens := newEnrollmentService(t)
	deviceID := uuid.New()
	pubKey := generateEd25519PublicKey(t)
	token := seedClaimToken(t, tokens, tid)

	_, err := svc.RedeemClaimToken(context.Background(), tid, deviceID, token, pubKey)
	if err != nil {
		t.Fatalf("RedeemClaimToken: %v", err)
	}

	e, err := svc.GetEnrollmentStatus(context.Background(), tid, deviceID)
	if err != nil {
		t.Fatalf("GetEnrollmentStatus: %v", err)
	}
	if e.Status != repository.EnrollmentStatusEnrolled {
		t.Errorf("status = %s, want enrolled", e.Status)
	}
	if e.DeviceID != deviceID {
		t.Errorf("deviceID = %s, want %s", e.DeviceID, deviceID)
	}
}

func TestDeviceLifecycleStateMachine(t *testing.T) {
	t.Parallel()
	svc, tid, tokens := newEnrollmentService(t)
	deviceID := uuid.New()
	pubKey := generateEd25519PublicKey(t)
	token := seedClaimToken(t, tokens, tid)

	// Step 1: Enroll → enrolled.
	_, err := svc.RedeemClaimToken(context.Background(), tid, deviceID, token, pubKey)
	if err != nil {
		t.Fatalf("RedeemClaimToken: %v", err)
	}
	e, _ := svc.GetEnrollmentStatus(context.Background(), tid, deviceID)
	if e.Status != repository.EnrollmentStatusEnrolled {
		t.Fatalf("step 1: status = %s, want enrolled", e.Status)
	}

	// Step 2: RefreshCert → active (first mTLS handshake equivalent).
	_, err = svc.RefreshCertificate(context.Background(), tid, deviceID)
	if err != nil {
		t.Fatalf("RefreshCertificate: %v", err)
	}
	e, _ = svc.GetEnrollmentStatus(context.Background(), tid, deviceID)
	if e.Status != repository.EnrollmentStatusActive {
		t.Fatalf("step 2: status = %s, want active", e.Status)
	}

	// Step 3: Revoke → revoked.
	if err := svc.RevokeDevice(context.Background(), tid, deviceID); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	e, err = svc.GetEnrollmentStatus(context.Background(), tid, deviceID)
	if err != nil {
		t.Fatalf("step 3: GetEnrollmentStatus after revoke: %v", err)
	}
	if e.Status != repository.EnrollmentStatusRevoked {
		t.Errorf("step 3: status = %s, want revoked", e.Status)
	}
}
