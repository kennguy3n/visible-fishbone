package identity_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

func newSvc(t *testing.T) (*identity.Service, *memory.Store, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "Tenant", Slug: "tenant", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	svc := identity.New(
		memory.NewDeviceRepository(s),
		memory.NewClaimTokenRepository(s),
		memory.NewAuditLogRepository(s),
	)
	return svc, s, tn.ID
}

func TestGenerateAndRedeemClaimToken(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	ctx := context.Background()

	res, err := svc.GenerateClaimToken(ctx, tenantID, 0, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if res.Plaintext == "" {
		t.Fatal("plaintext empty")
	}
	if res.Token.ExpiresAt.IsZero() {
		t.Fatal("expires_at zero")
	}

	// Verify hash matches
	raw, err := base64.RawURLEncoding.DecodeString(res.Plaintext)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	h := sha256.Sum256(raw)
	if string(h[:]) != string(res.Token.TokenHash) {
		t.Errorf("hash mismatch")
	}

	dev, err := svc.RedeemClaimToken(ctx, tenantID, res.Plaintext, "laptop-1",
		repository.DevicePlatformMacOS, "ed25519-pub-base64", repository.Posture{})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if dev.Platform != repository.DevicePlatformMacOS || dev.Name != "laptop-1" {
		t.Errorf("device = %+v", dev)
	}
}

func TestRedeem_DoubleSpend(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	ctx := context.Background()
	res, err := svc.GenerateClaimToken(ctx, tenantID, time.Hour, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := svc.RedeemClaimToken(ctx, tenantID, res.Plaintext, "d1",
		repository.DevicePlatformIOS, "pk", repository.Posture{}); err != nil {
		t.Fatalf("first redeem: %v", err)
	}
	_, err = svc.RedeemClaimToken(ctx, tenantID, res.Plaintext, "d2",
		repository.DevicePlatformIOS, "pk2", repository.Posture{})
	if !errors.Is(err, repository.ErrForbidden) {
		t.Errorf("second redeem err = %v, want ErrForbidden", err)
	}
}

func TestRedeem_InvalidEncoding(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	_, err := svc.RedeemClaimToken(context.Background(), tenantID, "not!!base64",
		"d1", repository.DevicePlatformLinux, "pk", repository.Posture{})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v", err)
	}
}

func TestRedeem_UnknownToken(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	bogus := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	_, err := svc.RedeemClaimToken(context.Background(), tenantID, bogus,
		"d1", repository.DevicePlatformWindows, "pk", repository.Posture{})
	if !errors.Is(err, repository.ErrNotFound) && !errors.Is(err, repository.ErrForbidden) {
		t.Errorf("err = %v", err)
	}
}

func TestHeartbeatAndPosture(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newSvc(t)
	ctx := context.Background()
	res, _ := svc.GenerateClaimToken(ctx, tenantID, 0, nil)
	dev, err := svc.RedeemClaimToken(ctx, tenantID, res.Plaintext, "d", repository.DevicePlatformAndroid, "pk", repository.Posture{})
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}

	if err := svc.Heartbeat(ctx, tenantID, dev.ID); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	pTrue := true
	if err := svc.UpdatePosture(ctx, tenantID, dev.ID, repository.Posture{
		PasscodeSet:    &pTrue,
		BiometricReady: &pTrue,
	}); err != nil {
		t.Fatalf("posture: %v", err)
	}
}
