package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func newBindingService(t *testing.T) (*Service, repository.DeviceIdentityBindingRepository, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "Bind", Slug: "bind", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	bindings := memory.NewDeviceIdentityBindingRepository(s)
	svc := New(
		memory.NewDeviceRepository(s),
		memory.NewClaimTokenRepository(s),
		memory.NewAuditLogRepository(s),
		nil,
		WithDeviceIdentityBindings(bindings),
	)
	return svc, bindings, tn.ID
}

func TestRedeemClaimToken_BindsDeviceToIAMCoreUser(t *testing.T) {
	t.Parallel()
	svc, bindings, tid := newBindingService(t)

	gen, err := svc.GenerateClaimToken(context.Background(), tid, 0, nil)
	if err != nil {
		t.Fatalf("GenerateClaimToken: %v", err)
	}

	// Simulate an iam-core-authenticated enrollment by stamping an
	// iam-core identity on the request context.
	ctx := middleware.WithIAMCoreIdentityForTest(context.Background(), middleware.IAMCoreIdentity{
		Subject:     "iam-user-123",
		SNGTenantID: tid,
	})
	dev, err := svc.RedeemClaimToken(ctx, tid, gen.Plaintext, "Laptop", repository.DevicePlatformMacOS, "pubkey-abc", repository.Posture{})
	if err != nil {
		t.Fatalf("RedeemClaimToken: %v", err)
	}

	b, err := bindings.GetByDevice(context.Background(), tid, dev.ID)
	if err != nil {
		t.Fatalf("GetByDevice: %v", err)
	}
	if b.IAMCoreUserID != "iam-user-123" {
		t.Errorf("IAMCoreUserID = %q, want iam-user-123", b.IAMCoreUserID)
	}
	if b.Ed25519PublicKey != "pubkey-abc" {
		t.Errorf("Ed25519PublicKey = %q, want pubkey-abc", b.Ed25519PublicKey)
	}
}

func TestRedeemClaimToken_NoIAMCoreIdentity_NoBinding(t *testing.T) {
	t.Parallel()
	svc, bindings, tid := newBindingService(t)

	gen, err := svc.GenerateClaimToken(context.Background(), tid, 0, nil)
	if err != nil {
		t.Fatalf("GenerateClaimToken: %v", err)
	}
	// No iam-core identity on the context (legacy enrollment path).
	dev, err := svc.RedeemClaimToken(context.Background(), tid, gen.Plaintext, "Phone", repository.DevicePlatformIOS, "pubkey-xyz", repository.Posture{})
	if err != nil {
		t.Fatalf("RedeemClaimToken: %v", err)
	}
	if _, err := bindings.GetByDevice(context.Background(), tid, dev.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected no binding, got err=%v", err)
	}
}

func TestBindDeviceIdentity_UpsertAndList(t *testing.T) {
	t.Parallel()
	svc, bindings, tid := newBindingService(t)
	dev1 := uuid.New()
	dev2 := uuid.New()

	if err := svc.BindDeviceIdentity(context.Background(), tid, "iam-user-9", dev1, "k1"); err != nil {
		t.Fatalf("bind dev1: %v", err)
	}
	if err := svc.BindDeviceIdentity(context.Background(), tid, "iam-user-9", dev2, "k2"); err != nil {
		t.Fatalf("bind dev2: %v", err)
	}
	// Re-bind dev1 with a rotated key: must update, not duplicate.
	if err := svc.BindDeviceIdentity(context.Background(), tid, "iam-user-9", dev1, "k1-rotated"); err != nil {
		t.Fatalf("re-bind dev1: %v", err)
	}

	list, err := bindings.ListByIAMCoreUser(context.Background(), tid, "iam-user-9")
	if err != nil {
		t.Fatalf("ListByIAMCoreUser: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 bindings, got %d", len(list))
	}
	got, err := bindings.GetByDevice(context.Background(), tid, dev1)
	if err != nil {
		t.Fatalf("GetByDevice: %v", err)
	}
	if got.Ed25519PublicKey != "k1-rotated" {
		t.Errorf("key = %q, want k1-rotated (upsert should overwrite)", got.Ed25519PublicKey)
	}
}

func TestDeviceIdentityBinding_TenantIsolation(t *testing.T) {
	t.Parallel()
	svc, bindings, tid := newBindingService(t)
	other := uuid.New() // a different tenant id
	dev := uuid.New()

	if err := svc.BindDeviceIdentity(context.Background(), tid, "iam-user-1", dev, "k"); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// A different tenant must not see the binding.
	if _, err := bindings.GetByDevice(context.Background(), other, dev); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("cross-tenant read should be ErrNotFound, got %v", err)
	}
}

func TestBindDeviceIdentity_DisabledIsNoOp(t *testing.T) {
	t.Parallel()
	// Service constructed WITHOUT the bindings option.
	s := memory.NewStore()
	svc := New(memory.NewDeviceRepository(s), memory.NewClaimTokenRepository(s), memory.NewAuditLogRepository(s), nil)
	if err := svc.BindDeviceIdentity(context.Background(), uuid.New(), "u", uuid.New(), "k"); err != nil {
		t.Errorf("expected no-op nil, got %v", err)
	}
}
