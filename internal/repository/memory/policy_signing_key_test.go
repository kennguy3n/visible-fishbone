package memory_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func seedSigningKeyTenant(t *testing.T) (*memory.Store, repository.Tenant) {
	t.Helper()
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	tnt, err := tr.Create(ctx(), repository.Tenant{
		Name: "A", Slug: "a", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return s, tnt
}

func makeKey(keyID string) repository.PolicySigningKey {
	pub := make([]byte, 32)
	priv := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i)
		priv[i] = byte(i + 1)
	}
	return repository.PolicySigningKey{
		KeyID:     keyID,
		Algorithm: "ed25519",
		PublicKey: pub, PrivateKey: priv,
		Status: repository.PolicySigningKeyStatusActive,
	}
}

func TestSigningKey_Create_RejectsSecondActive(t *testing.T) {
	s, tnt := seedSigningKeyTenant(t)
	repo := memory.NewPolicySigningKeyRepository(s)
	if _, err := repo.Create(ctx(), tnt.ID, makeKey("k1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	_, err := repo.Create(ctx(), tnt.ID, makeKey("k2"))
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("expected ErrConflict for second active, got %v", err)
	}
}

func TestSigningKey_Create_RejectsDuplicateKeyID(t *testing.T) {
	s, tnt := seedSigningKeyTenant(t)
	repo := memory.NewPolicySigningKeyRepository(s)
	if _, err := repo.Create(ctx(), tnt.ID, makeKey("k1")); err != nil {
		t.Fatalf("first: %v", err)
	}
	// Rotate the first so we can attempt a second create with the
	// same key_id (which is what should conflict).
	if _, err := repo.Rotate(ctx(), tnt.ID, makeKey("k2"), time.Time{}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	dup := makeKey("k1") // re-using k1
	dup.Status = repository.PolicySigningKeyStatusActive
	// Now there's already one active (k2). To isolate the
	// key_id-conflict path, we revoke k2 first.
	if _, err := repo.Revoke(ctx(), tnt.ID, "k2", time.Time{}); err != nil {
		t.Fatalf("revoke k2: %v", err)
	}
	_, err := repo.Create(ctx(), tnt.ID, dup)
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("expected ErrConflict on duplicate key_id, got %v", err)
	}
}

func TestSigningKey_GetActive_FindsExactlyOne(t *testing.T) {
	s, tnt := seedSigningKeyTenant(t)
	repo := memory.NewPolicySigningKeyRepository(s)
	if _, err := repo.Create(ctx(), tnt.ID, makeKey("k1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := repo.GetActive(ctx(), tnt.ID)
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if got.KeyID != "k1" {
		t.Errorf("active key: %q", got.KeyID)
	}
}

func TestSigningKey_GetActive_NotFoundWhenAllRotated(t *testing.T) {
	s, tnt := seedSigningKeyTenant(t)
	repo := memory.NewPolicySigningKeyRepository(s)
	if _, err := repo.Create(ctx(), tnt.ID, makeKey("k1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := repo.Revoke(ctx(), tnt.ID, "k1", time.Time{}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, err := repo.GetActive(ctx(), tnt.ID)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSigningKey_Rotate_AtomicTransition(t *testing.T) {
	s, tnt := seedSigningKeyTenant(t)
	repo := memory.NewPolicySigningKeyRepository(s)
	if _, err := repo.Create(ctx(), tnt.ID, makeKey("k1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	at := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	rotated, err := repo.Rotate(ctx(), tnt.ID, makeKey("k2"), at)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated.KeyID != "k2" || rotated.Status != repository.PolicySigningKeyStatusActive {
		t.Errorf("rotate result: %+v", rotated)
	}
	old, err := repo.GetByKeyID(ctx(), tnt.ID, "k1")
	if err != nil {
		t.Fatalf("get k1: %v", err)
	}
	if old.Status != repository.PolicySigningKeyStatusRotated {
		t.Errorf("k1 status post-rotate: %q", old.Status)
	}
	if old.RotatedAt == nil || !old.RotatedAt.Equal(at) {
		t.Errorf("k1 RotatedAt: %v, want %v", old.RotatedAt, at)
	}
}

func TestSigningKey_Rotate_RejectsWhenNoActive(t *testing.T) {
	s, tnt := seedSigningKeyTenant(t)
	repo := memory.NewPolicySigningKeyRepository(s)
	_, err := repo.Rotate(ctx(), tnt.ID, makeKey("k1"), time.Time{})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("expected ErrNotFound when no active key, got %v", err)
	}
}

func TestSigningKey_Revoke_TransitionsToRevoked(t *testing.T) {
	s, tnt := seedSigningKeyTenant(t)
	repo := memory.NewPolicySigningKeyRepository(s)
	if _, err := repo.Create(ctx(), tnt.ID, makeKey("k1")); err != nil {
		t.Fatalf("create: %v", err)
	}
	at := time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC)
	revoked, err := repo.Revoke(ctx(), tnt.ID, "k1", at)
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if revoked.Status != repository.PolicySigningKeyStatusRevoked {
		t.Errorf("status: %q", revoked.Status)
	}
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(at) {
		t.Errorf("RevokedAt: %v", revoked.RevokedAt)
	}
	// Re-revoking already-revoked is a not-found.
	_, err = repo.Revoke(ctx(), tnt.ID, "k1", at)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("double revoke: want ErrNotFound, got %v", err)
	}
}

func TestSigningKey_List_OrdersByActivatedAtDesc(t *testing.T) {
	s, tnt := seedSigningKeyTenant(t)
	repo := memory.NewPolicySigningKeyRepository(s)
	k1 := makeKey("k1")
	k1.ActivatedAt = time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := repo.Create(ctx(), tnt.ID, k1); err != nil {
		t.Fatalf("k1: %v", err)
	}
	k2 := makeKey("k2")
	k2.ActivatedAt = time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)
	if _, err := repo.Rotate(ctx(), tnt.ID, k2, k2.ActivatedAt); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	keys, err := repo.List(ctx(), tnt.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
	if keys[0].KeyID != "k2" || keys[1].KeyID != "k1" {
		t.Errorf("order: want [k2, k1], got [%s, %s]", keys[0].KeyID, keys[1].KeyID)
	}
}

func TestSigningKey_RejectsUnknownTenant(t *testing.T) {
	s, _ := seedSigningKeyTenant(t)
	repo := memory.NewPolicySigningKeyRepository(s)
	// Use a different tenant id that hasn't been created.
	other, _ := memory.NewTenantRepository(s).Create(ctx(), repository.Tenant{
		Name: "B", Slug: "b", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if _, err := repo.Create(ctx(), other.ID, makeKey("k1")); err != nil {
		t.Fatalf("seed other: %v", err)
	}
	// Cross-tenant GetActive must return ErrNotFound: tenant B's
	// key shouldn't surface for tenant A.
	a, _ := memory.NewTenantRepository(s).Create(ctx(), repository.Tenant{
		Name: "C", Slug: "c", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	_, err := repo.GetActive(ctx(), a.ID)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("cross-tenant get: want ErrNotFound, got %v", err)
	}
}
