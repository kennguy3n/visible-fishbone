package policy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func newTestKeyService(t *testing.T) (*KeyService, *memory.Store, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	keyRepo := memory.NewPolicySigningKeyRepository(s)
	auditRepo := memory.NewAuditLogRepository(s)
	tenantRepo := memory.NewTenantRepository(s)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return NewKeyService(keyRepo, auditRepo), s, tnt.ID
}

func TestKeyService_CreateInitial_ProducesActiveEd25519(t *testing.T) {
	t.Parallel()
	svc, _, tid := newTestKeyService(t)
	k, err := svc.CreateInitial(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if k.Algorithm != "ed25519" {
		t.Errorf("algorithm: %q", k.Algorithm)
	}
	if k.Status != repository.PolicySigningKeyStatusActive {
		t.Errorf("status: %q", k.Status)
	}
	if len(k.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("public key size: %d", len(k.PublicKey))
	}
}

func TestKeyService_CreateInitial_ConflictsOnSecondCall(t *testing.T) {
	t.Parallel()
	svc, _, tid := newTestKeyService(t)
	if _, err := svc.CreateInitial(context.Background(), tid, nil); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := svc.CreateInitial(context.Background(), tid, nil)
	if !errors.Is(err, repository.ErrConflict) {
		t.Errorf("second create: want ErrConflict, got %v", err)
	}
}

func TestKeyService_GetActive_NoLazyCreate(t *testing.T) {
	t.Parallel()
	svc, _, tid := newTestKeyService(t)
	if _, err := svc.GetActive(context.Background(), tid); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("want ErrNotFound on fresh tenant, got %v", err)
	}
	// After explicit provisioning, GetActive returns the key.
	created, err := svc.CreateInitial(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	active, err := svc.GetActive(context.Background(), tid)
	if err != nil {
		t.Fatalf("get active post-create: %v", err)
	}
	if active.KeyID != created.KeyID {
		t.Errorf("want %q, got %q", created.KeyID, active.KeyID)
	}
}

// TestKeyService_EnsureKey_BrandNewTenant covers the
// first-compile-on-fresh-tenant bootstrap path: EnsureKey
// auto-provisions when the tenant has never had any signing key.
func TestKeyService_EnsureKey_BrandNewTenant(t *testing.T) {
	t.Parallel()
	svc, _, tid := newTestKeyService(t)
	if err := svc.EnsureKey(context.Background(), tid); err != nil {
		t.Fatalf("ensure (brand-new): %v", err)
	}
	// Idempotent: second call doesn't create a duplicate.
	if err := svc.EnsureKey(context.Background(), tid); err != nil {
		t.Fatalf("ensure (idempotent): %v", err)
	}
	keys, err := svc.List(context.Background(), tid)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("want 1 key after idempotent ensures, got %d", len(keys))
	}
}

// TestKeyService_EnsureKey_RefusesAfterRevocation is the
// load-bearing invariant: EnsureKey must NOT auto-provision when
// the tenant has historical keys but none active. Revoking the
// active key must halt compilation until an admin explicitly
// rotates — otherwise the revocation-incident escape hatch
// silently re-opens itself on the next compile request.
func TestKeyService_EnsureKey_RefusesAfterRevocation(t *testing.T) {
	t.Parallel()
	svc, _, tid := newTestKeyService(t)
	k, err := svc.CreateInitial(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.Revoke(context.Background(), tid, nil, k.KeyID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	err = svc.EnsureKey(context.Background(), tid)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("want ErrNotFound after revocation, got %v", err)
	}
	keys, err := svc.List(context.Background(), tid)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("EnsureKey lazy-created a replacement after revocation: %d keys", len(keys))
	}
}

func TestKeyService_Rotate_ReplacesActive(t *testing.T) {
	t.Parallel()
	svc, _, tid := newTestKeyService(t)
	first, err := svc.CreateInitial(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := svc.Rotate(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if first.KeyID == second.KeyID {
		t.Errorf("rotate returned same key id")
	}
	active, err := svc.GetActive(context.Background(), tid)
	if err != nil {
		t.Fatalf("get active: %v", err)
	}
	if active.KeyID != second.KeyID {
		t.Errorf("active key id: want %q, got %q", second.KeyID, active.KeyID)
	}
	// Old key is preserved with status='rotated' so receivers
	// holding pre-rotation bundles can still verify them.
	old, err := svc.GetByKeyID(context.Background(), tid, first.KeyID)
	if err != nil {
		t.Fatalf("get old: %v", err)
	}
	if old.Status != repository.PolicySigningKeyStatusRotated {
		t.Errorf("old status: %q", old.Status)
	}
	if old.RotatedAt == nil {
		t.Errorf("RotatedAt: nil")
	}
}

// TestKeyService_Revoke_PreventsSigning is the security-critical
// invariant for the revocation-incident response: after the admin
// revokes the active key, Sign MUST return ErrNotFound until a new
// key is explicitly provisioned. Before this was fixed, Sign
// lazy-created a fresh key via GetActive and happily proceeded,
// silently bypassing the incident response.
func TestKeyService_Revoke_PreventsSigning(t *testing.T) {
	t.Parallel()
	svc, _, tid := newTestKeyService(t)
	k, err := svc.CreateInitial(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.Revoke(context.Background(), tid, nil, k.KeyID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	_, _, err = svc.Sign(context.Background(), tid, []byte("payload"))
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("want ErrNotFound after revocation, got %v", err)
	}
	// Sanity: an explicit admin Rotate restores signing.
	newKey, err := svc.CreateInitial(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("recreate initial post-revoke: %v", err)
	}
	_, kid, err := svc.Sign(context.Background(), tid, []byte("payload"))
	if err != nil {
		t.Fatalf("sign post-recovery: %v", err)
	}
	if kid != newKey.KeyID {
		t.Errorf("sign returned wrong key id: %q vs %q", kid, newKey.KeyID)
	}
	if kid == k.KeyID {
		t.Errorf("sign reused revoked key id %q", kid)
	}
}

func TestKeyService_Sign_VerifiesAgainstPublicKey(t *testing.T) {
	t.Parallel()
	svc, _, tid := newTestKeyService(t)
	k, err := svc.CreateInitial(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	payload := []byte("the quick brown fox jumps over the lazy dog")
	sig, keyID, err := svc.Sign(context.Background(), tid, payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if keyID != k.KeyID {
		t.Errorf("key id mismatch: %q vs %q", keyID, k.KeyID)
	}
	if !ed25519.Verify(ed25519.PublicKey(k.PublicKey), payload, sig) {
		t.Errorf("ed25519 verification failed — signature did not match public key")
	}
}

func TestKeyService_List_OrdersByActivatedAtDesc(t *testing.T) {
	t.Parallel()
	svc, s, tid := newTestKeyService(t)
	// Deterministic clock so the ActivatedAt timestamps differ
	// by a clearly increasing amount.
	t0 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	step := time.Hour
	idx := 0
	s.SetClock(func() time.Time {
		now := t0.Add(time.Duration(idx) * step)
		idx++
		return now
	})
	if _, err := svc.CreateInitial(context.Background(), tid, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := svc.Rotate(context.Background(), tid, nil); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	keys, err := svc.List(context.Background(), tid)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("want 2 keys, got %d", len(keys))
	}
	if !keys[0].ActivatedAt.After(keys[1].ActivatedAt) {
		t.Errorf("list not ordered by activated_at DESC: %v", keys)
	}
}

func TestPassthroughWrapper(t *testing.T) {
	t.Parallel()
	w := PassthroughWrapper{}
	seed := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := w.Wrap(context.Background(), uuid.New(), seed)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if string(wrapped) != string(seed) {
		t.Errorf("wrap modified seed")
	}
	unwrapped, err := w.Unwrap(context.Background(), uuid.New(), wrapped)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(unwrapped) != string(seed) {
		t.Errorf("roundtrip mismatch")
	}
}

// TestPolicySigningKey_JSONMarshalOmitsPrivateKey is the
// defence-in-depth check pinning the `json:"-"` tag on
// `repository.PolicySigningKey.PrivateKey`. Handlers project to
// `PolicySigningKeyResponse` today, but a future refactor that
// accidentally passes the raw struct through `WriteJSON` /
// `json.Marshal` must NOT leak the seed onto the wire. This test
// is the wire-side invariant; the tag itself is the structural
// guarantee.
func TestPolicySigningKey_JSONMarshalOmitsPrivateKey(t *testing.T) {
	t.Parallel()
	k := repository.PolicySigningKey{
		ID:         uuid.New(),
		TenantID:   uuid.New(),
		KeyID:      "deadbeefdeadbeef",
		Algorithm:  "ed25519",
		PublicKey:  bytes.Repeat([]byte{0xAA}, 32),
		PrivateKey: bytes.Repeat([]byte{0xBB}, 32),
		Status:     repository.PolicySigningKeyStatusActive,
	}
	out, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(out, []byte(`"PrivateKey"`)) || bytes.Contains(out, []byte(`"private_key"`)) {
		t.Errorf("PrivateKey leaked into JSON: %s", out)
	}
	// Sanity-check that the wrapper field is still present so the
	// guard doesn't accidentally hide unrelated fields.
	if !bytes.Contains(out, []byte(`"PublicKey"`)) {
		t.Errorf("expected PublicKey in marshalled output, got %s", out)
	}
}
