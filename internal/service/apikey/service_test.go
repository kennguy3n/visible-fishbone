package apikey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// middlewareWithAPIKeyID is a test-only adapter to the
// middleware package's API-key context helper, kept here to
// minimize churn in the call sites below.
func middlewareWithAPIKeyID(ctx context.Context, id string) context.Context {
	return middleware.ContextWithAPIKeyID(ctx, id)
}

func newFixture(t *testing.T) (*Service, *memory.Store, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	tnt, err := tenants.Create(context.Background(), repository.Tenant{
		Name: "acme", Slug: "acme", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	repo := memory.NewTenantAPIKeyRepository(store)
	audit := memory.NewAuditLogRepository(store)
	svc := New(repo, audit,
		WithLogger(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))),
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }),
		WithAsyncTouch(func(fn func()) { fn() }),
	)
	return svc, store, tnt.ID
}

func TestCreate_GeneratesPrefixedPlaintextAndPersistsHash(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newFixture(t)

	res, err := svc.Create(context.Background(), tenantID, nil, CreateInput{
		Name:    "ci-bot",
		Subject: "bot:ci",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !strings.HasPrefix(res.Plaintext, KeyPrefix) {
		t.Fatalf("plaintext missing prefix: %q", res.Plaintext)
	}
	if len(res.Plaintext) < len(KeyPrefix)+30 {
		t.Fatalf("plaintext too short for 32-byte secret: %q", res.Plaintext)
	}
	if len(res.Record.Hash) != 32 {
		t.Fatalf("hash should be SHA-256 (32 bytes), got %d", len(res.Record.Hash))
	}
	if res.Record.Status != repository.TenantAPIKeyStatusActive {
		t.Fatalf("status should default to active, got %s", res.Record.Status)
	}
}

func TestCreate_RejectsEmptyFields(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newFixture(t)
	cases := []CreateInput{
		{Name: "", Subject: "x"},
		{Name: "x", Subject: ""},
		{Name: "   ", Subject: "x"},
		{Name: "x", Subject: "   "},
	}
	for _, in := range cases {
		_, err := svc.Create(context.Background(), tenantID, nil, in)
		if !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument for %+v, got %v", in, err)
		}
	}
}

func TestCreate_RejectsTooShortTTL(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newFixture(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	past := now.Add(-time.Hour)
	soon := now.Add(10 * time.Second)
	for _, exp := range []time.Time{past, soon} {
		_, err := svc.Create(context.Background(), tenantID, nil, CreateInput{
			Name: "x", Subject: "y", ExpiresAt: &exp,
		})
		if !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument for expires_at=%s, got %v", exp, err)
		}
	}
}

func TestLookup_ReturnsTenantAndSubjectOnValidKey(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newFixture(t)
	res, err := svc.Create(context.Background(), tenantID, nil, CreateInput{
		Name:    "ci-bot",
		Subject: "bot:ci",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	info, err := svc.Lookup(context.Background(), res.Plaintext)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if info.TenantID != tenantID {
		t.Fatalf("tenant mismatch: got %s want %s", info.TenantID, tenantID)
	}
	if info.Subject != "bot:ci" {
		t.Fatalf("subject mismatch: %q", info.Subject)
	}
	if info.ID != res.Record.ID.String() {
		t.Fatalf("id mismatch: %q vs %q", info.ID, res.Record.ID.String())
	}
}

func TestLookup_RejectsMalformedKeys(t *testing.T) {
	t.Parallel()
	svc, _, _ := newFixture(t)
	cases := []string{
		"",
		"sng_",                  // empty body
		"sng_!notbase64",        // invalid base64
		"sng_dGVzdA",            // base64 of "test" — only 4 bytes
		"other_dGVzdAo",         // wrong prefix
		"AAAAAAAAAAAAAAAAAAAAA", // no prefix at all
	}
	for _, k := range cases {
		_, err := svc.Lookup(context.Background(), k)
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey for %q, got %v", k, err)
		}
	}
}

func TestLookup_RejectsRevokedKey(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newFixture(t)
	res, err := svc.Create(context.Background(), tenantID, nil, CreateInput{
		Name: "x", Subject: "y",
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Revoke(context.Background(), tenantID, res.Record.ID, nil); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Lookup(context.Background(), res.Plaintext); !errors.Is(err, ErrKeyRevoked) {
		t.Fatalf("expected ErrKeyRevoked, got %v", err)
	}
}

func TestLookup_RejectsExpiredKey(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	tnt, _ := tenants.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	repo := memory.NewTenantAPIKeyRepository(store)
	now := time.Unix(1_700_000_000, 0).UTC()
	clock := now
	svc := New(repo, nil,
		WithClock(func() time.Time { return clock }),
		WithAsyncTouch(func(fn func()) { fn() }),
	)
	exp := now.Add(time.Hour)
	res, err := svc.Create(context.Background(), tnt.ID, nil, CreateInput{
		Name: "x", Subject: "y", ExpiresAt: &exp,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	clock = now.Add(2 * time.Hour) // skip past expiry
	if _, err := svc.Lookup(context.Background(), res.Plaintext); !errors.Is(err, ErrKeyExpired) {
		t.Fatalf("expected ErrKeyExpired, got %v", err)
	}
}

func TestLookup_TouchesLastUsedAt(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	tnt, _ := tenants.Create(context.Background(), repository.Tenant{
		Name: "t", Slug: "t", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	repo := memory.NewTenantAPIKeyRepository(store)
	svc := New(repo, nil,
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }),
		WithAsyncTouch(func(fn func()) { fn() }),
	)
	res, err := svc.Create(context.Background(), tnt.ID, nil, CreateInput{Name: "x", Subject: "y"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := svc.Lookup(context.Background(), res.Plaintext); err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	got, err := repo.Get(context.Background(), tnt.ID, res.Record.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.LastUsedAt == nil {
		t.Fatalf("expected LastUsedAt to be stamped after Lookup")
	}
}

func TestRevoke_IsIdempotent(t *testing.T) {
	t.Parallel()
	svc, _, tenantID := newFixture(t)
	res, err := svc.Create(context.Background(), tenantID, nil, CreateInput{Name: "x", Subject: "y"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	first, err := svc.Revoke(context.Background(), tenantID, res.Record.ID, nil)
	if err != nil {
		t.Fatalf("first Revoke: %v", err)
	}
	second, err := svc.Revoke(context.Background(), tenantID, res.Record.ID, nil)
	if err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
	if first.RevokedAt == nil || second.RevokedAt == nil {
		t.Fatalf("revoked_at not stamped")
	}
	if !first.RevokedAt.Equal(*second.RevokedAt) {
		t.Fatalf("idempotent Revoke should keep original revoked_at, got %s then %s", first.RevokedAt, second.RevokedAt)
	}
}

func TestList_ReturnsCreatedDesc(t *testing.T) {
	t.Parallel()
	svc, store, tenantID := newFixture(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	tick := now
	store.SetClock(func() time.Time {
		t := tick
		tick = tick.Add(time.Second)
		return t
	})
	for i := 0; i < 3; i++ {
		if _, err := svc.Create(context.Background(), tenantID, nil, CreateInput{
			Name: "k", Subject: "s",
		}); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}
	out, err := svc.List(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(out))
	}
	for i := 1; i < len(out); i++ {
		if out[i-1].CreatedAt.Before(out[i].CreatedAt) {
			t.Fatalf("list not desc by created_at: %v then %v", out[i-1].CreatedAt, out[i].CreatedAt)
		}
	}
}

// TestTenantAPIKey_JSONMarshalOmitsHash is the defence-in-depth
// check pinning the `json:"-"` tag on `repository.TenantAPIKey.Hash`.
// Handlers project to `APIKeyResponse` today, but a future refactor
// that accidentally passes the raw struct through `WriteJSON` /
// `json.Marshal` must NOT leak the SHA-256 hash onto the wire.
// Even though the hash is computationally infeasible to invert at
// 256 bits of preimage entropy, leaking it would let an attacker
// with a suspected plaintext verify the match offline without
// hitting the API — a class of probe we cut off at the type level.
// This test mirrors TestPolicySigningKey_JSONMarshalOmitsPrivateKey
// in internal/service/policy/keys_test.go.
func TestTenantAPIKey_JSONMarshalOmitsHash(t *testing.T) {
	t.Parallel()
	k := repository.TenantAPIKey{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Name:     "ci-prod",
		Subject:  "bot:ci",
		Hash:     bytes.Repeat([]byte{0xCC}, 32),
		Status:   repository.TenantAPIKeyStatusActive,
	}
	out, err := json.Marshal(k)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(out, []byte(`"Hash"`)) || bytes.Contains(out, []byte(`"hash"`)) {
		t.Errorf("Hash leaked into JSON: %s", out)
	}
	// Sanity-check that the public projection fields are still
	// present so the guard doesn't accidentally hide unrelated
	// fields.
	if !bytes.Contains(out, []byte(`"Name"`)) {
		t.Errorf("expected Name in marshalled output, got %s", out)
	}
	if !bytes.Contains(out, []byte(`"Subject"`)) {
		t.Errorf("expected Subject in marshalled output, got %s", out)
	}
}

// TestCreate_EnforcesActiveKeyCap pins the per-tenant active-key
// cap: once a tenant holds `cap` active keys, the next Create
// returns ErrResourceExhausted (mapped to HTTP 429 at the handler
// boundary). Revoked keys do not count against the cap so a
// rotate-then-revoke workflow does not eventually wedge the
// tenant out of issuing new keys.
func TestCreate_EnforcesActiveKeyCap(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	tnt, err := tenants.Create(context.Background(), repository.Tenant{
		Name: "acme", Slug: "acme", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	repo := memory.NewTenantAPIKeyRepository(store)
	svc := New(repo, nil,
		WithLogger(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))),
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }),
		WithAsyncTouch(func(fn func()) { fn() }),
		WithMaxActiveKeys(3),
	)
	created := make([]repository.TenantAPIKey, 0, 3)
	for i := 0; i < 3; i++ {
		res, err := svc.Create(context.Background(), tnt.ID, nil, CreateInput{
			Name: "k", Subject: "s",
		})
		if err != nil {
			t.Fatalf("Create %d: %v", i, err)
		}
		created = append(created, res.Record)
	}
	if _, err := svc.Create(context.Background(), tnt.ID, nil, CreateInput{
		Name: "overflow", Subject: "s",
	}); !errors.Is(err, repository.ErrResourceExhausted) {
		t.Fatalf("expected ErrResourceExhausted at cap, got %v", err)
	}
	if _, err := svc.Revoke(context.Background(), tnt.ID, created[0].ID, nil); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if _, err := svc.Create(context.Background(), tnt.ID, nil, CreateInput{
		Name: "after-revoke", Subject: "s",
	}); err != nil {
		t.Fatalf("Create after revoke should succeed (revoked keys don't count): %v", err)
	}
}

// TestCreate_AuditDetailsCarryActingAPIKeyID pins that when Create
// is invoked under an API-key-authenticated request (machine
// actor, no JWT user ID), the audit row's details JSON carries
// the acting API key ID under `acting_api_key_id`. The repository
// row's actor_id stays NULL because the schema reserves it for
// *user* UUIDs; machine-actor attribution lives in details.
func TestCreate_AuditDetailsCarryActingAPIKeyID(t *testing.T) {
	t.Parallel()
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	tnt, err := tenants.Create(context.Background(), repository.Tenant{
		Name: "acme", Slug: "acme", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	repo := memory.NewTenantAPIKeyRepository(store)
	audit := memory.NewAuditLogRepository(store)
	svc := New(repo, audit,
		WithLogger(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))),
		WithClock(func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }),
		WithAsyncTouch(func(fn func()) { fn() }),
	)
	actingKeyID := uuid.NewString()
	ctx := middlewareWithAPIKeyID(context.Background(), actingKeyID)
	if _, err := svc.Create(ctx, tnt.ID, nil, CreateInput{
		Name: "child", Subject: "bot:child",
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	page, err := audit.List(context.Background(), tnt.ID, repository.AuditFilter{}, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Items) == 0 {
		t.Fatalf("expected at least one audit row")
	}
	var got map[string]any
	if err := json.Unmarshal(page.Items[0].Details, &got); err != nil {
		t.Fatalf("unmarshal details: %v", err)
	}
	if got["acting_api_key_id"] != actingKeyID {
		t.Fatalf("expected acting_api_key_id=%q, got details=%v", actingKeyID, got)
	}
}
