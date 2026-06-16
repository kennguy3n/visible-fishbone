package appid

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func newTestService(t *testing.T, opts ...Option) (*Service, *memory.AppIDCatalogRepository) {
	t.Helper()
	repo := memory.NewAppIDCatalogRepository(nil)
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	svc, err := New(repo, signer, opts...)
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc, repo
}

func TestSeedIfEmptyPublishesSignedSeed(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	if err := svc.SeedIfEmpty(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}

	ver, err := svc.CurrentVersion(ctx)
	if err != nil {
		t.Fatalf("current version: %v", err)
	}
	if ver.AppCount != svc.SeedCount() {
		t.Fatalf("app count %d != seed count %d", ver.AppCount, svc.SeedCount())
	}
	if ver.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version %d", ver.SchemaVersion)
	}

	env, verFromBundle, err := svc.CurrentBundle(ctx)
	if err != nil {
		t.Fatalf("current bundle: %v", err)
	}
	if verFromBundle.Serial != ver.Serial {
		t.Fatalf("serial mismatch %d != %d", verFromBundle.Serial, ver.Serial)
	}
	decoded, err := env.DecodeVerified(svc.PublicKey())
	if err != nil {
		t.Fatalf("verify served bundle: %v", err)
	}
	if len(decoded.Apps) != svc.SeedCount() {
		t.Fatalf("decoded apps %d != seed %d", len(decoded.Apps), svc.SeedCount())
	}
	// Checksum recorded in the version row matches the signed payload.
	sum := sha256.Sum256(mustCanonical(t, decoded))
	if ver.Checksum != hex.EncodeToString(sum[:]) {
		t.Fatalf("checksum mismatch")
	}
}

func mustCanonical(t *testing.T, b *CatalogBundle) []byte {
	t.Helper()
	out, err := b.CanonicalBytes()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	return out
}

func TestSeedIfEmptyIdempotent(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	if err := svc.SeedIfEmpty(ctx); err != nil {
		t.Fatalf("seed 1: %v", err)
	}
	first, _ := svc.CurrentVersion(ctx)
	if err := svc.SeedIfEmpty(ctx); err != nil {
		t.Fatalf("seed 2: %v", err)
	}
	second, _ := svc.CurrentVersion(ctx)
	if first.Serial != second.Serial {
		t.Fatalf("seed not idempotent: serial changed %d -> %d", first.Serial, second.Serial)
	}
	versions, err := svc.ListVersions(ctx, 10)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("expected exactly one version after re-seed, got %d", len(versions))
	}
}

func TestRepublishBumpsSerialMonotonically(t *testing.T) {
	// Clock returns a fixed value, so monotonicity must come from the
	// serial+1 fallback, not from wall-clock advancing.
	fixed := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	svc, _ := newTestService(t, withClock(func() time.Time { return fixed }))
	ctx := context.Background()

	if err := svc.SeedIfEmpty(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	v1, _ := svc.CurrentVersion(ctx)
	v2, err := svc.Republish(ctx, "rotate")
	if err != nil {
		t.Fatalf("republish: %v", err)
	}
	if v2.Serial <= v1.Serial {
		t.Fatalf("serial not monotonic: %d -> %d", v1.Serial, v2.Serial)
	}
	if v2.Note != "rotate" {
		t.Fatalf("note not persisted: %q", v2.Note)
	}
	if v2.AppCount != v1.AppCount {
		t.Fatalf("republish changed app count %d -> %d", v1.AppCount, v2.AppCount)
	}
}

// fakePublisher records pushed bundles and can be made to fail.
type fakePublisher struct {
	mu      sync.Mutex
	calls   int
	last    []byte
	failErr error
}

func (f *fakePublisher) PublishBundle(_ context.Context, _ string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.last = append([]byte(nil), data...)
	return f.failErr
}

func TestPublishPushesEnvelopeWhenPublisherSet(t *testing.T) {
	pub := &fakePublisher{}
	svc, _ := newTestService(t, WithPublisher(pub))
	ctx := context.Background()

	if err := svc.SeedIfEmpty(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if pub.calls != 1 {
		t.Fatalf("expected one push, got %d", pub.calls)
	}
	var env SignedBundle
	if err := json.Unmarshal(pub.last, &env); err != nil {
		t.Fatalf("pushed payload not a signed bundle: %v", err)
	}
	if _, err := env.DecodeVerified(svc.PublicKey()); err != nil {
		t.Fatalf("pushed bundle does not verify: %v", err)
	}
}

func TestPublishSucceedsWhenPushFails(t *testing.T) {
	pub := &fakePublisher{failErr: context.DeadlineExceeded}
	svc, _ := newTestService(t, WithPublisher(pub))
	ctx := context.Background()

	// A push failure must not fail the publish — the version is durably
	// stored and edges can pull it.
	if err := svc.SeedIfEmpty(ctx); err != nil {
		t.Fatalf("seed should succeed despite push failure: %v", err)
	}
	if _, err := svc.CurrentVersion(ctx); err != nil {
		t.Fatalf("version should be stored: %v", err)
	}
}

func TestNewRejectsNilDeps(t *testing.T) {
	signer, _ := GenerateSigner()
	if _, err := New(nil, signer); err == nil {
		t.Fatal("expected error on nil repo")
	}
	repo := memory.NewAppIDCatalogRepository(nil)
	if _, err := New(repo, nil); err == nil {
		t.Fatal("expected error on nil signer")
	}
}

// TestSeedInvariants asserts the embedded seed is a real, meaningful
// catalog: a few hundred apps, unique ids, valid categories, and every
// app carries a content signal.
func TestSeedInvariants(t *testing.T) {
	apps, err := parseSeed(seedJSON)
	if err != nil {
		t.Fatalf("parse seed: %v", err)
	}
	if len(apps) < 200 {
		t.Fatalf("seed too small: %d apps (want >= 200)", len(apps))
	}
	seen := make(map[string]struct{}, len(apps))
	for _, a := range apps {
		if _, dup := seen[a.AppID]; dup {
			t.Fatalf("duplicate app_id %q", a.AppID)
		}
		seen[a.AppID] = struct{}{}
		if len(a.SNISuffixes) == 0 && len(a.HostSuffixes) == 0 && len(a.JA3) == 0 && len(a.BytePrefixes) == 0 {
			t.Fatalf("app %q has no content signal", a.AppID)
		}
		if a.Confidence < 0 || a.Confidence > 100 {
			t.Fatalf("app %q confidence out of range: %d", a.AppID, a.Confidence)
		}
	}
}

// TestSeedByteIdenticalToRustCatalog guards the cross-language contract:
// the Go embed copy and the Rust crate's canonical catalog.json must be
// byte-for-byte identical so both planes ship exactly the same
// signatures.
func TestSeedByteIdenticalToRustCatalog(t *testing.T) {
	rustPath := filepath.Join("..", "..", "..", "crates", "sng-appid", "data", "catalog.json")
	rustBytes, err := os.ReadFile(rustPath)
	if err != nil {
		t.Fatalf("read rust catalog: %v", err)
	}
	if string(rustBytes) != string(seedJSON) {
		t.Fatalf("seed copy drifted from %s — regenerate so both are byte-identical", rustPath)
	}
}
