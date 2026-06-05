package sandbox

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/sandbox/providers"
)

func seedTenant(t *testing.T, store *memory.Store) uuid.UUID {
	t.Helper()
	tid := uuid.New()
	slug := tid.String()[:8]
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tid, Name: slug, Slug: slug,
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return tid
}

const testSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

// testClock is the fixed timestamp the test service stamps via the
// injected clock seam, so assertions on service-generated timestamps
// are deterministic instead of racing wall-clock.
var testClock = time.Date(2024, 6, 1, 12, 0, 0, 0, time.UTC)

func newTestEnv(t *testing.T, p providers.Provider) (*Service, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tid := seedTenant(t, store)
	repo := memory.NewSandboxVerdictRepository(store)
	// Deterministic clock + monotonic id generator: the seams keep the
	// service's timestamps and row ids reproducible across runs while
	// still handing out distinct ids per row (the repository upserts by
	// (tenant, sha256), so distinct shas must not collide on id).
	var idCounter byte
	opts := []Option{
		WithCache(NewCache(WithCacheCapacity(16), WithCacheTTL(time.Minute))),
		withClock(func() time.Time { return testClock }),
		withIDGen(func() uuid.UUID {
			idCounter++
			return uuid.NewSHA1(uuid.NameSpaceOID, []byte{idCounter})
		}),
	}
	if p != nil {
		opts = append(opts, WithProvider(p))
	}
	return NewService(repo, opts...), tid
}

func TestLookupVerdict_NotFound(t *testing.T) {
	svc, tid := newTestEnv(t, nil)
	_, found, err := svc.LookupVerdict(context.Background(), tid, testSHA256)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatal("expected found=false for unknown hash")
	}
}

func TestSubmit_NoProvider(t *testing.T) {
	svc, tid := newTestEnv(t, nil)
	v, err := svc.Submit(context.Background(), Submission{
		TenantID: tid,
		SHA256:   testSHA256,
		Content:  []byte("test"),
	}, nil)
	if err != ErrNoProvider {
		t.Fatalf("expected ErrNoProvider, got: %v", err)
	}
	if v.SHA256 != testSHA256 {
		t.Fatalf("expected sha=%s, got %s", testSHA256, v.SHA256)
	}
	// Should be retrievable as a pending verdict.
	got, err := svc.GetVerdict(context.Background(), tid, testSHA256)
	if err != nil {
		t.Fatalf("GetVerdict: %v", err)
	}
	if got.SHA256 != testSHA256 {
		t.Fatalf("expected sha=%s, got %s", testSHA256, got.SHA256)
	}
}

func TestSubmit_SyncProvider(t *testing.T) {
	p := &stubProvider{syncResult: true, classification: providers.ClassMalicious, score: 0.9}
	svc, tid := newTestEnv(t, p)
	v, err := svc.Submit(context.Background(), Submission{
		TenantID: tid,
		SHA256:   testSHA256,
		Content:  []byte("evil"),
	}, nil)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if v.Classification != ClassMalicious {
		t.Fatalf("expected malicious, got %s", v.Classification)
	}
	if !v.Blocking() {
		t.Fatal("malicious verdict should be blocking")
	}

	// Should be cached: a second lookup should succeed.
	v2, found, err := svc.LookupVerdict(context.Background(), tid, testSHA256)
	if err != nil {
		t.Fatalf("LookupVerdict: %v", err)
	}
	if !found {
		t.Fatal("expected found=true after resolved submit")
	}
	if v2.Classification != ClassMalicious {
		t.Fatalf("expected malicious, got %s", v2.Classification)
	}
}

func TestSubmit_Dedup(t *testing.T) {
	p := &stubProvider{syncResult: true, classification: providers.ClassClean, score: 1.0}
	svc, tid := newTestEnv(t, p)

	_, err := svc.Submit(context.Background(), Submission{
		TenantID: tid, SHA256: testSHA256, Content: []byte("a"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Second submit: should return the cached/persisted verdict
	// without calling the provider again.
	p.submitCalled = 0
	v, err := svc.Submit(context.Background(), Submission{
		TenantID: tid, SHA256: testSHA256, Content: []byte("a"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.submitCalled > 0 {
		t.Fatal("expected dedup: provider should not have been called")
	}
	if v.Classification != ClassClean {
		t.Fatalf("expected clean, got %s", v.Classification)
	}
}

func TestPoll_AdvancesPending(t *testing.T) {
	p := &stubProvider{
		syncResult:     false,
		pollStatus:     providers.StatusComplete,
		classification: providers.ClassSuspicious,
		score:          0.6,
	}
	svc, tid := newTestEnv(t, p)

	// Submit returns pending.
	v, err := svc.Submit(context.Background(), Submission{
		TenantID: tid, SHA256: testSHA256, Content: []byte("test"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if v.Classification != ClassUnknown {
		t.Fatalf("expected unknown (pending), got %s", v.Classification)
	}

	// Poll resolves.
	v2, err := svc.Poll(context.Background(), tid, testSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Classification != ClassSuspicious {
		t.Fatalf("expected suspicious after poll, got %s", v2.Classification)
	}
}

func TestListVerdicts(t *testing.T) {
	p := &stubProvider{syncResult: true, classification: providers.ClassClean, score: 1.0}
	svc, tid := newTestEnv(t, p)

	sha1 := "0000000000000000000000000000000000000000000000000000000000000001"
	sha2 := "0000000000000000000000000000000000000000000000000000000000000002"
	for _, sha := range []string{sha1, sha2} {
		_, err := svc.Submit(context.Background(), Submission{
			TenantID: tid, SHA256: sha, Content: []byte("x"),
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	list, err := svc.ListVerdicts(context.Background(), tid, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 verdicts, got %d", len(list))
	}
}

func TestSubmit_InvalidSHA(t *testing.T) {
	svc, tid := newTestEnv(t, nil)
	_, err := svc.Submit(context.Background(), Submission{
		TenantID: tid, SHA256: "not-a-hash", Content: []byte("x"),
	}, nil)
	if err == nil {
		t.Fatal("expected error for invalid sha")
	}
}

func TestTenantIsolation(t *testing.T) {
	store := memory.NewStore()
	t1 := seedTenant(t, store)
	t2 := seedTenant(t, store)
	repo := memory.NewSandboxVerdictRepository(store)
	p := &stubProvider{syncResult: true, classification: providers.ClassClean, score: 1.0}
	svc := NewService(repo, WithProvider(p), WithCache(NewCache()))

	_, err := svc.Submit(context.Background(), Submission{
		TenantID: t1, SHA256: testSHA256, Content: []byte("x"),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	// t2 should NOT see t1's verdict.
	_, found, err := svc.LookupVerdict(context.Background(), t2, testSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatal("expected tenant isolation: t2 should not see t1's verdict")
	}
}

// stubProvider is a minimal providers.Provider for unit tests.
type stubProvider struct {
	syncResult     bool
	pollStatus     providers.Status
	classification providers.Classification
	score          float64
	submitCalled   int
	// zeroAnalyzedAt makes the provider return a zero AnalyzedAt so a
	// test can assert the service stamps its own (injected) clock.
	zeroAnalyzedAt bool
}

func (s *stubProvider) ID() string { return "stub" }

func (s *stubProvider) analyzedAt() time.Time {
	if s.zeroAnalyzedAt {
		return time.Time{}
	}
	return time.Now().UTC()
}

func (s *stubProvider) Submit(_ context.Context, f providers.File) (providers.SubmitResult, error) {
	s.submitCalled++
	if s.syncResult {
		return providers.SubmitResult{
			SandboxID: "test-id",
			Status:    providers.StatusComplete,
			Result: providers.PollResult{
				Status:         providers.StatusComplete,
				Classification: s.classification,
				Confidence:     s.score,
				Summary:        "stub sync verdict",
				AnalyzedAt:     s.analyzedAt(),
			},
		}, nil
	}
	return providers.SubmitResult{SandboxID: "test-id-async", Status: providers.StatusPending}, nil
}

// TestSubmit_StampsInjectedClockWhenProviderOmitsAnalyzedAt verifies
// the service falls back to its own clock (the injected seam) when the
// provider returns a zero AnalyzedAt, rather than persisting a zero
// timestamp.
func TestSubmit_StampsInjectedClockWhenProviderOmitsAnalyzedAt(t *testing.T) {
	p := &stubProvider{
		syncResult:     true,
		classification: providers.ClassMalicious,
		score:          0.9,
		zeroAnalyzedAt: true,
	}
	svc, tid := newTestEnv(t, p)
	v, err := svc.Submit(context.Background(), Submission{
		TenantID: tid, SHA256: testSHA256, Content: []byte("x"),
	}, nil)
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if !v.AnalyzedAt.Equal(testClock) {
		t.Fatalf("expected AnalyzedAt to use injected clock %v, got %v", testClock, v.AnalyzedAt)
	}
}

func (s *stubProvider) Poll(_ context.Context, _ string) (providers.PollResult, error) {
	return providers.PollResult{
		Status:         s.pollStatus,
		Classification: s.classification,
		Confidence:     s.score,
		Summary:        "stub poll verdict",
		AnalyzedAt:     time.Now().UTC(),
	}, nil
}

// TestCache unit-tests the cache independently.
func TestCache_PutGetEvict(t *testing.T) {
	c := NewCache(WithCacheCapacity(2), WithCacheTTL(time.Hour))
	tid := uuid.New()

	sha1 := "0000000000000000000000000000000000000000000000000000000000000001"
	sha2 := "0000000000000000000000000000000000000000000000000000000000000002"
	sha3 := "0000000000000000000000000000000000000000000000000000000000000003"

	c.Put(tid, Verdict{SHA256: sha1, Classification: ClassClean})
	c.Put(tid, Verdict{SHA256: sha2, Classification: ClassMalicious})

	if _, ok := c.Get(tid, sha1); !ok {
		t.Fatal("sha1 should be cached")
	}
	if _, ok := c.Get(tid, sha2); !ok {
		t.Fatal("sha2 should be cached")
	}

	// Eviction: adding sha3 should evict the oldest (sha1).
	c.Put(tid, Verdict{SHA256: sha3, Classification: ClassSuspicious})
	if _, ok := c.Get(tid, sha1); ok {
		t.Fatal("sha1 should have been evicted")
	}
	if _, ok := c.Get(tid, sha3); !ok {
		t.Fatal("sha3 should be cached")
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	now := time.Now().UTC()
	c := NewCache(WithCacheTTL(time.Second), withCacheClock(func() time.Time { return now }))
	tid := uuid.New()
	c.Put(tid, Verdict{SHA256: testSHA256, Classification: ClassClean})

	if _, ok := c.Get(tid, testSHA256); !ok {
		t.Fatal("should be cached immediately")
	}
	// Advance past TTL.
	now = now.Add(2 * time.Second)
	if _, ok := c.Get(tid, testSHA256); ok {
		t.Fatal("should have expired")
	}
}

func TestCache_IgnoresPending(t *testing.T) {
	c := NewCache()
	tid := uuid.New()
	c.Put(tid, Verdict{SHA256: testSHA256, Classification: ClassUnknown})
	if _, ok := c.Get(tid, testSHA256); ok {
		t.Fatal("unknown/pending verdicts should not be cached")
	}
}

func TestMemoryRepo_Upsert_RoundTrip(t *testing.T) {
	store := memory.NewStore()
	tid := seedTenant(t, store)
	repo := memory.NewSandboxVerdictRepository(store)

	ctx := context.Background()
	now := time.Now().UTC()
	row, err := repo.Upsert(ctx, tid, repository.SandboxVerdict{
		SHA256:         testSHA256,
		Classification: "malicious",
		Confidence:     0.95,
		Provider:       "cuckoo",
		SandboxID:      "42",
		Summary:        "ransomware",
		Status:         "complete",
		AnalyzedAt:     &now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if row.ID == uuid.Nil {
		t.Fatal("expected non-nil ID")
	}
	if row.SHA256 != testSHA256 {
		t.Fatalf("expected sha=%s, got %s", testSHA256, row.SHA256)
	}
	if row.Classification != "malicious" {
		t.Fatalf("expected malicious, got %s", row.Classification)
	}

	// Upsert (update path).
	updated, err := repo.Upsert(ctx, tid, repository.SandboxVerdict{
		SHA256:         testSHA256,
		Classification: "clean",
		Confidence:     1.0,
		Provider:       "cuckoo",
		Status:         "complete",
		AnalyzedAt:     &now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Classification != "clean" {
		t.Fatalf("expected clean after upsert, got %s", updated.Classification)
	}
	// ID should be the same (upsert preserves).
	if updated.ID != row.ID {
		t.Fatalf("expected same ID after upsert, got %s vs %s", updated.ID, row.ID)
	}
}
