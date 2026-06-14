package threatintel

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// fakePublisher records published bundles for assertions.
type fakePublisher struct {
	mu      sync.Mutex
	count   int
	last    []byte
	lastSub string
	err     error
}

func (p *fakePublisher) PublishBundle(_ context.Context, subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.count++
	p.last = data
	p.lastSub = subject
	return nil
}

func (p *fakePublisher) snapshot() (int, []byte, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.count, p.last, p.lastSub
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestService(t *testing.T, sources []Source, pub BundlePublisher, opts ...Option) *Service {
	t.Helper()
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	base := append([]Option{WithLogger(quietLogger())}, opts...)
	svc, err := NewService(sources, signer, pub, base...)
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestRefreshOncePublishesSignedBundle(t *testing.T) {
	pub := &fakePublisher{}
	sources := []Source{
		{Name: "rep", Kind: KindReputation, Fetcher: StaticFetcher{Data: []byte("evil.example\nbad.example\n")}},
		{Name: "cat-ads", Kind: KindCategory, Category: "ads", Fetcher: StaticFetcher{Data: []byte("ads.example\n")}},
	}
	svc := newTestService(t, sources, pub)

	res, err := svc.RefreshOnce(context.Background())
	if err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if !res.Published {
		t.Fatal("expected Published=true")
	}
	if res.ReputationSize != 2 {
		t.Fatalf("reputation size = %d", res.ReputationSize)
	}
	if res.CategorySizes["ads"] != 1 {
		t.Fatalf("ads size = %d", res.CategorySizes["ads"])
	}
	count, data, sub := pub.snapshot()
	if count != 1 {
		t.Fatalf("publish count = %d", count)
	}
	if sub != DefaultSubject {
		t.Fatalf("subject = %q", sub)
	}
	// Published envelope verifies against the signer's public key.
	var env SignedBundle
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if _, err := env.DecodeVerified(svc.signer.Public()); err != nil {
		t.Fatalf("published bundle failed verify: %v", err)
	}
}

func TestRefreshOnceFallsBackToLastKnownGood(t *testing.T) {
	pub := &fakePublisher{}
	flaky := &toggleFetcher{data: []byte("evil.example\n")}
	sources := []Source{{Name: "rep", Kind: KindReputation, Fetcher: flaky}}
	svc := newTestService(t, sources, pub)

	// First refresh succeeds and caches.
	if _, err := svc.RefreshOnce(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	// Now the upstream fails; the source must fall back to cache and
	// still publish.
	flaky.fail = true
	res, err := svc.RefreshOnce(context.Background())
	if err != nil {
		t.Fatalf("second refresh should publish from cache: %v", err)
	}
	if !res.Published || res.ReputationSize != 1 {
		t.Fatalf("expected cached publish, got %+v", res)
	}
	if res.SourcesFailed != 1 {
		t.Fatalf("expected 1 failed source, got %d", res.SourcesFailed)
	}
}

func TestRefreshOnceNoPublishWhenAllSourcesEmpty(t *testing.T) {
	pub := &fakePublisher{}
	sources := []Source{{Name: "rep", Kind: KindReputation, Fetcher: StaticFetcher{Err: errors.New("down")}}}
	svc := newTestService(t, sources, pub)

	res, err := svc.RefreshOnce(context.Background())
	if !errors.Is(err, errAllSourcesEmpty) {
		t.Fatalf("expected errAllSourcesEmpty, got %v", err)
	}
	if res.Published {
		t.Fatal("must not publish when no source contributed")
	}
	if count, _, _ := pub.snapshot(); count != 0 {
		t.Fatalf("publish count = %d, want 0 (edge keeps last-known-good)", count)
	}
}

func TestSerialMonotonic(t *testing.T) {
	pub := &fakePublisher{}
	sources := []Source{{Name: "rep", Kind: KindReputation, Fetcher: StaticFetcher{Data: []byte("evil.example\n")}}}
	// Frozen clock so two refreshes land in the same second; serials
	// must still strictly increase.
	frozen := time.Unix(1700000000, 0)
	svc := newTestService(t, sources, pub, withClock(func() time.Time { return frozen }))

	r1, err := svc.RefreshOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r2, err := svc.RefreshOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r2.Serial <= r1.Serial {
		t.Fatalf("serial not monotonic: %d then %d", r1.Serial, r2.Serial)
	}
}

func TestNewServiceValidation(t *testing.T) {
	signer, _ := GenerateSigner()
	pub := &fakePublisher{}

	cases := []struct {
		name    string
		sources []Source
	}{
		{"empty name", []Source{{Name: "", Kind: KindReputation, Fetcher: StaticFetcher{}}}},
		{"nil fetcher", []Source{{Name: "x", Kind: KindReputation}}},
		{"category without category name", []Source{{Name: "x", Kind: KindCategory, Fetcher: StaticFetcher{}}}},
		{"duplicate", []Source{
			{Name: "x", Kind: KindReputation, Fetcher: StaticFetcher{}},
			{Name: "x", Kind: KindReputation, Fetcher: StaticFetcher{}},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewService(tc.sources, signer, pub); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	pub := &fakePublisher{}
	sources := []Source{{Name: "rep", Kind: KindReputation, Fetcher: StaticFetcher{Data: []byte("evil.example\n")}}}
	svc := newTestService(t, sources, pub)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.Run(ctx, time.Hour)
		close(done)
	}()
	// Warm-up refresh publishes immediately; then cancel.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on context cancel")
	}
	if count, _, _ := pub.snapshot(); count < 1 {
		t.Fatal("expected at least the warm-up publish")
	}
}

// TestRefreshOnceBridgesSnapshotSource proves an in-process
// SnapshotFetcher source (the IOCStore bridge) lands its domains in the
// signed bundle under its category bucket, that a live update to the
// provider is reflected on the next refresh, and — because the source
// is AllowEmpty — that draining the provider to empty drains the bucket
// rather than re-publishing the stale last-known-good set (so expired
// IOCs do not linger in the bundle past their TTL).
func TestRefreshOnceBridgesSnapshotSource(t *testing.T) {
	pub := &fakePublisher{}
	domains := []string{"evil.example", "sub.bad.example"}
	sources := []Source{
		{Name: "rep", Kind: KindReputation, Fetcher: StaticFetcher{Data: []byte("known-bad.example\n")}},
		{Name: "ioc-aggregator", Kind: KindCategory, Category: "threat-intel-ioc", AllowEmpty: true,
			Fetcher: SnapshotFetcher{Provider: func() []string { return domains }}},
	}
	svc := newTestService(t, sources, pub)

	decodeCategory := func() []string {
		t.Helper()
		_, data, _ := pub.snapshot()
		var env SignedBundle
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatal(err)
		}
		bundle, err := env.DecodeVerified(svc.signer.Public())
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		return bundle.Categories["threat-intel-ioc"]
	}

	if _, err := svc.RefreshOnce(context.Background()); err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if got := decodeCategory(); !equalStringSet(got, []string{"evil.example", "sub.bad.example"}) {
		t.Fatalf("ioc category = %v, want [evil.example sub.bad.example]", got)
	}

	// Live provider update is picked up on the next refresh.
	domains = []string{"evil.example"}
	if _, err := svc.RefreshOnce(context.Background()); err != nil {
		t.Fatalf("second RefreshOnce: %v", err)
	}
	if got := decodeCategory(); !equalStringSet(got, []string{"evil.example"}) {
		t.Fatalf("after update ioc category = %v, want [evil.example]", got)
	}

	// All indicators expire / store swept → provider returns empty. The
	// AllowEmpty source must drain the bucket, NOT fall back to the
	// cached set, otherwise expired IOCs would persist past their TTL.
	domains = nil
	if _, err := svc.RefreshOnce(context.Background()); err != nil {
		t.Fatalf("third RefreshOnce: %v", err)
	}
	if got := decodeCategory(); len(got) != 0 {
		t.Fatalf("after drain ioc category = %v, want empty (stale IOCs must not linger)", got)
	}
}

func equalStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// toggleFetcher returns data, or an error once fail is set.
type toggleFetcher struct {
	data []byte
	fail bool
}

func (f *toggleFetcher) Fetch(context.Context) ([]byte, error) {
	if f.fail {
		return nil, errors.New("upstream down")
	}
	return f.data, nil
}
