package threatfeed

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

func silentLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

var fixedNow = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func newTestEngine(t *testing.T, feeds []Feed, opts ...Option) (*Engine, repository.ThreatFeedRepository, *Signer) {
	t.Helper()
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	repo := memory.NewStore().NewThreatFeedRepository()
	base := []Option{WithLogger(silentLogger()), WithClock(func() time.Time { return fixedNow })}
	eng, err := NewEngine(DefaultConfig(), feeds, signer, repo, append(base, opts...)...)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng, repo, signer
}

func ipFeed(name string, body string, etag string) Feed {
	return Feed{
		Name:       name,
		Kind:       "ip",
		Weight:     0.9,
		DefaultTTL: 7 * 24 * time.Hour,
		Parser:     IPListParser{Source: name},
		Fetcher:    StaticFetcher{Body: []byte(body), ETag: etag},
	}
}

// controllableFetcher fails when *fail is true, else returns body with
// no validators (always-modified path). Lets a test flip an upstream to
// unreachable mid-run to exercise last-good degradation.
type controllableFetcher struct {
	body []byte
	fail *bool
}

func (f controllableFetcher) Fetch(_ context.Context, _, _ string) (FetchResult, error) {
	if *f.fail {
		return FetchResult{}, errors.New("network down")
	}
	return FetchResult{Body: f.body}, nil
}

// errParser always fails parsing, simulating a garbage/corrupt feed.
type errParser struct{ name string }

func (p errParser) Name() string                   { return p.name }
func (p errParser) Parse([]byte) ([]ai.IOC, error) { return nil, errors.New("garbage feed") }

func TestEngine_NewEngineValidation(t *testing.T) {
	t.Parallel()
	signer, _ := GenerateSigner()
	repo := memory.NewStore().NewThreatFeedRepository()
	feeds := []Feed{ipFeed("a", "203.0.113.10\n", "")}
	if _, err := NewEngine(DefaultConfig(), feeds, nil, repo); err == nil {
		t.Fatal("nil signer should error")
	}
	if _, err := NewEngine(DefaultConfig(), feeds, signer, nil); err == nil {
		t.Fatal("nil repo should error")
	}
	if _, err := NewEngine(DefaultConfig(), nil, signer, repo); err == nil {
		t.Fatal("no feeds should error")
	}
}

func TestEngine_RefreshHappyPath(t *testing.T) {
	t.Parallel()
	eng, repo, signer := newTestEngine(t, []Feed{ipFeed("ipfeed", "203.0.113.10\n198.51.100.5\n", "e1")})
	ctx := context.Background()

	res, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if res.Skipped || res.Unchanged {
		t.Fatalf("first refresh should mint: %+v", res)
	}
	if res.Indicators != 2 || res.Serial <= 0 {
		t.Fatalf("result = %+v", res)
	}

	// Persisted bundle verifies against the signer's public key.
	latest, err := repo.LatestBundle(ctx)
	if err != nil {
		t.Fatalf("latest bundle: %v", err)
	}
	env, err := UnmarshalSignedBundle(latest.Envelope)
	if err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	bundle, err := env.DecodeVerified(signer.Public())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(bundle.Indicators) != 2 || bundle.Serial != res.Serial {
		t.Fatalf("decoded bundle = %+v", bundle)
	}
}

func TestEngine_UnchangedViaConditionalGET(t *testing.T) {
	t.Parallel()
	eng, _, _ := newTestEngine(t, []Feed{ipFeed("ipfeed", "203.0.113.10\n", "e1")})
	ctx := context.Background()

	first, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !second.Unchanged {
		t.Fatalf("identical content should be Unchanged: %+v", second)
	}
	if second.Serial != first.Serial {
		t.Fatalf("Unchanged should keep serial %d, got %d", first.Serial, second.Serial)
	}
	if len(second.Sources) != 1 || !second.Sources[0].NotModified {
		t.Fatalf("second refresh should hit conditional-GET 304 path: %+v", second.Sources)
	}
}

func TestEngine_UnchangedViaReparse(t *testing.T) {
	t.Parallel()
	// No ETag + AlwaysModified: each refresh re-parses, but the fixed
	// clock makes the stamped content identical, so the digest matches.
	feed := Feed{
		Name:       "ipfeed",
		Kind:       "ip",
		Weight:     0.9,
		DefaultTTL: 7 * 24 * time.Hour,
		Parser:     IPListParser{Source: "ipfeed"},
		Fetcher:    StaticFetcher{Body: []byte("203.0.113.10\n"), AlwaysModified: true},
	}
	eng, _, _ := newTestEngine(t, []Feed{feed})
	ctx := context.Background()

	if _, err := eng.RefreshOnce(ctx); err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if !second.Unchanged {
		t.Fatalf("re-parsed identical content should be Unchanged: %+v", second)
	}
	if second.Sources[0].NotModified {
		t.Fatal("AlwaysModified feed should not report NotModified")
	}
}

func TestEngine_KillSwitch(t *testing.T) {
	t.Parallel()
	eng, repo, _ := newTestEngine(t, []Feed{ipFeed("ipfeed", "203.0.113.10\n", "e1")})
	eng.SetEnabled(false)
	ctx := context.Background()

	res, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !res.Skipped {
		t.Fatalf("disabled engine should skip: %+v", res)
	}
	if _, err := repo.LatestBundle(ctx); !errors.Is(err, repository.ErrNotFound) {
		t.Fatal("disabled engine should not persist a bundle")
	}
}

func TestEngine_DegradesToLastGoodOnFetchError(t *testing.T) {
	t.Parallel()
	fail := false
	feed := Feed{
		Name:       "ipfeed",
		Kind:       "ip",
		Weight:     0.9,
		DefaultTTL: 7 * 24 * time.Hour,
		Parser:     IPListParser{Source: "ipfeed"},
		Fetcher:    controllableFetcher{body: []byte("203.0.113.10\n198.51.100.5\n"), fail: &fail},
	}
	eng, _, _ := newTestEngine(t, []Feed{feed})
	ctx := context.Background()

	first, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if first.Indicators != 2 {
		t.Fatalf("warm-up indicators = %d, want 2", first.Indicators)
	}

	// Upstream goes down: the engine must keep serving the last good set.
	fail = true
	degraded, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("degraded refresh returned error instead of degrading: %v", err)
	}
	if degraded.Indicators != 2 {
		t.Fatalf("degraded indicators = %d, want 2 (last good)", degraded.Indicators)
	}
	st := degraded.Sources[0]
	if st.Err == "" || !st.UsedCache {
		t.Fatalf("degraded stat should record error + cache use: %+v", st)
	}
}

func TestEngine_GarbageFeedDoesNotPoisonBundle(t *testing.T) {
	t.Parallel()
	good := ipFeed("good", "203.0.113.10\n", "g1")
	bad := Feed{
		Name:    "bad",
		Kind:    "ip",
		Weight:  0.9,
		Parser:  errParser{name: "bad"},
		Fetcher: StaticFetcher{Body: []byte("@@@garbage@@@"), ETag: "b1"},
	}
	eng, _, _ := newTestEngine(t, []Feed{good, bad})
	ctx := context.Background()

	res, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if res.Indicators != 1 {
		t.Fatalf("only the good feed should contribute, got %d", res.Indicators)
	}
	var badStat SourceStat
	for _, s := range res.Sources {
		if s.Source == "bad" {
			badStat = s
		}
	}
	if badStat.Err == "" {
		t.Fatalf("garbage feed should record a parse error: %+v", badStat)
	}
}

func TestEngine_SerialMonotonicOnContentChange(t *testing.T) {
	t.Parallel()
	body := []byte("203.0.113.10\n")
	bodyPtr := &body
	feed := Feed{
		Name:       "ipfeed",
		Kind:       "ip",
		Weight:     0.9,
		DefaultTTL: 7 * 24 * time.Hour,
		Parser:     IPListParser{Source: "ipfeed"},
		Fetcher:    ptrBodyFetcher{body: bodyPtr},
	}
	eng, _, _ := newTestEngine(t, []Feed{feed})
	ctx := context.Background()

	first, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	*bodyPtr = []byte("203.0.113.10\n198.51.100.5\n")
	second, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if second.Unchanged {
		t.Fatal("changed content should mint a new version")
	}
	if second.Serial <= first.Serial {
		t.Fatalf("serial not monotonic: %d -> %d", first.Serial, second.Serial)
	}
}

// ptrBodyFetcher always returns the current bytes at *body (no
// validators), so a test can mutate the upstream content between
// refreshes.
type ptrBodyFetcher struct{ body *[]byte }

func (f ptrBodyFetcher) Fetch(_ context.Context, _, _ string) (FetchResult, error) {
	return FetchResult{Body: *f.body}, nil
}

func TestEngine_ContinuesVersionLineAcrossRestart(t *testing.T) {
	t.Parallel()
	signer, _ := GenerateSigner()
	store := memory.NewStore()
	repo := store.NewThreatFeedRepository()
	clock := func() time.Time { return fixedNow }
	feeds := func() []Feed { return []Feed{ipFeed("ipfeed", "203.0.113.10\n", "e1")} }

	engA, err := NewEngine(DefaultConfig(), feeds(), signer, repo, WithLogger(silentLogger()), WithClock(clock))
	if err != nil {
		t.Fatalf("engine A: %v", err)
	}
	ctx := context.Background()
	resA, err := engA.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("refresh A: %v", err)
	}

	// A fresh engine over the same repo + identical content must
	// continue the same serial and not mint a churn version.
	engB, err := NewEngine(DefaultConfig(), feeds(), signer, repo, WithLogger(silentLogger()), WithClock(clock))
	if err != nil {
		t.Fatalf("engine B: %v", err)
	}
	resB, err := engB.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("refresh B: %v", err)
	}
	if !resB.Unchanged {
		t.Fatalf("restarted engine on identical content should be Unchanged: %+v", resB)
	}
	if resB.Serial != resA.Serial {
		t.Fatalf("restarted engine should continue serial %d, got %d", resA.Serial, resB.Serial)
	}
}

// mutableClock is a test clock that can be advanced between refreshes.
type mutableClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *mutableClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *mutableClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func TestEngine_NoVersionChurnFromRecencyDecay(t *testing.T) {
	t.Parallel()
	// A feed whose content never changes (conditional-GET 304 after the
	// warm-up). As wall-clock time advances between refreshes the
	// recency-decayed score of the cached indicators drifts downward,
	// but the engine must NOT mint a new bundle version: the content
	// digest tracks the indicator SET, not its decaying score. This is
	// the fleet-scale churn-avoidance guarantee — without it every
	// hourly tick would re-sign and re-publish to all tenants.
	clk := &mutableClock{t: fixedNow}
	signer, _ := GenerateSigner()
	repo := memory.NewStore().NewThreatFeedRepository()
	eng, err := NewEngine(DefaultConfig(), []Feed{ipFeed("ipfeed", "203.0.113.10\n", "e1")},
		signer, repo, WithLogger(silentLogger()), WithClock(clk.now))
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	ctx := context.Background()

	first, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if first.Unchanged || first.Indicators != 1 {
		t.Fatalf("warm-up should mint 1 indicator: %+v", first)
	}

	// Advance a full day per refresh; the score decays but the set is
	// identical, so every subsequent refresh must be Unchanged and keep
	// the same serial.
	for i := 0; i < 3; i++ {
		clk.advance(24 * time.Hour)
		res, err := eng.RefreshOnce(ctx)
		if err != nil {
			t.Fatalf("refresh %d: %v", i, err)
		}
		if !res.Unchanged {
			t.Fatalf("refresh %d minted a churn version despite identical set: %+v", i, res)
		}
		if res.Serial != first.Serial {
			t.Fatalf("refresh %d changed serial %d -> %d", i, first.Serial, res.Serial)
		}
	}
}

func TestEngine_HonorsDisabledSource(t *testing.T) {
	t.Parallel()
	good := ipFeed("good", "203.0.113.10\n", "g1")
	off := ipFeed("off", "198.51.100.5\n", "o1")
	eng, repo, _ := newTestEngine(t, []Feed{good, off})
	ctx := context.Background()

	// Operator switches "off" off in the registry (insert as disabled).
	if err := repo.UpsertSources(ctx, []repository.ThreatFeedSource{
		{Name: "off", DisplayName: "Off", Kind: "ip", Weight: 0.9, Enabled: false},
	}); err != nil {
		t.Fatalf("disable source: %v", err)
	}

	res, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if res.Indicators != 1 {
		t.Fatalf("only the enabled feed should contribute, got %d", res.Indicators)
	}
	var offStat SourceStat
	for _, s := range res.Sources {
		if s.Source == "off" {
			offStat = s
		}
	}
	if !offStat.Disabled || offStat.Indicators != 0 {
		t.Fatalf("disabled feed should be skipped with no indicators: %+v", offStat)
	}

	// The disable must survive the curated re-seed a leader runs at boot
	// (SeedRegistry upserts every feed enabled=true; the conflict path
	// preserves the operator's choice).
	if err := eng.SeedRegistry(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sources, err := repo.ListSources(ctx)
	if err != nil {
		t.Fatalf("list sources: %v", err)
	}
	for _, s := range sources {
		if s.Name == "off" && s.Enabled {
			t.Fatal("re-seed re-enabled an operator-disabled source")
		}
	}
	again, err := eng.RefreshOnce(ctx)
	if err != nil {
		t.Fatalf("refresh after reseed: %v", err)
	}
	if again.Indicators != 1 {
		t.Fatalf("disabled feed should stay skipped after reseed, got %d", again.Indicators)
	}
}

func TestEngine_SeedRegistry(t *testing.T) {
	t.Parallel()
	feeds := DefaultFeeds(nil, 0)
	eng, repo, _ := newTestEngine(t, feeds)
	ctx := context.Background()
	if err := eng.SeedRegistry(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := repo.ListSources(ctx)
	if err != nil {
		t.Fatalf("list sources: %v", err)
	}
	if len(got) != len(feeds) {
		t.Fatalf("seeded %d sources, want %d", len(got), len(feeds))
	}
}

func TestEngine_ConcurrentRefreshIsSerialized(t *testing.T) {
	t.Parallel()
	eng, repo, _ := newTestEngine(t, []Feed{ipFeed("ipfeed", "203.0.113.10\n", "e1")})
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := eng.RefreshOnce(ctx); err != nil {
				t.Errorf("concurrent refresh: %v", err)
			}
		}()
	}
	wg.Wait()

	if _, err := repo.LatestBundle(ctx); err != nil {
		t.Fatalf("a bundle should exist after concurrent refreshes: %v", err)
	}
}
