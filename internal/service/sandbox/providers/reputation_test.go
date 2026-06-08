package providers

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// stubDoer is an in-memory HTTPDoer: it returns a canned response
// (status + body) and records the last request for assertions. No
// network, so provider tests are hermetic.
type stubDoer struct {
	status   int
	body     string
	err      error
	lastReq  *http.Request
	reqCount int
	// per-call responses keyed by URL substring (optional); falls
	// back to status/body when no key matches.
	routes map[string]stubResponse
}

type stubResponse struct {
	status int
	body   string
}

func (s *stubDoer) Do(req *http.Request) (*http.Response, error) {
	s.lastReq = req
	s.reqCount++
	if s.err != nil {
		return nil, s.err
	}
	status, body := s.status, s.body
	for sub, r := range s.routes {
		if strings.Contains(req.URL.String(), sub) {
			status, body = r.status, r.body
			break
		}
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}, nil
}

func TestVirusTotal_Malicious(t *testing.T) {
	doer := &stubDoer{status: 200, body: `{
		"data": {"attributes": {
			"last_analysis_stats": {"malicious": 40, "suspicious": 2, "undetected": 10, "harmless": 0, "timeout": 0},
			"popular_threat_classification": {"suggested_threat_label": "trojan.emotet/x"}
		}}
	}`}
	vt := NewVirusTotal(VirusTotalConfig{APIKey: "k", MinRequestInterval: -1}, doer)

	res, err := vt.Submit(context.Background(), File{SHA256: "ab", Filename: "x"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Status != StatusComplete {
		t.Fatalf("status = %s, want complete", res.Status)
	}
	if res.Result.Classification != ClassMalicious {
		t.Fatalf("class = %s, want malicious", res.Result.Classification)
	}
	if res.Result.Provider != "virustotal" {
		t.Fatalf("provider = %s", res.Result.Provider)
	}
	if doer.lastReq.Header.Get("x-apikey") != "k" {
		t.Fatalf("missing x-apikey header")
	}
}

func TestVirusTotal_CleanAndUnknown(t *testing.T) {
	clean := &stubDoer{status: 200, body: `{"data":{"attributes":{"last_analysis_stats":{"malicious":0,"suspicious":0,"undetected":5,"harmless":60,"timeout":0}}}}`}
	vt := NewVirusTotal(VirusTotalConfig{APIKey: "k", MinRequestInterval: -1}, clean)
	res, err := vt.Submit(context.Background(), File{SHA256: "ab"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Result.Classification != ClassClean {
		t.Fatalf("class = %s, want clean", res.Result.Classification)
	}

	notFound := &stubDoer{status: 404, body: `{"error":{"code":"NotFoundError"}}`}
	vt2 := NewVirusTotal(VirusTotalConfig{APIKey: "k", MinRequestInterval: -1}, notFound)
	res2, err := vt2.Submit(context.Background(), File{SHA256: "cd"})
	if err != nil {
		t.Fatalf("submit 404: %v", err)
	}
	if res2.Result.Classification != ClassUnknown {
		t.Fatalf("404 class = %s, want unknown", res2.Result.Classification)
	}
}

func TestVirusTotal_Errors(t *testing.T) {
	// Unconfigured → unavailable.
	vt := NewVirusTotal(VirusTotalConfig{}, &stubDoer{status: 200})
	if _, err := vt.Submit(context.Background(), File{SHA256: "ab"}); err != ErrProviderUnavailable {
		t.Fatalf("unconfigured err = %v, want ErrProviderUnavailable", err)
	}
	// 429 → hard error.
	rl := NewVirusTotal(VirusTotalConfig{APIKey: "k", MinRequestInterval: -1}, &stubDoer{status: 429, body: ""})
	if _, err := rl.Submit(context.Background(), File{SHA256: "ab"}); err == nil {
		t.Fatalf("expected error on 429")
	}
}

func TestHybridAnalysis_VerdictAndScore(t *testing.T) {
	mal := &stubDoer{status: 200, body: `[{"verdict":"malicious","threat_score":95,"vx_family":"WannaCry"}]`}
	ha := NewHybridAnalysis(HybridAnalysisConfig{APIKey: "k", MinRequestInterval: -1}, mal)
	res, err := ha.Submit(context.Background(), File{SHA256: "ab"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Result.Classification != ClassMalicious {
		t.Fatalf("class = %s, want malicious", res.Result.Classification)
	}
	if ha.configured() && mal.lastReq.Header.Get("User-Agent") != "Falcon Sandbox" {
		t.Fatalf("missing Falcon Sandbox UA")
	}
	if mal.lastReq.Header.Get("api-key") != "k" {
		t.Fatalf("missing api-key header")
	}

	// Score-only fallback (no verdict string): 50 → suspicious by default thresholds.
	susp := &stubDoer{status: 200, body: `[{"verdict":"","threat_score":50}]`}
	ha2 := NewHybridAnalysis(HybridAnalysisConfig{APIKey: "k", MinRequestInterval: -1}, susp)
	res2, _ := ha2.Submit(context.Background(), File{SHA256: "ab"})
	if res2.Result.Classification != ClassSuspicious {
		t.Fatalf("score 50 class = %s, want suspicious", res2.Result.Classification)
	}

	// Empty array → unknown.
	none := &stubDoer{status: 200, body: `[]`}
	ha3 := NewHybridAnalysis(HybridAnalysisConfig{APIKey: "k", MinRequestInterval: -1}, none)
	res3, _ := ha3.Submit(context.Background(), File{SHA256: "ab"})
	if res3.Result.Classification != ClassUnknown {
		t.Fatalf("empty class = %s, want unknown", res3.Result.Classification)
	}
}

// fakeProvider is a Provider returning a fixed synchronous verdict
// or error, for aggregator tests.
type fakeProvider struct {
	id     string
	class  Classification
	conf   float64
	err    error
	status Status
}

func (f *fakeProvider) ID() string { return f.id }
func (f *fakeProvider) Submit(_ context.Context, _ File) (SubmitResult, error) {
	if f.err != nil {
		return SubmitResult{}, f.err
	}
	st := f.status
	if st == "" {
		st = StatusComplete
	}
	return SubmitResult{SandboxID: "id", Status: st, Result: PollResult{
		Status: StatusComplete, Classification: f.class, Confidence: f.conf, Provider: f.id,
		AnalyzedAt: time.Now(),
	}}, nil
}
func (f *fakeProvider) Poll(_ context.Context, _ string) (PollResult, error) {
	if f.err != nil {
		return PollResult{}, f.err
	}
	return PollResult{Status: StatusComplete, Classification: f.class, Confidence: f.conf, Provider: f.id}, nil
}

func TestAggregator_TakesStrictest(t *testing.T) {
	agg := NewAggregator("agg",
		&fakeProvider{id: "clean1", class: ClassClean, conf: 0.9},
		&fakeProvider{id: "vt", class: ClassMalicious, conf: 0.8},
		&fakeProvider{id: "ha", class: ClassSuspicious, conf: 0.5},
	)
	res, err := agg.Submit(context.Background(), File{SHA256: "ab"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Result.Classification != ClassMalicious {
		t.Fatalf("class = %s, want malicious (strictest)", res.Result.Classification)
	}
	if res.Result.Provider != "vt" {
		t.Fatalf("winning provider = %s, want vt", res.Result.Provider)
	}
	if !strings.Contains(res.Result.Summary, "clean1=clean") || !strings.Contains(res.Result.Summary, "ha=suspicious") {
		t.Fatalf("summary missing per-provider breakdown: %q", res.Result.Summary)
	}
}

func TestAggregator_UnknownDoesNotOverrideClean(t *testing.T) {
	agg := NewAggregator("agg",
		&fakeProvider{id: "vt", class: ClassUnknown},
		&fakeProvider{id: "ha", class: ClassClean, conf: 0.7},
	)
	res, err := agg.Submit(context.Background(), File{SHA256: "ab"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Result.Classification != ClassClean {
		t.Fatalf("class = %s, want clean", res.Result.Classification)
	}
}

func TestAggregator_AllUnavailable(t *testing.T) {
	agg := NewAggregator("agg",
		&fakeProvider{id: "vt", err: ErrProviderUnavailable},
		&fakeProvider{id: "ha", err: ErrProviderUnavailable},
	)
	if _, err := agg.Submit(context.Background(), File{SHA256: "ab"}); err != ErrProviderUnavailable {
		t.Fatalf("err = %v, want ErrProviderUnavailable", err)
	}
}

func TestAggregator_PartialFailureStillResolves(t *testing.T) {
	agg := NewAggregator("agg",
		&fakeProvider{id: "vt", class: ClassMalicious, conf: 0.9},
		&fakeProvider{id: "ha", err: context.DeadlineExceeded},
	)
	res, err := agg.Submit(context.Background(), File{SHA256: "ab"})
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if res.Result.Classification != ClassMalicious {
		t.Fatalf("class = %s, want malicious", res.Result.Classification)
	}
}

func TestAggregator_Empty(t *testing.T) {
	agg := NewAggregator("")
	if agg.ID() != "aggregator" {
		t.Fatalf("default id = %s", agg.ID())
	}
	if _, err := agg.Submit(context.Background(), File{SHA256: "ab"}); err != ErrProviderUnavailable {
		t.Fatalf("empty aggregator err = %v", err)
	}
}

func TestRateLimiter_Paces(t *testing.T) {
	rl := newRateLimiter(50 * time.Millisecond)
	start := time.Now()
	for i := 0; i < 3; i++ {
		if err := rl.acquire(context.Background()); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	// Three acquisitions at 50ms spacing: slots at 0, 50, 100ms.
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Fatalf("limiter did not pace: %v elapsed", elapsed)
	}
}

func TestRateLimiter_ContextCancel(t *testing.T) {
	rl := newRateLimiter(time.Hour)
	_ = rl.acquire(context.Background()) // consume first slot (immediate)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := rl.acquire(ctx); err == nil {
		t.Fatalf("expected context error on cancelled acquire")
	}
}

func TestRateLimiter_TailCancellationReclaimsSlot(t *testing.T) {
	t0 := time.Unix(0, 0).UTC()
	interval := time.Minute
	rl := newRateLimiter(interval)
	rl.now = func() time.Time { return t0 } // frozen clock

	// A consumes the first (immediate) slot; next == t0+interval.
	if err := rl.acquire(context.Background()); err != nil {
		t.Fatalf("A acquire: %v", err)
	}
	// B reserves t0+interval then abandons mid-sleep. Since B holds the
	// tail, its slot must be reclaimed so `next` rewinds to that slot
	// (t0+interval) — the abandoned slot becomes reusable by the next
	// arrival rather than the gate skewing pacing forward to t0+2*interval.
	rl.sleep = func(context.Context, time.Duration) error { return context.Canceled }
	if err := rl.acquire(context.Background()); err == nil {
		t.Fatalf("B acquire: expected cancellation error")
	}
	rl.mu.Lock()
	got := rl.next
	rl.mu.Unlock()
	if want := t0.Add(interval); !got.Equal(want) {
		t.Fatalf("tail cancellation did not reclaim slot: next=%v want %v", got, want)
	}
}

func TestRateLimiter_NonTailCancellationDoesNotOverlap(t *testing.T) {
	t0 := time.Unix(0, 0).UTC()
	interval := time.Minute
	rl := newRateLimiter(interval)
	rl.now = func() time.Time { return t0 } // frozen clock

	// A consumes the first (immediate) slot; next == t0+interval.
	if err := rl.acquire(context.Background()); err != nil {
		t.Fatalf("A acquire: %v", err)
	}

	// B reserves t0+interval. While B is "sleeping", C reserves the slot
	// after B (t0+2*interval) and is admitted; THEN B's context is
	// cancelled. B must not rewind `next` into C's reserved slot.
	var tailAfterC time.Time
	rl.sleep = func(ctx context.Context, d time.Duration) error {
		prev := rl.sleep
		rl.sleep = func(context.Context, time.Duration) error { return nil } // C admitted
		if err := rl.acquire(context.Background()); err != nil {
			t.Fatalf("C acquire: %v", err)
		}
		rl.sleep = prev
		rl.mu.Lock()
		tailAfterC = rl.next
		rl.mu.Unlock()
		return context.Canceled // B abandons
	}
	if err := rl.acquire(context.Background()); err == nil {
		t.Fatalf("B acquire: expected cancellation error")
	}

	// C reserved t0+3*interval as the tail; B's bail-out must leave it
	// untouched so the next arrival cannot collide with C's slot.
	if want := t0.Add(3 * interval); !tailAfterC.Equal(want) {
		t.Fatalf("C tail = %v, want %v", tailAfterC, want)
	}
	rl.mu.Lock()
	got := rl.next
	rl.mu.Unlock()
	if !got.Equal(tailAfterC) {
		t.Fatalf("non-tail cancellation corrupted pacing: next=%v want %v (overlap with C)", got, tailAfterC)
	}
}

func TestRateLimiter_DisabledIsImmediate(t *testing.T) {
	rl := newRateLimiter(0)
	start := time.Now()
	for i := 0; i < 100; i++ {
		if err := rl.acquire(context.Background()); err != nil {
			t.Fatalf("acquire: %v", err)
		}
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatalf("disabled limiter should be immediate")
	}
}
