package dem_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/dem"
)

// stubAlerts is an in-memory AlertGateway recording emitted alerts.
type stubAlerts struct {
	mu      sync.Mutex
	emitted []repository.Alert
}

func (s *stubAlerts) Emit(_ context.Context, tenantID uuid.UUID, a repository.Alert) (repository.Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a.ID = uuid.New()
	a.TenantID = tenantID
	s.emitted = append(s.emitted, a)
	return a, nil
}

func (s *stubAlerts) List(_ context.Context, tenantID uuid.UUID, filter repository.AlertListFilter, _ repository.Page) (repository.PageResult[repository.Alert], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kinds := map[string]struct{}{}
	for _, k := range filter.Kinds {
		kinds[k] = struct{}{}
	}
	var items []repository.Alert
	for _, a := range s.emitted {
		if a.TenantID != tenantID {
			continue
		}
		if len(kinds) > 0 {
			if _, ok := kinds[a.Kind]; !ok {
				continue
			}
		}
		items = append(items, a)
	}
	return repository.PageResult[repository.Alert]{Items: items}, nil
}

func (s *stubAlerts) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.emitted)
}

type harness struct {
	svc    *dem.Service
	repo   *memory.DEMRepository
	alerts *stubAlerts
	now    time.Time
}

func newHarness(t *testing.T, cfg dem.Config) *harness {
	t.Helper()
	store := memory.NewStore()
	h := &harness{
		repo:   memory.NewDEMRepository(store),
		alerts: &stubAlerts{},
		now:    time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC),
	}
	store.SetClock(func() time.Time { return h.now })
	svc, err := dem.NewService(h.repo, h.alerts, cfg, dem.WithClock(func() time.Time { return h.now }))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	h.svc = svc
	return h
}

func okResult(now time.Time, totalMs float64) repository.DEMProbeResult {
	v := totalMs
	status := 200
	return repository.DEMProbeResult{
		TargetKey:  "zoom",
		TargetName: "Zoom",
		ProbeKind:  dem.ProbeKindHTTPS,
		Success:    true,
		TotalMs:    &v,
		HTTPStatus: &status,
		ObservedAt: now,
	}
}

func failResultAt(now time.Time) repository.DEMProbeResult {
	return repository.DEMProbeResult{
		TargetKey:  "zoom",
		TargetName: "Zoom",
		ProbeKind:  dem.ProbeKindHTTPS,
		Success:    false,
		ErrorKind:  dem.ErrorKindTimeout,
		ObservedAt: now,
	}
}

func TestService_Ingest_ComputesHealthyScore(t *testing.T) {
	h := newHarness(t, dem.DefaultConfig())
	tenant := uuid.New()

	res, err := h.svc.Ingest(context.Background(), tenant, []repository.DEMProbeResult{
		okResult(h.now, 20),
		okResult(h.now, 30),
	})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if res.Accepted != 2 {
		t.Fatalf("accepted = %d, want 2", res.Accepted)
	}
	if len(res.Scores) != 1 {
		t.Fatalf("scores = %d, want 1", len(res.Scores))
	}
	sc := res.Scores[0]
	if sc.Availability != 1 || sc.Score < 99 {
		t.Fatalf("healthy score = %v (avail %v), want ~100/1", sc.Score, sc.Availability)
	}
	if h.alerts.count() != 0 {
		t.Fatalf("healthy ingest raised %d alerts, want 0", h.alerts.count())
	}

	latest, err := h.svc.LatestScores(context.Background(), tenant)
	if err != nil {
		t.Fatalf("latest: %v", err)
	}
	if len(latest) != 1 || latest[0].TargetKey != "zoom" {
		t.Fatalf("latest scores = %+v", latest)
	}
}

// failingBaselineRepo wraps a real DEMRepository but forces
// MutateTargetState to fail, simulating the baseline-update backend
// going down *after* a score has already been durably stored by
// InsertScore. It counts successful InsertScore calls so the test can
// assert the score really was persisted.
type failingBaselineRepo struct {
	repository.DEMRepository
	insertedScores int
}

func (f *failingBaselineRepo) InsertScore(ctx context.Context, tenantID uuid.UUID, s repository.DEMExperienceScore) (repository.DEMExperienceScore, error) {
	out, err := f.DEMRepository.InsertScore(ctx, tenantID, s)
	if err == nil {
		f.insertedScores++
	}
	return out, err
}

func (f *failingBaselineRepo) MutateTargetState(
	_ context.Context,
	_ uuid.UUID,
	_, _ string,
	_ func(repository.DEMTargetState) (repository.DEMTargetState, error),
) (repository.DEMTargetState, error) {
	return repository.DEMTargetState{}, errors.New("baseline backend unavailable")
}

// TestService_Ingest_ReportsStoredScoreWhenBaselineUpdateFails proves
// that a score which was durably stored is still returned in the
// ingest response even when the secondary baseline update fails. The
// baseline fold / alert emission is best-effort and must not erase a
// score the client could otherwise read back via GET /scores.
func TestService_Ingest_ReportsStoredScoreWhenBaselineUpdateFails(t *testing.T) {
	store := memory.NewStore()
	now := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	store.SetClock(func() time.Time { return now })
	repo := &failingBaselineRepo{DEMRepository: memory.NewDEMRepository(store)}
	alerts := &stubAlerts{}
	svc, err := dem.NewService(repo, alerts, dem.DefaultConfig(),
		dem.WithClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("new service: %v", err)
	}

	res, err := svc.Ingest(context.Background(), uuid.New(), []repository.DEMProbeResult{
		okResult(now, 20),
		okResult(now, 30),
	})
	// Ingest must not fail: raw results and the score are durably
	// stored; only the secondary baseline update failed (logged).
	if err != nil {
		t.Fatalf("ingest returned error: %v", err)
	}
	if res.Accepted != 2 {
		t.Fatalf("accepted = %d, want 2", res.Accepted)
	}
	if repo.insertedScores != 1 {
		t.Fatalf("insertedScores = %d, want 1 (score must be durably stored)", repo.insertedScores)
	}
	if len(res.Scores) != 1 {
		t.Fatalf("scores = %d, want 1 — a durably stored score must be reported even when the baseline update fails", len(res.Scores))
	}
}

func TestService_Ingest_RejectsBadResult(t *testing.T) {
	h := newHarness(t, dem.DefaultConfig())
	tenant := uuid.New()
	_, err := h.svc.Ingest(context.Background(), tenant, []repository.DEMProbeResult{
		{TargetKey: "zoom", TargetName: "Zoom", ProbeKind: "carrier-pigeon", ObservedAt: h.now, Success: true},
	})
	if err == nil {
		t.Fatalf("expected error for invalid probe_kind")
	}
}

// TestService_Ingest_RejectsMissingObservedAt verifies the observed_at
// contract is actually enforced. An absent observed_at_ms arrives as the
// Unix epoch (time.UnixMilli(0)) from the handler, and an unset domain
// value is Go's zero time; both must be rejected as invalid argument.
func TestService_Ingest_RejectsMissingObservedAt(t *testing.T) {
	h := newHarness(t, dem.DefaultConfig())
	tenant := uuid.New()

	cases := map[string]time.Time{
		"epoch (absent observed_at_ms)": time.UnixMilli(0).UTC(),
		"go zero time":                  {},
	}
	for name, observedAt := range cases {
		t.Run(name, func(t *testing.T) {
			r := okResult(h.now, 20)
			r.ObservedAt = observedAt
			_, err := h.svc.Ingest(context.Background(), tenant, []repository.DEMProbeResult{r})
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("expected ErrInvalidArgument for %s, got %v", name, err)
			}
		})
	}
}

func TestService_DegradationRaisesAlert(t *testing.T) {
	cfg := dem.DefaultConfig()
	h := newHarness(t, cfg)
	tenant := uuid.New()
	ctx := context.Background()

	// Mature a healthy baseline: many windows of fast, available
	// probes. Advance the clock past the window each iteration so each
	// ingest scores a fresh, fully-healthy window (~100).
	for i := 0; i < 15; i++ {
		h.now = h.now.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
		if _, err := h.svc.Ingest(ctx, tenant, []repository.DEMProbeResult{
			okResult(h.now, 20),
			okResult(h.now, 25),
		}); err != nil {
			t.Fatalf("baseline ingest %d: %v", i, err)
		}
	}
	if h.alerts.count() != 0 {
		t.Fatalf("healthy baseline raised %d alerts, want 0", h.alerts.count())
	}

	// Now the target goes fully dark: a window of all-failed probes.
	h.now = h.now.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
	if _, err := h.svc.Ingest(ctx, tenant, []repository.DEMProbeResult{
		failResultAt(h.now),
		failResultAt(h.now),
	}); err != nil {
		t.Fatalf("degraded ingest: %v", err)
	}
	if h.alerts.count() != 1 {
		t.Fatalf("degradation raised %d alerts, want 1", h.alerts.count())
	}

	alerts, err := h.svc.ListAlerts(ctx, tenant, nil, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	if len(alerts.Items) != 1 {
		t.Fatalf("listed %d alerts, want 1", len(alerts.Items))
	}
	a := alerts.Items[0]
	if a.Kind != dem.ExperienceDegradedKind || a.Dimension != "zoom" {
		t.Fatalf("alert kind/dim = %s/%s", a.Kind, a.Dimension)
	}
	if a.Severity != repository.AlertSeverityCritical {
		t.Fatalf("severity = %s, want critical (availability 0)", a.Severity)
	}
}

func TestService_AlertCooldown(t *testing.T) {
	cfg := dem.DefaultConfig()
	h := newHarness(t, cfg)
	tenant := uuid.New()
	ctx := context.Background()

	// Two consecutive degraded windows within the cooldown window
	// should yield exactly one alert.
	for i := 0; i < 2; i++ {
		h.now = h.now.Add(time.Duration(cfg.WindowSeconds+1) * time.Second)
		if _, err := h.svc.Ingest(ctx, tenant, []repository.DEMProbeResult{
			failResultAt(h.now),
		}); err != nil {
			t.Fatalf("degraded ingest %d: %v", i, err)
		}
	}
	if h.alerts.count() != 1 {
		t.Fatalf("cooldown: %d alerts, want 1", h.alerts.count())
	}

	// After the cooldown elapses, a further degraded window re-alerts.
	h.now = h.now.Add(cfg.AlertCooldown + time.Minute)
	if _, err := h.svc.Ingest(ctx, tenant, []repository.DEMProbeResult{
		failResultAt(h.now),
	}); err != nil {
		t.Fatalf("post-cooldown ingest: %v", err)
	}
	if h.alerts.count() != 2 {
		t.Fatalf("post-cooldown: %d alerts, want 2", h.alerts.count())
	}
}

func TestService_EffectiveTargets_DefaultsAndOverride(t *testing.T) {
	h := newHarness(t, dem.DefaultConfig())
	tenant := uuid.New()
	ctx := context.Background()

	base, err := h.svc.ListEffectiveTargets(ctx, tenant)
	if err != nil {
		t.Fatalf("list effective: %v", err)
	}
	if len(base) != len(dem.ManagedDefaultTargets()) {
		t.Fatalf("effective defaults = %d, want %d", len(base), len(dem.ManagedDefaultTargets()))
	}

	// A custom target with a new key adds one.
	if _, err := h.svc.CreateTarget(ctx, tenant, repository.DEMTarget{
		TargetKey: "internal_wiki", Name: "Wiki", ProbeKind: dem.ProbeKindHTTPS,
		Address: "https://wiki.internal", Enabled: true,
	}); err != nil {
		t.Fatalf("create custom: %v", err)
	}
	// Disabling a default key removes it from the effective set.
	if _, err := h.svc.CreateTarget(ctx, tenant, repository.DEMTarget{
		TargetKey: "github", Name: "GitHub (off)", ProbeKind: dem.ProbeKindHTTPS,
		Address: "https://github.com", Enabled: false,
	}); err != nil {
		t.Fatalf("create disable: %v", err)
	}

	eff, err := h.svc.ListEffectiveTargets(ctx, tenant)
	if err != nil {
		t.Fatalf("list effective 2: %v", err)
	}
	keys := map[string]bool{}
	for _, tg := range eff {
		keys[tg.TargetKey] = true
	}
	if !keys["internal_wiki"] {
		t.Fatalf("custom target missing from effective set")
	}
	if keys["github"] {
		t.Fatalf("disabled default still present in effective set")
	}
}

func TestService_CreateTarget_Validation(t *testing.T) {
	h := newHarness(t, dem.DefaultConfig())
	tenant := uuid.New()
	ctx := context.Background()

	// Missing address.
	if _, err := h.svc.CreateTarget(ctx, tenant, repository.DEMTarget{
		TargetKey: "x", Name: "X", ProbeKind: dem.ProbeKindHTTPS,
	}); err == nil {
		t.Fatalf("expected validation error for missing address")
	}
	// Defaults applied for interval/timeout when omitted.
	created, err := h.svc.CreateTarget(ctx, tenant, repository.DEMTarget{
		TargetKey: "x", Name: "X", ProbeKind: dem.ProbeKindHTTPS, Address: "https://x.test", Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.IntervalSeconds != dem.DefaultProbeIntervalSeconds || created.TimeoutMs != dem.DefaultProbeTimeoutMs {
		t.Fatalf("defaults not applied: %+v", created)
	}
}

func TestService_PruneRetention(t *testing.T) {
	cfg := dem.DefaultConfig()
	h := newHarness(t, cfg)
	tenant := uuid.New()
	ctx := context.Background()

	if _, err := h.svc.Ingest(ctx, tenant, []repository.DEMProbeResult{okResult(h.now, 20)}); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// Advance well past both retention horizons, then sweep.
	h.now = h.now.Add(cfg.RawRetention + cfg.ScoreRetention + 24*time.Hour)
	raw, scores, err := h.svc.PruneRetention(ctx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if raw < 1 || scores < 1 {
		t.Fatalf("pruned raw=%d scores=%d, want >=1 each", raw, scores)
	}
}
