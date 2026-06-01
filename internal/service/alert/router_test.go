// Package alert_test exercises the Router's emit-time
// suppression matching + lifecycle pass-throughs.
//
// Pins:
//   - Matching suppression rule pushes new alert to Suppressed.
//   - Cache is invalidated on Create / Delete suppression.
//   - Acknowledge / Resolve enforce state machine via repo.
//   - publish failures must NOT roll back persistence.
package alert_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/alert"
)

func ctx() context.Context { return context.Background() }

type recordingPub struct {
	mu       sync.Mutex
	calls    []recordedCall
	failNext bool
}

type recordedCall struct {
	subject string
	payload []byte
}

func (p *recordingPub) Publish(ctx context.Context, subject string, data []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.failNext {
		p.failNext = false
		return errors.New("nats: simulated outage")
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	p.calls = append(p.calls, recordedCall{subject: subject, payload: cp})
	return nil
}

func seedTenant(t *testing.T) (*memory.Store, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	s.SetClock(func() time.Time { return time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC) })
	tr := memory.NewTenantRepository(s)
	tnt, err := tr.Create(ctx(), repository.Tenant{
		Name: "T", Slug: "t",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return s, tnt.ID
}

func makeAlert(tnt uuid.UUID) repository.Alert {
	now := time.Now().UTC()
	return repository.Alert{
		Kind:           "baseline.zscore_exceeded",
		Severity:       repository.AlertSeverityWarning,
		Dimension:      "auth.failures",
		ObservedValue:  100,
		BaselineMean:   10,
		BaselineStdDev: 2,
		ZScore:         45,
		WindowStart:    now.Add(-time.Minute),
		WindowEnd:      now,
		WindowSeconds:  60,
		Summary:        "spike",
		Evidence:       []byte(`{}`),
	}
}

func TestRouter_Emit_NoSuppression(t *testing.T) {
	s, tnt := seedTenant(t)
	r := alert.NewRouter(
		memory.NewAlertRepository(s),
		memory.NewAlertSuppressionRepository(s),
		nil,
		alert.Options{},
	)
	saved, err := r.Emit(ctx(), tnt, makeAlert(tnt))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if saved.State != repository.AlertStateOpen {
		t.Fatalf("state = %s, want open", saved.State)
	}
	if saved.SuppressedBy != nil {
		t.Fatalf("SuppressedBy = %v, want nil", saved.SuppressedBy)
	}
}

func TestRouter_Emit_MatchedSuppressionGoesTerminal(t *testing.T) {
	s, tnt := seedTenant(t)
	r := alert.NewRouter(
		memory.NewAlertRepository(s),
		memory.NewAlertSuppressionRepository(s),
		nil,
		alert.Options{},
	)
	kind := "baseline.zscore_exceeded"
	rule, err := r.CreateSuppression(ctx(), tnt, repository.AlertSuppression{
		Kind: &kind, Reason: "burn-in",
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	saved, err := r.Emit(ctx(), tnt, makeAlert(tnt))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if saved.State != repository.AlertStateSuppressed {
		t.Fatalf("state = %s, want suppressed", saved.State)
	}
	if saved.SuppressedBy == nil || *saved.SuppressedBy != rule.ID {
		t.Fatalf("SuppressedBy = %v, want %v", saved.SuppressedBy, rule.ID)
	}
}

func TestRouter_Emit_PublishesPerSeveritySubject(t *testing.T) {
	s, tnt := seedTenant(t)
	pub := &recordingPub{}
	r := alert.NewRouter(
		memory.NewAlertRepository(s),
		memory.NewAlertSuppressionRepository(s),
		pub,
		alert.Options{SubjectPrefix: "sng"},
	)
	saved, err := r.Emit(ctx(), tnt, makeAlert(tnt))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if len(pub.calls) != 1 {
		t.Fatalf("publishes = %d, want 1", len(pub.calls))
	}
	wantSubj := "sng." + tnt.String() + ".alerts." + saved.Kind + "." + string(saved.Severity)
	if pub.calls[0].subject != wantSubj {
		t.Fatalf("subject = %s, want %s", pub.calls[0].subject, wantSubj)
	}
	var roundTrip repository.Alert
	if err := json.Unmarshal(pub.calls[0].payload, &roundTrip); err != nil {
		t.Fatalf("round-trip: %v", err)
	}
	if roundTrip.ID != saved.ID {
		t.Fatalf("payload id = %v, want %v", roundTrip.ID, saved.ID)
	}
}

func TestRouter_Emit_PublishFailureDoesNotRollback(t *testing.T) {
	s, tnt := seedTenant(t)
	pub := &recordingPub{failNext: true}
	r := alert.NewRouter(
		memory.NewAlertRepository(s),
		memory.NewAlertSuppressionRepository(s),
		pub,
		alert.Options{},
	)
	saved, err := r.Emit(ctx(), tnt, makeAlert(tnt))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if saved.ID == uuid.Nil {
		t.Fatalf("alert not persisted on publish failure")
	}
}

func TestRouter_AcknowledgeAndResolve(t *testing.T) {
	s, tnt := seedTenant(t)
	r := alert.NewRouter(
		memory.NewAlertRepository(s),
		memory.NewAlertSuppressionRepository(s),
		nil,
		alert.Options{},
	)
	saved, err := r.Emit(ctx(), tnt, makeAlert(tnt))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	by := uuid.New()
	acked, err := r.Acknowledge(ctx(), tnt, saved.ID, &by)
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	if acked.State != repository.AlertStateAcknowledged {
		t.Fatalf("state = %s, want acknowledged", acked.State)
	}
	resolved, err := r.Resolve(ctx(), tnt, saved.ID, &by)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if resolved.State != repository.AlertStateResolved {
		t.Fatalf("state = %s, want resolved", resolved.State)
	}
}

func TestRouter_SuppressionCache_InvalidatedOnCreateDelete(t *testing.T) {
	s, tnt := seedTenant(t)
	r := alert.NewRouter(
		memory.NewAlertRepository(s),
		memory.NewAlertSuppressionRepository(s),
		nil,
		alert.Options{},
	)
	// Emit prior to suppression — must persist as Open.
	saved1, err := r.Emit(ctx(), tnt, makeAlert(tnt))
	if err != nil {
		t.Fatalf("emit1: %v", err)
	}
	if saved1.State != repository.AlertStateOpen {
		t.Fatalf("state = %s, want open", saved1.State)
	}

	// Add suppression; cache is invalidated, next emit is suppressed.
	kind := "baseline.zscore_exceeded"
	rule, err := r.CreateSuppression(ctx(), tnt, repository.AlertSuppression{
		Kind: &kind, Reason: "operator-defined",
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	saved2, err := r.Emit(ctx(), tnt, makeAlert(tnt))
	if err != nil {
		t.Fatalf("emit2: %v", err)
	}
	if saved2.State != repository.AlertStateSuppressed {
		t.Fatalf("state = %s, want suppressed", saved2.State)
	}

	// Delete rule; cache invalidated; next emit open again.
	if err := r.DeleteSuppression(ctx(), tnt, rule.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	saved3, err := r.Emit(ctx(), tnt, makeAlert(tnt))
	if err != nil {
		t.Fatalf("emit3: %v", err)
	}
	if saved3.State != repository.AlertStateOpen {
		t.Fatalf("state = %s, want open after suppression delete", saved3.State)
	}
}

func TestRouter_Suppression_MatchesDimensionWildcard(t *testing.T) {
	s, tnt := seedTenant(t)
	r := alert.NewRouter(
		memory.NewAlertRepository(s),
		memory.NewAlertSuppressionRepository(s),
		nil,
		alert.Options{},
	)
	// Rule scoped by dimension only (kind wildcard).
	dim := "auth.failures"
	if _, err := r.CreateSuppression(ctx(), tnt, repository.AlertSuppression{
		Dimension: &dim, Reason: "burn-in",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	saved, err := r.Emit(ctx(), tnt, makeAlert(tnt))
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if saved.State != repository.AlertStateSuppressed {
		t.Fatalf("state = %s, want suppressed (dim wildcard rule)", saved.State)
	}
	// Same kind but different dimension — NOT suppressed.
	other := makeAlert(tnt)
	other.Dimension = "dns.queries.NXDOMAIN"
	saved2, err := r.Emit(ctx(), tnt, other)
	if err != nil {
		t.Fatalf("emit2: %v", err)
	}
	if saved2.State != repository.AlertStateOpen {
		t.Fatalf("state = %s, want open (different dim)", saved2.State)
	}
}

func TestRouter_ListAndGet(t *testing.T) {
	s, tnt := seedTenant(t)
	r := alert.NewRouter(
		memory.NewAlertRepository(s),
		memory.NewAlertSuppressionRepository(s),
		nil,
		alert.Options{},
	)
	for i := 0; i < 3; i++ {
		if _, err := r.Emit(ctx(), tnt, makeAlert(tnt)); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	pg, err := r.List(ctx(), tnt, repository.AlertListFilter{}, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pg.Items) != 3 {
		t.Fatalf("len = %d, want 3", len(pg.Items))
	}
	got, err := r.Get(ctx(), tnt, pg.Items[0].ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.ID != pg.Items[0].ID {
		t.Fatalf("get returned wrong row")
	}
}

// countingSuppressions wraps a repository.AlertSuppressionRepository
// and exposes a ListActive counter so tests can assert how many
// times the suppression cache fell through to the repository.
type countingSuppressions struct {
	repository.AlertSuppressionRepository
	mu              sync.Mutex
	listActiveCalls int
	gate            chan struct{} // optional: blocks ListActive until released
}

func (c *countingSuppressions) ListActive(
	ctx context.Context,
	tenantID uuid.UUID,
	at time.Time,
) ([]repository.AlertSuppression, error) {
	c.mu.Lock()
	c.listActiveCalls++
	g := c.gate
	c.mu.Unlock()
	if g != nil {
		<-g
	}
	return c.AlertSuppressionRepository.ListActive(ctx, tenantID, at)
}

// TestRouter_SuppressionCache_CoalescesConcurrentMisses pins
// the PR #40 round-8 ANALYSIS_0001 fix: a thundering herd of
// concurrent Emits for the same tenant whose suppression cache
// is cold must collapse into exactly one ListActive call via
// the per-tenant singleflight group.
func TestRouter_SuppressionCache_CoalescesConcurrentMisses(t *testing.T) {
	s, tnt := seedTenant(t)
	suppr := &countingSuppressions{
		AlertSuppressionRepository: memory.NewAlertSuppressionRepository(s),
		gate:                       make(chan struct{}),
	}
	r := alert.NewRouter(
		memory.NewAlertRepository(s),
		suppr,
		nil,
		alert.Options{},
	)

	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.Emit(ctx(), tnt, makeAlert(tnt))
			errs <- err
		}()
	}
	// Give all goroutines a beat to land inside the singleflight
	// before we release the gate. 50ms is plenty on any
	// reasonable scheduler; if the test machine is so loaded
	// that 16 goroutines can't spawn in 50ms, the singleflight
	// path will still coalesce them — just may collect fewer.
	// We assert the count is >= the herd size below.
	time.Sleep(50 * time.Millisecond)
	close(suppr.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("emit failed: %v", err)
		}
	}
	suppr.mu.Lock()
	calls := suppr.listActiveCalls
	suppr.mu.Unlock()
	if calls != 1 {
		t.Fatalf("ListActive call count = %d, want 1 (singleflight coalescing)", calls)
	}
}

func TestRouter_RejectsNilTenant(t *testing.T) {
	s, _ := seedTenant(t)
	r := alert.NewRouter(
		memory.NewAlertRepository(s),
		memory.NewAlertSuppressionRepository(s),
		nil,
		alert.Options{},
	)
	_, err := r.Emit(ctx(), uuid.Nil, makeAlert(uuid.New()))
	if !errors.Is(err, repository.ErrInvalidArgument) {
		// Wrap is fine, just need ErrInvalidArgument in chain or message.
		if err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Fatalf("err = %v, want ErrInvalidArgument", err)
		}
	}
}
