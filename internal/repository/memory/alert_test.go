// Package memory_test — alert_test exercises the three alert
// repositories: AlertRepository, AlertSuppressionRepository,
// AlertFeedbackRepository.
//
// The state-machine pins (Acknowledge / Resolve transitions,
// terminal-state rejection, idempotency) are the most important
// contract pins here — the postgres impl must mirror them.
package memory_test

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func seedAlertTenant(t *testing.T) (*memory.Store, repository.Tenant) {
	t.Helper()
	s := newStore(t)
	tr := memory.NewTenantRepository(s)
	tnt, err := tr.Create(ctx(), repository.Tenant{
		Name: "AL", Slug: "al",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return s, tnt
}

func makeAlert(tenantID uuid.UUID) repository.Alert {
	now := time.Now().UTC()
	return repository.Alert{
		TenantID:       tenantID,
		Kind:           "baseline.zscore_exceeded",
		Severity:       repository.AlertSeverityWarning,
		Dimension:      "dns.queries.NXDOMAIN",
		ObservedValue:  500,
		BaselineMean:   100,
		BaselineStdDev: 25,
		ZScore:         16,
		WindowStart:    now.Add(-time.Minute),
		WindowEnd:      now,
		WindowSeconds:  60,
		Summary:        "DNS NXDOMAIN spike",
		Evidence:       []byte(`{"sample_count":1000}`),
		State:          repository.AlertStateOpen,
	}
}

// --- AlertRepository ----------------------------------------------------

func TestAlert_Create_HappyPath(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	repo := memory.NewAlertRepository(s)
	saved, err := repo.Create(ctx(), tnt.ID, makeAlert(tnt.ID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if saved.ID == uuid.Nil {
		t.Fatalf("missing id")
	}
	if saved.State != repository.AlertStateOpen {
		t.Fatalf("state = %s, want open", saved.State)
	}
}

func TestAlert_Create_RejectsInvalid(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	repo := memory.NewAlertRepository(s)
	cases := map[string]func(a *repository.Alert){
		"empty kind":        func(a *repository.Alert) { a.Kind = "" },
		"empty dimension":   func(a *repository.Alert) { a.Dimension = "" },
		"empty summary":     func(a *repository.Alert) { a.Summary = "" },
		"invalid severity":  func(a *repository.Alert) { a.Severity = "" },
		"invalid state":     func(a *repository.Alert) { a.State = "bogus" },
		"window end before": func(a *repository.Alert) { a.WindowEnd = a.WindowStart.Add(-time.Second) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := makeAlert(tnt.ID)
			mutate(&a)
			_, err := repo.Create(ctx(), tnt.ID, a)
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestAlert_Acknowledge_IdempotentAndTerminalReject(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	repo := memory.NewAlertRepository(s)
	saved, err := repo.Create(ctx(), tnt.ID, makeAlert(tnt.ID))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	by := uuid.New()
	at := time.Now().UTC()
	acked, err := repo.Acknowledge(ctx(), tnt.ID, saved.ID, &by, at)
	if err != nil {
		t.Fatalf("ack: %v", err)
	}
	if acked.State != repository.AlertStateAcknowledged {
		t.Fatalf("state = %s, want acknowledged", acked.State)
	}
	if acked.AcknowledgedBy == nil || *acked.AcknowledgedBy != by {
		t.Fatalf("AcknowledgedBy = %v, want %v", acked.AcknowledgedBy, by)
	}
	// Idempotent: re-ack same alert returns the unchanged row.
	again, err := repo.Acknowledge(ctx(), tnt.ID, saved.ID, &by, at.Add(time.Hour))
	if err != nil {
		t.Fatalf("re-ack: %v", err)
	}
	if again.UpdatedAt != acked.UpdatedAt {
		t.Fatalf("UpdatedAt mutated on idempotent ack")
	}

	// Resolve makes it terminal.
	_, err = repo.Resolve(ctx(), tnt.ID, saved.ID, &by, at)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// Acking a terminal alert is ErrConflict (state-machine
	// violation, not malformed input). The handler maps this
	// to HTTP 409 per the OpenAPI contract.
	_, err = repo.Acknowledge(ctx(), tnt.ID, saved.ID, &by, at)
	if !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("ack-after-resolve err = %v, want ErrConflict", err)
	}
}

func TestAlert_Resolve_FromOpenAndAcknowledged(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	repo := memory.NewAlertRepository(s)
	a1, err := repo.Create(ctx(), tnt.ID, makeAlert(tnt.ID))
	if err != nil {
		t.Fatalf("create a1: %v", err)
	}
	a2, err := repo.Create(ctx(), tnt.ID, makeAlert(tnt.ID))
	if err != nil {
		t.Fatalf("create a2: %v", err)
	}
	by := uuid.New()
	at := time.Now().UTC()

	// Resolve straight from Open.
	r1, err := repo.Resolve(ctx(), tnt.ID, a1.ID, &by, at)
	if err != nil {
		t.Fatalf("resolve a1: %v", err)
	}
	if r1.State != repository.AlertStateResolved {
		t.Fatalf("state = %s, want resolved", r1.State)
	}

	// Resolve via Acknowledged.
	if _, err := repo.Acknowledge(ctx(), tnt.ID, a2.ID, &by, at); err != nil {
		t.Fatalf("ack a2: %v", err)
	}
	r2, err := repo.Resolve(ctx(), tnt.ID, a2.ID, &by, at)
	if err != nil {
		t.Fatalf("resolve a2: %v", err)
	}
	if r2.State != repository.AlertStateResolved {
		t.Fatalf("state = %s, want resolved", r2.State)
	}

	// Idempotent: re-resolving is a no-op.
	r2b, err := repo.Resolve(ctx(), tnt.ID, a2.ID, &by, at.Add(time.Hour))
	if err != nil {
		t.Fatalf("re-resolve a2: %v", err)
	}
	if r2b.UpdatedAt != r2.UpdatedAt {
		t.Fatalf("UpdatedAt mutated on idempotent resolve")
	}
}

func TestAlert_Resolve_RejectsSuppressed(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	repo := memory.NewAlertRepository(s)
	a := makeAlert(tnt.ID)
	a.State = repository.AlertStateSuppressed
	supBy := uuid.New()
	a.SuppressedBy = &supBy
	saved, err := repo.Create(ctx(), tnt.ID, a)
	if err != nil {
		t.Fatalf("create suppressed: %v", err)
	}
	by := uuid.New()
	at := time.Now().UTC()
	// Resolving a suppressed alert is a state-machine
	// conflict (terminal→terminal), mapped to HTTP 409.
	if _, err := repo.Resolve(ctx(), tnt.ID, saved.ID, &by, at); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
}

func TestAlert_List_FilterByStateAndDimension(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	repo := memory.NewAlertRepository(s)
	open1, _ := repo.Create(ctx(), tnt.ID, makeAlert(tnt.ID))
	open2 := makeAlert(tnt.ID)
	open2.Dimension = "auth.failures"
	other, _ := repo.Create(ctx(), tnt.ID, open2)

	by := uuid.New()
	if _, err := repo.Resolve(ctx(), tnt.ID, other.ID, &by, time.Now().UTC()); err != nil {
		t.Fatalf("resolve other: %v", err)
	}

	// Filter by state: only open alerts.
	pg, err := repo.List(ctx(), tnt.ID, repository.AlertListFilter{
		States: []repository.AlertState{repository.AlertStateOpen},
	}, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(pg.Items) != 1 || pg.Items[0].ID != open1.ID {
		t.Fatalf("len=%d, want 1 open alert (%v)", len(pg.Items), open1.ID)
	}

	// Filter by dimension.
	pg2, err := repo.List(ctx(), tnt.ID, repository.AlertListFilter{
		Dimensions: []string{"auth.failures"},
	}, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list 2: %v", err)
	}
	if len(pg2.Items) != 1 || pg2.Items[0].ID != other.ID {
		t.Fatalf("len=%d, want 1 auth.failures alert", len(pg2.Items))
	}
}

// --- AlertSuppressionRepository ----------------------------------------

func TestSuppression_CreateAndListActive(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	repo := memory.NewAlertSuppressionRepository(s)

	kind := "baseline.zscore_exceeded"
	expired := time.Now().Add(-time.Hour)
	active := time.Now().Add(time.Hour)
	if _, err := repo.Create(ctx(), tnt.ID, repository.AlertSuppression{
		Kind: &kind, Reason: "noisy probe", ExpiresAt: &expired,
	}); err != nil {
		t.Fatalf("create expired: %v", err)
	}
	if _, err := repo.Create(ctx(), tnt.ID, repository.AlertSuppression{
		Kind: &kind, Reason: "still active", ExpiresAt: &active,
	}); err != nil {
		t.Fatalf("create active: %v", err)
	}
	if _, err := repo.Create(ctx(), tnt.ID, repository.AlertSuppression{
		Kind: &kind, Reason: "never expires",
	}); err != nil {
		t.Fatalf("create never expires: %v", err)
	}

	out, err := repo.ListActive(ctx(), tnt.ID, time.Now())
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("len = %d, want 2 active (filtered expired)", len(out))
	}
}

func TestSuppression_Create_RejectsScopeNonempty(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	repo := memory.NewAlertSuppressionRepository(s)
	_, err := repo.Create(ctx(), tnt.ID, repository.AlertSuppression{
		Reason: "no kind, no dim",
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestSuppression_Delete(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	repo := memory.NewAlertSuppressionRepository(s)
	kind := "k"
	saved, err := repo.Create(ctx(), tnt.ID, repository.AlertSuppression{
		Kind: &kind, Reason: "r",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := repo.Delete(ctx(), tnt.ID, saved.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := repo.Get(ctx(), tnt.ID, saved.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("post-delete get: %v, want ErrNotFound", err)
	}
}

// --- AlertFeedbackRepository -------------------------------------------

func TestFeedback_Create_OneFeedbackPerAlert(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	alertRepo := memory.NewAlertRepository(s)
	fbRepo := memory.NewAlertFeedbackRepository(s)
	a, err := alertRepo.Create(ctx(), tnt.ID, makeAlert(tnt.ID))
	if err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	_, err = fbRepo.Create(ctx(), tnt.ID, repository.AlertFeedback{
		AlertID:  a.ID,
		Decision: repository.AlertFeedbackFalsePositive,
		Notes:    "noisy probe",
	})
	if err != nil {
		t.Fatalf("create feedback: %v", err)
	}
	// Second feedback on same alert -> ErrConflict.
	_, err = fbRepo.Create(ctx(), tnt.ID, repository.AlertFeedback{
		AlertID:  a.ID,
		Decision: repository.AlertFeedbackTruePositive,
	})
	if !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("dup feedback err = %v, want ErrConflict", err)
	}
}

func TestFeedback_ListByDimension_ScopedAndSince(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	alertRepo := memory.NewAlertRepository(s)
	fbRepo := memory.NewAlertFeedbackRepository(s)

	a1 := makeAlert(tnt.ID)
	a1.Dimension = "auth.failures"
	saved1, _ := alertRepo.Create(ctx(), tnt.ID, a1)

	a2 := makeAlert(tnt.ID)
	a2.Dimension = "dns.queries.NXDOMAIN"
	saved2, _ := alertRepo.Create(ctx(), tnt.ID, a2)

	if _, err := fbRepo.Create(ctx(), tnt.ID, repository.AlertFeedback{
		AlertID: saved1.ID, Decision: repository.AlertFeedbackFalsePositive,
	}); err != nil {
		t.Fatalf("fb1: %v", err)
	}
	if _, err := fbRepo.Create(ctx(), tnt.ID, repository.AlertFeedback{
		AlertID: saved2.ID, Decision: repository.AlertFeedbackFalsePositive,
	}); err != nil {
		t.Fatalf("fb2: %v", err)
	}

	// Use a far-past since cutoff; the in-memory store uses a
	// fixed test clock starting at 2025-01-01 which would
	// otherwise be before time.Now() and filter every row.
	out, err := fbRepo.ListByDimension(ctx(), tnt.ID, "auth.failures", 0, time.Time{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out) != 1 || out[0].AlertID != saved1.ID {
		t.Fatalf("len = %d, want 1 (scope to auth.failures)", len(out))
	}
}

func TestFeedback_Create_RejectsInvalidDecision(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	fbRepo := memory.NewAlertFeedbackRepository(s)
	_, err := fbRepo.Create(ctx(), tnt.ID, repository.AlertFeedback{
		AlertID:  uuid.New(),
		Decision: "bogus",
	})
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestFeedback_Create_RejectsMissingAlert(t *testing.T) {
	s, tnt := seedAlertTenant(t)
	fbRepo := memory.NewAlertFeedbackRepository(s)
	_, err := fbRepo.Create(ctx(), tnt.ID, repository.AlertFeedback{
		AlertID:  uuid.New(), // not seeded
		Decision: repository.AlertFeedbackTruePositive,
	})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}
