// Package dlpreview_test exercises the review-queue service against the
// in-memory repository, so the behavioural contract (state machine,
// tenant isolation, audit, digest, privacy) is pinned without a
// database. The Postgres repo is verified separately under the
// `integration` build tag.
package dlpreview_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

// recordingAudit is a test AuditSink that captures every record.
type recordingAudit struct {
	mu      sync.Mutex
	records []dlpreview.AuditRecord
	failOn  dlpreview.AuditAction // if set, RecordReview fails for this action
}

func (a *recordingAudit) RecordReview(_ context.Context, rec dlpreview.AuditRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failOn != "" && rec.Action == a.failOn {
		return errors.New("audit sink failure")
	}
	a.records = append(a.records, rec)
	return nil
}

func (a *recordingAudit) all() []dlpreview.AuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]dlpreview.AuditRecord(nil), a.records...)
}

// fixedClock returns a deterministic, monotonically advancing clock.
func fixedClock(start time.Time) func() time.Time {
	var mu sync.Mutex
	cur := start
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		t := cur
		cur = cur.Add(time.Second)
		return t
	}
}

func newService(t *testing.T, audit dlpreview.AuditSink, clock func() time.Time) *dlpreview.Service {
	t.Helper()
	repo := memory.NewDLPReviewRepository()
	opts := []dlpreview.Option{}
	if audit != nil {
		opts = append(opts, dlpreview.WithAuditSink(audit))
	}
	if clock != nil {
		opts = append(opts, dlpreview.WithClock(clock))
	}
	svc, err := dlpreview.New(repo, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

func sampleInput() dlpreview.EnqueueInput {
	return dlpreview.EnqueueInput{
		Signal:         "ai_app_upload",
		DestinationApp: "chatgpt",
		Severity:       dlpreview.SeverityHigh,
		Confidence:     0.91,
		Findings: []dlpreview.FindingAggregate{
			{Kind: dlpreview.FindingSecret, Label: "github_token", Count: 1, MaxConfidence: 1.0, Severity: dlpreview.SeverityHigh},
			{Kind: dlpreview.FindingPII, Label: "ssn_us", Count: 2, MaxConfidence: 0.8, Severity: dlpreview.SeverityMedium},
		},
	}
}

// recordingHook captures block-hook invocations.
type recordingHook struct {
	mu      sync.Mutex
	tenants []uuid.UUID
	events  []dlpreview.ReviewEvent
}

func (h *recordingHook) OnBlock(_ context.Context, tenantID uuid.UUID, ev dlpreview.ReviewEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.tenants = append(h.tenants, tenantID)
	h.events = append(h.events, ev)
}

func (h *recordingHook) calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.tenants)
}

// TestBlockHook_FiresOnlyForBlock proves the enforcement hook fires for
// a block decision (carrying the tenant + the blocked event) and not for
// approve or dismiss, since only a block changes the per-app override
// set.
func TestBlockHook_FiresOnlyForBlock(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		decide   func(*dlpreview.Service, context.Context, uuid.UUID, uuid.UUID) error
		wantCall bool
	}{
		{"block", func(s *dlpreview.Service, ctx context.Context, tn, id uuid.UUID) error {
			_, err := s.Block(ctx, tn, id, "op@x.test")
			return err
		}, true},
		{"approve", func(s *dlpreview.Service, ctx context.Context, tn, id uuid.UUID) error {
			_, err := s.Approve(ctx, tn, id, "op@x.test")
			return err
		}, false},
		{"dismiss", func(s *dlpreview.Service, ctx context.Context, tn, id uuid.UUID) error {
			_, err := s.Dismiss(ctx, tn, id, "op@x.test")
			return err
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hook := &recordingHook{}
			repo := memory.NewDLPReviewRepository()
			svc, err := dlpreview.New(repo, dlpreview.WithBlockHook(hook))
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			tenant := uuid.New()
			ev, err := svc.Enqueue(context.Background(), tenant, sampleInput())
			if err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			if err := tc.decide(svc, context.Background(), tenant, ev.ID); err != nil {
				t.Fatalf("decide: %v", err)
			}
			if got := hook.calls(); (got > 0) != tc.wantCall {
				t.Fatalf("hook calls = %d, wantCall = %v", got, tc.wantCall)
			}
			if tc.wantCall {
				if hook.tenants[0] != tenant {
					t.Errorf("hook tenant = %v, want %v", hook.tenants[0], tenant)
				}
				if hook.events[0].ID != ev.ID || hook.events[0].State != dlpreview.StateBlocked {
					t.Errorf("hook event = %+v, want id %v state blocked", hook.events[0], ev.ID)
				}
			}
		})
	}
}

func TestNew_NilRepository(t *testing.T) {
	t.Parallel()
	if _, err := dlpreview.New(nil); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("New(nil) err = %v, want ErrInvalidArgument", err)
	}
}

func TestEnqueue_StoresPendingAndAudits(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{}
	start := time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)
	svc := newService(t, audit, fixedClock(start))
	tenant := uuid.New()

	ev, err := svc.Enqueue(context.Background(), tenant, sampleInput())
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if ev.ID == uuid.Nil {
		t.Fatal("expected a generated id")
	}
	if ev.State != dlpreview.StatePending {
		t.Fatalf("state = %q, want pending", ev.State)
	}
	if !ev.CreatedAt.Equal(start) {
		t.Fatalf("created_at = %v, want %v", ev.CreatedAt, start)
	}
	if ev.DecidedAt != nil || ev.DecidedBy != nil {
		t.Fatal("pending event must have no decision")
	}
	recs := audit.all()
	if len(recs) != 1 || recs[0].Action != dlpreview.AuditEnqueue || recs[0].Actor != "system" {
		t.Fatalf("audit = %+v, want one system enqueue", recs)
	}
	if recs[0].ResultState != dlpreview.StatePending {
		t.Fatalf("audit result state = %q, want pending", recs[0].ResultState)
	}
}

func TestEnqueue_DefaultsSignal(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, nil)
	in := sampleInput()
	in.Signal = ""
	ev, err := svc.Enqueue(context.Background(), uuid.New(), in)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if ev.Signal != "ai_app_upload" {
		t.Fatalf("signal = %q, want default ai_app_upload", ev.Signal)
	}
}

func TestEnqueue_Validation(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, nil)
	tenant := uuid.New()
	cases := map[string]func(*dlpreview.EnqueueInput){
		"empty destination":   func(in *dlpreview.EnqueueInput) { in.DestinationApp = "" },
		"bad severity":        func(in *dlpreview.EnqueueInput) { in.Severity = "extreme" },
		"confidence too high": func(in *dlpreview.EnqueueInput) { in.Confidence = 1.5 },
		"confidence negative": func(in *dlpreview.EnqueueInput) { in.Confidence = -0.1 },
		"finding bad kind":    func(in *dlpreview.EnqueueInput) { in.Findings[0].Kind = "raw" },
		"finding empty label": func(in *dlpreview.EnqueueInput) { in.Findings[0].Label = "" },
		"finding zero count":  func(in *dlpreview.EnqueueInput) { in.Findings[0].Count = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := sampleInput()
			mutate(&in)
			if _, err := svc.Enqueue(context.Background(), tenant, in); !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
	t.Run("nil tenant", func(t *testing.T) {
		if _, err := svc.Enqueue(context.Background(), uuid.Nil, sampleInput()); !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("err = %v, want ErrInvalidArgument", err)
		}
	})
}

func TestDecide_ApproveBlockDismiss(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		decide func(*dlpreview.Service, context.Context, uuid.UUID, uuid.UUID, string) (dlpreview.ReviewEvent, error)
		want   dlpreview.ReviewState
		action dlpreview.AuditAction
	}{
		{"approve", (*dlpreview.Service).Approve, dlpreview.StateApproved, dlpreview.AuditApprove},
		{"block", (*dlpreview.Service).Block, dlpreview.StateBlocked, dlpreview.AuditBlock},
		{"dismiss", (*dlpreview.Service).Dismiss, dlpreview.StateDismissed, dlpreview.AuditDismiss},
	} {
		t.Run(tc.name, func(t *testing.T) {
			audit := &recordingAudit{}
			svc := newService(t, audit, fixedClock(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)))
			tenant := uuid.New()
			ev, err := svc.Enqueue(context.Background(), tenant, sampleInput())
			if err != nil {
				t.Fatalf("Enqueue: %v", err)
			}
			decided, err := tc.decide(svc, context.Background(), tenant, ev.ID, "reviewer@acme.test")
			if err != nil {
				t.Fatalf("decide: %v", err)
			}
			if decided.State != tc.want {
				t.Fatalf("state = %q, want %q", decided.State, tc.want)
			}
			if decided.DecidedAt == nil || decided.DecidedBy == nil || *decided.DecidedBy != "reviewer@acme.test" {
				t.Fatalf("decision audit fields not set: %+v", decided)
			}
			recs := audit.all()
			if len(recs) != 2 || recs[1].Action != tc.action {
				t.Fatalf("audit = %+v, want enqueue then %s", recs, tc.action)
			}
		})
	}
}

func TestDecide_DoubleDecisionConflicts(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, nil)
	tenant := uuid.New()
	ev, err := svc.Enqueue(context.Background(), tenant, sampleInput())
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if _, err := svc.Approve(context.Background(), tenant, ev.ID, "a@x.test"); err != nil {
		t.Fatalf("first approve: %v", err)
	}
	if _, err := svc.Block(context.Background(), tenant, ev.ID, "b@x.test"); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("second decision err = %v, want ErrConflict", err)
	}
}

func TestDecide_UnknownEventNotFound(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, nil)
	if _, err := svc.Approve(context.Background(), uuid.New(), uuid.New(), "a@x.test"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDecide_EmptyActorRejected(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, nil)
	tenant := uuid.New()
	ev, _ := svc.Enqueue(context.Background(), tenant, sampleInput())
	if _, err := svc.Approve(context.Background(), tenant, ev.ID, ""); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestTenantIsolation(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, nil)
	tenantA, tenantB := uuid.New(), uuid.New()
	ev, err := svc.Enqueue(context.Background(), tenantA, sampleInput())
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// Tenant B cannot read tenant A's event.
	if _, err := svc.Get(context.Background(), tenantB, ev.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cross-tenant Get err = %v, want ErrNotFound", err)
	}
	// Tenant B cannot decide tenant A's event.
	if _, err := svc.Approve(context.Background(), tenantB, ev.ID, "intruder@evil.test"); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("cross-tenant Approve err = %v, want ErrNotFound", err)
	}
	// Tenant B's list is empty.
	list, err := svc.List(context.Background(), tenantB, dlpreview.ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("tenant B list = %d events, want 0", len(list))
	}
}

func TestList_NewestFirstAndStateFilter(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, fixedClock(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)))
	tenant := uuid.New()
	var ids []uuid.UUID
	for i := 0; i < 3; i++ {
		ev, err := svc.Enqueue(context.Background(), tenant, sampleInput())
		if err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		ids = append(ids, ev.ID)
	}
	// Decide the middle one so we can filter on state.
	if _, err := svc.Block(context.Background(), tenant, ids[1], "r@x.test"); err != nil {
		t.Fatalf("Block: %v", err)
	}

	all, err := svc.List(context.Background(), tenant, dlpreview.ListFilter{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("list len = %d, want 3", len(all))
	}
	// Newest first: ids[2] then ids[1] then ids[0].
	if all[0].ID != ids[2] || all[2].ID != ids[0] {
		t.Fatalf("order = %v, want newest first", []uuid.UUID{all[0].ID, all[1].ID, all[2].ID})
	}

	pending := dlpreview.StatePending
	onlyPending, err := svc.List(context.Background(), tenant, dlpreview.ListFilter{State: &pending})
	if err != nil {
		t.Fatalf("List(pending): %v", err)
	}
	if len(onlyPending) != 2 {
		t.Fatalf("pending list = %d, want 2", len(onlyPending))
	}
	for _, ev := range onlyPending {
		if ev.State != dlpreview.StatePending {
			t.Fatalf("filtered event state = %q", ev.State)
		}
	}
}

func TestList_LimitApplied(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, fixedClock(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)))
	tenant := uuid.New()
	for i := 0; i < 5; i++ {
		if _, err := svc.Enqueue(context.Background(), tenant, sampleInput()); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	got, err := svc.List(context.Background(), tenant, dlpreview.ListFilter{Limit: 2})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("list len = %d, want 2 (limit)", len(got))
	}
}

func TestDigest_AggregatesBacklog(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, fixedClock(time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)))
	tenant := uuid.New()

	// 3 high to chatgpt, 1 critical to a suspected app; block one.
	for i := 0; i < 3; i++ {
		if _, err := svc.Enqueue(context.Background(), tenant, sampleInput()); err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}
	crit := sampleInput()
	crit.DestinationApp = dlpreview.SuspectedAppSentinel
	crit.Severity = dlpreview.SeverityCritical
	critEv, err := svc.Enqueue(context.Background(), tenant, crit)
	if err != nil {
		t.Fatalf("Enqueue crit: %v", err)
	}
	if _, err := svc.Block(context.Background(), tenant, critEv.ID, "r@x.test"); err != nil {
		t.Fatalf("Block: %v", err)
	}

	dig, err := svc.Digest(context.Background(), tenant, 24*time.Hour)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if dig.Summary.Total != 4 {
		t.Fatalf("total = %d, want 4", dig.Summary.Total)
	}
	if dig.Summary.Pending != 3 {
		t.Fatalf("pending = %d, want 3", dig.Summary.Pending)
	}
	if dig.Summary.ByState[dlpreview.StateBlocked] != 1 {
		t.Fatalf("blocked = %d, want 1", dig.Summary.ByState[dlpreview.StateBlocked])
	}
	if dig.Summary.BySeverity[dlpreview.SeverityHigh] != 3 || dig.Summary.BySeverity[dlpreview.SeverityCritical] != 1 {
		t.Fatalf("severity counts = %+v", dig.Summary.BySeverity)
	}
	// Only the pending backlog feeds PendingByApp (the blocked critical
	// to the suspected app is excluded).
	if dig.Summary.PendingByApp["chatgpt"] != 3 {
		t.Fatalf("pending chatgpt = %d, want 3", dig.Summary.PendingByApp["chatgpt"])
	}
	if _, ok := dig.Summary.PendingByApp[dlpreview.SuspectedAppSentinel]; ok {
		t.Fatal("decided event must not appear in PendingByApp")
	}
	if dig.Window != 24*time.Hour || dig.TenantID != tenant {
		t.Fatalf("digest envelope = %+v", dig)
	}
}

func TestDigest_WindowExcludesOlderEvents(t *testing.T) {
	t.Parallel()
	// Clock far in the past for the first enqueue, then jump forward so
	// the event falls outside a short window.
	var mu sync.Mutex
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}
	repo := memory.NewDLPReviewRepository()
	svc, err := dlpreview.New(repo, dlpreview.WithClock(clock))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tenant := uuid.New()
	if _, err := svc.Enqueue(context.Background(), tenant, sampleInput()); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// Advance 10 days.
	mu.Lock()
	now = now.Add(10 * 24 * time.Hour)
	mu.Unlock()

	dig, err := svc.Digest(context.Background(), tenant, time.Hour)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if dig.Summary.Total != 0 {
		t.Fatalf("total = %d, want 0 (event older than window)", dig.Summary.Total)
	}
}

func TestDigest_RejectsNonPositiveWindow(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, nil)
	if _, err := svc.Digest(context.Background(), uuid.New(), 0); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestAuditFailurePropagates(t *testing.T) {
	t.Parallel()
	audit := &recordingAudit{failOn: dlpreview.AuditEnqueue}
	svc := newService(t, audit, nil)
	if _, err := svc.Enqueue(context.Background(), uuid.New(), sampleInput()); err == nil {
		t.Fatal("expected enqueue to fail when audit sink fails")
	}
}

func TestReturnedEventIsACopy(t *testing.T) {
	t.Parallel()
	svc := newService(t, nil, nil)
	tenant := uuid.New()
	ev, err := svc.Enqueue(context.Background(), tenant, sampleInput())
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// Mutating the returned findings must not affect stored state.
	ev.Findings[0].Label = "tampered"
	got, err := svc.Get(context.Background(), tenant, ev.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Findings[0].Label == "tampered" {
		t.Fatal("stored findings were mutated through returned slice")
	}
}
