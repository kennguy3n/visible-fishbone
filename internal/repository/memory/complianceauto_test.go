package memory_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func TestComplianceAutoRepository_RunsLatest(t *testing.T) {
	t.Parallel()
	repo := memory.NewComplianceAutoRepository()
	ctx := context.Background()
	tenant := uuid.New()

	if _, err := repo.LatestRun(ctx, tenant); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("LatestRun on empty = %v, want ErrNotFound", err)
	}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	first, err := repo.RecordRun(ctx, tenant, repository.ComplianceAutoRunRow{
		StartedAt: base, FinishedAt: base.Add(time.Second), ControlsTotal: 10, ControlsPass: 9, ControlsFail: 1,
	})
	if err != nil {
		t.Fatalf("record first run: %v", err)
	}
	if first.ID == uuid.Nil || first.TenantID != tenant {
		t.Fatalf("run not stamped: %+v", first)
	}

	later, err := repo.RecordRun(ctx, tenant, repository.ComplianceAutoRunRow{
		StartedAt: base.Add(time.Hour), FinishedAt: base.Add(time.Hour + time.Second), ControlsTotal: 10, ControlsPass: 10,
	})
	if err != nil {
		t.Fatalf("record later run: %v", err)
	}

	got, err := repo.LatestRun(ctx, tenant)
	if err != nil {
		t.Fatalf("latest run: %v", err)
	}
	if got.ID != later.ID {
		t.Fatalf("latest run = %s, want the more recent %s", got.ID, later.ID)
	}

	// Tenant isolation.
	if _, err := repo.LatestRun(ctx, uuid.New()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("LatestRun for other tenant = %v, want ErrNotFound", err)
	}
}

func TestComplianceAutoRepository_ApplyEvaluation(t *testing.T) {
	t.Parallel()
	repo := memory.NewComplianceAutoRepository()
	ctx := context.Background()
	tenant := uuid.New()
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)

	first := repository.ComplianceAutoEvaluation{
		Run: repository.ComplianceAutoRunRow{
			StartedAt: base, FinishedAt: base.Add(time.Second),
			ControlsTotal: 2, ControlsPass: 1, ControlsFail: 1,
		},
		Statuses: []repository.ComplianceAutoControlStatusRow{
			{Framework: "SOC2", ControlID: "CC6.1", Status: "fail", CollectorID: "policy_default_deny", ObservedAt: base},
			{Framework: "SOC2", ControlID: "CC6.7", Status: "pass", CollectorID: "encryption_at_rest", ObservedAt: base},
		},
		Evidence: []repository.ComplianceAutoEvidenceRow{
			{Framework: "SOC2", ControlID: "CC6.1", Status: "fail", CollectorID: "policy_default_deny", ObservedAt: base},
			{Framework: "SOC2", ControlID: "CC6.7", Status: "pass", CollectorID: "encryption_at_rest", ObservedAt: base},
		},
		Frameworks: []repository.ComplianceAutoFrameworkStateRow{
			{Framework: "SOC2", ControlsTotal: 2, ControlsPass: 1, ControlsFail: 1, EvaluatedAt: base},
		},
	}

	run, err := repo.ApplyEvaluation(ctx, tenant, first)
	if err != nil {
		t.Fatalf("apply first: %v", err)
	}
	if run.ID == uuid.Nil || run.TenantID != tenant {
		t.Fatalf("run not stamped: %+v", run)
	}

	// The run is the latest, and every child row is stamped with its id.
	latest, err := repo.LatestRun(ctx, tenant)
	if err != nil || latest.ID != run.ID {
		t.Fatalf("latest run = %v (err %v), want %s", latest.ID, err, run.ID)
	}
	statuses, err := repo.ListControlStatus(ctx, tenant, "")
	if err != nil {
		t.Fatalf("list status: %v", err)
	}
	if len(statuses) != 2 {
		t.Fatalf("status rows = %d, want 2", len(statuses))
	}
	for _, s := range statuses {
		if s.RunID != run.ID {
			t.Fatalf("status %s run id = %s, want %s", s.ControlID, s.RunID, run.ID)
		}
	}
	ev, err := repo.ListEvidence(ctx, tenant, "", 0)
	if err != nil {
		t.Fatalf("list evidence: %v", err)
	}
	if len(ev) != 2 {
		t.Fatalf("evidence rows = %d, want 2", len(ev))
	}
	for _, e := range ev {
		if e.RunID != run.ID {
			t.Fatalf("evidence %s run id = %s, want %s", e.ControlID, e.RunID, run.ID)
		}
	}

	// A second sweep upserts control + framework state in place (no
	// duplicates) and appends fresh evidence, all under the new run id.
	second := repository.ComplianceAutoEvaluation{
		Run: repository.ComplianceAutoRunRow{
			StartedAt: base.Add(time.Hour), FinishedAt: base.Add(time.Hour + time.Second),
			ControlsTotal: 2, ControlsPass: 2,
		},
		Statuses: []repository.ComplianceAutoControlStatusRow{
			{Framework: "SOC2", ControlID: "CC6.1", Status: "pass", CollectorID: "policy_default_deny", ObservedAt: base.Add(time.Hour)},
			{Framework: "SOC2", ControlID: "CC6.7", Status: "pass", CollectorID: "encryption_at_rest", ObservedAt: base.Add(time.Hour)},
		},
		Evidence: []repository.ComplianceAutoEvidenceRow{
			{Framework: "SOC2", ControlID: "CC6.1", Status: "pass", CollectorID: "policy_default_deny", ObservedAt: base.Add(time.Hour)},
		},
		Frameworks: []repository.ComplianceAutoFrameworkStateRow{
			{Framework: "SOC2", ControlsTotal: 2, ControlsPass: 2, EvaluatedAt: base.Add(time.Hour)},
		},
	}
	run2, err := repo.ApplyEvaluation(ctx, tenant, second)
	if err != nil {
		t.Fatalf("apply second: %v", err)
	}

	statuses, err = repo.ListControlStatus(ctx, tenant, "")
	if err != nil {
		t.Fatalf("list status after second: %v", err)
	}
	if len(statuses) != 2 {
		t.Fatalf("status rows after second = %d, want 2 (upsert in place)", len(statuses))
	}
	for _, s := range statuses {
		if s.Status != "pass" || s.RunID != run2.ID {
			t.Fatalf("status %s not advanced: status=%q run=%s", s.ControlID, s.Status, s.RunID)
		}
	}
	states, err := repo.ListFrameworkState(ctx, tenant)
	if err != nil {
		t.Fatalf("list framework: %v", err)
	}
	if len(states) != 1 || states[0].ControlsPass != 2 || states[0].LastRunID != run2.ID {
		t.Fatalf("framework state not advanced in place: %+v", states)
	}
	ev, err = repo.ListEvidence(ctx, tenant, "", 0)
	if err != nil {
		t.Fatalf("list evidence after second: %v", err)
	}
	if len(ev) != 3 {
		t.Fatalf("evidence rows after second = %d, want 3 (append-only)", len(ev))
	}

	// Tenant isolation: another tenant sees nothing.
	if _, err := repo.LatestRun(ctx, uuid.New()); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("other tenant LatestRun = %v, want ErrNotFound", err)
	}
}

func TestComplianceAutoRepository_ControlStatusUpsert(t *testing.T) {
	t.Parallel()
	repo := memory.NewComplianceAutoRepository()
	ctx := context.Background()
	tenant := uuid.New()
	runID := uuid.New()

	ins, err := repo.UpsertControlStatus(ctx, tenant, repository.ComplianceAutoControlStatusRow{
		Framework: "SOC2", ControlID: "CC6.1", Status: "fail", CollectorID: "policy_default_deny",
		Summary: "allow", Source: "policy_graph", Details: json.RawMessage(`{"default_deny":false}`),
		ObservedAt: time.Now().UTC(), RunID: runID,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if ins.ID == uuid.Nil || ins.CreatedAt.IsZero() {
		t.Fatalf("insert not stamped: %+v", ins)
	}

	// Upsert on the same (tenant, framework, control) updates in place.
	upd, err := repo.UpsertControlStatus(ctx, tenant, repository.ComplianceAutoControlStatusRow{
		Framework: "SOC2", ControlID: "CC6.1", Status: "pass", CollectorID: "policy_default_deny",
		Summary: "deny", Source: "policy_graph", Details: json.RawMessage(`{"default_deny":true}`),
		ObservedAt: time.Now().UTC(), RunID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.ID != ins.ID {
		t.Fatalf("update changed id: %s -> %s", ins.ID, upd.ID)
	}
	if !upd.CreatedAt.Equal(ins.CreatedAt) {
		t.Fatalf("update changed created_at")
	}
	if upd.Status != "pass" {
		t.Fatalf("status not updated: %q", upd.Status)
	}

	// A different control inserts a new row.
	if _, err := repo.UpsertControlStatus(ctx, tenant, repository.ComplianceAutoControlStatusRow{
		Framework: "ISO_27001", ControlID: "A.8.2", Status: "pass", CollectorID: "policy_default_deny", RunID: runID,
	}); err != nil {
		t.Fatalf("insert iso: %v", err)
	}

	all, err := repo.ListControlStatus(ctx, tenant, "")
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("list all = %d, want 2", len(all))
	}

	soc2, err := repo.ListControlStatus(ctx, tenant, "SOC2")
	if err != nil {
		t.Fatalf("list soc2: %v", err)
	}
	if len(soc2) != 1 || soc2[0].Framework != "SOC2" {
		t.Fatalf("framework filter failed: %+v", soc2)
	}

	// Tenant isolation.
	other, err := repo.ListControlStatus(ctx, uuid.New(), "")
	if err != nil {
		t.Fatalf("list other tenant: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("other tenant sees %d rows, want 0", len(other))
	}
}

func TestComplianceAutoRepository_Evidence(t *testing.T) {
	t.Parallel()
	repo := memory.NewComplianceAutoRepository()
	ctx := context.Background()
	tenant := uuid.New()
	base := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 3; i++ {
		if _, err := repo.AppendEvidence(ctx, tenant, repository.ComplianceAutoEvidenceRow{
			RunID: uuid.New(), Framework: "SOC2", ControlID: "CC6.1", CollectorID: "policy_default_deny",
			Status: "pass", Summary: "ok", Source: "policy_graph",
			Details:    json.RawMessage(`{"default_deny":true}`),
			ObservedAt: base.Add(time.Duration(i) * time.Hour),
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if _, err := repo.AppendEvidence(ctx, tenant, repository.ComplianceAutoEvidenceRow{
		RunID: uuid.New(), Framework: "SOC2", ControlID: "CC6.7", CollectorID: "encryption_at_rest",
		Status: "fail", ObservedAt: base.Add(4 * time.Hour),
	}); err != nil {
		t.Fatalf("append other control: %v", err)
	}

	// Newest-first ordering across all controls.
	all, err := repo.ListEvidence(ctx, tenant, "", 0)
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("evidence = %d, want 4", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].ObservedAt.Before(all[i].ObservedAt) {
			t.Fatalf("evidence not sorted newest-first at %d", i)
		}
	}

	// Filter by control id.
	filtered, err := repo.ListEvidence(ctx, tenant, "CC6.1", 0)
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(filtered) != 3 {
		t.Fatalf("filtered evidence = %d, want 3", len(filtered))
	}

	// Limit clamp.
	limited, err := repo.ListEvidence(ctx, tenant, "", 2)
	if err != nil {
		t.Fatalf("list limited: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("limited evidence = %d, want 2", len(limited))
	}

	// Tenant isolation.
	other, err := repo.ListEvidence(ctx, uuid.New(), "", 0)
	if err != nil {
		t.Fatalf("list other tenant: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("other tenant evidence = %d, want 0", len(other))
	}
}

func TestComplianceAutoRepository_RLSRuntimeStatus(t *testing.T) {
	t.Parallel()
	repo := memory.NewComplianceAutoRepository()
	ctx := context.Background()

	// The in-memory backend models a correctly-configured platform.
	got, err := repo.RLSRuntimeStatus(ctx)
	if err != nil {
		t.Fatalf("default status: %v", err)
	}
	if !got.Enforced || got.Role == "" {
		t.Fatalf("default status = %+v, want enforced with a role", got)
	}

	// The setter drives the collector both ways.
	repo.SetRLSStatus(repository.ComplianceAutoRLSStatus{Role: "postgres", Superuser: true, BypassRLS: true, Enforced: false})
	got, err = repo.RLSRuntimeStatus(ctx)
	if err != nil {
		t.Fatalf("after set: %v", err)
	}
	if got.Enforced || !got.Superuser || !got.BypassRLS || got.Role != "postgres" {
		t.Fatalf("after set = %+v, want a non-enforcing superuser role", got)
	}
}

func TestComplianceAutoRepository_FrameworkState(t *testing.T) {
	t.Parallel()
	repo := memory.NewComplianceAutoRepository()
	ctx := context.Background()
	tenant := uuid.New()
	runID := uuid.New()

	ins, err := repo.UpsertFrameworkState(ctx, tenant, repository.ComplianceAutoFrameworkStateRow{
		Framework: "SOC2", ControlsTotal: 10, ControlsPass: 8, ControlsFail: 2, LastRunID: runID, EvaluatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	upd, err := repo.UpsertFrameworkState(ctx, tenant, repository.ComplianceAutoFrameworkStateRow{
		Framework: "SOC2", ControlsTotal: 10, ControlsPass: 10, LastRunID: uuid.New(), EvaluatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.ID != ins.ID || !upd.CreatedAt.Equal(ins.CreatedAt) {
		t.Fatalf("upsert did not update in place: %+v vs %+v", upd, ins)
	}
	if upd.ControlsPass != 10 {
		t.Fatalf("pass not updated: %d", upd.ControlsPass)
	}

	if _, err := repo.UpsertFrameworkState(ctx, tenant, repository.ComplianceAutoFrameworkStateRow{
		Framework: "ISO_27001", ControlsTotal: 6, ControlsPass: 6, LastRunID: runID,
	}); err != nil {
		t.Fatalf("insert iso: %v", err)
	}

	states, err := repo.ListFrameworkState(ctx, tenant)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(states) != 2 {
		t.Fatalf("states = %d, want 2", len(states))
	}
	// Sorted by framework name.
	if states[0].Framework != "ISO_27001" || states[1].Framework != "SOC2" {
		t.Fatalf("states not sorted: %s, %s", states[0].Framework, states[1].Framework)
	}

	// Tenant isolation.
	other, err := repo.ListFrameworkState(ctx, uuid.New())
	if err != nil {
		t.Fatalf("list other: %v", err)
	}
	if len(other) != 0 {
		t.Fatalf("other tenant states = %d, want 0", len(other))
	}
}
