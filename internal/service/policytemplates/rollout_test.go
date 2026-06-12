package policytemplates

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	memrepo "github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// failingUpsertRepo wraps the in-memory repository and forces
// UpsertApplied to fail for one specific tenant, so the roll-out
// rollback path can be exercised deterministically.
type failingUpsertRepo struct {
	*memrepo.PolicyTemplateRepository
	failFor uuid.UUID
	err     error
}

func (r *failingUpsertRepo) UpsertApplied(ctx context.Context, applied AppliedTemplate) (AppliedTemplate, error) {
	if applied.TenantID == r.failFor {
		return AppliedTemplate{}, r.err
	}
	return r.PolicyTemplateRepository.UpsertApplied(ctx, applied)
}

func TestPreviewRollout_ClassifiesEachTenant(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	sel := Selection{Industry: IndustryFinance, Country: "DE"}

	// One tenant already on the target baseline (noop), one on a
	// different baseline (update), one with no baseline (create).
	noop := uuid.New()
	if _, err := svc.Apply(ctx, noop, sel); err != nil {
		t.Fatalf("seed noop tenant: %v", err)
	}
	update := uuid.New()
	if _, err := svc.Apply(ctx, update, Selection{Industry: IndustryRetail, Country: "US"}); err != nil {
		t.Fatalf("seed update tenant: %v", err)
	}
	create := uuid.New()

	preview, err := svc.PreviewRollout(ctx, []uuid.UUID{noop, update, create}, sel)
	if err != nil {
		t.Fatalf("PreviewRollout: %v", err)
	}
	if preview.Regime != RegimeEUGDPR {
		t.Errorf("DE should resolve to eu-gdpr, got %q", preview.Regime)
	}
	if len(preview.Targets) != 3 {
		t.Fatalf("expected 3 target diffs, got %d", len(preview.Targets))
	}
	want := map[uuid.UUID]RolloutAction{
		noop:   RolloutActionNoop,
		update: RolloutActionUpdate,
		create: RolloutActionCreate,
	}
	for _, target := range preview.Targets {
		if got := target.Action; got != want[target.TenantID] {
			t.Errorf("tenant %s: action = %q, want %q", target.TenantID, got, want[target.TenantID])
		}
		switch target.Action {
		case RolloutActionCreate:
			if target.Current != nil {
				t.Errorf("create tenant should have no current baseline")
			}
		default:
			if target.Current == nil {
				t.Errorf("%s tenant should expose its current baseline", target.Action)
			}
		}
	}

	// Preview must not have written anything for the create tenant.
	if _, err := svc.GetApplied(ctx, create); !errors.Is(err, ErrNotFound) {
		t.Errorf("preview wrote a baseline for the create tenant: %v", err)
	}
}

func TestExecuteRollout_AppliesAcrossTenants(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	sel := Selection{Industry: IndustryHealthcare, Country: "GB"}

	fresh := uuid.New()
	already := uuid.New()
	if _, err := svc.Apply(ctx, already, sel); err != nil {
		t.Fatalf("seed already-applied tenant: %v", err)
	}

	result, err := svc.ExecuteRollout(ctx, []uuid.UUID{fresh, already}, sel)
	if err != nil {
		t.Fatalf("ExecuteRollout: %v", err)
	}
	if result.Applied != 1 || result.Unchanged != 1 || result.Failed != 0 {
		t.Fatalf("counts = applied:%d unchanged:%d failed:%d, want 1/1/0",
			result.Applied, result.Unchanged, result.Failed)
	}

	byTenant := map[uuid.UUID]RolloutOutcome{}
	for _, o := range result.Outcomes {
		byTenant[o.TenantID] = o
	}
	if byTenant[fresh].Status != RolloutStatusApplied {
		t.Errorf("fresh tenant status = %q, want applied", byTenant[fresh].Status)
	}
	if byTenant[fresh].GraphHash != result.GraphHash {
		t.Errorf("fresh tenant graph hash mismatch")
	}
	if byTenant[already].Status != RolloutStatusUnchanged {
		t.Errorf("already-applied tenant status = %q, want unchanged", byTenant[already].Status)
	}

	// The fresh tenant is now persisted.
	got, err := svc.GetApplied(ctx, fresh)
	if err != nil {
		t.Fatalf("GetApplied(fresh): %v", err)
	}
	if got.GraphHash != result.GraphHash {
		t.Errorf("fresh tenant baseline not persisted")
	}
}

func TestExecuteRollout_SameRegimeDifferentCountryRewritesMetadata(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// DE and FR are distinct countries that share RegimeEUGDPR, so a
	// same-industry roll-out across them yields an identical GraphHash.
	// The roll-out must still rewrite the stored Country (matching
	// Apply's behaviour) rather than skip the write as "unchanged".
	deRegime, _ := RegimeForCountry("DE")
	frRegime, _ := RegimeForCountry("FR")
	if deRegime != frRegime {
		t.Fatalf("test assumes DE and FR share a regime, got %q vs %q", deRegime, frRegime)
	}

	tenant := uuid.New()
	if _, err := svc.Apply(ctx, tenant, Selection{Industry: IndustryFinance, Country: "DE"}); err != nil {
		t.Fatalf("seed DE baseline: %v", err)
	}

	sel := Selection{Industry: IndustryFinance, Country: "FR"}
	result, err := svc.ExecuteRollout(ctx, []uuid.UUID{tenant}, sel)
	if err != nil {
		t.Fatalf("ExecuteRollout: %v", err)
	}
	if result.Applied != 1 || result.Unchanged != 0 {
		t.Fatalf("counts = applied:%d unchanged:%d, want applied:1 unchanged:0 "+
			"(same-regime country swap must rewrite, not no-op)",
			result.Applied, result.Unchanged)
	}
	if got := result.Outcomes[0].Status; got != RolloutStatusApplied {
		t.Errorf("outcome status = %q, want applied", got)
	}

	// The stored baseline now reflects the new country.
	stored, err := svc.GetApplied(ctx, tenant)
	if err != nil {
		t.Fatalf("GetApplied: %v", err)
	}
	if stored.Country != "FR" {
		t.Errorf("stored country = %q, want FR (metadata must follow the roll-out)", stored.Country)
	}
}

func TestExecuteRollout_IsolatesFailureAndRollsBack(t *testing.T) {
	ctx := context.Background()
	sel := Selection{Industry: IndustryFinance, Country: "FR"}

	bad := uuid.New()
	withPrior := uuid.New()
	good := uuid.New()

	mem := memrepo.NewPolicyTemplateRepository()
	repo := &failingUpsertRepo{
		PolicyTemplateRepository: mem,
		failFor:                  bad,
		err:                      errors.New("boom"),
	}
	svc := New(repo, nil)

	// Give withPrior an existing (different) baseline so the rollback
	// path has something to restore. Seed it through the underlying
	// repo so the fault injector does not block the seed.
	priorResolved, err := Resolve(Selection{Industry: IndustryRetail, Country: "US"})
	if err != nil {
		t.Fatalf("resolve prior: %v", err)
	}
	if _, err := mem.UpsertApplied(ctx, appliedFromResolved(withPrior, priorResolved)); err != nil {
		t.Fatalf("seed prior baseline: %v", err)
	}

	// bad is processed first so its failure must NOT abort good/withPrior.
	result, err := svc.ExecuteRollout(ctx, []uuid.UUID{bad, withPrior, good}, sel)
	if err != nil {
		t.Fatalf("ExecuteRollout: %v", err)
	}
	if result.Failed != 1 || result.Applied != 2 {
		t.Fatalf("counts = applied:%d failed:%d, want applied:2 failed:1", result.Applied, result.Failed)
	}

	byTenant := map[uuid.UUID]RolloutOutcome{}
	for _, o := range result.Outcomes {
		byTenant[o.TenantID] = o
	}

	// The failing tenant had no prior baseline: failed, and rolled back
	// to the clean (no-baseline) state.
	badOutcome := byTenant[bad]
	if badOutcome.Status != RolloutStatusFailed || badOutcome.Error == "" {
		t.Errorf("bad tenant = %+v, want failed with error", badOutcome)
	}
	if !badOutcome.RolledBack {
		t.Errorf("bad tenant should report rolled_back (no prior baseline left behind)")
	}
	if _, err := svc.GetApplied(ctx, bad); !errors.Is(err, ErrNotFound) {
		t.Errorf("failed tenant should have no persisted baseline, got %v", err)
	}

	// The good tenants in the same batch still applied.
	if byTenant[good].Status != RolloutStatusApplied {
		t.Errorf("good tenant status = %q, want applied", byTenant[good].Status)
	}
	if byTenant[withPrior].Status != RolloutStatusApplied {
		t.Errorf("withPrior tenant status = %q, want applied", byTenant[withPrior].Status)
	}
}

func TestRolloutValidation(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	if _, err := svc.ExecuteRollout(ctx, nil, Selection{Industry: IndustryFinance, Country: "DE"}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("empty tenant list err = %v, want ErrInvalidArgument", err)
	}
	if _, err := svc.PreviewRollout(ctx, []uuid.UUID{uuid.Nil}, Selection{Industry: IndustryFinance, Country: "DE"}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("nil tenant id err = %v, want ErrInvalidArgument", err)
	}
	if _, err := svc.ExecuteRollout(ctx, []uuid.UUID{uuid.New()}, Selection{Industry: "bogus", Country: "DE"}); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("bad selection err = %v, want ErrInvalidArgument", err)
	}
}

func TestExecuteRollout_DeduplicatesTenants(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()
	sel := Selection{Industry: IndustryTechnology, Country: "US"}

	result, err := svc.ExecuteRollout(ctx, []uuid.UUID{tenant, tenant, tenant}, sel)
	if err != nil {
		t.Fatalf("ExecuteRollout: %v", err)
	}
	if len(result.Outcomes) != 1 {
		t.Fatalf("expected 1 de-duplicated outcome, got %d", len(result.Outcomes))
	}
	if result.Applied != 1 {
		t.Errorf("applied = %d, want 1", result.Applied)
	}
}

func TestExecuteRollout_ContextCancelledIsTotal(t *testing.T) {
	svc, _ := newTestService(t)
	sel := Selection{Industry: IndustryFinance, Country: "DE"}

	// Cancel before any tenant is processed: the roll-out must not
	// surface an error (so the handler emits a 200 reflecting true
	// state) and every tenant must get a terminal outcome.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tenants := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	result, err := svc.ExecuteRollout(ctx, tenants, sel)
	if err != nil {
		t.Fatalf("ExecuteRollout must not error on cancellation: %v", err)
	}
	if result.Cancelled != len(tenants) {
		t.Fatalf("cancelled = %d, want %d", result.Cancelled, len(tenants))
	}
	if result.Applied != 0 || result.Failed != 0 || result.Unchanged != 0 {
		t.Errorf("counts = applied:%d unchanged:%d failed:%d, want all 0",
			result.Applied, result.Unchanged, result.Failed)
	}
	if len(result.Outcomes) != len(tenants) {
		t.Fatalf("outcomes = %d, want %d (every tenant reported)", len(result.Outcomes), len(tenants))
	}
	for _, o := range result.Outcomes {
		if o.Status != RolloutStatusCancelled {
			t.Errorf("tenant %s status = %q, want cancelled", o.TenantID, o.Status)
		}
	}
	// No write occurred for any tenant: a cancelled roll-out is clean.
	for _, tid := range tenants {
		if _, err := svc.GetApplied(context.Background(), tid); !errors.Is(err, ErrNotFound) {
			t.Errorf("tenant %s should have no baseline after cancellation: %v", tid, err)
		}
	}
}

func TestSelectionOptions(t *testing.T) {
	svc, _ := newTestService(t)
	opts := svc.SelectionOptions()

	if len(opts.Industries) == 0 {
		t.Fatal("expected industry options")
	}
	// Industries are sorted and carry their catalog template id.
	for i := 1; i < len(opts.Industries); i++ {
		if opts.Industries[i-1].Industry > opts.Industries[i].Industry {
			t.Errorf("industries not sorted: %q before %q",
				opts.Industries[i-1].Industry, opts.Industries[i].Industry)
		}
	}
	if opts.Industries[0].TemplateID == "" {
		t.Error("industry option missing template id")
	}

	// Every country option resolves to the regime the renderer agrees on.
	if len(opts.Countries) == 0 {
		t.Fatal("expected country options")
	}
	for _, c := range opts.Countries {
		regime, ok := RegimeForCountry(c.Country)
		if !ok || regime != c.Regime {
			t.Errorf("country %q regime = %q, RegimeForCountry = (%q,%v)", c.Country, c.Regime, regime, ok)
		}
	}
}
