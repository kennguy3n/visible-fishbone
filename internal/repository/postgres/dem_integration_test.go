//go:build integration

package postgres_test

import (
	"errors"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
)

func f64p(v float64) *float64 { return &v }

// TestDEM_InsertProbeResults_Integration exercises the DEM raw-probe
// ingest path against a real, RLS-enforced Postgres running as the
// non-superuser sng_app role.
//
// This is a regression guard: dem_probe_results has row-level security
// enabled (migration 082), and Postgres rejects COPY FROM on any
// RLS-enabled table. The repository therefore must use a plain
// (chunked) INSERT. The Go service tests cover only the in-memory repo,
// so without this integration test the postgres ingest path was never
// exercised under RLS and a COPY-based implementation would 500 in
// production while every test stayed green.
func TestDEM_InsertProbeResults_Integration(t *testing.T) {
	t.Parallel()
	store, cleanup := startPostgres(t)
	t.Cleanup(cleanup)

	tntA := mustTenant(t, store.NewTenantRepository())
	tntB := mustTenant(t, store.NewTenantRepository())
	repo := postgres.NewDEMRepository(store)

	base := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	since := base.Add(-time.Hour)

	t.Run("ingest_under_rls_and_rollup", func(t *testing.T) {
		// A mixed batch: successful probes (empty ErrorKind -> NULL,
		// populated timings + http_status) and a failed probe (no
		// timings, a bucketed error_kind, NULL http_status). Both the
		// NULL coercion and the CHECK constraints are exercised.
		results := []repository.DEMProbeResult{
			{
				TargetKey: "github", TargetName: "GitHub", ProbeKind: "https", Success: true,
				DNSMs: f64p(3), TCPMs: f64p(8), TLSMs: f64p(12), TTFBMs: f64p(28), TotalMs: f64p(41),
				HTTPStatus: intp(200), ObservedAt: base,
			},
			{
				TargetKey: "github", TargetName: "GitHub", ProbeKind: "https", Success: true,
				DNSMs: f64p(4), TCPMs: f64p(9), TLSMs: f64p(13), TTFBMs: f64p(31), TotalMs: f64p(46),
				HTTPStatus: intp(200), ObservedAt: base.Add(time.Second),
			},
			{
				TargetKey: "github", TargetName: "GitHub", ProbeKind: "https", Success: false,
				ErrorKind: "timeout", ObservedAt: base.Add(2 * time.Second),
			},
		}
		if err := repo.InsertProbeResults(bgCtx(), tntA.ID, results); err != nil {
			t.Fatalf("InsertProbeResults under RLS: %v", err)
		}

		agg, err := repo.WindowAggregate(bgCtx(), tntA.ID, "github", since)
		if err != nil {
			t.Fatalf("WindowAggregate: %v", err)
		}
		if agg.SampleCount != 3 {
			t.Fatalf("SampleCount = %d, want 3", agg.SampleCount)
		}
		if agg.SuccessCount != 2 {
			t.Fatalf("SuccessCount = %d, want 2", agg.SuccessCount)
		}
		if agg.LatencyP50Ms == nil {
			t.Fatal("LatencyP50Ms should be set from the successful probes")
		}
	})

	t.Run("tenant_isolation", func(t *testing.T) {
		// Tenant B never ingested anything; under RLS it must not see
		// tenant A's rows.
		agg, err := repo.WindowAggregate(bgCtx(), tntB.ID, "github", since)
		if err != nil {
			t.Fatalf("WindowAggregate (B): %v", err)
		}
		if agg.SampleCount != 0 {
			t.Fatalf("tenant B SampleCount = %d, want 0 (RLS leak)", agg.SampleCount)
		}
	})

	t.Run("chunked_insert_crosses_boundary", func(t *testing.T) {
		// More rows than demProbeInsertChunk (1000) so the repo splits
		// the batch across multiple INSERT statements; all rows must land.
		const n = 1500
		results := make([]repository.DEMProbeResult, 0, n)
		for i := 0; i < n; i++ {
			results = append(results, repository.DEMProbeResult{
				TargetKey: "slack", TargetName: "Slack", ProbeKind: "https", Success: true,
				TotalMs: f64p(float64(20 + i%10)), ObservedAt: base.Add(time.Duration(i) * time.Millisecond),
			})
		}
		if err := repo.InsertProbeResults(bgCtx(), tntA.ID, results); err != nil {
			t.Fatalf("chunked InsertProbeResults: %v", err)
		}
		agg, err := repo.WindowAggregate(bgCtx(), tntA.ID, "slack", since)
		if err != nil {
			t.Fatalf("WindowAggregate (slack): %v", err)
		}
		if agg.SampleCount != n {
			t.Fatalf("SampleCount = %d, want %d", agg.SampleCount, n)
		}
	})

	t.Run("check_violation_maps_to_invalid_argument", func(t *testing.T) {
		// An out-of-range probe_kind trips the table CHECK; the repo
		// must map it to ErrInvalidArgument (not a raw 500), exactly as
		// the prior COPY path did.
		err := repo.InsertProbeResults(bgCtx(), tntA.ID, []repository.DEMProbeResult{
			{TargetKey: "x", TargetName: "X", ProbeKind: "ftp", Success: true, ObservedAt: base},
		})
		if !errors.Is(err, repository.ErrInvalidArgument) {
			t.Fatalf("bad probe_kind: want ErrInvalidArgument, got %v", err)
		}
	})

	t.Run("empty_batch_is_noop", func(t *testing.T) {
		if err := repo.InsertProbeResults(bgCtx(), tntA.ID, nil); err != nil {
			t.Fatalf("empty batch: %v", err)
		}
	})
}
