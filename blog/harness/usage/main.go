// Command usage seeds realistic per-tenant metering data by driving the
// production PostgresStore.BatchUpsertUsage path — the exact additive
// upsert the control plane's flush worker uses (metering/store.go).
//
// This is NOT a "write fake rows behind the service's back" tool: it
// persists through the same system-scoped, RLS-aware upsert the live
// flush worker calls, so the rows are indistinguishable from those a
// real billing period would accumulate. The control plane's GET
// /usage and /admin/cost-report read straight from tenant_usage, so
// seeded rows surface immediately with no restart.
//
// Honesty notes for the S7 (cost & metering) blog post:
//   - Seeding mirrors the cost engine's own period model so the
//     dashboard's projected figures and the admin cost report come out
//     consistent and credible, instead of the ~600x anomaly ratios and
//     deeply-negative margins that result from feeding mismatched
//     period semantics into elapsedFraction extrapolation:
//   - Current period (in progress): each meter's row holds the
//     ELAPSED-PROPORTIONAL consumption so far — runRate ×
//     elapsedFraction(period, now). The control plane projects it
//     back (÷ elapsedFraction) to reconstruct the steady-state run
//     rate, so projected usage ≈ runRate and projected spend lands
//     within tier revenue.
//   - History (complete months): each row holds that month's TOTAL.
//     TenantUsageHistory SUMs rows per calendar month, and the cost
//     model prices the monthly total directly (no ×days), so a
//     daily meter's month row is daily_baseline × days-in-month —
//     NOT a single day. Storing a single day here is exactly what
//     made history baselines read ~30x too cheap and blew the
//     anomaly ratios up.
//   - History is 5 trailing complete months ramping up to the current
//     period (a growing-tenant trend), with a small deterministic,
//     tenant+meter-keyed jitter so the lines are not suspiciously
//     smooth but are reproducible across reruns.
//   - Initech carries one MODELLED url-categorisation surge: its
//     current run rate is ~2.5x its historical trend, a realistic
//     mid-period traffic ramp that the cost-anomaly detector flags as a
//     ~3x warning while the tenant stays profitable. Every other meter
//     runs at its steady-state baseline (runRate == baseline).
//   - Idempotent: a tenant that already has current-period rows is
//     skipped, so a rerun neither doubles current usage nor re-adds
//     history (BatchUpsertUsage is additive).
package main

import (
	"context"
	"fmt"
	"hash/fnv"
	"log/slog"
	"math"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kennguy3n/visible-fishbone/internal/service/metering"
)

// seeded customer tenants (the ShieldNet Platform system tenant is
// deliberately excluded — it is not a billed customer).
var tenants = []struct {
	id   string
	name string
	tier string
}{
	{"92112770-7c0a-410b-b0f4-09dde70e063a", "Acme Retail Group", "enterprise"},
	{"3bd7bb7b-d48a-4569-8f97-46be31ae8e5a", "Globex Health Systems", "enterprise"},
	{"b6520bda-e7bb-4af9-9c53-7b0051eae65b", "Initech Financial", "professional"},
	{"0c8d2d9d-896d-45b1-8001-6a6776f832b9", "Umbrella Logistics", "starter"},
}

// baseline is each tenant's STEADY-STATE full-period consumption per
// meter — the value the cost engine should project the current period
// to and the level the trailing-month history ramps toward. For daily
// meters (url_cat_lookups, malware_scans, policy_evaluations) this is a
// representative single-DAY volume; for monthly meters it is the
// full-MONTH volume. Budgeted meters (llm_*, url_cat_lookups,
// policy_evaluations) sit at a fraction of the tier hard limit (see
// metering/budget.go); the unbudgeted cost-driver meters
// (malware_scans, clickhouse_rows_written, s3_bytes_archived,
// bandwidth_proxied_bytes) carry realistic absolute volumes that feed
// the dollar breakdown in the admin cost report. Volumes are calibrated
// so each tenant's projected monthly spend lands comfortably inside its
// tier revenue (starter $99 / professional $499 / enterprise $1999).
var baseline = map[string]map[metering.Meter]int64{
	"Acme Retail Group": { // enterprise $1999 — busy retailer, ~$1.1k projected spend
		metering.MeterLLMCalls:              13_000,            // 65% of 20k/mo
		metering.MeterLLMTokensUsed:         12_000_000,        // 60% of 20M/mo
		metering.MeterURLCatLookups:         120_000,           // 6% of 2M/day (url-cat is the dearest meter)
		metering.MeterPolicyEvaluations:     60_000_000,        // 60% of 100M/day
		metering.MeterMalwareScans:          5_000,             // /day
		metering.MeterClickHouseRowsWritten: 300_000_000,       // /month
		metering.MeterS3BytesArchived:       1_500_000_000_000, // 1.5 TB/month
		metering.MeterBandwidthProxiedBytes: 5_000_000_000_000, // 5 TB/month
	},
	"Globex Health Systems": { // enterprise $1999 — moderate, ~$0.7k projected spend
		metering.MeterLLMCalls:              8_600,
		metering.MeterLLMTokensUsed:         8_000_000,
		metering.MeterURLCatLookups:         80_000,
		metering.MeterPolicyEvaluations:     40_000_000,
		metering.MeterMalwareScans:          3_000,
		metering.MeterClickHouseRowsWritten: 200_000_000,
		metering.MeterS3BytesArchived:       1_000_000_000_000,
		metering.MeterBandwidthProxiedBytes: 3_000_000_000_000,
	},
	"Initech Financial": { // professional $499 — ~$0.44k projected spend
		metering.MeterLLMCalls:              3_250,
		metering.MeterLLMTokensUsed:         3_000_000,
		metering.MeterURLCatLookups:         30_000, // baseline; current run rate is the surge below
		metering.MeterPolicyEvaluations:     15_000_000,
		metering.MeterMalwareScans:          1_200,
		metering.MeterClickHouseRowsWritten: 100_000_000,
		metering.MeterS3BytesArchived:       400_000_000_000,
		metering.MeterBandwidthProxiedBytes: 1_500_000_000_000,
	},
	"Umbrella Logistics": { // starter $99 — light, ~$59 projected spend
		metering.MeterLLMCalls:              600,
		metering.MeterLLMTokensUsed:         600_000,
		metering.MeterURLCatLookups:         6_000,
		metering.MeterPolicyEvaluations:     3_000_000,
		metering.MeterMalwareScans:          200,
		metering.MeterClickHouseRowsWritten: 20_000_000,
		metering.MeterS3BytesArchived:       60_000_000_000,
		metering.MeterBandwidthProxiedBytes: 300_000_000_000,
	},
}

// currentRunRate overrides the current-period run rate for specific
// (tenant, meter) pairs where the in-progress period deviates from the
// historical baseline. Anything not listed runs at its baseline.
//
// Initech's url-categorisation run rate is ~2.5x its baseline this
// period — a realistic mid-period traffic surge. History stays at the
// 30k/day baseline, so the cost-anomaly detector sees the projected
// monthly url-cat spend at ~3x the trailing-month median and raises a
// (non-critical) warning, while Initech still clears its $499 tier.
var currentRunRate = map[string]map[metering.Meter]int64{
	"Initech Financial": {
		metering.MeterURLCatLookups: 75_000, // 2.5x the 30k/day baseline
	},
}

// historyRamp is the fraction of the baseline each of the 5 trailing
// complete months carries (oldest first), modelling a tenant whose
// usage grows toward the current period.
var historyRamp = []float64{0.64, 0.72, 0.80, 0.87, 0.94}

func main() {
	ctx := context.Background()

	pool, err := openPool(ctx)
	if err != nil {
		fatal("connect postgres: " + err.Error())
	}
	defer pool.Close()

	store, err := metering.NewPostgresStore(pool, envOr("PG_APP_ROLE", "sng_app"), false)
	if err != nil {
		fatal("new store: " + err.Error())
	}

	now := time.Now().UTC()
	seededTenants, seededRows := 0, 0
	for _, t := range tenants {
		tid := uuid.MustParse(t.id)

		// Idempotency: skip a tenant that already has current-period
		// rows so a rerun neither doubles current usage nor re-adds
		// history (BatchUpsertUsage is additive).
		existing, err := store.TenantCurrentUsage(ctx, tid, now)
		if err != nil {
			fatal(fmt.Sprintf("current usage for %s: %v", t.name, err))
		}
		if len(existing) > 0 {
			logf("SKIP  %-22s already has %d current rows (idempotent)", t.name, len(existing))
			continue
		}

		deltas := buildDeltas(tid, t.name, now)
		if err := store.BatchUpsertUsage(ctx, deltas); err != nil {
			fatal(fmt.Sprintf("upsert usage for %s: %v", t.name, err))
		}
		logf("OK    %-22s seeded %d usage rows (current + 5mo history)", t.name, len(deltas))
		seededTenants++
		seededRows += len(deltas)
	}
	logf("\nseeded %d usage rows across %d tenants", seededRows, seededTenants)
}

// buildDeltas assembles the current-period row plus 5 trailing months
// of history for every metered dimension of one tenant. The two halves
// deliberately carry different period semantics so the cost engine
// reads them consistently (see the package-level honesty notes):
//   - current row: runRate × elapsedFraction(period, now), so the
//     control plane's ÷-elapsedFraction projection reconstructs runRate;
//   - history rows: each holds that calendar month's TOTAL — for a
//     daily meter that is daily_baseline × days-in-that-month, since the
//     history query SUMs per month and the cost model prices the total
//     directly.
func buildDeltas(tid uuid.UUID, name string, now time.Time) []metering.UsageDelta {
	base := baseline[name]
	out := make([]metering.UsageDelta, 0, len(base)*6)

	for meter, baseVal := range base {
		period := metering.DefaultMeterPeriod(meter)

		// Current period bucket: seed only the elapsed-proportional
		// slice of the run rate so the control plane projects it back to
		// runRate. The run rate is the baseline unless overridden.
		runRate := baseVal
		if rr, ok := currentRunRate[name][meter]; ok {
			runRate = rr
		}
		cs, ce := period.Bounds(now)
		current := int64(math.Round(float64(runRate) * elapsedFraction(period, now)))
		if current < 1 {
			current = 1 // keep the meter present even at the very start of a period
		}
		out = append(out, metering.UsageDelta{
			TenantID: tid, Meter: meter, PeriodStart: cs, PeriodEnd: ce, Delta: current,
		})

		// 5 trailing complete months, ramping up to the baseline. The
		// history query groups by calendar month and SUMs, and the cost
		// model prices that monthly sum directly, so each month's row
		// must be the MONTHLY TOTAL: a daily meter's baseline is a
		// per-day figure, multiplied by the days in that specific month;
		// a monthly meter's baseline is already the monthly total.
		monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		for k := len(historyRamp); k >= 1; k-- {
			ms := monthStart.AddDate(0, -k, 0)
			me := ms.AddDate(0, 1, 0)
			monthlyBase := baseVal
			if period == metering.PeriodDaily {
				monthlyBase = baseVal * daysInMonth(ms)
			}
			frac := historyRamp[len(historyRamp)-k]
			val := int64(float64(monthlyBase) * frac)
			val += jitter(tid, meter, ms, val) // +/- up to ~4%, deterministic
			if val < 0 {
				val = 0
			}
			out = append(out, metering.UsageDelta{
				TenantID: tid, Meter: meter, PeriodStart: ms, PeriodEnd: me, Delta: val,
			})
		}
	}
	return out
}

// elapsedFraction mirrors the control plane's metering.elapsedFraction
// (cost.go): the fraction of `period` containing `now` that has elapsed,
// floored at 0.01 (never extrapolate beyond 100x) and capped at 1. The
// harness reproduces it rather than importing it because it is
// unexported; ProjectToPeriodEnd is its public inverse and the two must
// agree for projected usage to reconstruct the seeded run rate.
func elapsedFraction(period metering.Period, at time.Time) float64 {
	start, end := period.Bounds(at)
	total := end.Sub(start).Seconds()
	if total <= 0 {
		return 1
	}
	frac := at.UTC().Sub(start).Seconds() / total
	const minFraction = 0.01
	if frac < minFraction {
		return minFraction
	}
	if frac > 1 {
		return 1
	}
	return frac
}

// daysInMonth returns the number of days in the calendar month
// containing t.
func daysInMonth(t time.Time) int64 {
	firstNext := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	return int64(firstNext.AddDate(0, 0, -1).Day())
}

// jitter returns a small deterministic +/- perturbation (~±4% of v)
// keyed on tenant+meter+month, so history lines are realistically
// uneven yet reproducible across reruns.
func jitter(tid uuid.UUID, meter metering.Meter, month time.Time, v int64) int64 {
	h := fnv.New64a()
	_, _ = h.Write(tid[:])
	_, _ = h.Write([]byte(meter))
	_, _ = h.Write([]byte(month.Format("2006-01")))
	// map hash to [-1.0, 1.0)
	r := (float64(h.Sum64()%2000) / 1000.0) - 1.0
	return int64(r * 0.04 * float64(v))
}

func openPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		envOr("PG_HOST", "localhost"), envOr("PG_PORT", "5432"),
		envOr("PG_USER", "sng"), envOr("PG_PASSWORD", "sng"),
		envOr("PG_DATABASE", "sng"), envOr("PG_SSLMODE", "disable"),
	)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	// Adopt the RLS app-role on every connection, exactly as the
	// control plane does (afterConnectSetRole in cmd/sng-control).
	appRole := envOr("PG_APP_ROLE", "sng_app")
	if appRole != "" {
		setRole := "SET SESSION ROLE " + pgx.Identifier{appRole}.Sanitize()
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			if _, err := conn.Exec(ctx, setRole); err != nil {
				return fmt.Errorf("set session role %q: %w", appRole, err)
			}
			return nil
		}
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var logger = slog.New(slog.NewTextHandler(os.Stderr, nil))

func logf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }

func fatal(msg string) {
	logger.Error(msg)
	os.Exit(1)
}
