// Command anomalies seeds *real* anomaly-detection alerts by driving
// the production baseline.Detector over a realistic per-dimension time
// series and persisting whatever the detector genuinely emits.
//
// This is deliberately NOT a "write fake alert rows" tool. It wires the
// exact same objects the control plane wires (postgres baseline +
// alert + suppression repositories, baseline.Service, baseline.Detector,
// alert.Router) and feeds Observations through Detector.ObserveAndScore.
// The detector computes the Welford/EWMA z-scores itself and only emits
// when max(|zW|,|zE|) >= the model's ZThreshold after warmup. Every
// alert that lands is therefore a genuine detector verdict on the fed
// series — the evidence the S3/S6 blog posts show in the Alerts UI.
//
// Design choices for honest, reproducible evidence:
//   - The warmup series is a fixed, seeded pseudo-random walk around a
//     per-dimension mean (deterministic: same run => same series =>
//     same z-scores), so the captured alerts are reproducible.
//   - Spikes are injected at known buckets; the resulting severity
//     (warning >= 3.0σ, critical >= 4.5σ) falls out of the real math,
//     not a hand-set field.
//   - Idempotent: a tenant that already has alerts is skipped, so the
//     baseline models aren't re-folded and alerts aren't duplicated on
//     a rerun.
//
// Usage:
//
//	AUTH_JWT_SECRET unused here; DB creds come from PG_* env (same as
//	the control plane). Run with the control plane's environment:
//	  go run ./blog/harness/anomalies
package main

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kennguy3n/visible-fishbone/blog/harness/fleet"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
	"github.com/kennguy3n/visible-fishbone/internal/service/alert"
	"github.com/kennguy3n/visible-fishbone/internal/service/baseline"
)

// seeded tenants whose baselines this harness folds — the first four
// scenario tenants. Identities come from the shared fleet package (the
// single source of truth), so they always match seed-summary.json.
var tenants = []fleet.Tenant{fleet.Acme(), fleet.Globex(), fleet.Initech(), fleet.Umbrella()}

// dimProfile is one monitored metric and the spikes injected after
// warmup. mean/std drive the warmup walk; spikeMultiples are how many
// multiples of std above the mean the spike bucket carries (the actual
// z-score the detector reports is close to but not exactly this, since
// the EWMA variance has its own dynamics — we let the detector decide).
type dimProfile struct {
	dim           string
	kind          string
	mean, std     float64
	spikeMultiple []float64 // injected after warmup, one alert candidate each
}

// Per-dimension profiles. Spike multiples are tuned so the run yields a
// realistic spread of warning (>=3σ) and critical (>=4.5σ) alerts
// across dimensions, but the severity itself is computed by the
// detector, not asserted here.
var profiles = []dimProfile{
	{"egress_bytes_per_min", "baseline.exfil_volume", 4_200_000, 480_000, []float64{5.2}}, // data-exfil spike -> critical
	{"dns_nxdomain_rate", "baseline.dga_c2", 18, 4.0, []float64{3.4}},                     // DGA/C2 beaconing -> warning
	{"auth_failures_per_min", "baseline.credential_stuffing", 6, 2.2, []float64{4.8}},     // credential stuffing -> critical
	{"blocked_sessions_per_min", "baseline.policy_block_surge", 140, 22, []float64{3.1}},  // policy-block surge -> warning
	{"newly_registered_domain_hits", "baseline.nrd_access", 9, 3.0, []float64{3.6}},       // NRD access burst -> warning
}

const windowSeconds = 60

func main() {
	ctx := context.Background()

	pool, err := openPool(ctx)
	if err != nil {
		fatal("connect postgres: " + err.Error())
	}
	defer pool.Close()

	store := postgres.NewStoreWithPool(postgres.NewReadWritePool(postgres.ReadWritePoolConfig{
		Primary: pool,
		AppRole: envOr("PG_APP_ROLE", "sng_app"),
	}))
	baselineRepo := store.NewBaselineModelRepository()
	alertRepo := store.NewAlertRepository()
	suppRepo := store.NewAlertSuppressionRepository()

	router := alert.NewRouter(alertRepo, suppRepo, nil, alert.Options{})
	svc := baseline.NewService(baselineRepo)
	det := baseline.NewDetector(svc, router, baseline.DetectorOptions{})

	totalEmitted := 0
	for _, t := range tenants {
		tid := uuid.MustParse(t.ID)

		// Idempotency: skip a tenant that already has alerts so a
		// rerun neither re-folds baselines nor duplicates alerts.
		existing, err := alertRepo.List(ctx, tid, repository.AlertListFilter{}, repository.Page{Limit: 1})
		if err != nil {
			fatal(fmt.Sprintf("list alerts for %s: %v", t.Name, err))
		}
		if len(existing.Items) > 0 {
			logf("SKIP  %-22s already has alerts (idempotent)", t.Name)
			continue
		}

		emitted := seedTenant(ctx, det, tid)
		logf("OK    %-22s emitted %d real anomaly alerts", t.Name, emitted)
		totalEmitted += emitted
	}
	logf("\nseeded %d anomaly alerts across %d tenants", totalEmitted, len(tenants))
}

// seedTenant feeds the warmup walk + spikes for every profile and
// returns how many alerts the detector actually emitted.
func seedTenant(ctx context.Context, det *baseline.Detector, tid uuid.UUID) int {
	// Deterministic RNG keyed on the tenant so each tenant gets a
	// stable-but-distinct series (reproducible across runs).
	seed := int64(0)
	for _, b := range tid[:8] {
		seed = seed*31 + int64(b)
	}
	// math/rand (not crypto/rand) is intentional: the series must be
	// deterministic and reproducible from a per-tenant seed so the
	// captured alerts are stable across runs. This is synthetic
	// test-data generation, not a security-sensitive draw.
	rng := rand.New(rand.NewSource(seed)) //nolint:gosec // G404: deterministic, reproducible synthetic data; not security-sensitive

	const warmup = 36 // > MinWarmupSamples (30) so spikes are eligible

	emitted := 0
	for _, p := range profiles {
		// Back-date the series so the spike buckets are recent: the
		// last spike lands ~1 window before "now".
		total := warmup + len(p.spikeMultiple)
		base := time.Now().UTC().Add(-time.Duration(total) * time.Duration(windowSeconds) * time.Second)

		// A mutable clock the detector reads for CreatedAt/WindowEnd.
		obsAt := base
		det.SetClock(func() time.Time { return obsAt })

		// Warmup: normal buckets, no alert expected (the detector
		// gates on warmup + threshold; we don't assert, we observe).
		for i := 0; i < warmup; i++ {
			v := p.mean + rng.NormFloat64()*p.std
			if v < 0 {
				v = 0
			}
			obsAt = base.Add(time.Duration(i) * time.Duration(windowSeconds) * time.Second)
			if _, _, err := det.ObserveAndScore(ctx, tid, p.dim, windowSeconds,
				baseline.Observation{Value: v, At: obsAt}, p.kind); err != nil {
				fatal(fmt.Sprintf("observe %s/%s warmup[%d]: %v", tid, p.dim, i, err))
			}
		}

		// Spikes: a bucket far above the established mean. The
		// detector computes the z-score and decides severity.
		for j, mult := range p.spikeMultiple {
			v := p.mean + math.Abs(mult)*p.std
			obsAt = base.Add(time.Duration(warmup+j) * time.Duration(windowSeconds) * time.Second)
			_, a, err := det.ObserveAndScore(ctx, tid, p.dim, windowSeconds,
				baseline.Observation{Value: v, At: obsAt}, p.kind)
			if err != nil {
				fatal(fmt.Sprintf("observe %s/%s spike[%d]: %v", tid, p.dim, j, err))
			}
			if a != nil {
				emitted++
			}
		}
	}
	return emitted
}

func openPool(ctx context.Context) (*pgxpool.Pool, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		envOr("PG_HOST", "127.0.0.1"), envOr("PG_PORT", "5432"),
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
			var cur string
			if err := conn.QueryRow(ctx, "SELECT current_user").Scan(&cur); err != nil {
				return err
			}
			if cur != appRole {
				return fmt.Errorf("current_user=%q want %q", cur, appRole)
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

func logf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
func fatal(msg string)                { fmt.Fprintln(os.Stderr, "fatal: "+msg); os.Exit(1) }
