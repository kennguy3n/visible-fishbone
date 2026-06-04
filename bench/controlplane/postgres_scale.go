package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresScaleConfig parameterises the Postgres-at-scale bench. It
// needs a live Postgres with the SNG migrations already applied and the
// runtime app role provisioned (the integration test does this via
// testcontainers; an operator can point --dsn at a throwaway database).
type PostgresScaleConfig struct {
	// DSN is a superuser/bootstrap connection string. The bench opens
	// a second pool from it that SET SESSION ROLE-s to AppRole so RLS
	// is enforced exactly as in production, and uses the bootstrap
	// (superuser) pool itself as the RLS-bypassing baseline.
	DSN string
	// AppRole is the non-superuser runtime role RLS applies to.
	AppRole string
	// TenantCount is how many tenants to seed.
	TenantCount int
	// PoolSize is the max connections for the app pool (the pool
	// whose saturation point we probe).
	PoolSize int
	// SampleQueries is how many timed queries each latency
	// measurement issues.
	SampleQueries int
}

// DefaultPostgresScaleConfig returns the full-scale configuration.
func DefaultPostgresScaleConfig(dsn string) PostgresScaleConfig {
	return PostgresScaleConfig{
		DSN:           dsn,
		AppRole:       "sng_app",
		TenantCount:   5000,
		PoolSize:      32,
		SampleQueries: 2000,
	}
}

// RunPostgresScaleBench seeds the database and measures RLS overhead,
// connection-pool saturation, and online-DDL speed at tenant scale.
func RunPostgresScaleBench(ctx context.Context, cfg PostgresScaleConfig) (*PostgresScaleSection, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("postgres-scale requires --dsn (or run --dry-run)")
	}
	if cfg.AppRole == "" {
		cfg.AppRole = "sng_app"
	}
	if cfg.PoolSize <= 0 {
		cfg.PoolSize = 32
	}
	if cfg.SampleQueries <= 0 {
		cfg.SampleQueries = 2000
	}

	superPool, err := pgxpool.New(ctx, cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("open superuser pool: %w", err)
	}
	defer superPool.Close()

	appPool, err := openAppPool(ctx, cfg.DSN, cfg.AppRole, cfg.PoolSize)
	if err != nil {
		return nil, fmt.Errorf("open app-role pool: %w", err)
	}
	defer appPool.Close()

	tenantIDs, err := seedScaleData(ctx, superPool, cfg.TenantCount)
	if err != nil {
		return nil, fmt.Errorf("seed scale data: %w", err)
	}

	section := &PostgresScaleSection{TenantCount: cfg.TenantCount}

	rls, err := measureRLSOverhead(ctx, appPool, superPool, tenantIDs, cfg.SampleQueries)
	if err != nil {
		return nil, err
	}
	section.RLS = rls

	pool, err := measurePoolSaturation(ctx, appPool, cfg.PoolSize, tenantIDs)
	if err != nil {
		return nil, err
	}
	section.Pool = pool

	mig, err := measureMigration(ctx, superPool)
	if err != nil {
		return nil, err
	}
	section.Migration = mig

	section.RowCounts, err = countRows(ctx, superPool)
	if err != nil {
		return nil, err
	}
	section.IndexSizeBytes, err = indexSizes(ctx, superPool)
	if err != nil {
		return nil, err
	}
	return section, nil
}

// openAppPool opens a pool whose every connection adopts AppRole for
// its session, so queries run as a non-superuser and RLS is enforced —
// mirroring the production pool (cmd/sng-control afterConnectSetRole)
// and the integration harness.
func openAppPool(ctx context.Context, dsn, appRole string, size int) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse pool cfg: %w", err)
	}
	poolCfg.MaxConns = int32(size) //nolint:gosec // operator-supplied small bound
	roleIdent := pgx.Identifier{appRole}.Sanitize()
	poolCfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, fmt.Sprintf("SET SESSION ROLE %s", roleIdent))
		return err
	}
	return pgxpool.NewWithConfig(ctx, poolCfg)
}

// seedScaleData bulk-inserts tenants plus 3 sites and a policy graph
// per tenant as the superuser (RLS FORCE does not apply to superusers,
// so no per-tenant GUC dance is needed for the seed). Returns the
// generated tenant IDs for the latency probes. Inserts are batched so
// seeding thousands of tenants stays fast.
func seedScaleData(ctx context.Context, pool *pgxpool.Pool, tenantCount int) ([]uuid.UUID, error) {
	ids := make([]uuid.UUID, 0, tenantCount)
	const batch = 500
	graph := []byte(`{"default_action":"deny","rules":[]}`)

	for start := 0; start < tenantCount; start += batch {
		end := start + batch
		if end > tenantCount {
			end = tenantCount
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			return nil, fmt.Errorf("begin seed tx: %w", err)
		}
		for i := start; i < end; i++ {
			tid := uuid.New()
			ids = append(ids, tid)
			if _, err := tx.Exec(ctx,
				`INSERT INTO tenants (id, name, slug, status, tier) VALUES ($1,$2,$3,'active','professional')`,
				tid, fmt.Sprintf("scale-tenant-%06d", i), fmt.Sprintf("scale-%06d", i),
			); err != nil {
				_ = tx.Rollback(ctx)
				return nil, fmt.Errorf("insert tenant %d: %w", i, err)
			}
			for s := 0; s < 3; s++ {
				if _, err := tx.Exec(ctx,
					`INSERT INTO sites (tenant_id, name, slug, template) VALUES ($1,$2,$3,'branch')`,
					tid, fmt.Sprintf("site-%d", s), fmt.Sprintf("site-%d", s),
				); err != nil {
					_ = tx.Rollback(ctx)
					return nil, fmt.Errorf("insert site for tenant %d: %w", i, err)
				}
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO policy_graphs (tenant_id, version, graph, compiler_version)
				 VALUES ($1, 1, $2, 'sng-policy/0.1')`,
				tid, graph,
			); err != nil {
				_ = tx.Rollback(ctx)
				return nil, fmt.Errorf("insert policy graph for tenant %d: %w", i, err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("commit seed batch: %w", err)
		}
	}
	return ids, nil
}

// measureRLSOverhead times the same tenant-scoped query with RLS
// enforced (app role + sng.tenant_id GUC) versus bypassed (superuser),
// and returns the p99s plus the percentage overhead.
func measureRLSOverhead(ctx context.Context, appPool, superPool *pgxpool.Pool, tenantIDs []uuid.UUID, samples int) (RLSOverhead, error) {
	withRLS := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		tid := tenantIDs[i%len(tenantIDs)]
		start := time.Now()
		err := pgx.BeginFunc(ctx, appPool, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SELECT set_config('sng.tenant_id', $1, true)", tid.String()); err != nil {
				return err
			}
			var n int
			return tx.QueryRow(ctx, "SELECT count(*) FROM sites").Scan(&n)
		})
		if err != nil {
			return RLSOverhead{}, fmt.Errorf("rls query: %w", err)
		}
		withRLS = append(withRLS, time.Since(start))
	}

	withoutRLS := make([]time.Duration, 0, samples)
	for i := 0; i < samples; i++ {
		tid := tenantIDs[i%len(tenantIDs)]
		start := time.Now()
		var n int
		if err := superPool.QueryRow(ctx, "SELECT count(*) FROM sites WHERE tenant_id = $1", tid).Scan(&n); err != nil {
			return RLSOverhead{}, fmt.Errorf("baseline query: %w", err)
		}
		withoutRLS = append(withoutRLS, time.Since(start))
	}

	withP99 := percentileMs(withRLS, 99)
	withoutP99 := percentileMs(withoutRLS, 99)
	var overhead float64
	if withoutP99 > 0 {
		overhead = (withP99 - withoutP99) / withoutP99 * 100
	}
	return RLSOverhead{
		WithRLSP99Ms:    withP99,
		WithoutRLSP99Ms: withoutP99,
		OverheadPct:     overhead,
	}, nil
}

// measurePoolSaturation ramps concurrent queries against the app pool
// and reports the concurrency at which throughput stops climbing (the
// pool's queries queue once concurrency exceeds the pool size) plus the
// peak queries/sec observed.
func measurePoolSaturation(ctx context.Context, appPool *pgxpool.Pool, poolSize int, tenantIDs []uuid.UUID) (PoolSaturation, error) {
	levels := []int{poolSize / 2, poolSize, poolSize * 2, poolSize * 4}
	const perWorker = 50

	var maxRPS float64
	saturation := poolSize
	prevRPS := 0.0
	for _, level := range levels {
		if level < 1 {
			continue
		}
		rps, err := runPoolLevel(ctx, appPool, level, perWorker, tenantIDs)
		if err != nil {
			return PoolSaturation{}, err
		}
		if rps > maxRPS {
			maxRPS = rps
		}
		// "Saturated" once a doubling of concurrency yields < 10% more
		// throughput — beyond this the pool is the bottleneck.
		if prevRPS > 0 && rps < prevRPS*1.10 {
			saturation = level
			break
		}
		saturation = level
		prevRPS = rps
	}
	return PoolSaturation{
		PoolSize:              poolSize,
		SaturationConcurrency: saturation,
		MaxQueriesPerSec:      maxRPS,
	}, nil
}

// runPoolLevel runs `concurrency` workers, each issuing perWorker
// trivial RLS-scoped queries, and returns the achieved queries/sec.
func runPoolLevel(ctx context.Context, appPool *pgxpool.Pool, concurrency, perWorker int, tenantIDs []uuid.UUID) (float64, error) {
	var wg sync.WaitGroup
	errs := make([]error, concurrency)
	start := time.Now()
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				tid := tenantIDs[(idx+i)%len(tenantIDs)]
				err := pgx.BeginFunc(ctx, appPool, func(tx pgx.Tx) error {
					if _, err := tx.Exec(ctx, "SELECT set_config('sng.tenant_id', $1, true)", tid.String()); err != nil {
						return err
					}
					var n int
					return tx.QueryRow(ctx, "SELECT count(*) FROM sites").Scan(&n)
				})
				if err != nil {
					errs[idx] = err
					return
				}
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)
	for _, e := range errs {
		if e != nil {
			return 0, fmt.Errorf("pool level %d: %w", concurrency, e)
		}
	}
	total := float64(concurrency * perWorker)
	if elapsed <= 0 {
		return 0, nil
	}
	return total / elapsed.Seconds(), nil
}

// measureMigration times an online ADD COLUMN on the seeded sites
// table, then drops the column so the bench is repeatable. NOTE:
// Postgres 11+ adds a nullable / constant-default column as a
// metadata-only change, so this is expected to be fast even at scale —
// the measurement documents that the SNG schema's growth operations do
// not table-rewrite, rather than implying a slow migration.
func measureMigration(ctx context.Context, pool *pgxpool.Pool) (MigrationSpeed, error) {
	const stmt = "ALTER TABLE sites ADD COLUMN bench_scratch_flag BOOLEAN NOT NULL DEFAULT false"
	var rowCount int64
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM sites").Scan(&rowCount); err != nil {
		return MigrationSpeed{}, fmt.Errorf("count sites: %w", err)
	}
	start := time.Now()
	if _, err := pool.Exec(ctx, stmt); err != nil {
		return MigrationSpeed{}, fmt.Errorf("add column: %w", err)
	}
	elapsed := time.Since(start)
	if _, err := pool.Exec(ctx, "ALTER TABLE sites DROP COLUMN bench_scratch_flag"); err != nil {
		return MigrationSpeed{}, fmt.Errorf("drop column: %w", err)
	}
	return MigrationSpeed{
		RowCount:  rowCount,
		Statement: "ALTER TABLE sites ADD COLUMN ... NOT NULL DEFAULT false",
		ElapsedMs: float64(elapsed.Nanoseconds()) / 1e6,
	}, nil
}

// countRows returns the row count of the seeded tables.
func countRows(ctx context.Context, pool *pgxpool.Pool) (map[string]int64, error) {
	out := map[string]int64{}
	for _, table := range []string{"tenants", "sites", "policy_graphs"} {
		var n int64
		// Table names are a fixed allow-list above, not user input.
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil { //nolint:gosec // fixed allow-list
			return nil, fmt.Errorf("count %s: %w", table, err)
		}
		out[table] = n
	}
	return out, nil
}

// indexSizes returns the on-disk size of the seeded tables' indexes.
func indexSizes(ctx context.Context, pool *pgxpool.Pool) (map[string]int64, error) {
	rows, err := pool.Query(ctx, `
		SELECT indexrelid::regclass::text AS index_name, pg_relation_size(indexrelid) AS bytes
		FROM pg_index
		WHERE indrelid IN ('tenants'::regclass, 'sites'::regclass, 'policy_graphs'::regclass)`)
	if err != nil {
		return nil, fmt.Errorf("query index sizes: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var name string
		var bytes int64
		if err := rows.Scan(&name, &bytes); err != nil {
			return nil, fmt.Errorf("scan index size: %w", err)
		}
		out[name] = bytes
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate index sizes: %w", err)
	}
	return out, nil
}
