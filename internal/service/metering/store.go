package metering

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore is the production UsageStore + BudgetStore backed by
// pgxpool. It mirrors internal/repository/postgres's transaction
// conventions: every tenant-scoped statement runs inside a short
// transaction that sets the transaction-local `sng.tenant_id` GUC so
// the migration-040 RLS policy isolates the tenant, while the
// cross-tenant flush and the platform cost report run with
// `sng.system_role='true'`.
//
// It lives in the metering package (rather than
// internal/repository/postgres) so Session K stays self-contained and
// does not edit the shared Store/repos registry that other parallel
// sessions also touch; the GUC + role-adoption logic is duplicated
// deliberately and kept faithful to the original.
type PostgresStore struct {
	pool          *pgxpool.Pool
	appRole       string
	pgBouncerMode bool
}

// NewPostgresStore wraps a primary pgxpool.Pool. appRole and
// pgBouncerMode mirror the values used to build the main repository
// pool: when pgBouncerMode is true the store issues a transaction-local
// `SET LOCAL ROLE <appRole>` at the top of every transaction (session
// mode adopts the role per-connection, so the SET is unnecessary
// there).
func NewPostgresStore(pool *pgxpool.Pool, appRole string, pgBouncerMode bool) (*PostgresStore, error) {
	if pool == nil {
		return nil, fmt.Errorf("metering: postgres store: pool must not be nil")
	}
	return &PostgresStore{pool: pool, appRole: appRole, pgBouncerMode: pgBouncerMode}, nil
}

// adoptLocalRole issues SET LOCAL ROLE when in PgBouncer mode.
func (s *PostgresStore) adoptLocalRole(ctx context.Context, tx pgx.Tx) error {
	if !s.pgBouncerMode || s.appRole == "" {
		return nil
	}
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgx.Identifier{s.appRole}.Sanitize()); err != nil {
		return fmt.Errorf("set local role: %w", err)
	}
	return nil
}

// withTenant runs fn inside a transaction whose sng.tenant_id GUC is
// set to tenantID, so RLS scopes every statement to that tenant.
func (s *PostgresStore) withTenant(ctx context.Context, tenantID uuid.UUID, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.adoptLocalRole(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('sng.tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("set tenant context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// withSystem runs fn inside a transaction that signals system-level
// access via sng.system_role='true', so the RLS policy's system-role
// bypass clause permits cross-tenant reads / writes. Used by the
// background flush worker and the platform cost report only.
func (s *PostgresStore) withSystem(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin system tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.adoptLocalRole(ctx, tx); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('sng.system_role', 'true', true)"); err != nil {
		return fmt.Errorf("set system context: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit system tx: %w", err)
	}
	return nil
}

// BatchUpsertUsage applies every delta in a single system-scoped
// transaction via one multi-row, additive upsert. The unnest form
// keeps the statement count at one regardless of batch size, and the
// `value = tenant_usage.value + EXCLUDED.value` clause guarantees a
// replayed or concurrent flush adds rather than overwrites.
func (s *PostgresStore) BatchUpsertUsage(ctx context.Context, deltas []UsageDelta) error {
	if len(deltas) == 0 {
		return nil
	}
	tenantIDs := make([]uuid.UUID, len(deltas))
	meters := make([]string, len(deltas))
	starts := make([]time.Time, len(deltas))
	ends := make([]time.Time, len(deltas))
	values := make([]int64, len(deltas))
	for i, d := range deltas {
		tenantIDs[i] = d.TenantID
		meters[i] = string(d.Meter)
		starts[i] = d.PeriodStart
		ends[i] = d.PeriodEnd
		values[i] = d.Delta
	}
	const q = `
INSERT INTO tenant_usage (tenant_id, meter, period_start, period_end, value)
SELECT * FROM unnest($1::uuid[], $2::text[], $3::date[], $4::date[], $5::bigint[])
ON CONFLICT (tenant_id, meter, period_start)
DO UPDATE SET value = tenant_usage.value + EXCLUDED.value`
	return s.withSystem(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, q, tenantIDs, meters, starts, ends, values); err != nil {
			return fmt.Errorf("batch upsert usage: %w", err)
		}
		return nil
	})
}

// TenantPeriodUsage returns the persisted value for one
// (tenant, meter, period_start), or 0 if absent.
func (s *PostgresStore) TenantPeriodUsage(ctx context.Context, tenantID uuid.UUID, meter Meter, periodStart time.Time) (int64, error) {
	var value int64
	err := s.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const q = `SELECT value FROM tenant_usage WHERE tenant_id = $1 AND meter = $2 AND period_start = $3::date`
		row := tx.QueryRow(ctx, q, tenantID, string(meter), periodStart)
		if err := row.Scan(&value); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				value = 0
				return nil
			}
			return fmt.Errorf("scan period usage: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return value, nil
}

// TenantCurrentUsage returns every usage row for a tenant whose period
// contains `at`.
func (s *PostgresStore) TenantCurrentUsage(ctx context.Context, tenantID uuid.UUID, at time.Time) ([]UsageRecord, error) {
	var out []UsageRecord
	err := s.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const q = `
SELECT meter, period_start, period_end, value, updated_at
FROM tenant_usage
WHERE tenant_id = $1 AND period_start <= $2::date AND period_end > $2::date
ORDER BY meter`
		rows, err := tx.Query(ctx, q, tenantID, at.UTC())
		if err != nil {
			return fmt.Errorf("query current usage: %w", err)
		}
		defer rows.Close()
		recs, err := scanUsageRows(rows, tenantID)
		if err != nil {
			return err
		}
		out = recs
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TenantUsageHistory returns monthly-aggregated usage for a tenant over
// the trailing `months` calendar months. Rows are summed per
// (month, meter); PeriodStart is the first day of the month and
// PeriodEnd the first day of the next.
func (s *PostgresStore) TenantUsageHistory(ctx context.Context, tenantID uuid.UUID, months int) ([]UsageRecord, error) {
	if months <= 0 {
		months = 6
	}
	var out []UsageRecord
	err := s.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const q = `
SELECT date_trunc('month', period_start)::date AS month_start,
       meter,
       SUM(value)::bigint AS total
FROM tenant_usage
WHERE tenant_id = $1
  AND period_start >= (date_trunc('month', now()) - make_interval(months => $2))::date
GROUP BY month_start, meter
ORDER BY month_start DESC, meter`
		rows, err := tx.Query(ctx, q, tenantID, months)
		if err != nil {
			return fmt.Errorf("query usage history: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				monthStart time.Time
				meter      string
				total      int64
			)
			if err := rows.Scan(&monthStart, &meter, &total); err != nil {
				return fmt.Errorf("scan usage history: %w", err)
			}
			monthStart = monthStart.UTC()
			out = append(out, UsageRecord{
				TenantID:    tenantID,
				Meter:       Meter(meter),
				PeriodStart: monthStart,
				PeriodEnd:   monthStart.AddDate(0, 1, 0),
				Value:       total,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// PlatformCurrentUsage returns every tenant's usage rows whose period
// contains `at`, for the MSP/admin platform-wide cost report. Runs
// system-scoped so it crosses tenant boundaries.
func (s *PostgresStore) PlatformCurrentUsage(ctx context.Context, at time.Time) ([]UsageRecord, error) {
	var out []UsageRecord
	err := s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `
SELECT tenant_id, meter, period_start, period_end, value, updated_at
FROM tenant_usage
WHERE period_start <= $1::date AND period_end > $1::date
ORDER BY tenant_id, meter`
		rows, err := tx.Query(ctx, q, at.UTC())
		if err != nil {
			return fmt.Errorf("query platform usage: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				r         UsageRecord
				meter     string
				updatedAt time.Time
			)
			if err := rows.Scan(&r.TenantID, &meter, &r.PeriodStart, &r.PeriodEnd, &r.Value, &updatedAt); err != nil {
				return fmt.Errorf("scan platform usage: %w", err)
			}
			r.Meter = Meter(meter)
			r.PeriodStart = r.PeriodStart.UTC()
			r.PeriodEnd = r.PeriodEnd.UTC()
			r.UpdatedAt = updatedAt
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// scanUsageRows scans (meter, period_start, period_end, value,
// updated_at) rows for a fixed tenant.
func scanUsageRows(rows pgx.Rows, tenantID uuid.UUID) ([]UsageRecord, error) {
	var out []UsageRecord
	for rows.Next() {
		var (
			r         UsageRecord
			meter     string
			updatedAt time.Time
		)
		if err := rows.Scan(&meter, &r.PeriodStart, &r.PeriodEnd, &r.Value, &updatedAt); err != nil {
			return nil, fmt.Errorf("scan usage row: %w", err)
		}
		r.TenantID = tenantID
		r.Meter = Meter(meter)
		r.PeriodStart = r.PeriodStart.UTC()
		r.PeriodEnd = r.PeriodEnd.UTC()
		r.UpdatedAt = updatedAt
		out = append(out, r)
	}
	return out, nil
}

// --- BudgetStore -----------------------------------------------------------

// TenantBudgets returns every budget override row for a tenant.
func (s *PostgresStore) TenantBudgets(ctx context.Context, tenantID uuid.UUID) ([]BudgetLimit, error) {
	var out []BudgetLimit
	err := s.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const q = `SELECT meter, soft_limit, hard_limit, period FROM tenant_budgets WHERE tenant_id = $1 ORDER BY meter`
		rows, err := tx.Query(ctx, q, tenantID)
		if err != nil {
			return fmt.Errorf("query tenant budgets: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				meter  string
				period string
				lim    BudgetLimit
			)
			if err := rows.Scan(&meter, &lim.SoftLimit, &lim.HardLimit, &period); err != nil {
				return fmt.Errorf("scan tenant budget: %w", err)
			}
			lim.Meter = Meter(meter)
			lim.Period = Period(period)
			out = append(out, lim)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TenantBudgetsBatch returns the override rows for many tenants in a
// single query (WHERE tenant_id = ANY($1)) rather than one query per
// tenant. It runs system-scoped — like PlatformCurrentUsage, its only
// caller is the platform-wide cost report, which already crosses tenant
// boundaries under the system role — so a single statement can return
// every tenant's overrides at once. Rows are grouped by tenant id and
// kept in (tenant_id, meter) order so each tenant's slice matches the
// deterministic ordering of the single-tenant TenantBudgets query. A
// tenant with no override rows is simply absent from the result map.
func (s *PostgresStore) TenantBudgetsBatch(ctx context.Context, tenantIDs []uuid.UUID) (map[uuid.UUID][]BudgetLimit, error) {
	out := make(map[uuid.UUID][]BudgetLimit, len(tenantIDs))
	if len(tenantIDs) == 0 {
		return out, nil
	}
	err := s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `SELECT tenant_id, meter, soft_limit, hard_limit, period
FROM tenant_budgets
WHERE tenant_id = ANY($1)
ORDER BY tenant_id, meter`
		rows, err := tx.Query(ctx, q, tenantIDs)
		if err != nil {
			return fmt.Errorf("query tenant budgets batch: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				tenantID uuid.UUID
				meter    string
				period   string
				lim      BudgetLimit
			)
			if err := rows.Scan(&tenantID, &meter, &lim.SoftLimit, &lim.HardLimit, &period); err != nil {
				return fmt.Errorf("scan tenant budget batch: %w", err)
			}
			lim.Meter = Meter(meter)
			lim.Period = Period(period)
			out[tenantID] = append(out[tenantID], lim)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UpsertTenantBudget inserts or replaces one budget override.
func (s *PostgresStore) UpsertTenantBudget(ctx context.Context, tenantID uuid.UUID, limit BudgetLimit) error {
	return s.UpsertTenantBudgets(ctx, tenantID, []BudgetLimit{limit})
}

// UpsertTenantBudgets inserts or replaces every override in a single
// tenant-scoped transaction via one multi-row upsert, so a batch of
// overrides is applied all-or-nothing: if any row fails the whole
// transaction rolls back and no partial set is left behind. The unnest
// form keeps the statement count at one regardless of batch size.
func (s *PostgresStore) UpsertTenantBudgets(ctx context.Context, tenantID uuid.UUID, limits []BudgetLimit) error {
	if len(limits) == 0 {
		return nil
	}
	meters := make([]string, len(limits))
	softs := make([]int64, len(limits))
	hards := make([]int64, len(limits))
	periods := make([]string, len(limits))
	for i, l := range limits {
		meters[i] = string(l.Meter)
		softs[i] = l.SoftLimit
		hards[i] = l.HardLimit
		periods[i] = string(l.Period)
	}
	const q = `
INSERT INTO tenant_budgets (tenant_id, meter, soft_limit, hard_limit, period)
SELECT $1, * FROM unnest($2::text[], $3::bigint[], $4::bigint[], $5::text[])
ON CONFLICT (tenant_id, meter)
DO UPDATE SET soft_limit = EXCLUDED.soft_limit,
              hard_limit = EXCLUDED.hard_limit,
              period     = EXCLUDED.period`
	return s.withTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, q, tenantID, meters, softs, hards, periods); err != nil {
			return fmt.Errorf("upsert tenant budgets: %w", err)
		}
		return nil
	})
}

// ensure PostgresStore satisfies both store interfaces.
var (
	_ UsageStore  = (*PostgresStore)(nil)
	_ BudgetStore = (*PostgresStore)(nil)
)
