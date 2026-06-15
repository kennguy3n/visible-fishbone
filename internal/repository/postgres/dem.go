// Package postgres — dem.go is the postgres implementation of the
// Digital Experience Monitoring repository (WP5). It owns the four
// dem_* tables from migrations 091-094.
//
// Target CRUD, the rolling-window aggregate, and score listing are
// tenant-scoped (RLS via sng.tenant_id). The two retention prunes
// run cross-tenant under the system role, mirroring the background
// -worker access pattern documented on withSystem.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DEMRepository owns the dem_targets, dem_probe_results,
// dem_experience_scores, and dem_target_state tables.
type DEMRepository struct{ s *Store }

// NewDEMRepository binds a Store.
func NewDEMRepository(s *Store) *DEMRepository { return &DEMRepository{s: s} }

var _ repository.DEMRepository = (*DEMRepository)(nil)

const demTargetCols = `
id, tenant_id, target_key, name, probe_kind, address, port,
enabled, interval_seconds, timeout_ms, created_at, updated_at
`

const demScoreCols = `
id, tenant_id, target_key, target_name, score, availability,
latency_p50_ms, latency_p95_ms, sample_count, window_seconds,
window_start, window_end, created_at
`

const demStateCols = `
id, tenant_id, target_key, target_name, ewma_score, ewma_variance,
last_score, sample_count, degraded, last_alert_at, last_observed_at,
created_at, updated_at
`

// demProbeCopyColumns is the column order InsertProbeResults streams
// via COPY; id and created_at take their column defaults.
var demProbeCopyColumns = []string{
	"tenant_id", "target_key", "target_name", "probe_kind", "success",
	"dns_ms", "tcp_ms", "tls_ms", "ttfb_ms", "total_ms",
	"http_status", "error_kind", "observed_at",
}

// floatOrNil / intOrNil / textOrNil coerce optional Go values into
// the `any` a NULLable column expects: a typed nil becomes SQL NULL.
func floatOrNil(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

func intOrNil(p *int) any {
	if p == nil {
		return nil
	}
	return *p
}

func textOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// nullFloatPtr / nullIntPtr project a scanned SQL NULL wrapper back
// onto the optional pointer field of a row struct.
func nullFloatPtr(n sql.NullFloat64) *float64 {
	if !n.Valid {
		return nil
	}
	v := n.Float64
	return &v
}

func nullIntPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

func scanDEMTarget(row pgx.Row) (repository.DEMTarget, error) {
	var (
		t    repository.DEMTarget
		port sql.NullInt64
	)
	if err := row.Scan(
		&t.ID, &t.TenantID, &t.TargetKey, &t.Name, &t.ProbeKind, &t.Address, &port,
		&t.Enabled, &t.IntervalSeconds, &t.TimeoutMs, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return repository.DEMTarget{}, err
	}
	t.Port = nullIntPtr(port)
	return t, nil
}

func scanDEMScore(row pgx.Row) (repository.DEMExperienceScore, error) {
	var (
		s        repository.DEMExperienceScore
		p50, p95 sql.NullFloat64
	)
	if err := row.Scan(
		&s.ID, &s.TenantID, &s.TargetKey, &s.TargetName, &s.Score, &s.Availability,
		&p50, &p95, &s.SampleCount, &s.WindowSeconds, &s.WindowStart, &s.WindowEnd, &s.CreatedAt,
	); err != nil {
		return repository.DEMExperienceScore{}, err
	}
	s.LatencyP50Ms = nullFloatPtr(p50)
	s.LatencyP95Ms = nullFloatPtr(p95)
	return s, nil
}

func scanDEMState(row pgx.Row) (repository.DEMTargetState, error) {
	var (
		st                       repository.DEMTargetState
		ewmaScore, ewmaVar, last sql.NullFloat64
		lastAlertAt, lastObsAt   deletedAtScan
	)
	if err := row.Scan(
		&st.ID, &st.TenantID, &st.TargetKey, &st.TargetName,
		&ewmaScore, &ewmaVar, &last, &st.SampleCount, &st.Degraded,
		&lastAlertAt, &lastObsAt, &st.CreatedAt, &st.UpdatedAt,
	); err != nil {
		return repository.DEMTargetState{}, err
	}
	st.EWMAScore = nullFloatPtr(ewmaScore)
	st.EWMAVariance = nullFloatPtr(ewmaVar)
	st.LastScore = nullFloatPtr(last)
	if lastAlertAt.Valid {
		v := lastAlertAt.Time
		st.LastAlertAt = &v
	}
	if lastObsAt.Valid {
		v := lastObsAt.Time
		st.LastObservedAt = &v
	}
	return st, nil
}

// -----------------------------------------------------------------------
// Targets
// -----------------------------------------------------------------------

// CreateTarget persists a new custom target. A duplicate
// (tenant, target_key) surfaces as ErrConflict; a CHECK violation
// (bad port / interval / timeout / probe_kind) as ErrInvalidArgument.
func (r *DEMRepository) CreateTarget(
	ctx context.Context,
	tenantID uuid.UUID,
	t repository.DEMTarget,
) (repository.DEMTarget, error) {
	if tenantID == uuid.Nil {
		return repository.DEMTarget{}, repository.ErrInvalidArgument
	}
	if t.TargetKey == "" || t.Name == "" || t.ProbeKind == "" || t.Address == "" {
		return repository.DEMTarget{}, repository.ErrInvalidArgument
	}
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	var out repository.DEMTarget
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO dem_targets
    (id, tenant_id, target_key, name, probe_kind, address, port,
     enabled, interval_seconds, timeout_ms)
VALUES
    ($1::uuid, $2::uuid, $3, $4, $5, $6, $7,
     $8, $9, $10)
RETURNING ` + demTargetCols
		row := tx.QueryRow(ctx, q,
			t.ID, tenantID, t.TargetKey, t.Name, t.ProbeKind, t.Address, intOrNil(t.Port),
			t.Enabled, t.IntervalSeconds, t.TimeoutMs,
		)
		scanned, err := scanDEMTarget(row)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("insert dem_targets: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// GetTarget returns one target by id, scoped to tenant.
func (r *DEMRepository) GetTarget(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.DEMTarget, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.DEMTarget{}, repository.ErrInvalidArgument
	}
	var out repository.DEMTarget
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+demTargetCols+` FROM dem_targets WHERE id = $1::uuid`, id)
		scanned, err := scanDEMTarget(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select dem_targets: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// UpdateTarget mutates the addressable fields of an existing target.
// target_key is immutable (it is the scoring dimension), so it is
// not updated here.
func (r *DEMRepository) UpdateTarget(
	ctx context.Context,
	tenantID uuid.UUID,
	t repository.DEMTarget,
) (repository.DEMTarget, error) {
	if tenantID == uuid.Nil || t.ID == uuid.Nil {
		return repository.DEMTarget{}, repository.ErrInvalidArgument
	}
	if t.Name == "" || t.ProbeKind == "" || t.Address == "" {
		return repository.DEMTarget{}, repository.ErrInvalidArgument
	}
	var out repository.DEMTarget
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
UPDATE dem_targets
SET name             = $2,
    probe_kind       = $3,
    address          = $4,
    port             = $5,
    enabled          = $6,
    interval_seconds = $7,
    timeout_ms       = $8,
    updated_at       = NOW()
WHERE id = $1::uuid
RETURNING ` + demTargetCols
		row := tx.QueryRow(ctx, q,
			t.ID, t.Name, t.ProbeKind, t.Address, intOrNil(t.Port),
			t.Enabled, t.IntervalSeconds, t.TimeoutMs,
		)
		scanned, err := scanDEMTarget(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("update dem_targets: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// DeleteTarget removes a custom target by id.
func (r *DEMRepository) DeleteTarget(ctx context.Context, tenantID, id uuid.UUID) error {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM dem_targets WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete dem_targets: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// ListTargets enumerates a tenant's custom targets, keyset
// paginated by (created_at, id).
func (r *DEMRepository) ListTargets(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.DEMTarget], error) {
	if tenantID == uuid.Nil {
		return repository.PageResult[repository.DEMTarget]{}, repository.ErrInvalidArgument
	}
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.DEMTarget]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.DEMTarget]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		cmp, dir := "<", "DESC"
		if page.Order == repository.SortAsc {
			cmp, dir = ">", "ASC"
		}
		args := []any{nil, nil, page.Limit}
		if !cur.T.IsZero() || cur.I != uuid.Nil {
			args[0] = cur.T
			args[1] = cur.I
		}
		q := fmt.Sprintf(`
SELECT %s
FROM dem_targets
WHERE ($1::timestamptz IS NULL OR (created_at, id) %s ($1::timestamptz, $2::uuid))
ORDER BY created_at %s, id %s
LIMIT $3
`, demTargetCols, cmp, dir, dir)
		rows, qerr := tx.Query(ctx, q, args...)
		if qerr != nil {
			return fmt.Errorf("list dem_targets: %w", qerr)
		}
		defer rows.Close()
		items := make([]repository.DEMTarget, 0, page.Limit)
		for rows.Next() {
			t, serr := scanDEMTarget(rows)
			if serr != nil {
				return fmt.Errorf("scan dem_targets: %w", serr)
			}
			items = append(items, t)
		}
		if rerr := rows.Err(); rerr != nil {
			return fmt.Errorf("iterate dem_targets: %w", rerr)
		}
		res.Items = items
		if len(items) == page.Limit && len(items) > 0 {
			last := items[len(items)-1]
			res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		return nil
	})
	return res, err
}

// -----------------------------------------------------------------------
// Raw probe results
// -----------------------------------------------------------------------

// InsertProbeResults bulk-loads ingested samples via COPY inside one
// tenant-scoped transaction. COPY sidesteps the multi-row INSERT
// parameter ceiling and keeps the ingest hot path cheap; RLS WITH
// CHECK on the tenant policy still applies to every copied row.
func (r *DEMRepository) InsertProbeResults(
	ctx context.Context,
	tenantID uuid.UUID,
	results []repository.DEMProbeResult,
) error {
	if tenantID == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	if len(results) == 0 {
		return nil
	}
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows := make([][]any, 0, len(results))
		for _, res := range results {
			rows = append(rows, []any{
				tenantID, res.TargetKey, res.TargetName, res.ProbeKind, res.Success,
				floatOrNil(res.DNSMs), floatOrNil(res.TCPMs), floatOrNil(res.TLSMs),
				floatOrNil(res.TTFBMs), floatOrNil(res.TotalMs),
				intOrNil(res.HTTPStatus), textOrNil(res.ErrorKind), res.ObservedAt.UTC(),
			})
		}
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"dem_probe_results"}, demProbeCopyColumns,
			pgx.CopyFromRows(rows),
		); err != nil {
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("copy dem_probe_results: %w", err)
		}
		return nil
	})
}

// WindowAggregate rolls up one target's results observed at/after
// `since`. Latency percentiles are computed in SQL over the best
// available timing (total → TTFB → TCP → DNS) of successful probes;
// availability is the success ratio over all probes in the window.
func (r *DEMRepository) WindowAggregate(
	ctx context.Context,
	tenantID uuid.UUID,
	targetKey string,
	since time.Time,
) (repository.DEMWindowAggregate, error) {
	if tenantID == uuid.Nil || targetKey == "" {
		return repository.DEMWindowAggregate{}, repository.ErrInvalidArgument
	}
	agg := repository.DEMWindowAggregate{TargetKey: targetKey}
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
SELECT
    count(*)                                  AS sample_count,
    count(*) FILTER (WHERE success)           AS success_count,
    percentile_cont(0.5) WITHIN GROUP (
        ORDER BY COALESCE(total_ms, ttfb_ms, tcp_ms, dns_ms)
    ) FILTER (WHERE success AND COALESCE(total_ms, ttfb_ms, tcp_ms, dns_ms) IS NOT NULL) AS p50,
    percentile_cont(0.95) WITHIN GROUP (
        ORDER BY COALESCE(total_ms, ttfb_ms, tcp_ms, dns_ms)
    ) FILTER (WHERE success AND COALESCE(total_ms, ttfb_ms, tcp_ms, dns_ms) IS NOT NULL) AS p95,
    min(observed_at)                          AS window_start,
    max(observed_at)                          AS window_end
FROM dem_probe_results
WHERE target_key = $1 AND observed_at >= $2::timestamptz`
		var (
			p50, p95            sql.NullFloat64
			winStart, winEnd    deletedAtScan
			sampleCt, successCt int
		)
		row := tx.QueryRow(ctx, q, targetKey, since.UTC())
		if err := row.Scan(&sampleCt, &successCt, &p50, &p95, &winStart, &winEnd); err != nil {
			return fmt.Errorf("aggregate dem_probe_results: %w", err)
		}
		agg.SampleCount = sampleCt
		agg.SuccessCount = successCt
		agg.LatencyP50Ms = nullFloatPtr(p50)
		agg.LatencyP95Ms = nullFloatPtr(p95)
		if winStart.Valid {
			agg.WindowStart = winStart.Time
		}
		if winEnd.Valid {
			agg.WindowEnd = winEnd.Time
		}
		return nil
	})
	if err != nil {
		return repository.DEMWindowAggregate{}, err
	}
	return agg, nil
}

// demPruneBatch bounds how many rows a single retention DELETE removes.
// The first sweep after a retention horizon is widened (or after a
// backlog accumulates across the fleet's 5,000 tenants) could otherwise
// match millions of rows; an unbounded DELETE would hold a long
// table-level lock and balloon WAL in one transaction. Batching keeps
// each statement's lock footprint and WAL generation bounded, and —
// because every batch commits in its own transaction (see
// pruneBatched) — locks are released between batches so concurrent
// ingests are not starved. 5,000 is large enough that a steady-state
// hourly sweep finishes in one or two iterations, yet small enough to
// keep any single transaction cheap.
const demPruneBatch = 5000

// PruneProbeResults deletes raw results created before `before`
// across all tenants, in bounded batches. Runs under the system role.
func (r *DEMRepository) PruneProbeResults(ctx context.Context, before time.Time) (int64, error) {
	const q = `
DELETE FROM dem_probe_results
WHERE ctid IN (
    SELECT ctid FROM dem_probe_results
    WHERE created_at < $1::timestamptz
    LIMIT $2
)`
	return r.pruneBatched(ctx, "dem_probe_results", q, before)
}

// pruneBatched runs `q` — a DELETE bounded by `LIMIT $2` — under the
// system role repeatedly until a sweep removes fewer rows than
// demPruneBatch, i.e. the expired backlog is drained. Each batch is its
// own transaction so the retention sweep never holds a long lock or
// generates unbounded WAL regardless of how far behind it has fallen.
// `table` names the swept relation for error context only. Returns the
// total rows removed across all batches.
func (r *DEMRepository) pruneBatched(ctx context.Context, table, q string, before time.Time) (int64, error) {
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var batch int64
		err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, q, before.UTC(), demPruneBatch)
			if err != nil {
				return fmt.Errorf("prune %s: %w", table, err)
			}
			batch = tag.RowsAffected()
			return nil
		})
		if err != nil {
			return total, err
		}
		total += batch
		if batch < demPruneBatch {
			return total, nil
		}
	}
}

// -----------------------------------------------------------------------
// Experience scores
// -----------------------------------------------------------------------

// InsertScore appends one experience-score sample.
func (r *DEMRepository) InsertScore(
	ctx context.Context,
	tenantID uuid.UUID,
	s repository.DEMExperienceScore,
) (repository.DEMExperienceScore, error) {
	if tenantID == uuid.Nil {
		return repository.DEMExperienceScore{}, repository.ErrInvalidArgument
	}
	if s.TargetKey == "" || s.TargetName == "" {
		return repository.DEMExperienceScore{}, repository.ErrInvalidArgument
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	var out repository.DEMExperienceScore
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO dem_experience_scores
    (id, tenant_id, target_key, target_name, score, availability,
     latency_p50_ms, latency_p95_ms, sample_count, window_seconds,
     window_start, window_end)
VALUES
    ($1::uuid, $2::uuid, $3, $4, $5, $6,
     $7, $8, $9, $10,
     $11::timestamptz, $12::timestamptz)
RETURNING ` + demScoreCols
		row := tx.QueryRow(ctx, q,
			s.ID, tenantID, s.TargetKey, s.TargetName, s.Score, s.Availability,
			floatOrNil(s.LatencyP50Ms), floatOrNil(s.LatencyP95Ms), s.SampleCount, s.WindowSeconds,
			s.WindowStart.UTC(), s.WindowEnd.UTC(),
		)
		scanned, err := scanDEMScore(row)
		if err != nil {
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("insert dem_experience_scores: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// ListScores enumerates score samples matching the filter, keyset
// paginated by (created_at, id).
func (r *DEMRepository) ListScores(
	ctx context.Context,
	tenantID uuid.UUID,
	filter repository.DEMScoreFilter,
	page repository.Page,
) (repository.PageResult[repository.DEMExperienceScore], error) {
	if tenantID == uuid.Nil {
		return repository.PageResult[repository.DEMExperienceScore]{}, repository.ErrInvalidArgument
	}
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.DEMExperienceScore]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.DEMExperienceScore]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		cmp, dir := "<", "DESC"
		if page.Order == repository.SortAsc {
			cmp, dir = ">", "ASC"
		}
		var since, until any
		if !filter.Since.IsZero() {
			since = filter.Since.UTC()
		}
		if !filter.Until.IsZero() {
			until = filter.Until.UTC()
		}
		args := []any{nil, nil, filter.TargetKeys, since, until, page.Limit}
		if !cur.T.IsZero() || cur.I != uuid.Nil {
			args[0] = cur.T
			args[1] = cur.I
		}
		q := fmt.Sprintf(`
SELECT %s
FROM dem_experience_scores
WHERE ($1::timestamptz IS NULL OR (created_at, id) %s ($1::timestamptz, $2::uuid))
  AND ($3::text[] IS NULL OR cardinality($3::text[]) = 0 OR target_key = ANY($3::text[]))
  AND ($4::timestamptz IS NULL OR created_at >= $4::timestamptz)
  AND ($5::timestamptz IS NULL OR created_at <= $5::timestamptz)
ORDER BY created_at %s, id %s
LIMIT $6
`, demScoreCols, cmp, dir, dir)
		rows, qerr := tx.Query(ctx, q, args...)
		if qerr != nil {
			return fmt.Errorf("list dem_experience_scores: %w", qerr)
		}
		defer rows.Close()
		items := make([]repository.DEMExperienceScore, 0, page.Limit)
		for rows.Next() {
			s, serr := scanDEMScore(rows)
			if serr != nil {
				return fmt.Errorf("scan dem_experience_scores: %w", serr)
			}
			items = append(items, s)
		}
		if rerr := rows.Err(); rerr != nil {
			return fmt.Errorf("iterate dem_experience_scores: %w", rerr)
		}
		res.Items = items
		if len(items) == page.Limit && len(items) > 0 {
			last := items[len(items)-1]
			res.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
		}
		return nil
	})
	return res, err
}

// LatestScores returns the newest score sample per target_key for a
// tenant, newest first.
func (r *DEMRepository) LatestScores(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.DEMExperienceScore, error) {
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	var out []repository.DEMExperienceScore
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q := fmt.Sprintf(`
SELECT %s FROM (
    SELECT DISTINCT ON (target_key) %s
    FROM dem_experience_scores
    ORDER BY target_key, created_at DESC, id DESC
) latest
ORDER BY created_at DESC, id DESC`, demScoreCols, demScoreCols)
		rows, qerr := tx.Query(ctx, q)
		if qerr != nil {
			return fmt.Errorf("latest dem_experience_scores: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			s, serr := scanDEMScore(rows)
			if serr != nil {
				return fmt.Errorf("scan dem_experience_scores: %w", serr)
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

// PruneScores deletes score samples created before `before` across
// all tenants, in bounded batches. Runs under the system role.
func (r *DEMRepository) PruneScores(ctx context.Context, before time.Time) (int64, error) {
	const q = `
DELETE FROM dem_experience_scores
WHERE ctid IN (
    SELECT ctid FROM dem_experience_scores
    WHERE created_at < $1::timestamptz
    LIMIT $2
)`
	return r.pruneBatched(ctx, "dem_experience_scores", q, before)
}

// -----------------------------------------------------------------------
// Per-target rolling state
// -----------------------------------------------------------------------

// GetTargetState returns the baseline row for (tenant, target_key).
// The bool is false (nil error) when no row exists yet.
func (r *DEMRepository) GetTargetState(
	ctx context.Context,
	tenantID uuid.UUID,
	targetKey string,
) (repository.DEMTargetState, bool, error) {
	if tenantID == uuid.Nil || targetKey == "" {
		return repository.DEMTargetState{}, false, repository.ErrInvalidArgument
	}
	var (
		out   repository.DEMTargetState
		found bool
	)
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT `+demStateCols+` FROM dem_target_state WHERE target_key = $1`, targetKey)
		scanned, err := scanDEMState(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("select dem_target_state: %w", err)
		}
		out = scanned
		found = true
		return nil
	})
	if err != nil {
		return repository.DEMTargetState{}, false, err
	}
	return out, found, nil
}

// UpsertTargetState inserts or updates the baseline row keyed by
// (tenant, target_key).
func (r *DEMRepository) UpsertTargetState(
	ctx context.Context,
	tenantID uuid.UUID,
	st repository.DEMTargetState,
) (repository.DEMTargetState, error) {
	if tenantID == uuid.Nil || st.TargetKey == "" || st.TargetName == "" {
		return repository.DEMTargetState{}, repository.ErrInvalidArgument
	}
	if st.ID == uuid.Nil {
		st.ID = uuid.New()
	}
	var out repository.DEMTargetState
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO dem_target_state
    (id, tenant_id, target_key, target_name, ewma_score, ewma_variance,
     last_score, sample_count, degraded, last_alert_at, last_observed_at)
VALUES
    ($1::uuid, $2::uuid, $3, $4, $5, $6,
     $7, $8, $9, $10::timestamptz, $11::timestamptz)
ON CONFLICT (tenant_id, target_key) DO UPDATE SET
    target_name      = EXCLUDED.target_name,
    ewma_score       = EXCLUDED.ewma_score,
    ewma_variance    = EXCLUDED.ewma_variance,
    last_score       = EXCLUDED.last_score,
    sample_count     = EXCLUDED.sample_count,
    degraded         = EXCLUDED.degraded,
    last_alert_at    = EXCLUDED.last_alert_at,
    last_observed_at = EXCLUDED.last_observed_at,
    updated_at       = NOW()
RETURNING ` + demStateCols
		row := tx.QueryRow(ctx, q,
			st.ID, tenantID, st.TargetKey, st.TargetName,
			floatOrNil(st.EWMAScore), floatOrNil(st.EWMAVariance), floatOrNil(st.LastScore),
			st.SampleCount, st.Degraded, optionalTime(st.LastAlertAt), optionalTime(st.LastObservedAt),
		)
		scanned, err := scanDEMState(row)
		if err != nil {
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("upsert dem_target_state: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// MutateTargetState performs the baseline read-modify-write inside a
// single transaction, holding a row-level lock for the whole cycle so
// concurrent ingests for the same (tenant, target_key) cannot lose
// each other's EWMA update.
//
// It first INSERTs a zero-baseline row ON CONFLICT DO NOTHING so the
// subsequent SELECT ... FOR UPDATE always has a row to lock (a bare
// FOR UPDATE locks nothing when the row is absent, which would leave
// the first concurrent observation unserialized). The locked row is
// then handed to mutate and the returned state is written back via
// the same transaction.
func (r *DEMRepository) MutateTargetState(
	ctx context.Context,
	tenantID uuid.UUID,
	targetKey, targetName string,
	mutate func(prev repository.DEMTargetState) (repository.DEMTargetState, error),
) (repository.DEMTargetState, error) {
	if tenantID == uuid.Nil || targetKey == "" || targetName == "" {
		return repository.DEMTargetState{}, repository.ErrInvalidArgument
	}
	if mutate == nil {
		return repository.DEMTargetState{}, repository.ErrInvalidArgument
	}
	var out repository.DEMTargetState
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Ensure a baseline row exists so FOR UPDATE has a row to
		// lock. A freshly created row carries a zero baseline
		// (sample_count 0, NULL ewma) the caller reads as a first
		// observation.
		if _, err := tx.Exec(ctx, `
INSERT INTO dem_target_state (id, tenant_id, target_key, target_name)
VALUES ($1::uuid, $2::uuid, $3, $4)
ON CONFLICT (tenant_id, target_key) DO NOTHING`,
			uuid.New(), tenantID, targetKey, targetName,
		); err != nil {
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("ensure dem_target_state: %w", err)
		}

		// Lock the row for the read-modify-write cycle.
		row := tx.QueryRow(ctx,
			`SELECT `+demStateCols+` FROM dem_target_state WHERE target_key = $1 FOR UPDATE`,
			targetKey)
		prev, err := scanDEMState(row)
		if err != nil {
			return fmt.Errorf("lock dem_target_state: %w", err)
		}

		next, err := mutate(prev)
		if err != nil {
			return err
		}

		// Persist the computed state on the locked row. target_key is
		// the lock/identity key and is never rewritten here.
		const q = `
UPDATE dem_target_state SET
    target_name      = $2,
    ewma_score       = $3,
    ewma_variance    = $4,
    last_score       = $5,
    sample_count     = $6,
    degraded         = $7,
    last_alert_at    = $8::timestamptz,
    last_observed_at = $9::timestamptz,
    updated_at       = NOW()
WHERE target_key = $1
RETURNING ` + demStateCols
		upd := tx.QueryRow(ctx, q,
			targetKey, targetName,
			floatOrNil(next.EWMAScore), floatOrNil(next.EWMAVariance), floatOrNil(next.LastScore),
			next.SampleCount, next.Degraded,
			optionalTime(next.LastAlertAt), optionalTime(next.LastObservedAt),
		)
		scanned, err := scanDEMState(upd)
		if err != nil {
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			return fmt.Errorf("update dem_target_state: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}
