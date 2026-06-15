package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ComplianceAutoRepository is the Postgres-backed
// repository.ComplianceAutoRepository (WP6). It lives in its own file —
// including its Store constructor and the interface assertion — so it
// never co-edits the shared postgres/repos.go or postgres/store.go.
type ComplianceAutoRepository struct{ s *Store }

// NewComplianceAutoRepository binds the Store to
// repository.ComplianceAutoRepository.
func (s *Store) NewComplianceAutoRepository() *ComplianceAutoRepository {
	return &ComplianceAutoRepository{s: s}
}

var _ repository.ComplianceAutoRepository = (*ComplianceAutoRepository)(nil)

// jsonOrEmpty coalesces a nil/empty RawMessage to a valid empty JSON
// object so the NOT NULL JSONB columns always receive parseable input.
func jsonOrEmpty(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	return raw
}

// --- runs -----------------------------------------------------------------

func scanRun(row pgx.Row) (repository.ComplianceAutoRunRow, error) {
	var r repository.ComplianceAutoRunRow
	if err := row.Scan(
		&r.ID,
		&r.TenantID,
		&r.StartedAt,
		&r.FinishedAt,
		&r.ControlsTotal,
		&r.ControlsPass,
		&r.ControlsFail,
		&r.ControlsNA,
		&r.CreatedAt,
	); err != nil {
		return repository.ComplianceAutoRunRow{}, err
	}
	return r, nil
}

func (r *ComplianceAutoRepository) RecordRun(ctx context.Context, tenantID uuid.UUID, run repository.ComplianceAutoRunRow) (repository.ComplianceAutoRunRow, error) {
	var out repository.ComplianceAutoRunRow
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO compliance_auto_runs
    (tenant_id, started_at, finished_at, controls_total, controls_pass, controls_fail, controls_na)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING id, tenant_id, started_at, finished_at, controls_total, controls_pass, controls_fail, controls_na, created_at`
		scanned, err := scanRun(tx.QueryRow(ctx, q,
			tenantID,
			run.StartedAt,
			run.FinishedAt,
			run.ControlsTotal,
			run.ControlsPass,
			run.ControlsFail,
			run.ControlsNA,
		))
		if err != nil {
			return fmt.Errorf("insert compliance_auto_runs: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *ComplianceAutoRepository) LatestRun(ctx context.Context, tenantID uuid.UUID) (repository.ComplianceAutoRunRow, error) {
	var out repository.ComplianceAutoRunRow
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Defence-in-depth: predicate on tenant_id explicitly in
		// addition to RLS (withTenantRO). The explicit predicate keeps
		// the tenant boundary correct even if RLS is bypassed (superuser
		// / RLS-bypass role / GUC unset) — critical here because the
		// LIMIT 1 over an unfiltered scan would otherwise silently return
		// another tenant's latest run. The tenant_id index is used either
		// way, so there is no cost.
		const q = `
SELECT id, tenant_id, started_at, finished_at, controls_total, controls_pass, controls_fail, controls_na, created_at
FROM compliance_auto_runs
WHERE tenant_id = $1
ORDER BY started_at DESC, id DESC
LIMIT 1`
		scanned, err := scanRun(tx.QueryRow(ctx, q, tenantID))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("get latest compliance_auto_runs: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// --- control status -------------------------------------------------------

func scanControlStatus(row pgx.Row) (repository.ComplianceAutoControlStatusRow, error) {
	var r repository.ComplianceAutoControlStatusRow
	if err := row.Scan(
		&r.ID,
		&r.TenantID,
		&r.Framework,
		&r.ControlID,
		&r.Status,
		&r.CollectorID,
		&r.Summary,
		&r.Source,
		&r.Details,
		&r.ObservedAt,
		&r.RunID,
		&r.CreatedAt,
		&r.UpdatedAt,
	); err != nil {
		return repository.ComplianceAutoControlStatusRow{}, err
	}
	return r, nil
}

func (r *ComplianceAutoRepository) UpsertControlStatus(ctx context.Context, tenantID uuid.UUID, row repository.ComplianceAutoControlStatusRow) (repository.ComplianceAutoControlStatusRow, error) {
	var out repository.ComplianceAutoControlStatusRow
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO compliance_auto_control_status
    (tenant_id, framework, control_id, status, collector_id, summary, source, details, observed_at, run_id)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (tenant_id, framework, control_id) DO UPDATE SET
    status       = EXCLUDED.status,
    collector_id = EXCLUDED.collector_id,
    summary      = EXCLUDED.summary,
    source       = EXCLUDED.source,
    details      = EXCLUDED.details,
    observed_at  = EXCLUDED.observed_at,
    run_id       = EXCLUDED.run_id,
    updated_at   = now()
RETURNING id, tenant_id, framework, control_id, status, collector_id, summary, source, details, observed_at, run_id, created_at, updated_at`
		scanned, err := scanControlStatus(tx.QueryRow(ctx, q,
			tenantID,
			row.Framework,
			row.ControlID,
			row.Status,
			row.CollectorID,
			row.Summary,
			row.Source,
			jsonOrEmpty(row.Details),
			row.ObservedAt,
			row.RunID,
		))
		if err != nil {
			return fmt.Errorf("upsert compliance_auto_control_status: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *ComplianceAutoRepository) ListControlStatus(ctx context.Context, tenantID uuid.UUID, framework string) ([]repository.ComplianceAutoControlStatusRow, error) {
	var out []repository.ComplianceAutoControlStatusRow
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Defence-in-depth: always predicate on tenant_id in addition to
		// RLS (withTenantRO), optionally narrowing by framework.
		q := `
SELECT id, tenant_id, framework, control_id, status, collector_id, summary, source, details, observed_at, run_id, created_at, updated_at
FROM compliance_auto_control_status
WHERE tenant_id = $1`
		args := []any{tenantID}
		if framework != "" {
			q += ` AND framework = $2`
			args = append(args, framework)
		}
		q += ` ORDER BY framework ASC, control_id ASC`
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanControlStatus(rows)
			if err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

// --- evidence -------------------------------------------------------------

func scanEvidence(row pgx.Row) (repository.ComplianceAutoEvidenceRow, error) {
	var r repository.ComplianceAutoEvidenceRow
	if err := row.Scan(
		&r.ID,
		&r.TenantID,
		&r.RunID,
		&r.Framework,
		&r.ControlID,
		&r.CollectorID,
		&r.Status,
		&r.Summary,
		&r.Source,
		&r.Details,
		&r.ObservedAt,
		&r.CreatedAt,
	); err != nil {
		return repository.ComplianceAutoEvidenceRow{}, err
	}
	return r, nil
}

func (r *ComplianceAutoRepository) AppendEvidence(ctx context.Context, tenantID uuid.UUID, row repository.ComplianceAutoEvidenceRow) (repository.ComplianceAutoEvidenceRow, error) {
	var out repository.ComplianceAutoEvidenceRow
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO compliance_auto_evidence
    (tenant_id, run_id, framework, control_id, collector_id, status, summary, source, details, observed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
RETURNING id, tenant_id, run_id, framework, control_id, collector_id, status, summary, source, details, observed_at, created_at`
		scanned, err := scanEvidence(tx.QueryRow(ctx, q,
			tenantID,
			row.RunID,
			row.Framework,
			row.ControlID,
			row.CollectorID,
			row.Status,
			row.Summary,
			row.Source,
			jsonOrEmpty(row.Details),
			row.ObservedAt,
		))
		if err != nil {
			return fmt.Errorf("insert compliance_auto_evidence: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *ComplianceAutoRepository) ListEvidence(ctx context.Context, tenantID uuid.UUID, controlID string, limit int) ([]repository.ComplianceAutoEvidenceRow, error) {
	if limit <= 0 {
		limit = repository.DefaultPageLimit
	}
	if limit > repository.MaxPageLimit {
		limit = repository.MaxPageLimit
	}
	var out []repository.ComplianceAutoEvidenceRow
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Defence-in-depth: always predicate on tenant_id in addition to
		// RLS (withTenantRO), optionally narrowing by control_id.
		q := `
SELECT id, tenant_id, run_id, framework, control_id, collector_id, status, summary, source, details, observed_at, created_at
FROM compliance_auto_evidence
WHERE tenant_id = $1`
		args := []any{tenantID}
		argN := 1
		if controlID != "" {
			argN++
			q += fmt.Sprintf(` AND control_id = $%d`, argN)
			args = append(args, controlID)
		}
		argN++
		q += fmt.Sprintf(` ORDER BY observed_at DESC, id DESC LIMIT $%d`, argN)
		args = append(args, limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanEvidence(rows)
			if err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}

// --- framework state ------------------------------------------------------

func scanFrameworkState(row pgx.Row) (repository.ComplianceAutoFrameworkStateRow, error) {
	var r repository.ComplianceAutoFrameworkStateRow
	if err := row.Scan(
		&r.ID,
		&r.TenantID,
		&r.Framework,
		&r.ControlsTotal,
		&r.ControlsPass,
		&r.ControlsFail,
		&r.ControlsNA,
		&r.LastRunID,
		&r.EvaluatedAt,
		&r.CreatedAt,
		&r.UpdatedAt,
	); err != nil {
		return repository.ComplianceAutoFrameworkStateRow{}, err
	}
	return r, nil
}

func (r *ComplianceAutoRepository) UpsertFrameworkState(ctx context.Context, tenantID uuid.UUID, row repository.ComplianceAutoFrameworkStateRow) (repository.ComplianceAutoFrameworkStateRow, error) {
	var out repository.ComplianceAutoFrameworkStateRow
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO compliance_auto_framework_state
    (tenant_id, framework, controls_total, controls_pass, controls_fail, controls_na, last_run_id, evaluated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT (tenant_id, framework) DO UPDATE SET
    controls_total = EXCLUDED.controls_total,
    controls_pass  = EXCLUDED.controls_pass,
    controls_fail  = EXCLUDED.controls_fail,
    controls_na    = EXCLUDED.controls_na,
    last_run_id    = EXCLUDED.last_run_id,
    evaluated_at   = EXCLUDED.evaluated_at,
    updated_at     = now()
RETURNING id, tenant_id, framework, controls_total, controls_pass, controls_fail, controls_na, last_run_id, evaluated_at, created_at, updated_at`
		scanned, err := scanFrameworkState(tx.QueryRow(ctx, q,
			tenantID,
			row.Framework,
			row.ControlsTotal,
			row.ControlsPass,
			row.ControlsFail,
			row.ControlsNA,
			row.LastRunID,
			row.EvaluatedAt,
		))
		if err != nil {
			return fmt.Errorf("upsert compliance_auto_framework_state: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

func (r *ComplianceAutoRepository) ListFrameworkState(ctx context.Context, tenantID uuid.UUID) ([]repository.ComplianceAutoFrameworkStateRow, error) {
	var out []repository.ComplianceAutoFrameworkStateRow
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Defence-in-depth: predicate on tenant_id explicitly in addition
		// to RLS (withTenantRO).
		const q = `
SELECT id, tenant_id, framework, controls_total, controls_pass, controls_fail, controls_na, last_run_id, evaluated_at, created_at, updated_at
FROM compliance_auto_framework_state
WHERE tenant_id = $1
ORDER BY framework ASC`
		rows, err := tx.Query(ctx, q, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			item, err := scanFrameworkState(rows)
			if err != nil {
				return err
			}
			out = append(out, item)
		}
		return rows.Err()
	})
	return out, err
}
