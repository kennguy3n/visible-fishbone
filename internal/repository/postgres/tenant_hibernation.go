package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy/hibernation"
)

// tenantHibernationColumns is the canonical column order shared by every
// SELECT/RETURNING in this file, so the scan helper stays in lock-step
// with the queries.
const tenantHibernationColumns = `
	tenant_id, state, reason, hibernated_at, woke_at, updated_at`

// TenantHibernationRepository owns the tenant_hibernation table
// (migration 068): the per-tenant scale-to-zero state the dormant-tenant
// hibernation controller reads and writes.
//
// Every method runs under withSystem (sng.system_role='true') because
// the access is cross-tenant background work: the leader-only controller
// scans every tenant and the per-replica registry sync reads the whole
// set, neither of which has a tenant request context. RLS stays
// FORCE-enabled; the table's system policy (migration 068) is what
// admits this access, exactly as the tenant_migrations resume runner
// does.
//
// It implements hibernation.Store (declared in the service package), so
// the dependency points inward and this file is the only place that
// knows both the SQL schema and the domain type.
//
// Construct one with Store.NewTenantHibernationRepository.
type TenantHibernationRepository struct{ s *Store }

var _ hibernation.Store = (*TenantHibernationRepository)(nil)

// List returns every persisted hibernation record. Tenants with no row
// are absent (active by default), so the controller/registry treat
// "not present" as active.
func (r *TenantHibernationRepository) List(ctx context.Context) ([]hibernation.Record, error) {
	out := make([]hibernation.Record, 0)
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `SELECT ` + tenantHibernationColumns + `
			FROM tenant_hibernation
			ORDER BY tenant_id`
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return fmt.Errorf("query tenant_hibernation: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			rec, scanErr := scanTenantHibernation(rows)
			if scanErr != nil {
				return fmt.Errorf("scan tenant_hibernation: %w", scanErr)
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SetHibernated upserts the tenant to the hibernated state, stamping
// hibernated_at at `at`. Idempotent.
func (r *TenantHibernationRepository) SetHibernated(ctx context.Context, tenantID uuid.UUID, reason string, at time.Time) (hibernation.Record, error) {
	return r.upsert(ctx, tenantID, hibernation.StateHibernated, reason, at)
}

// SetActive upserts the tenant to the active state, stamping woke_at at
// `at`. Idempotent and safe for a tenant that was never hibernated.
func (r *TenantHibernationRepository) SetActive(ctx context.Context, tenantID uuid.UUID, reason string, at time.Time) (hibernation.Record, error) {
	return r.upsert(ctx, tenantID, hibernation.StateActive, reason, at)
}

// upsert writes the (tenant, state) row. The state-specific timestamp
// column (hibernated_at for hibernated, woke_at for active) is advanced
// to `at`; the other is preserved, so the row keeps the audit trail of
// the most recent transition in each direction.
func (r *TenantHibernationRepository) upsert(ctx context.Context, tenantID uuid.UUID, state hibernation.State, reason string, at time.Time) (hibernation.Record, error) {
	if tenantID == uuid.Nil || !state.Valid() {
		return hibernation.Record{}, fmt.Errorf("tenant_hibernation: invalid argument")
	}
	if at.IsZero() {
		at = time.Now()
	}
	var hibernatedAt, wokeAt *time.Time
	if state.Hibernated() {
		hibernatedAt = &at
	} else {
		wokeAt = &at
	}
	var out hibernation.Record
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `
			INSERT INTO tenant_hibernation
				(tenant_id, state, reason, hibernated_at, woke_at)
			VALUES ($1::uuid, $2, $3, $4, $5)
			ON CONFLICT (tenant_id) DO UPDATE SET
				state         = EXCLUDED.state,
				reason        = EXCLUDED.reason,
				hibernated_at = COALESCE(EXCLUDED.hibernated_at, tenant_hibernation.hibernated_at),
				woke_at       = COALESCE(EXCLUDED.woke_at, tenant_hibernation.woke_at)
			RETURNING ` + tenantHibernationColumns
		row := tx.QueryRow(ctx, q, tenantID, string(state), reason, hibernatedAt, wokeAt)
		scanned, scanErr := scanTenantHibernation(row)
		if scanErr != nil {
			return fmt.Errorf("upsert tenant_hibernation: %w", scanErr)
		}
		out = scanned
		return nil
	})
	if err != nil {
		return hibernation.Record{}, err
	}
	return out, nil
}

func scanTenantHibernation(sc rolloutRowScanner) (hibernation.Record, error) {
	var (
		rec          hibernation.Record
		state        string
		hibernatedAt deletedAtScan
		wokeAt       deletedAtScan
	)
	if err := sc.Scan(
		&rec.TenantID,
		&state,
		&rec.Reason,
		&hibernatedAt,
		&wokeAt,
		&rec.UpdatedAt,
	); err != nil {
		return hibernation.Record{}, err
	}
	rec.State = hibernation.State(state)
	if hibernatedAt.Valid {
		t := hibernatedAt.Time
		rec.HibernatedAt = &t
	}
	if wokeAt.Valid {
		t := wokeAt.Time
		rec.WokeAt = &t
	}
	return rec, nil
}
