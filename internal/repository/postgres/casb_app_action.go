package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// CASBNoOpsStore is the postgres backend for the CASB NoOps pipeline
// (it satisfies casb.NoOpsStore). It persists the migration-061 tables —
// casb_app_classifications, casb_app_action_policies, casb_app_actions
// — plus the digest cursor in casb_app_digest_state. Every method runs
// inside withTenant/withTenantRO so the per-tenant RLS policies on
// those tables enforce isolation: a tenant transaction can only ever
// read or write its own rows. Only aggregates are stored — no device
// IDs, hostnames or user identities — matching the privacy posture of
// the shadow-IT discoverer that feeds it.
//
// It depends only on the repository row types (not the casb service
// package), so it avoids the casb -> policy -> middleware -> postgres
// -> casb import cycle. The casb.NoOpsStore interface is satisfied
// structurally; a compile-time assertion lives in the casb test package.
type CASBNoOpsStore struct{ s *Store }

// NewCASBNoOpsStore constructs the postgres NoOps store over the shared
// connection pool.
func NewCASBNoOpsStore(s *Store) *CASBNoOpsStore { return &CASBNoOpsStore{s: s} }

// --- classifications ------------------------------------------------------

func (r *CASBNoOpsStore) UpsertClassification(ctx context.Context, tenantID uuid.UUID, c repository.AppClassification) (repository.AppClassification, error) {
	if tenantID == uuid.Nil || c.AppName == "" {
		return repository.AppClassification{}, repository.ErrInvalidArgument
	}
	if c.ClassifiedAt.IsZero() {
		c.ClassifiedAt = time.Now().UTC()
	}
	var out repository.AppClassification
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO casb_app_classifications
			    (tenant_id, app_name, category, risk_score, sanction,
			     confidence, source, rationale, classified_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (tenant_id, app_name) DO UPDATE SET
			    category      = EXCLUDED.category,
			    risk_score    = EXCLUDED.risk_score,
			    sanction      = EXCLUDED.sanction,
			    confidence    = EXCLUDED.confidence,
			    source        = EXCLUDED.source,
			    rationale     = EXCLUDED.rationale,
			    classified_at = EXCLUDED.classified_at
			RETURNING tenant_id, app_name, category, risk_score, sanction,
			          confidence, source, rationale, classified_at`,
			tenantID, c.AppName, c.Category, c.RiskScore, string(c.Sanction),
			c.Confidence, c.Source, c.Rationale, c.ClassifiedAt,
		).Scan(
			&out.TenantID, &out.AppName, &out.Category, &out.RiskScore, &out.Sanction,
			&out.Confidence, &out.Source, &out.Rationale, &out.ClassifiedAt,
		)
	})
	if err != nil {
		return repository.AppClassification{}, err
	}
	return out, nil
}

func (r *CASBNoOpsStore) GetClassification(ctx context.Context, tenantID uuid.UUID, appName string) (repository.AppClassification, error) {
	if tenantID == uuid.Nil || appName == "" {
		return repository.AppClassification{}, repository.ErrInvalidArgument
	}
	var out repository.AppClassification
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT tenant_id, app_name, category, risk_score, sanction,
			       confidence, source, rationale, classified_at
			FROM casb_app_classifications
			WHERE tenant_id = $1 AND app_name = $2`, tenantID, appName,
		).Scan(
			&out.TenantID, &out.AppName, &out.Category, &out.RiskScore, &out.Sanction,
			&out.Confidence, &out.Source, &out.Rationale, &out.ClassifiedAt,
		)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.AppClassification{}, repository.ErrNotFound
		}
		return repository.AppClassification{}, err
	}
	return out, nil
}

func (r *CASBNoOpsStore) ListClassifications(ctx context.Context, tenantID uuid.UUID) ([]repository.AppClassification, error) {
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	var out []repository.AppClassification
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT tenant_id, app_name, category, risk_score, sanction,
			       confidence, source, rationale, classified_at
			FROM casb_app_classifications
			WHERE tenant_id = $1
			ORDER BY app_name`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c repository.AppClassification
			if err := rows.Scan(
				&c.TenantID, &c.AppName, &c.Category, &c.RiskScore, &c.Sanction,
				&c.Confidence, &c.Source, &c.Rationale, &c.ClassifiedAt,
			); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// --- action policy --------------------------------------------------------

func (r *CASBNoOpsStore) GetActionPolicy(ctx context.Context, tenantID uuid.UUID) (repository.ActionPolicy, error) {
	if tenantID == uuid.Nil {
		return repository.ActionPolicy{}, repository.ErrInvalidArgument
	}
	var out repository.ActionPolicy
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT tenant_id, auto_enforce_enabled, min_risk, min_confidence, updated_at
			FROM casb_app_action_policies
			WHERE tenant_id = $1`, tenantID,
		).Scan(&out.TenantID, &out.AutoEnforceEnabled, &out.MinRisk, &out.MinConfidence, &out.UpdatedAt)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ActionPolicy{}, repository.ErrNotFound
		}
		return repository.ActionPolicy{}, err
	}
	return out, nil
}

func (r *CASBNoOpsStore) UpsertActionPolicy(ctx context.Context, tenantID uuid.UUID, p repository.ActionPolicy) (repository.ActionPolicy, error) {
	if tenantID == uuid.Nil {
		return repository.ActionPolicy{}, repository.ErrInvalidArgument
	}
	p.UpdatedAt = time.Now().UTC()
	var out repository.ActionPolicy
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO casb_app_action_policies
			    (tenant_id, auto_enforce_enabled, min_risk, min_confidence, updated_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id) DO UPDATE SET
			    auto_enforce_enabled = EXCLUDED.auto_enforce_enabled,
			    min_risk             = EXCLUDED.min_risk,
			    min_confidence       = EXCLUDED.min_confidence,
			    updated_at           = EXCLUDED.updated_at
			RETURNING tenant_id, auto_enforce_enabled, min_risk, min_confidence, updated_at`,
			tenantID, p.AutoEnforceEnabled, p.MinRisk, p.MinConfidence, p.UpdatedAt,
		).Scan(&out.TenantID, &out.AutoEnforceEnabled, &out.MinRisk, &out.MinConfidence, &out.UpdatedAt)
	})
	if err != nil {
		return repository.ActionPolicy{}, err
	}
	return out, nil
}

// --- audit trail ----------------------------------------------------------

func (r *CASBNoOpsStore) AppendAction(ctx context.Context, tenantID uuid.UUID, a repository.CASBAppAction) (repository.CASBAppAction, error) {
	if tenantID == uuid.Nil || a.AppName == "" {
		return repository.CASBAppAction{}, repository.ErrInvalidArgument
	}
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now().UTC()
	}
	var out repository.CASBAppAction
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO casb_app_actions
			    (id, tenant_id, app_name, category, enforcement, traffic_class,
			     mode, risk_score, confidence, sanction, applied, reason, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			RETURNING id, tenant_id, app_name, category, enforcement, traffic_class,
			          mode, risk_score, confidence, sanction, applied, reason, created_at`,
			a.ID, tenantID, a.AppName, a.Category, string(a.Enforcement), string(a.TrafficClass),
			string(a.Mode), a.RiskScore, a.Confidence, string(a.Sanction), a.Applied, a.Reason, a.CreatedAt,
		).Scan(
			&out.ID, &out.TenantID, &out.AppName, &out.Category, &out.Enforcement, &out.TrafficClass,
			&out.Mode, &out.RiskScore, &out.Confidence, &out.Sanction, &out.Applied, &out.Reason, &out.CreatedAt,
		)
	})
	if err != nil {
		return repository.CASBAppAction{}, err
	}
	return out, nil
}

func (r *CASBNoOpsStore) ListActionsSince(ctx context.Context, tenantID uuid.UUID, since time.Time) ([]repository.CASBAppAction, error) {
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	var out []repository.CASBAppAction
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, app_name, category, enforcement, traffic_class,
			       mode, risk_score, confidence, sanction, applied, reason, created_at
			FROM casb_app_actions
			WHERE tenant_id = $1 AND created_at > $2
			ORDER BY created_at ASC, id ASC`, tenantID, since)
		if err != nil {
			return err
		}
		defer rows.Close()
		return scanActions(rows, &out)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *CASBNoOpsStore) ListActions(ctx context.Context, tenantID uuid.UUID, limit int) ([]repository.CASBAppAction, error) {
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	if limit <= 0 {
		limit = 100
	}
	var out []repository.CASBAppAction
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, app_name, category, enforcement, traffic_class,
			       mode, risk_score, confidence, sanction, applied, reason, created_at
			FROM casb_app_actions
			WHERE tenant_id = $1
			ORDER BY created_at DESC, id DESC
			LIMIT $2`, tenantID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		return scanActions(rows, &out)
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func scanActions(rows pgx.Rows, out *[]repository.CASBAppAction) error {
	for rows.Next() {
		var a repository.CASBAppAction
		if err := rows.Scan(
			&a.ID, &a.TenantID, &a.AppName, &a.Category, &a.Enforcement, &a.TrafficClass,
			&a.Mode, &a.RiskScore, &a.Confidence, &a.Sanction, &a.Applied, &a.Reason, &a.CreatedAt,
		); err != nil {
			return err
		}
		*out = append(*out, a)
	}
	return rows.Err()
}

// --- digest cursor --------------------------------------------------------

func (r *CASBNoOpsStore) GetDigestState(ctx context.Context, tenantID uuid.UUID) (repository.DigestState, error) {
	if tenantID == uuid.Nil {
		return repository.DigestState{}, repository.ErrInvalidArgument
	}
	var out repository.DigestState
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT tenant_id, last_digest_at, last_actions_at
			FROM casb_app_digest_state
			WHERE tenant_id = $1`, tenantID,
		).Scan(&out.TenantID, &out.LastDigestAt, &out.LastActionsAt)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.DigestState{}, repository.ErrNotFound
		}
		return repository.DigestState{}, err
	}
	return out, nil
}

func (r *CASBNoOpsStore) UpsertDigestState(ctx context.Context, tenantID uuid.UUID, st repository.DigestState) (repository.DigestState, error) {
	if tenantID == uuid.Nil {
		return repository.DigestState{}, repository.ErrInvalidArgument
	}
	var out repository.DigestState
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO casb_app_digest_state
			    (tenant_id, last_digest_at, last_actions_at)
			VALUES ($1, $2, $3)
			ON CONFLICT (tenant_id) DO UPDATE SET
			    last_digest_at  = EXCLUDED.last_digest_at,
			    last_actions_at = EXCLUDED.last_actions_at
			RETURNING tenant_id, last_digest_at, last_actions_at`,
			tenantID, st.LastDigestAt, st.LastActionsAt,
		).Scan(&out.TenantID, &out.LastDigestAt, &out.LastActionsAt)
	})
	if err != nil {
		return repository.DigestState{}, err
	}
	return out, nil
}
