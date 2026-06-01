// Package postgres — alert.go is the postgres implementation
// of the three alert repositories: AlertRepository,
// AlertSuppressionRepository, and AlertFeedbackRepository.
//
// All three live in one file because they share a small set of
// helpers (scan-from-row, suppression matching, the state
// transition pre-checks) and the deployed surface is small —
// one table per repo. Splitting them into three files would be
// premature when the total Go source is < 800 lines.
//
// State machine pre-checks for Acknowledge / Resolve happen
// inside the SQL via WHERE clauses on `state` — the driver
// translates "zero rows affected" into either ErrNotFound
// (the alert vanished) or ErrConflict (terminal-state
// transition; maps to HTTP 409 in the handler). This keeps
// the state machine definitive in SQL:
// any non-driver caller hitting the same row sees the same
// rejections.
package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// -----------------------------------------------------------------------
// AlertRepository
// -----------------------------------------------------------------------

// AlertRepository owns the alerts table.
type AlertRepository struct{ s *Store }

const alertSelectColumns = `
id, tenant_id, kind, severity, dimension,
observed_value, baseline_mean, baseline_stddev, z_score,
window_start, window_end, window_seconds,
summary, evidence, state,
suppressed_by, acknowledged_by, acknowledged_at,
resolved_by, resolved_at,
created_at, updated_at
`

// scanAlert pulls one row into the typed Alert. Nullable
// pointer fields (suppressed_by, acknowledged_*, resolved_*)
// are deserialised into *uuid.UUID / *time.Time so the wire
// shape stays honest about which fields are populated.
func scanAlert(row pgx.Row) (repository.Alert, error) {
	var (
		a              repository.Alert
		evidence       []byte
		state          string
		severity       string
		suppressedBy   nullableUUID
		acknowledgedBy nullableUUID
		acknowledgedAt deletedAtScan
		resolvedBy     nullableUUID
		resolvedAt     deletedAtScan
	)
	if err := row.Scan(
		&a.ID, &a.TenantID, &a.Kind, &severity, &a.Dimension,
		&a.ObservedValue, &a.BaselineMean, &a.BaselineStdDev, &a.ZScore,
		&a.WindowStart, &a.WindowEnd, &a.WindowSeconds,
		&a.Summary, &evidence, &state,
		&suppressedBy, &acknowledgedBy, &acknowledgedAt,
		&resolvedBy, &resolvedAt,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return repository.Alert{}, err
	}
	a.Severity = repository.AlertSeverity(severity)
	a.State = repository.AlertState(state)
	a.Evidence = evidence
	if suppressedBy.Valid {
		v := suppressedBy.ID
		a.SuppressedBy = &v
	}
	if acknowledgedBy.Valid {
		v := acknowledgedBy.ID
		a.AcknowledgedBy = &v
	}
	if acknowledgedAt.Valid {
		v := acknowledgedAt.Time
		a.AcknowledgedAt = &v
	}
	if resolvedBy.Valid {
		v := resolvedBy.ID
		a.ResolvedBy = &v
	}
	if resolvedAt.Valid {
		v := resolvedAt.Time
		a.ResolvedAt = &v
	}
	return a, nil
}

// optionalUUID returns the supplied *uuid.UUID as `any` for use
// with pgx — nil pointer or uuid.Nil values are coerced to a
// typed nil so postgres receives a NULL rather than the
// zero uuid '00000000-...'.
func optionalUUID(u *uuid.UUID) any {
	if u == nil || *u == uuid.Nil {
		return nil
	}
	return *u
}

// optionalTime returns the supplied *time.Time as `any` (the
// UTC normalised value) or nil for a NULL column.
func optionalTime(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return t.UTC()
}

// optionalString returns the supplied *string as `any` or nil
// for a NULL column.
func optionalString(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// Create persists a freshly-emitted alert. The caller supplies
// a fully-populated Alert struct — the statistical context is
// snapshot-copied at emit time so the alert is self-explaining
// even after the underlying baseline drifts.
func (r *AlertRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	a repository.Alert,
) (repository.Alert, error) {
	if tenantID == uuid.Nil {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if a.Kind == "" || a.Dimension == "" || a.Summary == "" {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if !a.Severity.IsValid() {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if a.State == "" {
		a.State = repository.AlertStateOpen
	}
	if !a.State.IsValid() {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if a.WindowEnd.Before(a.WindowStart) {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if a.WindowSeconds <= 0 {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	if len(a.Evidence) == 0 {
		a.Evidence = []byte(`{}`)
	}
	var out repository.Alert
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO alerts
    (id, tenant_id, kind, severity, dimension,
     observed_value, baseline_mean, baseline_stddev, z_score,
     window_start, window_end, window_seconds,
     summary, evidence, state,
     suppressed_by, acknowledged_by, acknowledged_at,
     resolved_by, resolved_at)
VALUES
    ($1::uuid, $2::uuid, $3, $4, $5,
     $6, $7, $8, $9,
     $10, $11, $12,
     $13, $14::jsonb, $15,
     $16, $17, $18,
     $19, $20)
RETURNING ` + alertSelectColumns
		row := tx.QueryRow(ctx, q,
			a.ID, tenantID, a.Kind, string(a.Severity), a.Dimension,
			a.ObservedValue, a.BaselineMean, a.BaselineStdDev, a.ZScore,
			a.WindowStart.UTC(), a.WindowEnd.UTC(), a.WindowSeconds,
			a.Summary, a.Evidence, string(a.State),
			optionalUUID(a.SuppressedBy), optionalUUID(a.AcknowledgedBy), optionalTime(a.AcknowledgedAt),
			optionalUUID(a.ResolvedBy), optionalTime(a.ResolvedAt),
		)
		scanned, err := scanAlert(row)
		if err != nil {
			if isCheckViolation(err) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("insert alerts: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// Get returns one alert by ID, scoped to tenant.
func (r *AlertRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.Alert, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	var out repository.Alert
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + alertSelectColumns + `
FROM alerts
WHERE id = $1::uuid`
		row := tx.QueryRow(ctx, q, id)
		scanned, err := scanAlert(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select alerts: %w", err)
		}
		out = scanned
		return nil
	})
	return out, err
}

// List enumerates alerts in CreatedAt-DESC order. Filters are
// AND-composed; an empty filter slice matches everything.
// Empty array params are passed as NULL via the helper so the
// `array IS NULL OR ...` predicate skips that filter — pgx
// encodes an empty []string as NULL on the wire.
func (r *AlertRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	filter repository.AlertListFilter,
	page repository.Page,
) (repository.PageResult[repository.Alert], error) {
	if tenantID == uuid.Nil {
		return repository.PageResult[repository.Alert]{}, repository.ErrInvalidArgument
	}
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.Alert]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.Alert]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		var cmp string
		var dir string
		if page.Order == repository.SortAsc {
			cmp, dir = ">", "ASC"
		} else {
			cmp, dir = "<", "DESC"
		}
		var states []string
		for _, s := range filter.States {
			states = append(states, string(s))
		}
		q := fmt.Sprintf(`
SELECT %s
FROM alerts
WHERE ($1::timestamptz IS NULL OR (created_at, id) %s ($1::timestamptz, $2::uuid))
  AND ($3::text[] IS NULL OR cardinality($3::text[]) = 0 OR state = ANY($3::text[]))
  AND ($4::text[] IS NULL OR cardinality($4::text[]) = 0 OR kind = ANY($4::text[]))
  AND ($5::text[] IS NULL OR cardinality($5::text[]) = 0 OR dimension = ANY($5::text[]))
ORDER BY created_at %s, id %s
LIMIT $6
`, alertSelectColumns, cmp, dir, dir)
		args := []any{nil, nil, states, filter.Kinds, filter.Dimensions, page.Limit}
		if !cur.T.IsZero() || cur.I != uuid.Nil {
			args[0] = cur.T
			args[1] = cur.I
		}
		rows, qerr := tx.Query(ctx, q, args...)
		if qerr != nil {
			return fmt.Errorf("list alerts: %w", qerr)
		}
		defer rows.Close()
		items := make([]repository.Alert, 0, page.Limit)
		for rows.Next() {
			a, serr := scanAlert(rows)
			if serr != nil {
				return fmt.Errorf("scan alerts: %w", serr)
			}
			items = append(items, a)
		}
		if rerr := rows.Err(); rerr != nil {
			return fmt.Errorf("iterate alerts: %w", rerr)
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

// Acknowledge transitions an alert from Open to Acknowledged.
// Idempotent on already-acknowledged alerts (returns the
// unchanged row). Returns ErrConflict when the alert is in a
// terminal state (resolved / suppressed) — the handler maps
// this to HTTP 409 per the OpenAPI contract. The pre-check
// and the UPDATE are inside the same transaction so the
// state observed by the pre-check is the state the UPDATE
// rejects against.
func (r *AlertRepository) Acknowledge(
	ctx context.Context,
	tenantID, id uuid.UUID,
	by *uuid.UUID,
	at time.Time,
) (repository.Alert, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	var out repository.Alert
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		var existingState string
		if err := tx.QueryRow(ctx,
			`SELECT state FROM alerts WHERE id = $1::uuid`, id,
		).Scan(&existingState); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("pre-scan alerts: %w", err)
		}
		switch repository.AlertState(existingState) {
		case repository.AlertStateAcknowledged:
			row := tx.QueryRow(ctx,
				`SELECT `+alertSelectColumns+` FROM alerts WHERE id = $1::uuid`, id)
			scanned, scanErr := scanAlert(row)
			if scanErr != nil {
				return fmt.Errorf("re-scan alerts: %w", scanErr)
			}
			out = scanned
			return nil
		case repository.AlertStateResolved, repository.AlertStateSuppressed:
			return repository.ErrConflict
		}
		const upd = `
UPDATE alerts
SET state           = 'acknowledged',
    acknowledged_by = $2,
    acknowledged_at = $3::timestamptz,
    updated_at      = NOW()
WHERE id = $1::uuid AND state = 'open'
RETURNING ` + alertSelectColumns
		row := tx.QueryRow(ctx, upd, id, optionalUUID(by), at.UTC())
		scanned, scanErr := scanAlert(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// Lost the race: another writer transitioned the
			// row out of 'open' between the pre-scan and the
			// UPDATE. Treat as terminal-state conflict.
			return repository.ErrConflict
		}
		if scanErr != nil {
			return fmt.Errorf("update alerts ack: %w", scanErr)
		}
		out = scanned
		return nil
	})
	return out, err
}

// Resolve transitions an alert to Resolved. Allowed from Open
// or Acknowledged; returns ErrConflict when terminal (already
// Resolved is idempotent and returns the unchanged row). The
// handler maps ErrConflict to HTTP 409 per the OpenAPI contract.
func (r *AlertRepository) Resolve(
	ctx context.Context,
	tenantID, id uuid.UUID,
	by *uuid.UUID,
	at time.Time,
) (repository.Alert, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	var out repository.Alert
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		var existingState string
		if err := tx.QueryRow(ctx,
			`SELECT state FROM alerts WHERE id = $1::uuid`, id,
		).Scan(&existingState); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("pre-scan alerts: %w", err)
		}
		switch repository.AlertState(existingState) {
		case repository.AlertStateResolved:
			row := tx.QueryRow(ctx,
				`SELECT `+alertSelectColumns+` FROM alerts WHERE id = $1::uuid`, id)
			scanned, scanErr := scanAlert(row)
			if scanErr != nil {
				return fmt.Errorf("re-scan alerts: %w", scanErr)
			}
			out = scanned
			return nil
		case repository.AlertStateSuppressed:
			return repository.ErrConflict
		}
		const upd = `
UPDATE alerts
SET state       = 'resolved',
    resolved_by = $2,
    resolved_at = $3::timestamptz,
    updated_at  = NOW()
WHERE id = $1::uuid AND state IN ('open', 'acknowledged')
RETURNING ` + alertSelectColumns
		row := tx.QueryRow(ctx, upd, id, optionalUUID(by), at.UTC())
		scanned, scanErr := scanAlert(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// Lost the race: another writer transitioned the
			// row out of 'open'/'acknowledged' between the
			// pre-scan and the UPDATE. Terminal-state conflict.
			return repository.ErrConflict
		}
		if scanErr != nil {
			return fmt.Errorf("update alerts resolve: %w", scanErr)
		}
		out = scanned
		return nil
	})
	return out, err
}

// -----------------------------------------------------------------------
// AlertSuppressionRepository
// -----------------------------------------------------------------------

// AlertSuppressionRepository owns the alert_suppressions table.
type AlertSuppressionRepository struct{ s *Store }

const suppressionSelectColumns = `
id, tenant_id, kind, dimension, reason, created_by, created_at, expires_at
`

func scanSuppression(row pgx.Row) (repository.AlertSuppression, error) {
	var (
		s         repository.AlertSuppression
		kind      sql.NullString
		dimension sql.NullString
		createdBy nullableUUID
		expiresAt deletedAtScan
	)
	if err := row.Scan(
		&s.ID, &s.TenantID, &kind, &dimension, &s.Reason, &createdBy, &s.CreatedAt, &expiresAt,
	); err != nil {
		return repository.AlertSuppression{}, err
	}
	if kind.Valid {
		v := kind.String
		s.Kind = &v
	}
	if dimension.Valid {
		v := dimension.String
		s.Dimension = &v
	}
	if createdBy.Valid {
		v := createdBy.ID
		s.CreatedBy = &v
	}
	if expiresAt.Valid {
		v := expiresAt.Time
		s.ExpiresAt = &v
	}
	return s, nil
}

// Create persists a new suppression rule. ErrInvalidArgument
// when both Kind and Dimension are nil (mirrors the
// alert_suppressions_scope_nonempty CHECK).
func (r *AlertSuppressionRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	s repository.AlertSuppression,
) (repository.AlertSuppression, error) {
	if tenantID == uuid.Nil {
		return repository.AlertSuppression{}, repository.ErrInvalidArgument
	}
	if s.Kind == nil && s.Dimension == nil {
		return repository.AlertSuppression{}, repository.ErrInvalidArgument
	}
	if s.Reason == "" {
		return repository.AlertSuppression{}, repository.ErrInvalidArgument
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	var out repository.AlertSuppression
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO alert_suppressions
    (id, tenant_id, kind, dimension, reason, created_by, expires_at)
VALUES
    ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)
RETURNING ` + suppressionSelectColumns
		row := tx.QueryRow(ctx, q,
			s.ID, tenantID,
			optionalString(s.Kind), optionalString(s.Dimension),
			s.Reason, optionalUUID(s.CreatedBy), optionalTime(s.ExpiresAt),
		)
		scanned, scanErr := scanSuppression(row)
		if scanErr != nil {
			if isCheckViolation(scanErr) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(scanErr) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("insert alert_suppressions: %w", scanErr)
		}
		out = scanned
		return nil
	})
	return out, err
}

// Get returns one suppression by ID, scoped to tenant.
func (r *AlertSuppressionRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.AlertSuppression, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.AlertSuppression{}, repository.ErrInvalidArgument
	}
	var out repository.AlertSuppression
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + suppressionSelectColumns + `
FROM alert_suppressions WHERE id = $1::uuid`
		row := tx.QueryRow(ctx, q, id)
		scanned, scanErr := scanSuppression(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if scanErr != nil {
			return fmt.Errorf("select alert_suppressions: %w", scanErr)
		}
		out = scanned
		return nil
	})
	return out, err
}

// List enumerates suppressions in CreatedAt-DESC order.
func (r *AlertSuppressionRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.AlertSuppression], error) {
	if tenantID == uuid.Nil {
		return repository.PageResult[repository.AlertSuppression]{}, repository.ErrInvalidArgument
	}
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.AlertSuppression]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.AlertSuppression]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		var cmp string
		var dir string
		if page.Order == repository.SortAsc {
			cmp, dir = ">", "ASC"
		} else {
			cmp, dir = "<", "DESC"
		}
		args := []any{nil, nil, page.Limit}
		if !cur.T.IsZero() || cur.I != uuid.Nil {
			args[0] = cur.T
			args[1] = cur.I
		}
		q := fmt.Sprintf(`
SELECT %s
FROM alert_suppressions
WHERE ($1::timestamptz IS NULL OR (created_at, id) %s ($1::timestamptz, $2::uuid))
ORDER BY created_at %s, id %s
LIMIT $3
`, suppressionSelectColumns, cmp, dir, dir)
		rows, qerr := tx.Query(ctx, q, args...)
		if qerr != nil {
			return fmt.Errorf("list alert_suppressions: %w", qerr)
		}
		defer rows.Close()
		items := make([]repository.AlertSuppression, 0, page.Limit)
		for rows.Next() {
			s, serr := scanSuppression(rows)
			if serr != nil {
				return fmt.Errorf("scan alert_suppressions: %w", serr)
			}
			items = append(items, s)
		}
		if rerr := rows.Err(); rerr != nil {
			return fmt.Errorf("iterate alert_suppressions: %w", rerr)
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

// ListActive returns every currently-active suppression for a
// tenant (expires_at NULL OR expires_at > now). Used on every
// alert.Router.Emit; the router caches the slice for a short
// TTL.
func (r *AlertSuppressionRepository) ListActive(
	ctx context.Context,
	tenantID uuid.UUID,
	now time.Time,
) ([]repository.AlertSuppression, error) {
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	var out []repository.AlertSuppression
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + suppressionSelectColumns + `
FROM alert_suppressions
WHERE expires_at IS NULL OR expires_at > $1::timestamptz
ORDER BY created_at DESC, id DESC`
		rows, qerr := tx.Query(ctx, q, now.UTC())
		if qerr != nil {
			return fmt.Errorf("list active alert_suppressions: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			s, serr := scanSuppression(rows)
			if serr != nil {
				return fmt.Errorf("scan alert_suppressions active: %w", serr)
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

// Delete removes a suppression rule.
func (r *AlertSuppressionRepository) Delete(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM alert_suppressions WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete alert_suppressions: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// -----------------------------------------------------------------------
// AlertFeedbackRepository
// -----------------------------------------------------------------------

// AlertFeedbackRepository owns the alert_feedback table.
type AlertFeedbackRepository struct{ s *Store }

const feedbackSelectColumns = `
id, tenant_id, alert_id, decision, COALESCE(notes, ''), created_by, created_at
`

// feedbackJoinSelectColumns is the `f.`-qualified variant of
// feedbackSelectColumns used by ListByDimension. The JOIN against
// `alerts` introduces ambiguous column references (`id`,
// `tenant_id`, `created_at` exist on both tables) so the unqualified
// SELECT list is rejected by postgres at runtime. The two constants
// are kept in lockstep — see PR #40 round-9 BUG_0001 for the
// regression that motivated the split.
const feedbackJoinSelectColumns = `
f.id, f.tenant_id, f.alert_id, f.decision, COALESCE(f.notes, ''), f.created_by, f.created_at
`

func scanFeedback(row pgx.Row) (repository.AlertFeedback, error) {
	var (
		f         repository.AlertFeedback
		decision  string
		createdBy nullableUUID
	)
	if err := row.Scan(
		&f.ID, &f.TenantID, &f.AlertID, &decision, &f.Notes, &createdBy, &f.CreatedAt,
	); err != nil {
		return repository.AlertFeedback{}, err
	}
	f.Decision = repository.AlertFeedbackDecision(decision)
	if createdBy.Valid {
		v := createdBy.ID
		f.CreatedBy = &v
	}
	return f, nil
}

// Create persists feedback on an alert. ErrConflict when
// feedback already exists for the alert (mirrors the UNIQUE
// constraint on alert_id).
func (r *AlertFeedbackRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	f repository.AlertFeedback,
) (repository.AlertFeedback, error) {
	if tenantID == uuid.Nil || f.AlertID == uuid.Nil {
		return repository.AlertFeedback{}, repository.ErrInvalidArgument
	}
	if !f.Decision.IsValid() {
		return repository.AlertFeedback{}, repository.ErrInvalidArgument
	}
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	var out repository.AlertFeedback
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
INSERT INTO alert_feedback
    (id, tenant_id, alert_id, decision, notes, created_by)
VALUES
    ($1::uuid, $2::uuid, $3::uuid, $4, NULLIF($5, ''), $6)
RETURNING ` + feedbackSelectColumns
		row := tx.QueryRow(ctx, q,
			f.ID, tenantID, f.AlertID, string(f.Decision), f.Notes, optionalUUID(f.CreatedBy),
		)
		scanned, scanErr := scanFeedback(row)
		if scanErr != nil {
			if isUniqueViolation(scanErr) {
				return repository.ErrConflict
			}
			if isCheckViolation(scanErr) {
				return repository.ErrInvalidArgument
			}
			if isForeignKeyViolation(scanErr) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("insert alert_feedback: %w", scanErr)
		}
		out = scanned
		return nil
	})
	return out, err
}

// GetForAlert returns the feedback row for one alert.
func (r *AlertFeedbackRepository) GetForAlert(
	ctx context.Context,
	tenantID, alertID uuid.UUID,
) (repository.AlertFeedback, error) {
	if tenantID == uuid.Nil || alertID == uuid.Nil {
		return repository.AlertFeedback{}, repository.ErrInvalidArgument
	}
	var out repository.AlertFeedback
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + feedbackSelectColumns + `
FROM alert_feedback WHERE alert_id = $1::uuid`
		row := tx.QueryRow(ctx, q, alertID)
		scanned, scanErr := scanFeedback(row)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if scanErr != nil {
			return fmt.Errorf("select alert_feedback: %w", scanErr)
		}
		out = scanned
		return nil
	})
	return out, err
}

// Delete removes feedback for an alert. ErrNotFound when no
// feedback exists.
func (r *AlertFeedbackRepository) Delete(
	ctx context.Context,
	tenantID, alertID uuid.UUID,
) error {
	if tenantID == uuid.Nil || alertID == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx,
			`DELETE FROM alert_feedback WHERE alert_id = $1::uuid`, alertID,
		)
		if err != nil {
			return fmt.Errorf("delete alert_feedback: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

// ListByDimension returns every feedback row for alerts in the
// supplied (dimension, windowSeconds) tuple, ordered by
// created_at DESC. The `since` cut-off lets the tuning loop
// bound its lookback. A zero `since` is treated as "no lower
// bound"; a `windowSeconds <= 0` is treated as "no window
// filter" (see interface doc + PR #40 round-9 ANALYSIS_0002).
// This matches the memory implementation's semantics — see
// PR #40 round-8 ANALYSIS_0005 for the consistency note.
func (r *AlertFeedbackRepository) ListByDimension(
	ctx context.Context,
	tenantID uuid.UUID,
	dimension string,
	windowSeconds int,
	since time.Time,
) ([]repository.AlertFeedback, error) {
	if tenantID == uuid.Nil || dimension == "" {
		return nil, repository.ErrInvalidArgument
	}
	var out []repository.AlertFeedback
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Compose the WHERE clause + arg list dynamically so a
		// zero `since` does not emit a redundant
		// `created_at >= '0001-01-01'` predicate (technically
		// harmless but trips up query planners + obscures
		// operator-facing intent), and a `windowSeconds <= 0`
		// omits the window filter entirely so a dimension-wide
		// operator query still works.
		where := []string{"a.dimension = $1"}
		args := []any{dimension}
		if windowSeconds > 0 {
			args = append(args, windowSeconds)
			where = append(where, fmt.Sprintf("a.window_seconds = $%d", len(args)))
		}
		if !since.IsZero() {
			args = append(args, since.UTC())
			where = append(where, fmt.Sprintf("f.created_at >= $%d::timestamptz", len(args)))
		}
		q := `
SELECT ` + feedbackJoinSelectColumns + `
FROM alert_feedback f
JOIN alerts a ON a.id = f.alert_id
WHERE ` + strings.Join(where, " AND ") + `
ORDER BY f.created_at DESC, f.id DESC`
		rows, qerr := tx.Query(ctx, q, args...)
		if qerr != nil {
			return fmt.Errorf("list alert_feedback by dimension: %w", qerr)
		}
		defer rows.Close()
		for rows.Next() {
			f, serr := scanFeedback(rows)
			if serr != nil {
				return fmt.Errorf("scan alert_feedback: %w", serr)
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}
