package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

// defaultDLPReviewListLimit bounds List when the caller passes a
// non-positive limit.
const defaultDLPReviewListLimit = 100

// dlpReviewColumns is the canonical column order shared by every
// SELECT/RETURNING in this file, so the scan helper stays in lock-step
// with the queries.
const dlpReviewColumns = `
	id, tenant_id, signal, destination_app, severity, confidence,
	state, evidence_redacted, created_at, decided_at, decided_by`

// DLPReviewRepository owns the dlp_review_queue table (migration 060):
// the human-in-the-loop queue for AI-app DLP events the endpoint engine
// flagged but did not block. Every query runs inside
// withTenant/withTenantRO so the `sng.tenant_id` GUC is set and RLS
// scopes the rows to the caller's tenant.
//
// It implements dlpreview.Repository (declared in the service package),
// so the dependency points inward and this file is the only place that
// knows both the SQL schema and the domain type.
type DLPReviewRepository struct{ s *Store }

// NewDLPReviewRepository binds the Store to the dlpreview.Repository
// interface.
func NewDLPReviewRepository(s *Store) *DLPReviewRepository {
	return &DLPReviewRepository{s: s}
}

var _ dlpreview.Repository = (*DLPReviewRepository)(nil)

// Enqueue inserts ev and returns the stored row.
func (r *DLPReviewRepository) Enqueue(ctx context.Context, tenantID uuid.UUID, ev dlpreview.ReviewEvent) (dlpreview.ReviewEvent, error) {
	if tenantID == uuid.Nil || ev.ID == uuid.Nil || ev.TenantID != tenantID {
		return dlpreview.ReviewEvent{}, repository.ErrInvalidArgument
	}
	if ev.Signal == "" || ev.DestinationApp == "" || !ev.Severity.Valid() {
		return dlpreview.ReviewEvent{}, repository.ErrInvalidArgument
	}
	if ev.State != dlpreview.StatePending {
		return dlpreview.ReviewEvent{}, repository.ErrInvalidArgument
	}
	evidence, err := marshalFindings(ev.Findings)
	if err != nil {
		return dlpreview.ReviewEvent{}, err
	}

	var out dlpreview.ReviewEvent
	err = r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO dlp_review_queue
				(id, tenant_id, signal, destination_app, severity,
				 confidence, state, evidence_redacted)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8::jsonb)
			RETURNING ` + dlpReviewColumns
		row := tx.QueryRow(ctx, q,
			ev.ID, tenantID, ev.Signal, ev.DestinationApp, string(ev.Severity),
			ev.Confidence, string(ev.State), evidence,
		)
		scanned, scanErr := scanDLPReview(row)
		if scanErr != nil {
			return mapDLPReviewWriteErr(scanErr)
		}
		out = scanned
		return nil
	})
	if err != nil {
		return dlpreview.ReviewEvent{}, err
	}
	return out, nil
}

// Get returns the event by id within the tenant, or ErrNotFound.
func (r *DLPReviewRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (dlpreview.ReviewEvent, error) {
	var out dlpreview.ReviewEvent
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + dlpReviewColumns + `
			FROM dlp_review_queue WHERE id = $1::uuid`
		row := tx.QueryRow(ctx, q, id)
		scanned, scanErr := scanDLPReview(row)
		if scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("get dlp_review_queue: %w", scanErr)
		}
		out = scanned
		return nil
	})
	if err != nil {
		return dlpreview.ReviewEvent{}, err
	}
	return out, nil
}

// List returns the tenant's events, newest first, subject to f.
func (r *DLPReviewRepository) List(ctx context.Context, tenantID uuid.UUID, f dlpreview.ListFilter) ([]dlpreview.ReviewEvent, error) {
	if f.State != nil && !f.State.Valid() {
		return nil, repository.ErrInvalidArgument
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultDLPReviewListLimit
	}

	var out []dlpreview.ReviewEvent
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// A NULL $1 means "no state filter"; the predicate short-circuits
		// to TRUE so the partial/state index is still usable when a state
		// is supplied.
		const q = `
			SELECT ` + dlpReviewColumns + `
			FROM dlp_review_queue
			WHERE ($1::text IS NULL OR state = $1::text)
			ORDER BY created_at DESC, id
			LIMIT $2`
		var stateArg any
		if f.State != nil {
			stateArg = string(*f.State)
		}
		rows, err := tx.Query(ctx, q, stateArg, limit)
		if err != nil {
			return fmt.Errorf("query dlp_review_queue: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			ev, scanErr := scanDLPReviewRows(rows)
			if scanErr != nil {
				return fmt.Errorf("scan dlp_review_queue: %w", scanErr)
			}
			out = append(out, ev)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Transition moves a pending event to the terminal state `to`. It
// performs the state check in the UPDATE predicate so the transition is
// atomic, then disambiguates a zero-row result into ErrNotFound (no such
// event for the tenant) vs ErrConflict (already terminal).
func (r *DLPReviewRepository) Transition(ctx context.Context, tenantID, id uuid.UUID, to dlpreview.ReviewState, decidedBy string, decidedAt time.Time) (dlpreview.ReviewEvent, error) {
	if !to.IsTerminal() || decidedBy == "" {
		return dlpreview.ReviewEvent{}, repository.ErrInvalidArgument
	}

	var out dlpreview.ReviewEvent
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE dlp_review_queue
			SET state = $2, decided_at = $3, decided_by = $4
			WHERE id = $1::uuid AND state = 'pending'
			RETURNING ` + dlpReviewColumns
		row := tx.QueryRow(ctx, q, id, string(to), decidedAt.UTC(), decidedBy)
		scanned, scanErr := scanDLPReview(row)
		if scanErr == nil {
			out = scanned
			return nil
		}
		if !errors.Is(scanErr, pgx.ErrNoRows) {
			return mapDLPReviewWriteErr(scanErr)
		}
		// No row was updated: either the event does not exist for this
		// tenant, or it exists but is no longer pending. A second
		// tenant-scoped read tells the two apart so the caller gets a
		// precise error.
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM dlp_review_queue WHERE id = $1::uuid)`, id,
		).Scan(&exists); err != nil {
			return fmt.Errorf("probe dlp_review_queue: %w", err)
		}
		if exists {
			return repository.ErrConflict
		}
		return repository.ErrNotFound
	})
	if err != nil {
		return dlpreview.ReviewEvent{}, err
	}
	return out, nil
}

// Summary aggregates the tenant's events created at/after `since` in a
// single grouped scan.
func (r *DLPReviewRepository) Summary(ctx context.Context, tenantID uuid.UUID, since time.Time) (dlpreview.Summary, error) {
	sum := dlpreview.Summary{
		ByState:      make(map[dlpreview.ReviewState]int),
		BySeverity:   make(map[dlpreview.Severity]int),
		PendingByApp: make(map[string]int),
	}
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT state, severity, destination_app, COUNT(*)
			FROM dlp_review_queue
			WHERE created_at >= $1
			GROUP BY state, severity, destination_app`
		rows, err := tx.Query(ctx, q, since.UTC())
		if err != nil {
			return fmt.Errorf("aggregate dlp_review_queue: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				state    string
				severity string
				app      string
				count    int
			)
			if err := rows.Scan(&state, &severity, &app, &count); err != nil {
				return fmt.Errorf("scan dlp_review_queue summary: %w", err)
			}
			st := dlpreview.ReviewState(state)
			sum.Total += count
			sum.ByState[st] += count
			sum.BySeverity[dlpreview.Severity(severity)] += count
			if st == dlpreview.StatePending {
				sum.Pending += count
				sum.PendingByApp[app] += count
			}
		}
		return rows.Err()
	})
	if err != nil {
		return dlpreview.Summary{}, err
	}
	return sum, nil
}

// BlockedApps returns the distinct destination apps the tenant has
// blocked (at least one row in the blocked state), sorted for a
// deterministic bundle. RLS scopes the rows to the tenant.
func (r *DLPReviewRepository) BlockedApps(ctx context.Context, tenantID uuid.UUID) ([]string, error) {
	out := make([]string, 0)
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT DISTINCT destination_app
			FROM dlp_review_queue
			WHERE state = $1
			ORDER BY destination_app`
		rows, err := tx.Query(ctx, q, string(dlpreview.StateBlocked))
		if err != nil {
			return fmt.Errorf("query blocked dlp apps: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var app string
			if err := rows.Scan(&app); err != nil {
				return fmt.Errorf("scan blocked dlp app: %w", err)
			}
			out = append(out, app)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// marshalFindings serialises the redacted findings to a JSON array for
// the jsonb column, defaulting to `[]` so the column is never NULL.
func marshalFindings(findings []dlpreview.FindingAggregate) ([]byte, error) {
	if len(findings) == 0 {
		return []byte("[]"), nil
	}
	b, err := json.Marshal(findings)
	if err != nil {
		return nil, fmt.Errorf("marshal dlp review findings: %w", err)
	}
	return b, nil
}

// mapDLPReviewWriteErr translates Postgres constraint violations into
// the repository sentinels so callers get a stable, storage-agnostic
// error.
func mapDLPReviewWriteErr(err error) error {
	switch {
	case isCheckViolation(err):
		return repository.ErrInvalidArgument
	case isForeignKeyViolation(err):
		// tenant_id REFERENCES tenants(id): an unknown tenant.
		return repository.ErrNotFound
	case isUniqueViolation(err):
		return repository.ErrConflict
	default:
		return fmt.Errorf("write dlp_review_queue: %w", err)
	}
}

// scanDLPReview scans a single row (QueryRow) in dlpReviewColumns order.
func scanDLPReview(row pgx.Row) (dlpreview.ReviewEvent, error) {
	return scanDLPReviewInto(row)
}

// scanDLPReviewRows scans the current row of a pgx.Rows cursor.
func scanDLPReviewRows(rows pgx.Rows) (dlpreview.ReviewEvent, error) {
	return scanDLPReviewInto(rows)
}

// dlpReviewScanner is the row-scan surface shared by pgx.Row and
// pgx.Rows, so a single scan body serves both the single-row and cursor
// paths.
type dlpReviewScanner interface {
	Scan(dest ...any) error
}

func scanDLPReviewInto(s dlpReviewScanner) (dlpreview.ReviewEvent, error) {
	var (
		ev        dlpreview.ReviewEvent
		severity  string
		state     string
		evidence  []byte
		decidedAt *time.Time
		decidedBy *string
	)
	if err := s.Scan(
		&ev.ID, &ev.TenantID, &ev.Signal, &ev.DestinationApp, &severity, &ev.Confidence,
		&state, &evidence, &ev.CreatedAt, &decidedAt, &decidedBy,
	); err != nil {
		return dlpreview.ReviewEvent{}, err
	}
	ev.Severity = dlpreview.Severity(severity)
	ev.State = dlpreview.ReviewState(state)
	ev.DecidedAt = decidedAt
	ev.DecidedBy = decidedBy
	if len(evidence) > 0 {
		if err := json.Unmarshal(evidence, &ev.Findings); err != nil {
			return dlpreview.ReviewEvent{}, fmt.Errorf("unmarshal dlp review findings: %w", err)
		}
	}
	if ev.Findings == nil {
		ev.Findings = []dlpreview.FindingAggregate{}
	}
	return ev, nil
}
