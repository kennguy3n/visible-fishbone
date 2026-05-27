package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AuditLogRepository owns the audit_log table. Append-only — there
// are no Update or Delete methods.
type AuditLogRepository struct{ s *Store }

const auditSelectColumns = `
	id, tenant_id, actor_id, action, resource_type, resource_id, details, created_at
`

func scanAuditEntry(row pgx.Row) (repository.AuditEntry, error) {
	var (
		e          repository.AuditEntry
		actorID    nullableUUID
		resourceID nullableUUID
		details    []byte
	)
	if err := row.Scan(&e.ID, &e.TenantID, &actorID, &e.Action, &e.ResourceType, &resourceID, &details, &e.CreatedAt); err != nil {
		return repository.AuditEntry{}, err
	}
	if actorID.Valid {
		id := actorID.ID
		e.ActorID = &id
	}
	if resourceID.Valid {
		id := resourceID.ID
		e.ResourceID = &id
	}
	e.Details = json.RawMessage(details)
	return e, nil
}

func (r *AuditLogRepository) Append(ctx context.Context, tenantID uuid.UUID, e repository.AuditEntry) (repository.AuditEntry, error) {
	if tenantID == uuid.Nil ||
		strings.TrimSpace(e.Action) == "" ||
		strings.TrimSpace(e.ResourceType) == "" {
		return repository.AuditEntry{}, repository.ErrInvalidArgument
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if len(e.Details) == 0 {
		e.Details = json.RawMessage(`{}`)
	}
	var out repository.AuditEntry
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		var actorID any
		if e.ActorID != nil {
			actorID = *e.ActorID
		}
		var resourceID any
		if e.ResourceID != nil {
			resourceID = *e.ResourceID
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO audit_log (id, tenant_id, actor_id, action, resource_type, resource_id, details)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7::jsonb)
			RETURNING `+auditSelectColumns,
			e.ID, tenantID, actorID, e.Action, e.ResourceType, resourceID, []byte(e.Details),
		)
		var err error
		out, err = scanAuditEntry(row)
		if err != nil {
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("insert audit entry: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *AuditLogRepository) List(ctx context.Context, tenantID uuid.UUID, filter repository.AuditFilter, page repository.Page) (repository.PageResult[repository.AuditEntry], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.AuditEntry]{}, repository.ErrInvalidArgument
	}
	var (
		where []string
		args  []any
	)
	args = append(args, nil) // $1 cursor T
	args = append(args, nil) // $2 cursor I
	args = append(args, page.Limit)
	if !cur.T.IsZero() || cur.I != uuid.Nil {
		args[0] = cur.T
		args[1] = cur.I
	}
	cmp := "<"
	dir := "DESC"
	if page.Order == repository.SortAsc {
		cmp = ">"
		dir = "ASC"
	}
	where = append(where, fmt.Sprintf("($1::timestamptz IS NULL OR (created_at, id) %s ($1::timestamptz, $2::uuid))", cmp))
	if filter.ActorID != nil {
		args = append(args, *filter.ActorID)
		where = append(where, fmt.Sprintf("actor_id = $%d::uuid", len(args)))
	}
	if filter.ResourceType != "" {
		args = append(args, filter.ResourceType)
		where = append(where, fmt.Sprintf("resource_type = $%d", len(args)))
	}
	if filter.Action != "" {
		args = append(args, filter.Action)
		where = append(where, fmt.Sprintf("action = $%d", len(args)))
	}
	if filter.From != nil {
		args = append(args, filter.From.UTC())
		where = append(where, fmt.Sprintf("created_at >= $%d", len(args)))
	}
	if filter.To != nil {
		args = append(args, filter.To.UTC())
		where = append(where, fmt.Sprintf("created_at <= $%d", len(args)))
	}
	q := fmt.Sprintf(`
		SELECT %s
		FROM audit_log
		WHERE %s
		ORDER BY created_at %s, id %s
		LIMIT $3
	`, auditSelectColumns, strings.Join(where, " AND "), dir, dir)

	res := repository.PageResult[repository.AuditEntry]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list audit: %w", err)
		}
		defer rows.Close()
		items := make([]repository.AuditEntry, 0, page.Limit)
		for rows.Next() {
			e, err := scanAuditEntry(rows)
			if err != nil {
				return fmt.Errorf("scan audit: %w", err)
			}
			items = append(items, e)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate audit: %w", err)
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
