package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// --- KBEntryRepository ----------------------------------------------------

// KBEntryRepository is the Postgres-backed KB entry store.
type KBEntryRepository struct{ s *Store }

var _ repository.KBEntryRepository = (*KBEntryRepository)(nil)

func (r *KBEntryRepository) Create(
	ctx context.Context,
	tenantID *uuid.UUID,
	e repository.KBEntry,
) (repository.KBEntry, error) {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.Tags == nil {
		e.Tags = []string{}
	}
	var out repository.KBEntry
	run := func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO kb_entries (id, tenant_id, category, title, content, tags)
			VALUES ($1, $2, $3, $4, $5, $6)
			RETURNING id, tenant_id, category, title, content, tags, created_at, updated_at`,
			e.ID, tenantID, string(e.Category), e.Title, e.Content, e.Tags,
		).Scan(
			&out.ID, &out.TenantID, &out.Category, &out.Title,
			&out.Content, &out.Tags, &out.CreatedAt, &out.UpdatedAt,
		)
	}
	var err error
	if tenantID != nil {
		err = r.s.withTenant(ctx, tenantID.String(), run)
	} else {
		err = r.s.withSystem(ctx, run)
	}
	if err != nil {
		return repository.KBEntry{}, fmt.Errorf("kb create: %w", err)
	}
	return out, nil
}

func (r *KBEntryRepository) Get(
	ctx context.Context,
	tenantID *uuid.UUID,
	id uuid.UUID,
) (repository.KBEntry, error) {
	var out repository.KBEntry
	run := func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT id, tenant_id, category, title, content, tags, created_at, updated_at
			FROM kb_entries WHERE id = $1`, id,
		).Scan(
			&out.ID, &out.TenantID, &out.Category, &out.Title,
			&out.Content, &out.Tags, &out.CreatedAt, &out.UpdatedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return err
	}
	var err error
	if tenantID != nil {
		err = r.s.withTenantRO(ctx, tenantID.String(), run)
	} else {
		err = r.s.withSystem(ctx, run)
	}
	if err != nil {
		return repository.KBEntry{}, err
	}
	return out, nil
}

func (r *KBEntryRepository) List(
	ctx context.Context,
	tenantID *uuid.UUID,
	category *string,
	page repository.Page,
) (repository.PageResult[repository.KBEntry], error) {
	page = page.Normalize()
	var items []repository.KBEntry
	run := func(tx pgx.Tx) error {
		query := `SELECT id, tenant_id, category, title, content, tags, created_at, updated_at
			FROM kb_entries WHERE 1=1`
		args := []any{}
		n := 0
		if category != nil {
			n++
			query += fmt.Sprintf(" AND category = $%d", n)
			args = append(args, *category)
		}
		cur, err := decodeCursor(page.After)
		if err == nil && !cur.T.IsZero() {
			if page.Order == repository.SortAsc {
				n++
				query += fmt.Sprintf(" AND (created_at, id) > ($%d", n)
				args = append(args, cur.T)
				n++
				query += fmt.Sprintf(", $%d)", n)
				args = append(args, cur.I)
			} else {
				n++
				query += fmt.Sprintf(" AND (created_at, id) < ($%d", n)
				args = append(args, cur.T)
				n++
				query += fmt.Sprintf(", $%d)", n)
				args = append(args, cur.I)
			}
		}
		if page.Order == repository.SortAsc {
			query += " ORDER BY created_at ASC, id ASC"
		} else {
			query += " ORDER BY created_at DESC, id DESC"
		}
		n++
		query += fmt.Sprintf(" LIMIT $%d", n)
		args = append(args, page.Limit)

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e repository.KBEntry
			if err := rows.Scan(
				&e.ID, &e.TenantID, &e.Category, &e.Title,
				&e.Content, &e.Tags, &e.CreatedAt, &e.UpdatedAt,
			); err != nil {
				return err
			}
			items = append(items, e)
		}
		return rows.Err()
	}
	var err error
	if tenantID != nil {
		err = r.s.withTenantRO(ctx, tenantID.String(), run)
	} else {
		err = r.s.withSystem(ctx, run)
	}
	if err != nil {
		return repository.PageResult[repository.KBEntry]{}, err
	}
	result := repository.PageResult[repository.KBEntry]{Items: items}
	if len(items) == page.Limit {
		last := items[len(items)-1]
		result.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
	}
	return result, nil
}

func (r *KBEntryRepository) Update(
	ctx context.Context,
	tenantID *uuid.UUID,
	id uuid.UUID,
	patch repository.KBEntryPatch,
) (repository.KBEntry, error) {
	var out repository.KBEntry
	run := func(tx pgx.Tx) error {
		existing, err := r.getInTx(ctx, tx, id)
		if err != nil {
			return err
		}
		if patch.Category != nil {
			existing.Category = *patch.Category
		}
		if patch.Title != nil {
			existing.Title = *patch.Title
		}
		if patch.Content != nil {
			existing.Content = *patch.Content
		}
		if patch.Tags != nil {
			existing.Tags = *patch.Tags
		}
		err = tx.QueryRow(ctx, `
			UPDATE kb_entries SET category=$1, title=$2, content=$3, tags=$4, updated_at=now()
			WHERE id=$5
			RETURNING id, tenant_id, category, title, content, tags, created_at, updated_at`,
			string(existing.Category), existing.Title, existing.Content, existing.Tags, id,
		).Scan(
			&out.ID, &out.TenantID, &out.Category, &out.Title,
			&out.Content, &out.Tags, &out.CreatedAt, &out.UpdatedAt,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return err
	}
	var err error
	if tenantID != nil {
		err = r.s.withTenant(ctx, tenantID.String(), run)
	} else {
		err = r.s.withSystem(ctx, run)
	}
	if err != nil {
		return repository.KBEntry{}, err
	}
	return out, nil
}

func (r *KBEntryRepository) Delete(
	ctx context.Context,
	tenantID *uuid.UUID,
	id uuid.UUID,
) error {
	run := func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM kb_entries WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	}
	if tenantID != nil {
		return r.s.withTenant(ctx, tenantID.String(), run)
	}
	return r.s.withSystem(ctx, run)
}

func (r *KBEntryRepository) Search(
	ctx context.Context,
	tenantID *uuid.UUID,
	query string,
	limit int,
) ([]repository.KBEntry, error) {
	if limit <= 0 {
		limit = 10
	}
	var items []repository.KBEntry
	run := func(tx pgx.Tx) error {
		escaped := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(query)
		pattern := "%" + escaped + "%"
		rows, err := tx.Query(ctx, `
			SELECT id, tenant_id, category, title, content, tags, created_at, updated_at
			FROM kb_entries
			WHERE title ILIKE $1 OR content ILIKE $1
			   OR EXISTS (SELECT 1 FROM unnest(tags) t WHERE t ILIKE $1)
			ORDER BY created_at DESC
			LIMIT $2`, pattern, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e repository.KBEntry
			if err := rows.Scan(
				&e.ID, &e.TenantID, &e.Category, &e.Title,
				&e.Content, &e.Tags, &e.CreatedAt, &e.UpdatedAt,
			); err != nil {
				return err
			}
			items = append(items, e)
		}
		return rows.Err()
	}
	var err error
	if tenantID != nil {
		err = r.s.withTenantRO(ctx, tenantID.String(), run)
	} else {
		err = r.s.withSystem(ctx, run)
	}
	if err != nil {
		return nil, err
	}
	return items, nil
}

func (r *KBEntryRepository) getInTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) (repository.KBEntry, error) {
	var e repository.KBEntry
	err := tx.QueryRow(ctx, `
		SELECT id, tenant_id, category, title, content, tags, created_at, updated_at
		FROM kb_entries WHERE id = $1`, id,
	).Scan(&e.ID, &e.TenantID, &e.Category, &e.Title, &e.Content, &e.Tags, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return repository.KBEntry{}, repository.ErrNotFound
	}
	if err != nil {
		return repository.KBEntry{}, err
	}
	return e, nil
}

// --- TroubleshootSessionRepository ----------------------------------------

// TroubleshootSessionRepository is the Postgres-backed session store.
type TroubleshootSessionRepository struct{ s *Store }

var _ repository.TroubleshootSessionRepository = (*TroubleshootSessionRepository)(nil)

func (r *TroubleshootSessionRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	sess repository.TroubleshootSession,
) (repository.TroubleshootSession, error) {
	if sess.ID == uuid.Nil {
		sess.ID = uuid.New()
	}
	if sess.Messages == nil {
		sess.Messages = json.RawMessage("[]")
	}
	if sess.DiagnosticResults == nil {
		sess.DiagnosticResults = json.RawMessage("[]")
	}
	if sess.Status == "" {
		sess.Status = repository.TroubleshootSessionActive
	}
	var out repository.TroubleshootSession
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO troubleshoot_sessions (id, tenant_id, operator_id, issue, status, messages, diagnostic_results)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			RETURNING id, tenant_id, operator_id, issue, status, messages, diagnostic_results, created_at, updated_at`,
			sess.ID, tenantID, sess.OperatorID, sess.Issue, string(sess.Status),
			sess.Messages, sess.DiagnosticResults,
		).Scan(
			&out.ID, &out.TenantID, &out.OperatorID, &out.Issue, &out.Status,
			&out.Messages, &out.DiagnosticResults, &out.CreatedAt, &out.UpdatedAt,
		)
	})
	if err != nil {
		return repository.TroubleshootSession{}, fmt.Errorf("ts create: %w", err)
	}
	return out, nil
}

func (r *TroubleshootSessionRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.TroubleshootSession, error) {
	var out repository.TroubleshootSession
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `
			SELECT id, tenant_id, operator_id, issue, status, messages, diagnostic_results, created_at, updated_at
			FROM troubleshoot_sessions WHERE id = $1`, id,
		).Scan(
			&out.ID, &out.TenantID, &out.OperatorID, &out.Issue, &out.Status,
			&out.Messages, &out.DiagnosticResults, &out.CreatedAt, &out.UpdatedAt,
		)
		if errors.Is(e, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return e
	})
	if err != nil {
		return repository.TroubleshootSession{}, err
	}
	return out, nil
}

func (r *TroubleshootSessionRepository) Update(
	ctx context.Context,
	tenantID, id uuid.UUID,
	sess repository.TroubleshootSession,
) (repository.TroubleshootSession, error) {
	var out repository.TroubleshootSession
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `
			UPDATE troubleshoot_sessions SET
				issue=$1, status=$2, messages=$3, diagnostic_results=$4, updated_at=now()
			WHERE id=$5
			RETURNING id, tenant_id, operator_id, issue, status, messages, diagnostic_results, created_at, updated_at`,
			sess.Issue, string(sess.Status), sess.Messages, sess.DiagnosticResults, id,
		).Scan(
			&out.ID, &out.TenantID, &out.OperatorID, &out.Issue, &out.Status,
			&out.Messages, &out.DiagnosticResults, &out.CreatedAt, &out.UpdatedAt,
		)
		if errors.Is(e, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return e
	})
	if err != nil {
		return repository.TroubleshootSession{}, err
	}
	return out, nil
}

func (r *TroubleshootSessionRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.TroubleshootSession], error) {
	page = page.Normalize()
	var items []repository.TroubleshootSession
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		query := `SELECT id, tenant_id, operator_id, issue, status, messages, diagnostic_results, created_at, updated_at
			FROM troubleshoot_sessions WHERE 1=1`
		args := []any{}
		n := 0

		cur, err := decodeCursor(page.After)
		if err == nil && !cur.T.IsZero() {
			if page.Order == repository.SortAsc {
				n++
				query += fmt.Sprintf(" AND (created_at, id) > ($%d", n)
				args = append(args, cur.T)
				n++
				query += fmt.Sprintf(", $%d)", n)
				args = append(args, cur.I)
			} else {
				n++
				query += fmt.Sprintf(" AND (created_at, id) < ($%d", n)
				args = append(args, cur.T)
				n++
				query += fmt.Sprintf(", $%d)", n)
				args = append(args, cur.I)
			}
		}
		if page.Order == repository.SortAsc {
			query += " ORDER BY created_at ASC, id ASC"
		} else {
			query += " ORDER BY created_at DESC, id DESC"
		}
		n++
		query += fmt.Sprintf(" LIMIT $%d", n)
		args = append(args, page.Limit)

		rows, err := tx.Query(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s repository.TroubleshootSession
			if err := rows.Scan(
				&s.ID, &s.TenantID, &s.OperatorID, &s.Issue, &s.Status,
				&s.Messages, &s.DiagnosticResults, &s.CreatedAt, &s.UpdatedAt,
			); err != nil {
				return err
			}
			items = append(items, s)
		}
		return rows.Err()
	})
	if err != nil {
		return repository.PageResult[repository.TroubleshootSession]{}, err
	}
	result := repository.PageResult[repository.TroubleshootSession]{Items: items}
	if len(items) == page.Limit {
		last := items[len(items)-1]
		result.NextCursor = encodeCursor(pageCursor{T: last.CreatedAt, I: last.ID})
	}
	return result, nil
}
