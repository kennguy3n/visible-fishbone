package postgres

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// mapWriteErr translates a pgx scan/exec error from an INSERT/UPDATE
// path into the canonical repository sentinel errors, mirroring the
// mapping used by the older hand-written repositories (see site.go).
// A nil error passes through unchanged.
func mapWriteErr(err error, op string) error {
	if err == nil {
		return nil
	}
	if isUniqueViolation(err) {
		return repository.ErrConflict
	}
	if isCheckViolation(err) {
		return repository.ErrInvalidArgument
	}
	if isForeignKeyViolation(err) {
		return repository.ErrNotFound
	}
	return fmt.Errorf("%s: %w", op, err)
}

// filterClause is an optional equality predicate appended to a
// keyset-paginated list query (e.g. dlp_matches filtered by
// policy_id). The column name is caller-controlled (never user
// input), so it is interpolated directly.
type filterClause struct {
	column string
	value  any
}

// buildSortedListQuery is the generalised form of buildListQuery for
// tables whose keyset sort column is not literally named created_at
// (e.g. dlp_fingerprints.registered_at, dlp_matches.matched_at). The
// keyset tuple is (sortCol, id); an optional equality filter can be
// appended.
//
// Positional args are always: $1 = cursor timestamp (or NULL), $2 =
// cursor id, $3 = limit, and $4 = filter value when extra != nil.
func buildSortedListQuery(table, cols, sortCol string, cur pageCursor, order repository.SortOrder, limit int, extra *filterClause) (string, []any) {
	cmp, dir := "<", "DESC"
	if order == repository.SortAsc {
		cmp, dir = ">", "ASC"
	}
	args := []any{nil, nil, limit}
	if !cur.T.IsZero() || cur.I != uuid.Nil {
		args[0] = cur.T
		args[1] = cur.I
	}
	filter := ""
	if extra != nil {
		args = append(args, extra.value)
		filter = fmt.Sprintf("AND %s = $4", extra.column)
	}
	q := fmt.Sprintf(`
		SELECT %s
		FROM %s
		WHERE ($1::timestamptz IS NULL OR (%s, id) %s ($1::timestamptz, $2::uuid))
		%s
		ORDER BY %s %s, id %s
		LIMIT $3
	`, cols, table, sortCol, cmp, filter, sortCol, dir, dir)
	return q, args
}
