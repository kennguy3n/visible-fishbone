package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AppIDCatalogRepository owns the global, versioned Application-ID
// signature catalog (tables appid_catalog_versions / _entries /
// _bundles). NOT tenant-scoped — application signatures are fleet-wide
// knowledge — so every operation runs in a system-role transaction,
// matching the global app_registry / threat_intel_iocs pattern. The
// tenant-scoped read API enforces tenant auth at the handler layer and
// serves this same global content.
type AppIDCatalogRepository struct{ s *Store }

// NewAppIDCatalogRepository binds the catalog repository to the store.
// Declared here (not in repos.go) so the new-files-only repository
// rule holds: Go permits *Store methods in any file of the package.
func (s *Store) NewAppIDCatalogRepository() *AppIDCatalogRepository {
	return &AppIDCatalogRepository{s: s}
}

// Compile-time assertion that the postgres implementation satisfies
// the repository contract. Kept in this file rather than the central
// assert block in repos.go to avoid co-editing a shared hub file.
var _ repository.AppIDCatalogRepository = (*AppIDCatalogRepository)(nil)

// appidEntryCopyColumns is the column order CopyFrom streams into
// appid_catalog_entries; it must match the value order built in
// PublishVersion.
var appidEntryCopyColumns = []string{
	"serial", "app_id", "category",
	"sni_suffixes", "host_suffixes", "ja3", "byte_prefixes",
	"ports", "transport", "confidence",
}

const appidEntrySelectCols = `
serial, app_id, category, sni_suffixes, host_suffixes, ja3,
byte_prefixes, ports, transport, confidence
`

// PublishVersion writes a new catalog version, its entries, and its
// signed bundle atomically in one system-role transaction. The
// version row is inserted first (parent); a duplicate or regressing
// serial trips the primary-key unique constraint and is surfaced as
// ErrConflict so two concurrent publishers cannot fork history. The
// entries stream via COPY to sidestep the 65535-parameter ceiling a
// multi-row INSERT would hit for a few-hundred-app catalog.
func (r *AppIDCatalogRepository) PublishVersion(ctx context.Context, version repository.AppIDCatalogVersion, entries []repository.AppIDCatalogEntry, bundle repository.AppIDCatalogBundle) error {
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO appid_catalog_versions
			   (serial, schema_version, app_count, checksum, note, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6)`,
			version.Serial, version.SchemaVersion, version.AppCount,
			version.Checksum, version.Note, version.CreatedAt,
		); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("publish appid catalog serial %d: %w", version.Serial, repository.ErrConflict)
			}
			return fmt.Errorf("insert appid_catalog_versions: %w", err)
		}

		if len(entries) > 0 {
			rows := make([][]any, 0, len(entries))
			for _, e := range entries {
				rows = append(rows, []any{
					version.Serial, e.AppID, e.Category,
					textArray(e.SNISuffixes), textArray(e.HostSuffixes),
					textArray(e.JA3), textArray(e.BytePrefixes),
					intArray(e.Ports), e.Transport, e.Confidence,
				})
			}
			if _, err := tx.CopyFrom(ctx,
				pgx.Identifier{"appid_catalog_entries"}, appidEntryCopyColumns,
				pgx.CopyFromRows(rows),
			); err != nil {
				return fmt.Errorf("copy appid_catalog_entries: %w", err)
			}
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO appid_catalog_bundles
			   (serial, algorithm, key_id, public_key, payload, signature, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			version.Serial, bundle.Algorithm, bundle.KeyID,
			bundle.PublicKey, bundle.Payload, bundle.Signature, bundle.CreatedAt,
		); err != nil {
			return fmt.Errorf("insert appid_catalog_bundles: %w", err)
		}
		return nil
	})
}

// CurrentVersion returns the highest-serial version metadata, or
// ErrNotFound when the catalog has never been published.
func (r *AppIDCatalogRepository) CurrentVersion(ctx context.Context) (repository.AppIDCatalogVersion, error) {
	var v repository.AppIDCatalogVersion
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT serial, schema_version, app_count, checksum, note, created_at
			   FROM appid_catalog_versions
			  ORDER BY serial DESC
			  LIMIT 1`)
		if err := row.Scan(&v.Serial, &v.SchemaVersion, &v.AppCount, &v.Checksum, &v.Note, &v.CreatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("query current appid version: %w", err)
		}
		return nil
	})
	return v, err
}

// CurrentEntries returns every entry of the highest-serial version,
// ordered by app_id, or ErrNotFound when nothing has been published.
func (r *AppIDCatalogRepository) CurrentEntries(ctx context.Context) ([]repository.AppIDCatalogEntry, error) {
	var out []repository.AppIDCatalogEntry
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		var serial int64
		if err := tx.QueryRow(ctx,
			`SELECT serial FROM appid_catalog_versions ORDER BY serial DESC LIMIT 1`).Scan(&serial); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("query current appid serial: %w", err)
		}
		rows, err := tx.Query(ctx,
			`SELECT `+appidEntrySelectCols+`
			   FROM appid_catalog_entries
			  WHERE serial = $1
			  ORDER BY app_id`, serial)
		if err != nil {
			return fmt.Errorf("list appid_catalog_entries: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			e, scanErr := scanAppIDEntry(rows)
			if scanErr != nil {
				return scanErr
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

// CurrentBundle returns the signed bundle of the highest-serial
// version, or ErrNotFound when nothing has been published. Because a
// bundle is written atomically with its version, the highest-serial
// bundle is always the current one.
func (r *AppIDCatalogRepository) CurrentBundle(ctx context.Context) (repository.AppIDCatalogBundle, error) {
	var b repository.AppIDCatalogBundle
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx,
			`SELECT serial, algorithm, key_id, public_key, payload, signature, created_at
			   FROM appid_catalog_bundles
			  ORDER BY serial DESC
			  LIMIT 1`)
		if err := row.Scan(&b.Serial, &b.Algorithm, &b.KeyID, &b.PublicKey, &b.Payload, &b.Signature, &b.CreatedAt); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("query current appid bundle: %w", err)
		}
		return nil
	})
	return b, err
}

// ListVersions returns published version metadata newest-first,
// capped at limit (clamped to the repository page bounds).
func (r *AppIDCatalogRepository) ListVersions(ctx context.Context, limit int) ([]repository.AppIDCatalogVersion, error) {
	if limit <= 0 {
		limit = repository.DefaultPageLimit
	}
	if limit > repository.MaxPageLimit {
		limit = repository.MaxPageLimit
	}
	var out []repository.AppIDCatalogVersion
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT serial, schema_version, app_count, checksum, note, created_at
			   FROM appid_catalog_versions
			  ORDER BY serial DESC
			  LIMIT $1`, limit)
		if err != nil {
			return fmt.Errorf("list appid_catalog_versions: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var v repository.AppIDCatalogVersion
			if err := rows.Scan(&v.Serial, &v.SchemaVersion, &v.AppCount, &v.Checksum, &v.Note, &v.CreatedAt); err != nil {
				return fmt.Errorf("scan appid_catalog_versions: %w", err)
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

// scanAppIDEntry maps one entries row into the neutral row struct,
// decoding the text[]/int4[] columns into native slices.
func scanAppIDEntry(rows pgx.Rows) (repository.AppIDCatalogEntry, error) {
	var (
		e     repository.AppIDCatalogEntry
		ports []int32
	)
	if err := rows.Scan(
		&e.Serial, &e.AppID, &e.Category,
		&e.SNISuffixes, &e.HostSuffixes, &e.JA3, &e.BytePrefixes,
		&ports, &e.Transport, &e.Confidence,
	); err != nil {
		return repository.AppIDCatalogEntry{}, fmt.Errorf("scan appid_catalog_entries: %w", err)
	}
	e.Ports = make([]int, len(ports))
	for i, p := range ports {
		e.Ports[i] = int(p)
	}
	return e, nil
}

// textArray normalises a nil slice to an empty (non-nil) slice so the
// stored column is always a zero-length array rather than SQL NULL,
// keeping LoadAll round-trips total.
func textArray(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// intArray widens []int to the []int32 pgx encodes as int4[], and
// normalises nil to an empty array for the same reason as textArray.
func intArray(in []int) []int32 {
	out := make([]int32, len(in))
	for i, v := range in {
		out[i] = int32(v)
	}
	return out
}
