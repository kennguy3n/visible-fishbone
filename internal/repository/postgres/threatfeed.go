package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ThreatFeedRepository owns the managed threat-content engine's global
// tables (migrations 076-078): the source registry, per-source
// ingestion cursors, and the signed versioned bundle history. NONE are
// tenant-scoped — managed content is a fleet-wide signal — so every
// operation runs in a system-role transaction, mirroring the global
// app_registry / threat_intel_iocs pattern.
//
// The constructor and the compile-time interface assertion live in this
// NEW file (not the shared postgres/repos.go) so the managed engine
// adds no edit to a co-owned repository file.
type ThreatFeedRepository struct{ s *Store }

// NewThreatFeedRepository constructs the postgres-backed managed
// threat-content repository.
func (s *Store) NewThreatFeedRepository() *ThreatFeedRepository {
	return &ThreatFeedRepository{s: s}
}

var _ repository.ThreatFeedRepository = (*ThreatFeedRepository)(nil)

// --- source registry (migration 076) ---------------------------------

// UpsertSources idempotently writes the managed source registry inside
// one system-role transaction. created_at is preserved on an existing
// row (the column default only applies on insert); updated_at is bumped
// every call. The enabled flag is also preserved on conflict (NOT
// overwritten from the seed) so an operator's per-feed disable survives
// the curated re-seed every leader runs at boot; it is set from the
// input only on the initial insert.
func (r *ThreatFeedRepository) UpsertSources(ctx context.Context, sources []repository.ThreatFeedSource) error {
	if len(sources) == 0 {
		return nil
	}
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `
INSERT INTO threat_content_sources
    (name, display_name, kind, url, weight, enabled, default_ttl_seconds, created_at, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, now(), now())
ON CONFLICT (name) DO UPDATE SET
    display_name        = EXCLUDED.display_name,
    kind                = EXCLUDED.kind,
    url                 = EXCLUDED.url,
    weight              = EXCLUDED.weight,
    default_ttl_seconds = EXCLUDED.default_ttl_seconds,
    updated_at          = now()
    -- enabled is intentionally NOT updated here: it is operator-owned
    -- (see UpsertSources doc) and preserving it keeps a manual disable
    -- durable across the boot re-seed.
`
		for _, src := range sources {
			if _, err := tx.Exec(ctx, q,
				src.Name, src.DisplayName, src.Kind, src.URL,
				src.Weight, src.Enabled, src.DefaultTTLSeconds,
			); err != nil {
				return fmt.Errorf("upsert threat_content_sources %q: %w", src.Name, err)
			}
		}
		return nil
	})
}

// ListSources returns the managed-feed registry ordered by name.
func (r *ThreatFeedRepository) ListSources(ctx context.Context) ([]repository.ThreatFeedSource, error) {
	var out []repository.ThreatFeedSource
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT name, display_name, kind, url, weight, enabled, default_ttl_seconds, created_at, updated_at
FROM threat_content_sources
ORDER BY name`)
		if err != nil {
			return fmt.Errorf("list threat_content_sources: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var s repository.ThreatFeedSource
			if err := rows.Scan(
				&s.Name, &s.DisplayName, &s.Kind, &s.URL,
				&s.Weight, &s.Enabled, &s.DefaultTTLSeconds,
				&s.CreatedAt, &s.UpdatedAt,
			); err != nil {
				return fmt.Errorf("scan threat_content_sources: %w", err)
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

// --- ingestion state (migration 077) ---------------------------------

// SaveIngestState upserts one source's ingestion cursor + last outcome.
func (r *ThreatFeedRepository) SaveIngestState(ctx context.Context, state repository.ThreatFeedIngestState) error {
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `
INSERT INTO threat_content_ingest_state
    (source_name, last_attempt_at, last_success_at, last_error,
     indicator_count, consecutive_failures, etag, last_modified, updated_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
ON CONFLICT (source_name) DO UPDATE SET
    last_attempt_at      = EXCLUDED.last_attempt_at,
    last_success_at      = EXCLUDED.last_success_at,
    last_error           = EXCLUDED.last_error,
    indicator_count      = EXCLUDED.indicator_count,
    consecutive_failures = EXCLUDED.consecutive_failures,
    etag                 = EXCLUDED.etag,
    last_modified        = EXCLUDED.last_modified,
    updated_at           = now()
`
		if _, err := tx.Exec(ctx, q,
			state.SourceName,
			nullTime(state.LastAttemptAt),
			nullTime(state.LastSuccessAt),
			state.LastError,
			state.IndicatorCount,
			state.ConsecutiveFailures,
			state.ETag,
			state.LastModified,
		); err != nil {
			return fmt.Errorf("upsert threat_content_ingest_state %q: %w", state.SourceName, err)
		}
		return nil
	})
}

// ListIngestState returns every source's cursor ordered by source name.
func (r *ThreatFeedRepository) ListIngestState(ctx context.Context) ([]repository.ThreatFeedIngestState, error) {
	var out []repository.ThreatFeedIngestState
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
SELECT source_name, last_attempt_at, last_success_at, last_error,
       indicator_count, consecutive_failures, etag, last_modified, updated_at
FROM threat_content_ingest_state
ORDER BY source_name`)
		if err != nil {
			return fmt.Errorf("list threat_content_ingest_state: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				st                       repository.ThreatFeedIngestState
				lastAttempt, lastSuccess *time.Time
			)
			if err := rows.Scan(
				&st.SourceName, &lastAttempt, &lastSuccess, &st.LastError,
				&st.IndicatorCount, &st.ConsecutiveFailures, &st.ETag, &st.LastModified,
				&st.UpdatedAt,
			); err != nil {
				return fmt.Errorf("scan threat_content_ingest_state: %w", err)
			}
			if lastAttempt != nil {
				st.LastAttemptAt = *lastAttempt
			}
			if lastSuccess != nil {
				st.LastSuccessAt = *lastSuccess
			}
			out = append(out, st)
		}
		return rows.Err()
	})
	return out, err
}

// --- signed bundle versions (migration 078) --------------------------

// SaveBundle persists a signed bundle version. A serial collision (two
// replicas producing within the same wall-clock second) overwrites the
// row with the newer envelope: both are valid managed content, so
// last-writer-wins keeps the monotonic-serial contract without an
// expensive re-sign loop. created_at is preserved on conflict (it marks
// when the serial was first persisted), matching UpsertSources.
func (r *ThreatFeedRepository) SaveBundle(ctx context.Context, bundle repository.ThreatFeedBundle) error {
	counts := bundle.CountsByType
	if counts == nil {
		counts = map[string]int{}
	}
	countsJSON, err := json.Marshal(counts)
	if err != nil {
		return fmt.Errorf("marshal threat_content_bundles counts: %w", err)
	}
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
		const q = `
INSERT INTO threat_content_bundles
    (serial, schema_version, generated_at, key_id, algorithm,
     indicator_count, size_bytes, digest, counts_by_type, envelope, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, now())
ON CONFLICT (serial) DO UPDATE SET
    schema_version  = EXCLUDED.schema_version,
    generated_at    = EXCLUDED.generated_at,
    key_id          = EXCLUDED.key_id,
    algorithm       = EXCLUDED.algorithm,
    indicator_count = EXCLUDED.indicator_count,
    size_bytes      = EXCLUDED.size_bytes,
    digest          = EXCLUDED.digest,
    counts_by_type  = EXCLUDED.counts_by_type,
    envelope        = EXCLUDED.envelope
`
		if _, err := tx.Exec(ctx, q,
			bundle.Serial, bundle.SchemaVersion, bundle.GeneratedAt.UTC(),
			bundle.KeyID, bundle.Algorithm, bundle.IndicatorCount,
			bundle.SizeBytes, bundle.Digest, countsJSON, bundle.Envelope,
		); err != nil {
			return fmt.Errorf("upsert threat_content_bundles serial %d: %w", bundle.Serial, err)
		}
		return nil
	})
}

// LatestBundle returns the highest-serial bundle, or ErrNotFound when
// none has been produced yet.
func (r *ThreatFeedRepository) LatestBundle(ctx context.Context) (*repository.ThreatFeedBundle, error) {
	var out *repository.ThreatFeedBundle
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `
SELECT serial, schema_version, generated_at, key_id, algorithm,
       indicator_count, size_bytes, digest, counts_by_type, envelope, created_at
FROM threat_content_bundles
ORDER BY serial DESC
LIMIT 1`)
		var (
			b          repository.ThreatFeedBundle
			countsJSON []byte
		)
		if err := row.Scan(
			&b.Serial, &b.SchemaVersion, &b.GeneratedAt, &b.KeyID, &b.Algorithm,
			&b.IndicatorCount, &b.SizeBytes, &b.Digest, &countsJSON, &b.Envelope,
			&b.CreatedAt,
		); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("query latest threat_content_bundles: %w", err)
		}
		if len(countsJSON) > 0 {
			if err := json.Unmarshal(countsJSON, &b.CountsByType); err != nil {
				return fmt.Errorf("unmarshal threat_content_bundles counts: %w", err)
			}
		}
		out = &b
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LatestSerial returns the highest persisted serial, or 0 when no
// bundle exists. Cheap (no envelope decode) — used to seed the engine's
// monotonic serial across restarts and replicas.
func (r *ThreatFeedRepository) LatestSerial(ctx context.Context) (int64, error) {
	var serial int64
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		// COALESCE folds the empty-table case to 0 so the caller gets a
		// clean zero rather than an ErrNoRows it would have to special-case.
		return tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(serial), 0) FROM threat_content_bundles`,
		).Scan(&serial)
	})
	if err != nil {
		return 0, fmt.Errorf("query max threat_content_bundles serial: %w", err)
	}
	return serial, nil
}

// PruneBundles deletes all but the newest keep versions, bounding the
// history table. keep <= 0 retains everything.
func (r *ThreatFeedRepository) PruneBundles(ctx context.Context, keep int) error {
	if keep <= 0 {
		return nil
	}
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
		// Delete every serial below the keep-th highest. The subquery
		// is bounded by OFFSET so only the retained window is scanned.
		const q = `
DELETE FROM threat_content_bundles
WHERE serial < (
    SELECT serial FROM threat_content_bundles
    ORDER BY serial DESC
    OFFSET $1 LIMIT 1
)`
		if _, err := tx.Exec(ctx, q, keep-1); err != nil {
			return fmt.Errorf("prune threat_content_bundles: %w", err)
		}
		return nil
	})
}
