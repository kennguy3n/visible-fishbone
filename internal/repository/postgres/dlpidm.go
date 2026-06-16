package postgres

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DLPIDMRepository owns the dlp_idm_fingerprint_sets and
// dlp_ocr_idm_config tables (WP4 OCR/IDM control-plane state).
type DLPIDMRepository struct{ s *Store }

// NewDLPIDMRepository binds the Store to repository.DLPIDMRepository.
func (s *Store) NewDLPIDMRepository() *DLPIDMRepository {
	return &DLPIDMRepository{s: s}
}

var _ repository.DLPIDMRepository = (*DLPIDMRepository)(nil)

const idmFingerprintSetSelectColumns = `
	id, tenant_id, name, description, shingle_size, window_size,
	max_fingerprints, fingerprints, source_bytes, created_at, updated_at
`

// encodeFingerprints packs winnowed shingle hashes into a contiguous
// big-endian BYTEA blob (8 bytes each), matching the existing
// dlp_fingerprints.hash convention and the Rust edge's wire layout.
func encodeFingerprints(fps []uint64) []byte {
	b := make([]byte, len(fps)*8)
	for i, fp := range fps {
		binary.BigEndian.PutUint64(b[i*8:], fp)
	}
	return b
}

// decodeFingerprints reverses encodeFingerprints. A blob whose length
// is not a multiple of 8 is corrupt (the table CHECK forbids storing
// one), so it is surfaced as an error rather than silently truncated.
func decodeFingerprints(b []byte) ([]uint64, error) {
	if len(b)%8 != 0 {
		return nil, fmt.Errorf("fingerprint blob length %d is not a multiple of 8", len(b))
	}
	out := make([]uint64, len(b)/8)
	for i := range out {
		out[i] = binary.BigEndian.Uint64(b[i*8:])
	}
	return out, nil
}

func scanFingerprintSet(row pgx.Row) (repository.IDMFingerprintSet, error) {
	var (
		set  repository.IDMFingerprintSet
		blob []byte
	)
	if err := row.Scan(
		&set.ID, &set.TenantID, &set.Name, &set.Description,
		&set.ShingleSize, &set.WindowSize, &set.MaxFingerprints,
		&blob, &set.SourceBytes, &set.CreatedAt, &set.UpdatedAt,
	); err != nil {
		return repository.IDMFingerprintSet{}, err
	}
	fps, err := decodeFingerprints(blob)
	if err != nil {
		return repository.IDMFingerprintSet{}, fmt.Errorf("decode fingerprint set %s: %w", set.ID, err)
	}
	set.Fingerprints = fps
	return set, nil
}

func (r *DLPIDMRepository) CreateFingerprintSet(ctx context.Context, tenantID uuid.UUID, set repository.IDMFingerprintSet) (repository.IDMFingerprintSet, error) {
	if tenantID == uuid.Nil {
		return repository.IDMFingerprintSet{}, repository.ErrInvalidArgument
	}
	if set.ID == uuid.Nil {
		set.ID = uuid.New()
	}
	blob := encodeFingerprints(set.Fingerprints)
	count := len(set.Fingerprints)
	var out repository.IDMFingerprintSet
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO dlp_idm_fingerprint_sets
				(id, tenant_id, name, description, shingle_size, window_size,
				 max_fingerprints, fingerprints, fingerprint_count, source_bytes)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING ` + idmFingerprintSetSelectColumns
		var err error
		out, err = scanFingerprintSet(tx.QueryRow(ctx, q,
			set.ID, tenantID, set.Name, set.Description,
			set.ShingleSize, set.WindowSize, set.MaxFingerprints,
			blob, count, set.SourceBytes,
		))
		return mapWriteErr(err, "insert idm fingerprint set")
	})
	return out, err
}

func (r *DLPIDMRepository) GetFingerprintSet(ctx context.Context, tenantID, id uuid.UUID) (repository.IDMFingerprintSet, error) {
	var out repository.IDMFingerprintSet
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + idmFingerprintSetSelectColumns + ` FROM dlp_idm_fingerprint_sets WHERE id = $1::uuid`
		var err error
		out, err = scanFingerprintSet(tx.QueryRow(ctx, q, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select idm fingerprint set: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DLPIDMRepository) ListFingerprintSets(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.IDMFingerprintSet], error) {
	page = page.Normalize()
	cur, err := decodeCursor(page.After)
	if err != nil {
		return repository.PageResult[repository.IDMFingerprintSet]{}, repository.ErrInvalidArgument
	}
	res := repository.PageResult[repository.IDMFingerprintSet]{}
	err = r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		q, args := buildListQuery("dlp_idm_fingerprint_sets", idmFingerprintSetSelectColumns, cur, page.Order, page.Limit)
		rows, err := tx.Query(ctx, q, args...)
		if err != nil {
			return fmt.Errorf("list idm fingerprint sets: %w", err)
		}
		defer rows.Close()
		items := make([]repository.IDMFingerprintSet, 0, page.Limit)
		for rows.Next() {
			set, err := scanFingerprintSet(rows)
			if err != nil {
				return fmt.Errorf("scan idm fingerprint set: %w", err)
			}
			items = append(items, set)
		}
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate idm fingerprint sets: %w", err)
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

func (r *DLPIDMRepository) UpdateFingerprintSet(ctx context.Context, tenantID, id uuid.UUID, patch repository.IDMFingerprintSetPatch) (repository.IDMFingerprintSet, error) {
	var nameArg, descArg any
	if patch.Name != nil {
		nameArg = *patch.Name
	}
	if patch.Description != nil {
		descArg = *patch.Description
	}
	var out repository.IDMFingerprintSet
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			UPDATE dlp_idm_fingerprint_sets
			SET name        = COALESCE($2, name),
			    description = COALESCE($3, description)
			WHERE id = $1::uuid
			RETURNING ` + idmFingerprintSetSelectColumns
		var err error
		out, err = scanFingerprintSet(tx.QueryRow(ctx, q, id, nameArg, descArg))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		return mapWriteErr(err, "update idm fingerprint set")
	})
	return out, err
}

func (r *DLPIDMRepository) DeleteFingerprintSet(ctx context.Context, tenantID, id uuid.UUID) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM dlp_idm_fingerprint_sets WHERE id = $1::uuid`, id)
		if err != nil {
			return fmt.Errorf("delete idm fingerprint set: %w", err)
		}
		if ct.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *DLPIDMRepository) FingerprintSetStats(ctx context.Context, tenantID uuid.UUID) (repository.IDMFingerprintSetStats, error) {
	var out repository.IDMFingerprintSetStats
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			SELECT COUNT(*),
			       COALESCE(SUM(fingerprint_count), 0),
			       COALESCE(SUM(source_bytes), 0)
			FROM dlp_idm_fingerprint_sets`
		if err := tx.QueryRow(ctx, q).Scan(&out.SetCount, &out.TotalFingerprints, &out.TotalSourceBytes); err != nil {
			return fmt.Errorf("aggregate idm fingerprint sets: %w", err)
		}
		return nil
	})
	return out, err
}

const dlpOCRIDMConfigSelectColumns = `
	tenant_id, ocr_enabled, ocr_max_input_bytes, ocr_max_dimension,
	idm_enabled, idm_similarity_threshold, idm_shingle_size, idm_window_size,
	idm_max_fingerprints, created_at, updated_at
`

func scanConfig(row pgx.Row) (repository.DLPOCRIDMConfig, error) {
	var cfg repository.DLPOCRIDMConfig
	if err := row.Scan(
		&cfg.TenantID, &cfg.OCREnabled, &cfg.OCRMaxInputBytes, &cfg.OCRMaxDimension,
		&cfg.IDMEnabled, &cfg.IDMSimilarityThreshold, &cfg.IDMShingleSize, &cfg.IDMWindowSize,
		&cfg.IDMMaxFingerprints, &cfg.CreatedAt, &cfg.UpdatedAt,
	); err != nil {
		return repository.DLPOCRIDMConfig{}, err
	}
	return cfg, nil
}

func (r *DLPIDMRepository) GetConfig(ctx context.Context, tenantID uuid.UUID) (repository.DLPOCRIDMConfig, error) {
	var out repository.DLPOCRIDMConfig
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `SELECT ` + dlpOCRIDMConfigSelectColumns + ` FROM dlp_ocr_idm_config WHERE tenant_id = $1::uuid`
		var err error
		out, err = scanConfig(tx.QueryRow(ctx, q, tenantID))
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select dlp ocr/idm config: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *DLPIDMRepository) UpsertConfig(ctx context.Context, tenantID uuid.UUID, cfg repository.DLPOCRIDMConfig) (repository.DLPOCRIDMConfig, error) {
	if tenantID == uuid.Nil {
		return repository.DLPOCRIDMConfig{}, repository.ErrInvalidArgument
	}
	var out repository.DLPOCRIDMConfig
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		const q = `
			INSERT INTO dlp_ocr_idm_config
				(tenant_id, ocr_enabled, ocr_max_input_bytes, ocr_max_dimension,
				 idm_enabled, idm_similarity_threshold, idm_shingle_size,
				 idm_window_size, idm_max_fingerprints)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (tenant_id) DO UPDATE SET
				ocr_enabled              = EXCLUDED.ocr_enabled,
				ocr_max_input_bytes      = EXCLUDED.ocr_max_input_bytes,
				ocr_max_dimension        = EXCLUDED.ocr_max_dimension,
				idm_enabled              = EXCLUDED.idm_enabled,
				idm_similarity_threshold = EXCLUDED.idm_similarity_threshold,
				idm_shingle_size         = EXCLUDED.idm_shingle_size,
				idm_window_size          = EXCLUDED.idm_window_size,
				idm_max_fingerprints     = EXCLUDED.idm_max_fingerprints
			RETURNING ` + dlpOCRIDMConfigSelectColumns
		var err error
		out, err = scanConfig(tx.QueryRow(ctx, q,
			tenantID, cfg.OCREnabled, cfg.OCRMaxInputBytes, cfg.OCRMaxDimension,
			cfg.IDMEnabled, cfg.IDMSimilarityThreshold, cfg.IDMShingleSize,
			cfg.IDMWindowSize, cfg.IDMMaxFingerprints,
		))
		return mapWriteErr(err, "upsert dlp ocr/idm config")
	})
	return out, err
}
