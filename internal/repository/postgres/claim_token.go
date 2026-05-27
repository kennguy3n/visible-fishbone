package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ClaimTokenRepository owns the claim_tokens table.
type ClaimTokenRepository struct{ s *Store }

// claimTokenSelectColumns is the canonical column list for SELECT /
// RETURNING clauses. The literal contains the column name
// `token_hash` (an SHA-256 digest, not a secret), which gosec's
// G101 hardcoded-credentials heuristic flags as a false positive —
// the `#nosec G101` directive below suppresses that warning.
const claimTokenSelectColumns = `
	id, tenant_id, token_hash, expires_at, redeemed_at, created_by, created_at
` // #nosec G101 -- column name, not a secret

func scanClaimToken(row pgx.Row) (repository.ClaimToken, error) {
	var (
		t         repository.ClaimToken
		redeemed  deletedAtScan
		createdBy nullableUUID
	)
	if err := row.Scan(&t.ID, &t.TenantID, &t.TokenHash, &t.ExpiresAt, &redeemed, &createdBy, &t.CreatedAt); err != nil {
		return repository.ClaimToken{}, err
	}
	if redeemed.Valid {
		ts := redeemed.Time
		t.RedeemedAt = &ts
	}
	if createdBy.Valid {
		id := createdBy.ID
		t.CreatedBy = &id
	}
	return t, nil
}

func (r *ClaimTokenRepository) Create(ctx context.Context, tenantID uuid.UUID, t repository.ClaimToken) (repository.ClaimToken, error) {
	if tenantID == uuid.Nil || len(t.TokenHash) == 0 {
		return repository.ClaimToken{}, repository.ErrInvalidArgument
	}
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	var out repository.ClaimToken
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		var createdBy any
		if t.CreatedBy != nil {
			createdBy = *t.CreatedBy
		}
		row := tx.QueryRow(ctx, `
			INSERT INTO claim_tokens (id, tenant_id, token_hash, expires_at, created_by)
			VALUES ($1::uuid, $2::uuid, $3, $4, $5)
			RETURNING `+claimTokenSelectColumns,
			t.ID, tenantID, t.TokenHash, t.ExpiresAt.UTC(), createdBy,
		)
		var err error
		out, err = scanClaimToken(row)
		if err != nil {
			if isUniqueViolation(err) {
				return repository.ErrConflict
			}
			if isForeignKeyViolation(err) {
				return repository.ErrNotFound
			}
			return fmt.Errorf("insert claim token: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *ClaimTokenRepository) Redeem(ctx context.Context, tenantID uuid.UUID, hash []byte, now time.Time) (repository.ClaimToken, error) {
	var out repository.ClaimToken
	err := r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		// Atomic conditional update: only redeem when the token
		// hash matches, not already redeemed, and not expired.
		// RETURNING tells us whether we won the race.
		const q = `
			UPDATE claim_tokens
			SET redeemed_at = $2
			WHERE token_hash = $1
			  AND redeemed_at IS NULL
			  AND expires_at > $2
			RETURNING ` + claimTokenSelectColumns
		row := tx.QueryRow(ctx, q, hash, now.UTC())
		var err error
		out, err = scanClaimToken(row)
		if errors.Is(err, pgx.ErrNoRows) {
			// Either no token, expired, or already redeemed.
			// A follow-up SELECT disambiguates so callers can
			// render the right error message. Existence with a
			// hit on the original UPDATE filter would have
			// already returned — so any row here is either
			// expired or already redeemed; both map to Forbidden.
			var (
				redeemedAt deletedAtScan
				expiresAt  deletedAtScan
			)
			selErr := tx.QueryRow(ctx,
				`SELECT redeemed_at, expires_at FROM claim_tokens WHERE token_hash = $1`,
				hash,
			).Scan(&redeemedAt, &expiresAt)
			if errors.Is(selErr, pgx.ErrNoRows) {
				return repository.ErrNotFound
			}
			if selErr != nil {
				return fmt.Errorf("inspect claim token: %w", selErr)
			}
			return repository.ErrForbidden
		}
		if err != nil {
			return fmt.Errorf("redeem claim token: %w", err)
		}
		return nil
	})
	return out, err
}

func (r *ClaimTokenRepository) UnredeemByHash(ctx context.Context, tenantID uuid.UUID, hash []byte) error {
	return r.s.withTenant(ctx, tenantID.String(), func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`UPDATE claim_tokens SET redeemed_at = NULL WHERE token_hash = $1`,
			hash,
		)
		if err != nil {
			return fmt.Errorf("unredeem claim token: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return repository.ErrNotFound
		}
		return nil
	})
}

func (r *ClaimTokenRepository) GetByHash(ctx context.Context, tenantID uuid.UUID, hash []byte) (repository.ClaimToken, error) {
	var out repository.ClaimToken
	err := r.s.withTenantRO(ctx, tenantID.String(), func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT `+claimTokenSelectColumns+` FROM claim_tokens WHERE token_hash = $1`, hash)
		var err error
		out, err = scanClaimToken(row)
		if errors.Is(err, pgx.ErrNoRows) {
			return repository.ErrNotFound
		}
		if err != nil {
			return fmt.Errorf("select claim token: %w", err)
		}
		return nil
	})
	return out, err
}
