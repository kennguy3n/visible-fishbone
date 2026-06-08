package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ThreatIOCRepository owns the global threat_intel_iocs snapshot
// table. NOT tenant-scoped — threat-intel indicators are fleet-wide
// signals — so all operations run in a system-role transaction,
// matching the global app_registry pattern.
type ThreatIOCRepository struct{ s *Store }

const threatIOCCols = `
type, value, hash_algo, source, threat_actor, campaign,
confidence, first_seen, last_seen, expires_at
`

// threatIOCCopyColumns is the column order CopyFrom streams; it must
// match the value order built in ReplaceAll.
var threatIOCCopyColumns = []string{
	"type", "value", "hash_algo", "source", "threat_actor", "campaign",
	"confidence", "first_seen", "last_seen", "expires_at",
}

// nullTime maps the in-memory zero time ("unknown" / "permanent")
// onto a SQL NULL so it round-trips through LoadAll unchanged.
func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// ReplaceAll atomically swaps the persisted snapshot for the given
// set inside one system-role transaction: truncate, then bulk-load
// via COPY. Snapshot semantics keep the table in lock-step with the
// live store (including expiry removals) and COPY sidesteps the
// 65535-parameter ceiling a multi-row INSERT would hit for a large
// indicator set.
func (r *ThreatIOCRepository) ReplaceAll(ctx context.Context, iocs []repository.ThreatIOC) error {
	return r.s.withSystem(ctx, func(tx pgx.Tx) error {
		// DELETE (not TRUNCATE): TRUNCATE takes an ACCESS EXCLUSIVE
		// lock and cannot run in some pooled/replicated setups, while
		// a full DELETE inside the surrounding transaction is MVCC-safe
		// and rolls back cleanly if the COPY fails.
		if _, err := tx.Exec(ctx, `DELETE FROM threat_intel_iocs`); err != nil {
			return fmt.Errorf("clear threat_intel_iocs: %w", err)
		}
		if len(iocs) == 0 {
			return nil
		}
		rows := make([][]any, 0, len(iocs))
		for _, ioc := range iocs {
			rows = append(rows, []any{
				ioc.Type, ioc.Value, ioc.HashAlgo, ioc.Source,
				ioc.ThreatActor, ioc.Campaign, ioc.Confidence,
				nullTime(ioc.FirstSeen), nullTime(ioc.LastSeen), nullTime(ioc.ExpiresAt),
			})
		}
		if _, err := tx.CopyFrom(ctx,
			pgx.Identifier{"threat_intel_iocs"}, threatIOCCopyColumns,
			pgx.CopyFromRows(rows),
		); err != nil {
			return fmt.Errorf("copy threat_intel_iocs: %w", err)
		}
		return nil
	})
}

// LoadAll returns every persisted indicator. Used once at boot to
// re-warm the in-memory store; callers drop already-expired rows.
func (r *ThreatIOCRepository) LoadAll(ctx context.Context) ([]repository.ThreatIOC, error) {
	var out []repository.ThreatIOC
	err := r.s.withSystem(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+threatIOCCols+` FROM threat_intel_iocs`)
		if err != nil {
			return fmt.Errorf("list threat_intel_iocs: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var (
				ioc                          repository.ThreatIOC
				firstSeen, lastSeen, expires *time.Time
			)
			if err := rows.Scan(
				&ioc.Type, &ioc.Value, &ioc.HashAlgo, &ioc.Source,
				&ioc.ThreatActor, &ioc.Campaign, &ioc.Confidence,
				&firstSeen, &lastSeen, &expires,
			); err != nil {
				return fmt.Errorf("scan threat_intel_iocs: %w", err)
			}
			if firstSeen != nil {
				ioc.FirstSeen = *firstSeen
			}
			if lastSeen != nil {
				ioc.LastSeen = *lastSeen
			}
			if expires != nil {
				ioc.ExpiresAt = *expires
			}
			out = append(out, ioc)
		}
		return rows.Err()
	})
	return out, err
}
