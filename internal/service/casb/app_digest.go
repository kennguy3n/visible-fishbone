package casb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// AppDigest is the periodic per-tenant rollup that keeps the NoOps
// pipeline transparent: it summarises what the engine classified and
// did since the previous digest so an operator can review automation
// at a glance without trawling the audit trail.
type AppDigest struct {
	TenantID       uuid.UUID                 `json:"tenant_id"`
	Since          time.Time                 `json:"since"`
	GeneratedAt    time.Time                 `json:"generated_at"`
	DiscoveredApps int                       `json:"discovered_apps"`
	Actions        int                       `json:"actions"`
	AutoApplied    int                       `json:"auto_applied"`
	Recommended    int                       `json:"recommended"`
	ByEnforcement  map[ActionEnforcement]int `json:"by_enforcement"`
	HighRiskApps   []string                  `json:"high_risk_apps"`
	LastActionAt   time.Time                 `json:"last_action_at"`
}

// maxDigestHighRiskApps caps the high-risk app list so a tenant with a
// large inventory produces a bounded digest.
const maxDigestHighRiskApps = 50

// BuildDigest computes and emits the digest for one tenant, then
// advances the digest cursor so the next call only covers newer
// actions. It is the single digest emission point — callers (the
// periodic RunDigests sweep, or an operator-triggered refresh) get the
// same rollup. Read failures on the optional inputs degrade to a
// partial digest rather than failing outright; only a cursor-advance
// failure is returned, because losing the cursor would double-count
// next time.
func (e *AppNoOpsEngine) BuildDigest(ctx context.Context, tenantID uuid.UUID) (AppDigest, error) {
	if tenantID == uuid.Nil {
		return AppDigest{}, repository.ErrInvalidArgument
	}
	now := e.nowFunc()

	var since time.Time
	if st, err := e.store.GetDigestState(ctx, tenantID); err == nil {
		since = st.LastDigestAt
	} else if !errors.Is(err, repository.ErrNotFound) {
		e.logger.WarnContext(ctx, "casb: digest state lookup failed; covering full history",
			slog.String("tenant_id", tenantID.String()),
			slog.Any("error", err))
	}

	digest := AppDigest{
		TenantID:      tenantID,
		Since:         since,
		GeneratedAt:   now,
		ByEnforcement: make(map[ActionEnforcement]int),
	}

	actions, err := e.store.ListActionsSince(ctx, tenantID, since)
	if err != nil {
		return AppDigest{}, fmt.Errorf("list actions since: %w", err)
	}
	for _, a := range actions {
		digest.Actions++
		digest.ByEnforcement[a.Enforcement]++
		if a.Mode == ActionModeAuto && a.Applied {
			digest.AutoApplied++
		} else {
			digest.Recommended++
		}
		if a.CreatedAt.After(digest.LastActionAt) {
			digest.LastActionAt = a.CreatedAt
		}
	}

	if classes, err := e.store.ListClassifications(ctx, tenantID); err != nil {
		e.logger.WarnContext(ctx, "casb: digest classifications lookup failed; counts omitted",
			slog.String("tenant_id", tenantID.String()),
			slog.Any("error", err))
	} else {
		digest.DiscoveredApps = len(classes)
		var high []string
		for _, c := range classes {
			if c.Sanction == SanctionUnsanctioned && c.RiskScore >= riskBandEnforce {
				high = append(high, c.AppName)
			}
		}
		sort.Strings(high)
		if len(high) > maxDigestHighRiskApps {
			high = high[:maxDigestHighRiskApps]
		}
		digest.HighRiskApps = high
	}

	// Advance the cursor. LastActionsAt records the newest action this
	// digest observed so an operator can see staleness; LastDigestAt is
	// the window boundary for the next digest.
	lastActionsAt := since
	if digest.LastActionAt.After(lastActionsAt) {
		lastActionsAt = digest.LastActionAt
	}
	if _, err := e.store.UpsertDigestState(ctx, tenantID, DigestState{
		TenantID:      tenantID,
		LastDigestAt:  now,
		LastActionsAt: lastActionsAt,
	}); err != nil {
		return digest, fmt.Errorf("advance digest cursor: %w", err)
	}

	e.logger.InfoContext(ctx, "casb: noops digest",
		slog.String("tenant_id", tenantID.String()),
		slog.Int("discovered_apps", digest.DiscoveredApps),
		slog.Int("actions", digest.Actions),
		slog.Int("auto_applied", digest.AutoApplied),
		slog.Int("recommended", digest.Recommended),
		slog.Int("high_risk_apps", len(digest.HighRiskApps)))
	return digest, nil
}

// RunDigests builds the digest for every active tenant once. Intended
// to run on a schedule (e.g. daily). Per-tenant failures are logged and
// skipped; the first error is returned.
func (e *AppNoOpsEngine) RunDigests(ctx context.Context) error {
	if e.tenants == nil {
		return fmt.Errorf("casb: RunDigests requires a tenant repository")
	}
	var (
		firstErr error
		page     repository.Page
	)
	for {
		res, err := e.tenants.List(ctx, page)
		if err != nil {
			return fmt.Errorf("casb: list tenants: %w", err)
		}
		for _, t := range res.Items {
			if t.Status != repository.TenantStatusActive {
				continue
			}
			if _, err := e.BuildDigest(ctx, t.ID); err != nil {
				e.logger.WarnContext(ctx, "casb: noops digest failed",
					slog.String("tenant_id", t.ID.String()),
					slog.Any("error", err))
				if firstErr == nil {
					firstErr = err
				}
			}
		}
		if res.NextCursor == "" {
			break
		}
		page.After = res.NextCursor
	}
	return firstErr
}
