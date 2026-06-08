package memory

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// IPSRuleCategoryRepository is the in-memory implementation of
// repository.IPSRuleCategoryRepository (ips_rule_categories +
// ips_rule_category_stats, migration 050). It mirrors the Postgres
// store's tenant scoping, (tenant, category) override upsert, and
// (tenant, category, day) hit accumulation so service/handler tests
// behave identically against either backend.
type IPSRuleCategoryRepository struct{ s *Store }

// NewIPSRuleCategoryRepository binds the memory Store to
// repository.IPSRuleCategoryRepository.
func NewIPSRuleCategoryRepository(s *Store) *IPSRuleCategoryRepository {
	return &IPSRuleCategoryRepository{s: s}
}

var _ repository.IPSRuleCategoryRepository = (*IPSRuleCategoryRepository)(nil)

// dayKey truncates to the UTC calendar day so two timestamps on the
// same day collapse onto one stats row, matching the DATE column.
func dayKey(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

func selKey(tenantID uuid.UUID, category string) string {
	return tenantID.String() + "|" + category
}

func statKey(tenantID uuid.UUID, category string, day time.Time) string {
	return tenantID.String() + "|" + category + "|" + dayKey(day).Format("2006-01-02")
}

func (r *IPSRuleCategoryRepository) ListSelections(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.IPSRuleCategorySelection, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.IPSRuleCategorySelection, 0)
	for _, sel := range r.s.ipsRuleCategories {
		if sel.TenantID != tenantID {
			continue
		}
		out = append(out, sel)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Category < out[j].Category })
	return out, nil
}

func (r *IPSRuleCategoryRepository) SetEnabled(
	ctx context.Context,
	tenantID uuid.UUID,
	category string,
	enabled bool,
) (repository.IPSRuleCategorySelection, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.IPSRuleCategorySelection{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.IPSRuleCategorySelection{}, repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.IPSRuleCategorySelection{}, repository.ErrNotFound
	}
	now := r.s.clock()
	key := selKey(tenantID, category)
	sel, ok := r.s.ipsRuleCategories[key]
	if ok {
		sel.Enabled = enabled
		sel.UpdatedAt = now
	} else {
		sel = repository.IPSRuleCategorySelection{
			TenantID:  tenantID,
			Category:  category,
			Enabled:   enabled,
			CreatedAt: now,
			UpdatedAt: now,
		}
	}
	r.s.ipsRuleCategories[key] = sel
	return sel, nil
}

func (r *IPSRuleCategoryRepository) AddHits(
	ctx context.Context,
	tenantID uuid.UUID,
	category string,
	day time.Time,
	delta int64,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	if delta < 0 {
		return repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.ErrInvalidArgument
	}
	if _, ok := r.s.tenants[tenantID]; !ok {
		return repository.ErrNotFound
	}
	key := statKey(tenantID, category, day)
	stat, ok := r.s.ipsRuleCategoryStats[key]
	if !ok {
		stat = repository.IPSRuleCategoryDailyStat{
			TenantID: tenantID,
			Category: category,
			Day:      dayKey(day),
		}
	}
	stat.Hits += delta
	r.s.ipsRuleCategoryStats[key] = stat
	return nil
}

func (r *IPSRuleCategoryRepository) StatsSince(
	ctx context.Context,
	tenantID uuid.UUID,
	since time.Time,
) ([]repository.IPSRuleCategoryDailyStat, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	cutoff := dayKey(since)
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.IPSRuleCategoryDailyStat, 0)
	for _, stat := range r.s.ipsRuleCategoryStats {
		if stat.TenantID != tenantID {
			continue
		}
		if stat.Day.Before(cutoff) {
			continue
		}
		out = append(out, stat)
	}
	// Deterministic: newest day first, then category — matching the
	// Postgres ORDER BY day DESC, category.
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Day.Equal(out[j].Day) {
			return out[i].Day.After(out[j].Day)
		}
		return out[i].Category < out[j].Category
	})
	return out, nil
}
