package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

// ipsServiceUnderTest wires the service over the memory repository with
// a seeded tenant so RLS-equivalent tenant scoping is exercised.
func ipsServiceUnderTest(t *testing.T) (*IPSRuleService, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tenant, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "acme", Slug: "acme",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	repo := memory.NewIPSRuleCategoryRepository(store)
	svc := NewIPSRuleService(repo, nil)
	return svc, tenant.ID
}

func TestIPSRules_DefaultsAllEnabled(t *testing.T) {
	svc, tenant := ipsServiceUnderTest(t)
	cats, err := svc.ListCategories(context.Background(), tenant, 0)
	if err != nil {
		t.Fatalf("ListCategories: %v", err)
	}
	if len(cats) != len(AllIPSRuleCategories()) {
		t.Fatalf("want %d categories, got %d", len(AllIPSRuleCategories()), len(cats))
	}
	for _, c := range cats {
		if !c.Enabled {
			t.Errorf("category %s should default enabled", c.Category)
		}
	}

	enabled, err := svc.EnabledCategories(context.Background(), tenant)
	if err != nil {
		t.Fatalf("EnabledCategories: %v", err)
	}
	if len(enabled) != len(AllIPSRuleCategories()) {
		t.Errorf("want all categories enabled by default, got %d", len(enabled))
	}
}

func TestIPSRules_DisableThenReEnable(t *testing.T) {
	svc, tenant := ipsServiceUnderTest(t)
	ctx := context.Background()

	if err := svc.SetCategoryEnabled(ctx, tenant, IPSCategoryDoS, false); err != nil {
		t.Fatalf("disable dos: %v", err)
	}
	enabled, err := svc.EnabledCategories(ctx, tenant)
	if err != nil {
		t.Fatalf("EnabledCategories: %v", err)
	}
	for _, c := range enabled {
		if c == IPSCategoryDoS {
			t.Fatalf("dos should be disabled, still in enabled set")
		}
	}
	if got := len(enabled); got != len(AllIPSRuleCategories())-1 {
		t.Errorf("want %d enabled, got %d", len(AllIPSRuleCategories())-1, got)
	}

	// Reflected in ListCategories too.
	cats, err := svc.ListCategories(ctx, tenant, 0)
	if err != nil {
		t.Fatalf("ListCategories: %v", err)
	}
	for _, c := range cats {
		if c.Category == IPSCategoryDoS && c.Enabled {
			t.Errorf("dos should read disabled")
		}
	}

	// Re-enable.
	if err := svc.SetCategoryEnabled(ctx, tenant, IPSCategoryDoS, true); err != nil {
		t.Fatalf("re-enable dos: %v", err)
	}
	enabled, _ = svc.EnabledCategories(ctx, tenant)
	if len(enabled) != len(AllIPSRuleCategories()) {
		t.Errorf("want all enabled after re-enable, got %d", len(enabled))
	}
}

func TestIPSRules_RejectsUnknownCategory(t *testing.T) {
	svc, tenant := ipsServiceUnderTest(t)
	err := svc.SetCategoryEnabled(context.Background(), tenant, IPSRuleCategory("bogus"), false)
	if !errors.Is(err, ErrUnknownIPSCategory) {
		t.Fatalf("want ErrUnknownIPSCategory, got %v", err)
	}
	err = svc.RecordHits(context.Background(), tenant, IPSRuleCategory("bogus"), time.Now(), 1)
	if !errors.Is(err, ErrUnknownIPSCategory) {
		t.Fatalf("want ErrUnknownIPSCategory on RecordHits, got %v", err)
	}
}

func TestIPSRules_HitsAccumulateAndWindow(t *testing.T) {
	svc, tenant := ipsServiceUnderTest(t)
	ctx := context.Background()
	// Freeze the clock so "today" is deterministic.
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)
	svc.clock = func() time.Time { return now }

	// 3 hits today, 5 hits two days ago, all malware.
	if err := svc.RecordHits(ctx, tenant, IPSCategoryMalware, now, 3); err != nil {
		t.Fatalf("record today: %v", err)
	}
	if err := svc.RecordHits(ctx, tenant, IPSCategoryMalware, now.AddDate(0, 0, -2), 5); err != nil {
		t.Fatalf("record -2d: %v", err)
	}
	// 1 exploit hit today.
	if err := svc.RecordHits(ctx, tenant, IPSCategoryExploit, now, 1); err != nil {
		t.Fatalf("record exploit: %v", err)
	}

	cats, err := svc.ListCategories(ctx, tenant, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("ListCategories: %v", err)
	}
	byCat := map[IPSRuleCategory]IPSCategoryStatus{}
	for _, c := range cats {
		byCat[c.Category] = c
	}
	if got := byCat[IPSCategoryMalware]; got.HitsToday != 3 || got.HitsWindow != 8 {
		t.Errorf("malware: want today=3 window=8, got today=%d window=%d", got.HitsToday, got.HitsWindow)
	}
	if got := byCat[IPSCategoryExploit]; got.HitsToday != 1 || got.HitsWindow != 1 {
		t.Errorf("exploit: want today=1 window=1, got today=%d window=%d", got.HitsToday, got.HitsWindow)
	}

	// A 1-day lookback excludes the -2d hits from the window.
	cats1, _ := svc.ListCategories(ctx, tenant, 24*time.Hour)
	for _, c := range cats1 {
		if c.Category == IPSCategoryMalware && c.HitsWindow != 3 {
			t.Errorf("malware 1d window: want 3, got %d", c.HitsWindow)
		}
	}
}

func TestIPSRules_DailyHitsSeriesNewestFirst(t *testing.T) {
	svc, tenant := ipsServiceUnderTest(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 9, 0, 0, 0, time.UTC)
	svc.clock = func() time.Time { return now }

	_ = svc.RecordHits(ctx, tenant, IPSCategoryC2, now.AddDate(0, 0, -1), 2)
	_ = svc.RecordHits(ctx, tenant, IPSCategoryC2, now, 4)

	series, err := svc.DailyHits(ctx, tenant, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("DailyHits: %v", err)
	}
	if len(series) != 2 {
		t.Fatalf("want 2 points, got %d", len(series))
	}
	if !series[0].Day.After(series[1].Day) {
		t.Errorf("series should be newest-first: %v then %v", series[0].Day, series[1].Day)
	}
	if series[0].Hits != 4 || series[1].Hits != 2 {
		t.Errorf("unexpected hits: %d then %d", series[0].Hits, series[1].Hits)
	}
}

func TestIPSRules_TenantIsolation(t *testing.T) {
	store := memory.NewStore()
	ctx := context.Background()
	mk := func(slug string) uuid.UUID {
		ten, err := memory.NewTenantRepository(store).Create(ctx, repository.Tenant{
			Name: slug, Slug: slug,
			Status: repository.TenantStatusActive,
			Tier:   repository.TenantTierStarter,
		})
		if err != nil {
			t.Fatalf("seed %s: %v", slug, err)
		}
		return ten.ID
	}
	a, b := mk("a"), mk("b")
	svc := NewIPSRuleService(memory.NewIPSRuleCategoryRepository(store), nil)

	if err := svc.SetCategoryEnabled(ctx, a, IPSCategoryMalware, false); err != nil {
		t.Fatalf("disable for a: %v", err)
	}
	// Tenant b is unaffected: malware still enabled.
	enabledB, _ := svc.EnabledCategories(ctx, b)
	found := false
	for _, c := range enabledB {
		if c == IPSCategoryMalware {
			found = true
		}
	}
	if !found {
		t.Errorf("tenant b malware should remain enabled (isolation breach)")
	}
}

func TestClampLookbackDays(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want int
	}{
		{0, 7},
		{-5 * time.Hour, 7},
		{24 * time.Hour, 1},
		{36 * time.Hour, 2}, // ceil
		{7 * 24 * time.Hour, 7},
		{1000 * 24 * time.Hour, 90},
	}
	for _, tc := range cases {
		if got := clampLookbackDays(tc.in); got != tc.want {
			t.Errorf("clampLookbackDays(%v) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
