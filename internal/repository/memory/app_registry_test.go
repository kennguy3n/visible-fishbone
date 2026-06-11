package memory

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ListAll must return overrides in the same deterministic order as the
// postgres backend (created_at DESC, id DESC). The store holds overrides
// in a map, whose iteration order is randomized by the runtime, so
// without an explicit sort resolveTrafficClass — which picks the first
// matching override — could resolve a different class on the memory
// backend than in production.
func TestAppRegistryOverride_ListAll_OrdersCreatedAtDescIDDesc(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	repo := NewAppRegistryOverrideRepository(s)
	tenant := uuid.New()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	// Two overrides share a created_at to exercise the id tie-break.
	tie := base.Add(2 * time.Minute)
	specs := []struct {
		domain string
		at     time.Time
	}{
		{"oldest.example.com", base},
		{"middle.example.com", base.Add(time.Minute)},
		{"tie-a.example.com", tie},
		{"tie-b.example.com", tie},
		{"newest.example.com", base.Add(3 * time.Minute)},
	}
	for _, sp := range specs {
		s.SetClock(func() time.Time { return sp.at })
		if _, err := repo.Create(ctx, tenant, repository.AppRegistryOverride{
			CustomDomains:        []string{sp.domain},
			TrafficClassOverride: repository.TrafficClassInspectFull,
		}); err != nil {
			t.Fatalf("create override %q: %v", sp.domain, err)
		}
	}

	got, err := repo.ListAll(ctx, tenant)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(got) != len(specs) {
		t.Fatalf("ListAll returned %d overrides, want %d", len(got), len(specs))
	}

	// Primary key: created_at DESC. Tie-break: id DESC (lexical on the
	// UUID string, matching the postgres `ORDER BY ... id DESC`).
	for i := 1; i < len(got); i++ {
		prev, cur := got[i-1], got[i]
		if cur.CreatedAt.After(prev.CreatedAt) {
			t.Fatalf("not sorted by created_at DESC at %d: %s before %s",
				i, prev.CreatedAt, cur.CreatedAt)
		}
		if cur.CreatedAt.Equal(prev.CreatedAt) && cur.ID.String() > prev.ID.String() {
			t.Fatalf("tie not broken by id DESC at %d: %s before %s",
				i, prev.ID, cur.ID)
		}
	}

	// Newest first, oldest last (the unambiguous endpoints).
	if got[0].CustomDomains[0] != "newest.example.com" {
		t.Errorf("first = %v, want newest.example.com", got[0].CustomDomains)
	}
	if got[len(got)-1].CustomDomains[0] != "oldest.example.com" {
		t.Errorf("last = %v, want oldest.example.com", got[len(got)-1].CustomDomains)
	}
}

// ListAll must scope strictly to the requested tenant.
func TestAppRegistryOverride_ListAll_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	s := NewStore()
	repo := NewAppRegistryOverrideRepository(s)
	t1, t2 := uuid.New(), uuid.New()

	mk := func(tenant uuid.UUID, domain string) {
		if _, err := repo.Create(ctx, tenant, repository.AppRegistryOverride{
			CustomDomains:        []string{domain},
			TrafficClassOverride: repository.TrafficClassInspectFull,
		}); err != nil {
			t.Fatalf("create override: %v", err)
		}
	}
	mk(t1, "a.example.com")
	mk(t1, "b.example.com")
	mk(t2, "c.example.com")

	got, err := repo.ListAll(ctx, t1)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListAll(t1) returned %d overrides, want 2", len(got))
	}
	for _, ov := range got {
		if ov.TenantID != t1 {
			t.Errorf("ListAll(t1) leaked tenant %s", ov.TenantID)
		}
	}
}
