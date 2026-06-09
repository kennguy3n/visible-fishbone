//go:build integration

package postgres_test

import (
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func intp(v int) *int { return &v }

// TestCASBDiscoveredApp_TwoWriterCounts validates migration 056's
// split of the "how many users" signal into two independently-owned
// columns. casb_discovered_apps has two writers with different
// semantics that collide on (tenant_id, name) when an operator names a
// connector identically to a shadow-IT catalog app:
//
//   - API-mode connector sync writes UsersCount (the full account
//     roster) and leaves ActiveDeviceCount nil.
//   - Shadow-IT discovery writes ActiveDeviceCount (a windowed distinct
//     device count) and leaves UsersCount nil.
//
// Each writer must update only its own column; a nil pointer must
// leave the other writer's column untouched rather than regressing it
// to zero. This exercises the CASE WHEN ... IS NOT NULL guards in the
// upsert against real Postgres (and the GREATEST last_seen guard).
func TestCASBDiscoveredApp_TwoWriterCounts(t *testing.T) {
	t.Parallel()
	store, cleanup := startPostgres(t)
	t.Cleanup(cleanup)

	tnt := mustTenant(t, store.NewTenantRepository())
	repo := store.NewCASBDiscoveredAppRepository()

	t0 := time.Date(2024, 5, 1, 10, 0, 0, 0, time.UTC)

	// API-mode sync discovers "Box" with a 500-user roster.
	apiApp, err := repo.Upsert(bgCtx(), tnt.ID, repository.CASBDiscoveredApp{
		Name:       "Box",
		Vendor:     "box",
		Category:   "saas",
		RiskScore:  intp(40),
		UsersCount: intp(500),
		FirstSeen:  t0,
		LastSeen:   t0,
	})
	if err != nil {
		t.Fatalf("api-mode upsert: %v", err)
	}
	if got := deref(apiApp.UsersCount); got != 500 {
		t.Fatalf("api users_count = %d, want 500", got)
	}
	if got := deref(apiApp.ActiveDeviceCount); got != 0 {
		t.Fatalf("api active_device_count = %d, want 0 (untouched)", got)
	}

	// Shadow-IT flush observes 5 active devices for the same app. It
	// must update active_device_count WITHOUT clobbering the roster.
	shApp, err := repo.Upsert(bgCtx(), tnt.ID, repository.CASBDiscoveredApp{
		Name:              "Box",
		Vendor:            "Box",
		Category:          "collaboration",
		ActiveDeviceCount: intp(5),
		FirstSeen:         t0.Add(time.Hour),
		LastSeen:          t0.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("shadow upsert: %v", err)
	}
	if got := deref(shApp.UsersCount); got != 500 {
		t.Errorf("after shadow flush users_count = %d, want 500 (roster preserved)", got)
	}
	if got := deref(shApp.ActiveDeviceCount); got != 5 {
		t.Errorf("after shadow flush active_device_count = %d, want 5", got)
	}

	// A subsequent API-mode sync reporting a LEGITIMATELY lower roster
	// (e.g. licenses reclaimed) must still be able to decrease
	// users_count — proving we did not apply a GREATEST guard there —
	// while leaving the shadow active_device_count intact.
	lower, err := repo.Upsert(bgCtx(), tnt.ID, repository.CASBDiscoveredApp{
		Name:       "Box",
		Vendor:     "box",
		Category:   "saas",
		UsersCount: intp(300),
		FirstSeen:  t0,
		LastSeen:   t0.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatalf("api-mode re-sync: %v", err)
	}
	if got := deref(lower.UsersCount); got != 300 {
		t.Errorf("users_count = %d, want 300 (roster must be able to decrease)", got)
	}
	if got := deref(lower.ActiveDeviceCount); got != 5 {
		t.Errorf("active_device_count = %d, want 5 (preserved across api re-sync)", got)
	}

	// last_seen is monotonic: this upsert carries an OLDER timestamp,
	// which must not regress the newer value written above.
	stale, err := repo.Upsert(bgCtx(), tnt.ID, repository.CASBDiscoveredApp{
		Name:              "Box",
		Vendor:            "Box",
		Category:          "collaboration",
		ActiveDeviceCount: intp(7),
		FirstSeen:         t0,
		LastSeen:          t0.Add(30 * time.Minute), // older than 2h above
	})
	if err != nil {
		t.Fatalf("stale shadow upsert: %v", err)
	}
	if !stale.LastSeen.Equal(t0.Add(2 * time.Hour)) {
		t.Errorf("last_seen = %v, want %v (GREATEST guard, no regression)",
			stale.LastSeen, t0.Add(2*time.Hour))
	}
	if got := deref(stale.ActiveDeviceCount); got != 7 {
		t.Errorf("active_device_count = %d, want 7", got)
	}

	// Read-back through List confirms persistence of both columns.
	apps, err := repo.List(bgCtx(), tnt.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(apps) != 1 {
		t.Fatalf("list len = %d, want 1", len(apps))
	}
	if deref(apps[0].UsersCount) != 300 || deref(apps[0].ActiveDeviceCount) != 7 {
		t.Errorf("listed counts = users:%d devices:%d, want 300/7",
			deref(apps[0].UsersCount), deref(apps[0].ActiveDeviceCount))
	}
}

func deref(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
