package memory

import (
	"context"
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// TestWebhookDeliveryRepository_ListPendingAtomicClaim is the
// regression test for the PR6 review finding observing that the
// original implementation selected pending rows via SELECT...FOR
// UPDATE SKIP LOCKED inside a transaction that committed *before*
// the worker began per-row processing. Two workers calling
// ListPending concurrently could receive overlapping rows once
// their transactions both released their row locks at COMMIT,
// causing duplicate HTTP POSTs.
//
// The fix transitions each claimed row from 'pending' to
// 'processing' inside the same statement (postgres:
// UPDATE...RETURNING; memory: write-locked transition). This test
// drives the memory repo with N concurrent ListPending callers
// against M >> N pending rows and asserts the union of returned
// IDs across all callers contains zero duplicates.
func TestWebhookDeliveryRepository_ListPendingAtomicClaim(t *testing.T) {
	t.Parallel()
	store := NewStore()
	tenantRepo := NewTenantRepository(store)
	endpointRepo := NewWebhookEndpointRepository(store)
	deliveryRepo := NewWebhookDeliveryRepository(store)

	ctx := context.Background()
	tenant, err := tenantRepo.Create(ctx, repository.Tenant{
		Name: "atomic-claim-test", Slug: "atomic-claim",
		Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	ep, err := endpointRepo.Create(ctx, tenant.ID, repository.WebhookEndpoint{
		URL: "https://example.com/hook", Events: []string{"x"},
		SigningSecret: []byte("k"),
	})
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}

	const seedRows = 100
	wantIDs := make(map[uuid.UUID]struct{}, seedRows)
	now := time.Now().UTC()
	for i := 0; i < seedRows; i++ {
		d, err := deliveryRepo.Create(ctx, tenant.ID, repository.WebhookDelivery{
			EndpointID: ep.ID, EventType: "x",
			Payload:     json.RawMessage(`{}`),
			Status:      repository.WebhookDeliveryStatusPending,
			NextRetryAt: now.Add(-time.Minute),
		})
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		wantIDs[d.ID] = struct{}{}
	}

	const workers = 8
	const batch = 16
	var (
		mu          sync.Mutex
		seenByCount = make(map[uuid.UUID]int, seedRows)
		dupCount    atomic.Int32
		wg          sync.WaitGroup
	)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each worker drains until ListPending returns
			// empty, mirroring how the real worker loop
			// would race competing instances.
			for {
				rows, err := deliveryRepo.ListPending(ctx, batch, 0)
				if err != nil {
					t.Errorf("ListPending: %v", err)
					return
				}
				if len(rows) == 0 {
					return
				}
				mu.Lock()
				for _, r := range rows {
					seenByCount[r.ID]++
					if seenByCount[r.ID] > 1 {
						dupCount.Add(1)
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if got := dupCount.Load(); got != 0 {
		t.Errorf("duplicate claims observed: %d (atomic-claim invariant violated)", got)
	}
	if len(seenByCount) != seedRows {
		t.Errorf("rows claimed = %d, want %d (some rows lost)", len(seenByCount), seedRows)
	}
	for id := range wantIDs {
		if _, ok := seenByCount[id]; !ok {
			t.Errorf("row %s never claimed", id)
		}
	}
	// And every claimed row must now be in 'processing' status.
	for id := range seenByCount {
		got, err := deliveryRepo.Get(ctx, tenant.ID, id)
		if err != nil {
			t.Fatalf("get %s: %v", id, err)
		}
		if got.Status != repository.WebhookDeliveryStatusProcessing {
			t.Errorf("row %s status = %v, want processing", id, got.Status)
		}
		if got.LastAttemptAt == nil {
			t.Errorf("row %s LastAttemptAt nil, want set on claim", id)
		}
	}
}

// TestWebhookDeliveryRepository_ListPendingStuckRowReaper verifies
// the second half of the atomic-claim contract: a row stuck in
// 'processing' (because its worker crashed mid-delivery) is
// re-claimable once the processingTimeout window has elapsed
// since its last_attempt_at. This bounds worst-case redelivery
// latency under operator-set SLAs.
func TestWebhookDeliveryRepository_ListPendingStuckRowReaper(t *testing.T) {
	t.Parallel()
	store := NewStore()
	// We drive a fake clock so we can advance past the reaper
	// window without sleeping in the test.
	clk := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	store.SetClock(clk.Now)

	tenantRepo := NewTenantRepository(store)
	endpointRepo := NewWebhookEndpointRepository(store)
	deliveryRepo := NewWebhookDeliveryRepository(store)

	ctx := context.Background()
	tenant, err := tenantRepo.Create(ctx, repository.Tenant{
		Name: "reaper-test", Slug: "reaper",
		Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	ep, err := endpointRepo.Create(ctx, tenant.ID, repository.WebhookEndpoint{
		URL: "https://example.com/hook", Events: []string{"x"},
		SigningSecret: []byte("k"),
	})
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	d, err := deliveryRepo.Create(ctx, tenant.ID, repository.WebhookDelivery{
		EndpointID: ep.ID, EventType: "x",
		Payload:     json.RawMessage(`{}`),
		Status:      repository.WebhookDeliveryStatusPending,
		NextRetryAt: clk.Now(),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// First claim — moves row pending → processing, stamps
	// LastAttemptAt = now.
	rows, err := deliveryRepo.ListPending(ctx, 16, 5*time.Minute)
	if err != nil {
		t.Fatalf("ListPending#1: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != d.ID {
		t.Fatalf("ListPending#1 returned %d rows, want 1", len(rows))
	}

	// Within the reaper window, the row must NOT be re-claimed.
	clk.Advance(2 * time.Minute)
	rows, err = deliveryRepo.ListPending(ctx, 16, 5*time.Minute)
	if err != nil {
		t.Fatalf("ListPending#2: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("ListPending#2 returned %d rows within reaper window, want 0", len(rows))
	}

	// Past the reaper window, the stuck row is reclaimable.
	clk.Advance(4 * time.Minute) // total 6m, > 5m timeout
	rows, err = deliveryRepo.ListPending(ctx, 16, 5*time.Minute)
	if err != nil {
		t.Fatalf("ListPending#3: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != d.ID {
		t.Fatalf("ListPending#3 returned %d rows, want 1 (stuck row reaper)", len(rows))
	}
	// LastAttemptAt must have been refreshed by the re-claim,
	// otherwise concurrent reapers would all see the same stale
	// timestamp and re-claim simultaneously.
	if rows[0].LastAttemptAt == nil || !rows[0].LastAttemptAt.Equal(clk.Now()) {
		t.Errorf("LastAttemptAt = %v, want refreshed to %v", rows[0].LastAttemptAt, clk.Now())
	}

	// processingTimeout = 0 disables the reaper entirely — even
	// a very old stuck row stays put. Useful for tests that want
	// deterministic single-claim semantics.
	clk.Advance(time.Hour)
	rows, err = deliveryRepo.ListPending(ctx, 16, 0)
	if err != nil {
		t.Fatalf("ListPending#4: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("ListPending#4 with timeout=0 returned %d rows, want 0", len(rows))
	}
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{now: t} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
