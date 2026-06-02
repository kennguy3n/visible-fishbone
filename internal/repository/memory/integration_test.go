package memory

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// integrationFixtures spins up a Store + tenant + connector repo +
// delivery repo combo so each test in this file gets a clean
// state. Returned t.Cleanup is a noop; the Store is GC'd with the
// test.
func integrationFixtures(t *testing.T) (
	*Store,
	*IntegrationConnectorRepository,
	*IntegrationDeliveryRepository,
	repository.Tenant,
) {
	t.Helper()
	store := NewStore()
	tenantRepo := NewTenantRepository(store)
	cnRepo := NewIntegrationConnectorRepository(store)
	dlRepo := NewIntegrationDeliveryRepository(store)
	tenant, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name:   "int-fix-" + t.Name(),
		Slug:   "int-fix",
		Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	return store, cnRepo, dlRepo, tenant
}

func newSyslogConnector(tenantID uuid.UUID, name string, events ...string) repository.IntegrationConnector {
	return repository.IntegrationConnector{
		TenantID:    tenantID,
		Type:        repository.IntegrationConnectorSyslog,
		Name:        name,
		Description: "test",
		EventTypes:  events,
		Config:      json.RawMessage(`{"endpoint":"tcp://syslog.local:514"}`),
		Secret:      json.RawMessage(`{}`),
	}
}

func TestIntegrationConnector_CreateGetListUpdateDelete(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, repo, _, tenant := integrationFixtures(t)

	created, err := repo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "siem-a", "alert.opened"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Errorf("Create returned zero ID")
	}
	if created.Status != repository.IntegrationConnectorStatusActive {
		t.Errorf("default status = %v, want active", created.Status)
	}
	if created.LastTestResult != repository.IntegrationTestResultNever {
		t.Errorf("default last-test = %v, want never", created.LastTestResult)
	}

	got, err := repo.Get(ctx, tenant.ID, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != "siem-a" {
		t.Errorf("Get.Name = %q, want %q", got.Name, "siem-a")
	}

	// Wrong-tenant Get → NotFound.
	other := uuid.New()
	if _, err := repo.Get(ctx, other, created.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("cross-tenant Get err = %v, want ErrNotFound", err)
	}

	// Create a second connector to exercise List + ordering.
	second, err := repo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "siem-b"))
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}

	page, err := repo.List(ctx, tenant.ID, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("List len = %d, want 2", len(page.Items))
	}
	// Default order CreatedAt DESC — second created should be first.
	if page.Items[0].ID != second.ID {
		t.Errorf("List[0].ID = %s, want second %s", page.Items[0].ID, second.ID)
	}

	// Update — rename + change description + add an event type.
	created.Name = "siem-a-renamed"
	created.Description = "updated"
	created.EventTypes = []string{"alert.opened", "alert.resolved"}
	updated, err := repo.Update(ctx, tenant.ID, created)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "siem-a-renamed" || updated.Description != "updated" {
		t.Errorf("Update did not apply fields: %+v", updated)
	}
	if len(updated.EventTypes) != 2 {
		t.Errorf("Update EventTypes len = %d, want 2", len(updated.EventTypes))
	}

	// Conflict on rename to an existing name.
	updated.Name = "siem-b"
	if _, err := repo.Update(ctx, tenant.ID, updated); !errors.Is(err, repository.ErrConflict) {
		t.Errorf("rename to existing name err = %v, want ErrConflict", err)
	}

	// Delete the second connector; ensure first survives.
	if err := repo.Delete(ctx, tenant.ID, second.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := repo.Get(ctx, tenant.ID, second.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("post-Delete Get err = %v, want ErrNotFound", err)
	}
}

func TestIntegrationConnector_CreateValidation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, repo, _, tenant := integrationFixtures(t)

	cases := []struct {
		name string
		c    repository.IntegrationConnector
		want error
	}{
		{
			name: "missing tenant id",
			c:    newSyslogConnector(tenant.ID, "ok"),
			want: repository.ErrInvalidArgument,
		},
		{
			name: "missing name",
			c:    repository.IntegrationConnector{Type: repository.IntegrationConnectorSyslog},
			want: repository.ErrInvalidArgument,
		},
		{
			name: "unknown type",
			c: repository.IntegrationConnector{
				Type: repository.IntegrationConnectorType("totally-fake"),
				Name: "x",
			},
			want: repository.ErrInvalidArgument,
		},
	}
	// First case is "missing tenant id" — pass uuid.Nil.
	if _, err := repo.Create(ctx, uuid.Nil, cases[0].c); !errors.Is(err, cases[0].want) {
		t.Errorf("%s: err = %v, want %v", cases[0].name, err, cases[0].want)
	}
	for _, tc := range cases[1:] {
		if _, err := repo.Create(ctx, tenant.ID, tc.c); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestIntegrationConnector_CreateDuplicateName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, repo, _, tenant := integrationFixtures(t)
	if _, err := repo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "dup")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := repo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "dup")); !errors.Is(err, repository.ErrConflict) {
		t.Errorf("duplicate Create err = %v, want ErrConflict", err)
	}
}

func TestIntegrationConnector_SetStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, repo, _, tenant := integrationFixtures(t)
	created, err := repo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "ss"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := repo.SetStatus(ctx, tenant.ID, created.ID, repository.IntegrationConnectorStatusDisabled)
	if err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if got.Status != repository.IntegrationConnectorStatusDisabled {
		t.Errorf("Status = %v, want disabled", got.Status)
	}
	// Invalid status rejected.
	if _, err := repo.SetStatus(ctx, tenant.ID, created.ID, repository.IntegrationConnectorStatus("bogus")); !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("bogus SetStatus err = %v, want ErrInvalidArgument", err)
	}
}

func TestIntegrationConnector_RecordTestResult(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, repo, _, tenant := integrationFixtures(t)
	created, err := repo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "probe"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	at := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	got, err := repo.RecordTestResult(ctx, tenant.ID, created.ID,
		repository.IntegrationTestResultFailure, at, "TLS handshake timed out")
	if err != nil {
		t.Fatalf("RecordTestResult fail: %v", err)
	}
	if got.LastTestResult != repository.IntegrationTestResultFailure {
		t.Errorf("LastTestResult = %v, want failure", got.LastTestResult)
	}
	if got.LastTestError != "TLS handshake timed out" {
		t.Errorf("LastTestError = %q", got.LastTestError)
	}
	if got.LastTestAt == nil || !got.LastTestAt.Equal(at) {
		t.Errorf("LastTestAt = %v, want %v", got.LastTestAt, at)
	}
	// Subsequent success clears the error string.
	got, err = repo.RecordTestResult(ctx, tenant.ID, created.ID,
		repository.IntegrationTestResultSuccess, at.Add(time.Minute), "")
	if err != nil {
		t.Fatalf("RecordTestResult success: %v", err)
	}
	if got.LastTestResult != repository.IntegrationTestResultSuccess {
		t.Errorf("LastTestResult = %v, want success", got.LastTestResult)
	}
	if got.LastTestError != "" {
		t.Errorf("success did not clear LastTestError: %q", got.LastTestError)
	}
}

func TestIntegrationConnector_ListActive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, repo, _, tenant := integrationFixtures(t)
	if _, err := repo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "a", "alert.opened")); err != nil {
		t.Fatalf("a: %v", err)
	}
	disabled := newSyslogConnector(tenant.ID, "b", "alert.opened")
	dis, err := repo.Create(ctx, tenant.ID, disabled)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	if _, err := repo.SetStatus(ctx, tenant.ID, dis.ID, repository.IntegrationConnectorStatusDisabled); err != nil {
		t.Fatalf("disable b: %v", err)
	}
	// A subscribe-to-all connector — empty EventTypes matches every event.
	if _, err := repo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "c-all")); err != nil {
		t.Fatalf("c: %v", err)
	}

	active, err := repo.ListActive(ctx, tenant.ID, []string{"alert.opened"})
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if len(active) != 2 {
		t.Fatalf("ListActive len = %d, want 2 (active+subscribe-all)", len(active))
	}
	gotNames := map[string]struct{}{active[0].Name: {}, active[1].Name: {}}
	if _, ok := gotNames["a"]; !ok {
		t.Errorf("expected connector a in active set")
	}
	if _, ok := gotNames["c-all"]; !ok {
		t.Errorf("expected connector c-all (subscribe-to-all) in active set")
	}
	if _, ok := gotNames["b"]; ok {
		t.Errorf("disabled connector b leaked into ListActive")
	}

	// Mismatched event type → only the subscribe-to-all matches.
	active, err = repo.ListActive(ctx, tenant.ID, []string{"nonsuch"})
	if err != nil {
		t.Fatalf("ListActive 2: %v", err)
	}
	if len(active) != 1 || active[0].Name != "c-all" {
		t.Errorf("ListActive mismatch event = %v", active)
	}
}

func TestIntegrationDelivery_CreateGetList(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, cnRepo, dlRepo, tenant := integrationFixtures(t)
	c, err := cnRepo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "d"))
	if err != nil {
		t.Fatalf("create connector: %v", err)
	}
	d, err := dlRepo.Create(ctx, tenant.ID, repository.IntegrationDelivery{
		ConnectorID: c.ID, EventType: "alert.opened",
		Payload: json.RawMessage(`{"alert":"a"}`),
	})
	if err != nil {
		t.Fatalf("Create delivery: %v", err)
	}
	if d.Status != repository.IntegrationDeliveryStatusPending {
		t.Errorf("default delivery status = %v, want pending", d.Status)
	}
	got, err := dlRepo.Get(ctx, tenant.ID, d.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.EventType != "alert.opened" {
		t.Errorf("EventType = %q", got.EventType)
	}
	// List with connector filter.
	conn := c.ID
	page, err := dlRepo.List(ctx, tenant.ID, &conn, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(page.Items) != 1 {
		t.Errorf("List len = %d, want 1", len(page.Items))
	}
}

func TestIntegrationDelivery_UpdateStatus(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, cnRepo, dlRepo, tenant := integrationFixtures(t)
	c, err := cnRepo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "us"))
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	d, err := dlRepo.Create(ctx, tenant.ID, repository.IntegrationDelivery{
		ConnectorID: c.ID, EventType: "x",
		Payload: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("delivery: %v", err)
	}
	now := time.Now().UTC()
	err = dlRepo.UpdateStatus(ctx, tenant.ID, d.ID,
		repository.IntegrationDeliveryStatusDelivered, 1, "", 200, now.Add(time.Hour), "JIRA-42")
	if err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	got, err := dlRepo.Get(ctx, tenant.ID, d.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != repository.IntegrationDeliveryStatusDelivered {
		t.Errorf("Status = %v, want delivered", got.Status)
	}
	if got.ExternalReference != "JIRA-42" {
		t.Errorf("ExternalReference = %q, want JIRA-42", got.ExternalReference)
	}
	if got.Attempts != 1 || got.ResponseStatus != 200 {
		t.Errorf("attempts/responseStatus = %d/%d", got.Attempts, got.ResponseStatus)
	}
	// Passing externalRef="" preserves existing value.
	err = dlRepo.UpdateStatus(ctx, tenant.ID, d.ID,
		repository.IntegrationDeliveryStatusFailed, 2, "retry", 0, now.Add(2*time.Hour), "")
	if err != nil {
		t.Fatalf("UpdateStatus 2: %v", err)
	}
	got, _ = dlRepo.Get(ctx, tenant.ID, d.ID)
	if got.ExternalReference != "JIRA-42" {
		t.Errorf("ExternalReference cleared (got %q); empty externalRef must preserve", got.ExternalReference)
	}
}

// TestIntegrationDelivery_ListPendingAtomicClaim mirrors the
// webhook atomic-claim test: N concurrent workers draining M >> N
// pending rows must observe zero duplicate claims.
func TestIntegrationDelivery_ListPendingAtomicClaim(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, cnRepo, dlRepo, tenant := integrationFixtures(t)
	c, err := cnRepo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "claim"))
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	const seedRows = 100
	wantIDs := make(map[uuid.UUID]struct{}, seedRows)
	now := time.Now().UTC()
	for i := 0; i < seedRows; i++ {
		d, err := dlRepo.Create(ctx, tenant.ID, repository.IntegrationDelivery{
			ConnectorID: c.ID, EventType: "x",
			Payload:     json.RawMessage(`{}`),
			Status:      repository.IntegrationDeliveryStatusPending,
			NextRetryAt: now.Add(-time.Minute),
		})
		if err != nil {
			t.Fatalf("seed %d: %v", i, err)
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
			for {
				rows, err := dlRepo.ListPending(ctx, batch, 0)
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
		t.Errorf("duplicate claims observed: %d", got)
	}
	if len(seenByCount) != seedRows {
		t.Errorf("rows claimed = %d, want %d", len(seenByCount), seedRows)
	}
}

// TestIntegrationDelivery_ListPendingStuckReaper verifies the
// processingTimeout-based stuck-row reclaim path.
func TestIntegrationDelivery_ListPendingStuckReaper(t *testing.T) {
	t.Parallel()
	store := NewStore()
	clk := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	store.SetClock(clk.Now)
	tenantRepo := NewTenantRepository(store)
	cnRepo := NewIntegrationConnectorRepository(store)
	dlRepo := NewIntegrationDeliveryRepository(store)
	ctx := context.Background()
	tenant, err := tenantRepo.Create(ctx, repository.Tenant{
		Name: "reaper", Slug: "reaper", Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("tenant: %v", err)
	}
	c, err := cnRepo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "r"))
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	d, err := dlRepo.Create(ctx, tenant.ID, repository.IntegrationDelivery{
		ConnectorID: c.ID, EventType: "x",
		Payload:     json.RawMessage(`{}`),
		NextRetryAt: clk.Now().Add(-time.Second),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// First drain claims the row → moves to processing.
	first, err := dlRepo.ListPending(ctx, 10, time.Minute)
	if err != nil || len(first) != 1 || first[0].ID != d.ID {
		t.Fatalf("first claim = %v err=%v", first, err)
	}
	// Worker crashes — row remains in processing. Advance just
	// short of the timeout — second drain should NOT reclaim.
	clk.Advance(30 * time.Second)
	stale, _ := dlRepo.ListPending(ctx, 10, time.Minute)
	if len(stale) != 0 {
		t.Errorf("premature reclaim: %v", stale)
	}
	// Cross the timeout boundary → reclaim.
	clk.Advance(31 * time.Second)
	reclaimed, _ := dlRepo.ListPending(ctx, 10, time.Minute)
	if len(reclaimed) != 1 || reclaimed[0].ID != d.ID {
		t.Errorf("reclaim = %v, want stuck row", reclaimed)
	}
}

func TestIntegrationConnector_DeleteCascadesDeliveries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	_, cnRepo, dlRepo, tenant := integrationFixtures(t)
	c, err := cnRepo.Create(ctx, tenant.ID, newSyslogConnector(tenant.ID, "cascade"))
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	d, err := dlRepo.Create(ctx, tenant.ID, repository.IntegrationDelivery{
		ConnectorID: c.ID, EventType: "x", Payload: json.RawMessage(`{}`),
	})
	if err != nil {
		t.Fatalf("delivery: %v", err)
	}
	if err := cnRepo.Delete(ctx, tenant.ID, c.ID); err != nil {
		t.Fatalf("delete connector: %v", err)
	}
	if _, err := dlRepo.Get(ctx, tenant.ID, d.ID); !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("delivery survived connector delete; ON DELETE CASCADE not honoured")
	}
}
