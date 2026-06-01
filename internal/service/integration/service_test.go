package integration_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/integration"
)

// stubConnector is a controllable Connector implementation used
// across service + worker tests. The atomic counters let tests
// assert call counts without taking a mutex.
type stubConnector struct {
	kind     repository.IntegrationConnectorType
	sends    atomic.Int64
	tests    atomic.Int64
	sendFn   func(ctx context.Context, s integration.Sendable) (integration.SendResult, error)
	testFn   func(ctx context.Context, cfg, sec json.RawMessage) error
	lastSend integration.Sendable
}

func (s *stubConnector) Kind() repository.IntegrationConnectorType { return s.kind }

func (s *stubConnector) Send(ctx context.Context, in integration.Sendable) (integration.SendResult, error) {
	s.sends.Add(1)
	s.lastSend = in
	if s.sendFn != nil {
		return s.sendFn(ctx, in)
	}
	return integration.SendResult{ResponseStatus: 200}, nil
}

func (s *stubConnector) Test(ctx context.Context, cfg, sec json.RawMessage) error {
	s.tests.Add(1)
	if s.testFn != nil {
		return s.testFn(ctx, cfg, sec)
	}
	return nil
}

func newSvc(t *testing.T) (
	*integration.Service,
	*memory.Store,
	*stubConnector,
	uuid.UUID,
	uuid.UUID,
) {
	t.Helper()
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	tn, err := tenants.Create(context.Background(), repository.Tenant{
		Name:   "Acme",
		Slug:   "acme",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	stub := &stubConnector{kind: repository.IntegrationConnectorSyslog}
	registry := integration.Registry{
		repository.IntegrationConnectorSyslog: stub,
	}
	svc := integration.New(
		memory.NewIntegrationConnectorRepository(store),
		memory.NewIntegrationDeliveryRepository(store),
		memory.NewAuditLogRepository(store),
		registry,
		nil,
	)
	actor := uuid.New()
	return svc, store, stub, tn.ID, actor
}

func goodCreateInput() integration.CreateConnectorInput {
	return integration.CreateConnectorInput{
		Type:        repository.IntegrationConnectorSyslog,
		Name:        "primary-syslog",
		Description: "SOC syslog feed",
		EventTypes:  []string{"alert.created"},
		Config:      json.RawMessage(`{"endpoint":"tcp://syslog.local:514"}`),
		Secret:      json.RawMessage(`{"tls_cert":"-----BEGIN CERT-----"}`),
	}
}

func TestService_CreateConnector_HappyPath(t *testing.T) {
	svc, _, _, tn, actor := newSvc(t)
	in := goodCreateInput()
	got, err := svc.CreateConnector(context.Background(), tn, in, &actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ID == uuid.Nil {
		t.Fatalf("missing id")
	}
	if got.Type != in.Type || got.Name != in.Name {
		t.Fatalf("mismatch: %+v vs %+v", got, in)
	}
	if got.Status != repository.IntegrationConnectorStatusActive {
		t.Fatalf("status = %s, want active", got.Status)
	}
	if len(got.EventTypes) != 1 || got.EventTypes[0] != "alert.created" {
		t.Fatalf("events = %v", got.EventTypes)
	}
}

func TestService_CreateConnector_RejectsUnknownKind(t *testing.T) {
	svc, _, _, tn, actor := newSvc(t)
	in := goodCreateInput()
	in.Type = repository.IntegrationConnectorJira
	_, err := svc.CreateConnector(context.Background(), tn, in, &actor)
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument (no plugin)", err)
	}
}

func TestService_CreateConnector_RejectsInvalidArgs(t *testing.T) {
	svc, _, _, tn, actor := newSvc(t)
	cases := map[string]func(in *integration.CreateConnectorInput){
		"empty name":    func(in *integration.CreateConnectorInput) { in.Name = "" },
		"empty config":  func(in *integration.CreateConnectorInput) { in.Config = nil },
		"bad config":    func(in *integration.CreateConnectorInput) { in.Config = json.RawMessage(`{not-json`) },
		"bad secret":    func(in *integration.CreateConnectorInput) { in.Secret = json.RawMessage(`{still-bad`) },
		"invalid kind":  func(in *integration.CreateConnectorInput) { in.Type = "bogus" },
		"empty events":  func(in *integration.CreateConnectorInput) { in.EventTypes = []string{"   "} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := goodCreateInput()
			mutate(&in)
			_, err := svc.CreateConnector(context.Background(), tn, in, &actor)
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestService_UpdateConnector_PartialFields(t *testing.T) {
	svc, _, _, tn, actor := newSvc(t)
	created, err := svc.CreateConnector(context.Background(), tn, goodCreateInput(), &actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	updated, err := svc.UpdateConnector(context.Background(), tn, created.ID,
		integration.UpdateConnectorInput{
			Name:       "renamed",
			EventTypes: []string{"alert.created", "alert.resolved"},
		}, &actor)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != "renamed" {
		t.Fatalf("name = %s", updated.Name)
	}
	if len(updated.EventTypes) != 2 {
		t.Fatalf("events = %v", updated.EventTypes)
	}
	// Description + Config + Secret untouched.
	if updated.Description != created.Description {
		t.Fatalf("description mutated unexpectedly")
	}
	if string(updated.Config) != string(created.Config) {
		t.Fatalf("config mutated unexpectedly")
	}
}

func TestService_SetConnectorStatus_TogglesAndRejectsInvalid(t *testing.T) {
	svc, _, _, tn, actor := newSvc(t)
	c, err := svc.CreateConnector(context.Background(), tn, goodCreateInput(), &actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	disabled, err := svc.SetConnectorStatus(context.Background(), tn, c.ID,
		repository.IntegrationConnectorStatusDisabled, &actor)
	if err != nil {
		t.Fatalf("disable: %v", err)
	}
	if disabled.Status != repository.IntegrationConnectorStatusDisabled {
		t.Fatalf("status = %s, want disabled", disabled.Status)
	}
	_, err = svc.SetConnectorStatus(context.Background(), tn, c.ID,
		"bogus", &actor)
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestService_DeleteConnector_RemovesRow(t *testing.T) {
	svc, _, _, tn, actor := newSvc(t)
	c, err := svc.CreateConnector(context.Background(), tn, goodCreateInput(), &actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.DeleteConnector(context.Background(), tn, c.ID, &actor); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = svc.GetConnector(context.Background(), tn, c.ID)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestService_TestConnector_PersistsResult(t *testing.T) {
	svc, _, stub, tn, actor := newSvc(t)
	c, err := svc.CreateConnector(context.Background(), tn, goodCreateInput(), &actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// First probe fails — verify the row records the failure.
	stub.testFn = func(ctx context.Context, cfg, sec json.RawMessage) error {
		return errors.New("connection refused")
	}
	got, err := svc.TestConnector(context.Background(), tn, c.ID, &actor)
	if err == nil {
		t.Fatalf("err = nil, want probe failure")
	}
	if got.LastTestResult != repository.IntegrationTestResultFailure {
		t.Fatalf("LastTestResult = %s", got.LastTestResult)
	}
	if got.LastTestError == "" {
		t.Fatalf("LastTestError empty")
	}
	if stub.tests.Load() != 1 {
		t.Fatalf("Test() calls = %d", stub.tests.Load())
	}

	// Now success — verify the failure error is cleared.
	stub.testFn = func(ctx context.Context, cfg, sec json.RawMessage) error { return nil }
	got, err = svc.TestConnector(context.Background(), tn, c.ID, &actor)
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if got.LastTestResult != repository.IntegrationTestResultSuccess {
		t.Fatalf("LastTestResult = %s", got.LastTestResult)
	}
	if got.LastTestError != "" {
		t.Fatalf("LastTestError = %q, want empty after success", got.LastTestError)
	}
}

func TestService_TestConnector_RejectsUnknownKind(t *testing.T) {
	// Build a Service whose registry does NOT have syslog so
	// the test probe must reject the kind.
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	tn, err := tenants.Create(context.Background(), repository.Tenant{
		Name: "Acme", Slug: "acme",
		Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	// First create the connector via a "complete" registry.
	full := integration.New(
		memory.NewIntegrationConnectorRepository(store),
		memory.NewIntegrationDeliveryRepository(store),
		memory.NewAuditLogRepository(store),
		integration.Registry{
			repository.IntegrationConnectorSyslog: &stubConnector{kind: repository.IntegrationConnectorSyslog},
		},
		nil,
	)
	c, err := full.CreateConnector(context.Background(), tn.ID, goodCreateInput(), nil)
	if err != nil {
		t.Fatalf("seed connector: %v", err)
	}
	// Then re-build a Service with an EMPTY registry and call
	// TestConnector — should reject.
	empty := integration.New(
		memory.NewIntegrationConnectorRepository(store),
		memory.NewIntegrationDeliveryRepository(store),
		memory.NewAuditLogRepository(store),
		integration.Registry{},
		nil,
	)
	_, err = empty.TestConnector(context.Background(), tn.ID, c.ID, nil)
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument (no plugin)", err)
	}
}

func TestService_Enqueue_FansOutToMatchingConnectors(t *testing.T) {
	svc, _, _, tn, actor := newSvc(t)
	// Connector 1: subscribes to alert.created → match.
	if _, err := svc.CreateConnector(context.Background(), tn,
		integration.CreateConnectorInput{
			Type:       repository.IntegrationConnectorSyslog,
			Name:       "alerts-only",
			EventTypes: []string{"alert.created"},
			Config:     json.RawMessage(`{"endpoint":"tcp://a.local:514"}`),
		}, &actor); err != nil {
		t.Fatalf("create c1: %v", err)
	}
	// Connector 2: subscribes to telemetry.* only → no match.
	if _, err := svc.CreateConnector(context.Background(), tn,
		integration.CreateConnectorInput{
			Type:       repository.IntegrationConnectorSyslog,
			Name:       "telemetry-only",
			EventTypes: []string{"telemetry.flow"},
			Config:     json.RawMessage(`{"endpoint":"tcp://b.local:514"}`),
		}, &actor); err != nil {
		t.Fatalf("create c2: %v", err)
	}
	// Connector 3: subscribe-to-all → match.
	if _, err := svc.CreateConnector(context.Background(), tn,
		integration.CreateConnectorInput{
			Type:       repository.IntegrationConnectorSyslog,
			Name:       "all-events",
			EventTypes: nil,
			Config:     json.RawMessage(`{"endpoint":"tcp://c.local:514"}`),
		}, &actor); err != nil {
		t.Fatalf("create c3: %v", err)
	}
	deliveries, err := svc.Enqueue(context.Background(), tn, "alert.created",
		json.RawMessage(`{"alert_id":"abc"}`))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if len(deliveries) != 2 {
		t.Fatalf("deliveries = %d, want 2 (alerts-only + all-events)", len(deliveries))
	}
	for _, d := range deliveries {
		if d.Status != repository.IntegrationDeliveryStatusPending {
			t.Fatalf("status = %s, want pending", d.Status)
		}
		if d.EventType != "alert.created" {
			t.Fatalf("event = %s", d.EventType)
		}
	}
}

func TestService_Enqueue_RejectsInvalidInput(t *testing.T) {
	svc, _, _, tn, _ := newSvc(t)
	cases := []struct {
		name    string
		eventID string
		payload json.RawMessage
	}{
		{"empty event", "", json.RawMessage(`{}`)},
		{"whitespace event", "   ", json.RawMessage(`{}`)},
		{"bad json", "alert.created", json.RawMessage(`{not-json`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.Enqueue(context.Background(), tn, tc.eventID, tc.payload)
			if !errors.Is(err, repository.ErrInvalidArgument) {
				t.Fatalf("err = %v, want ErrInvalidArgument", err)
			}
		})
	}
}

func TestService_Enqueue_EmptyPayloadDefaultsToEmptyObject(t *testing.T) {
	svc, _, _, tn, actor := newSvc(t)
	if _, err := svc.CreateConnector(context.Background(), tn, goodCreateInput(), &actor); err != nil {
		t.Fatalf("create: %v", err)
	}
	deliveries, err := svc.Enqueue(context.Background(), tn, "alert.created", nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("deliveries = %d", len(deliveries))
	}
	if string(deliveries[0].Payload) != `{}` {
		t.Fatalf("payload = %s", deliveries[0].Payload)
	}
}

func TestService_Enqueue_NoConnectorsReturnsEmpty(t *testing.T) {
	svc, _, _, tn, _ := newSvc(t)
	deliveries, err := svc.Enqueue(context.Background(), tn, "alert.created", nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if len(deliveries) != 0 {
		t.Fatalf("deliveries = %d, want 0", len(deliveries))
	}
}

func TestService_Enqueue_SkipsOrphansOfUnsupportedKind(t *testing.T) {
	// Seed a connector via a registry that supports jira, then
	// rebuild the service with a registry that drops jira so
	// the row exists but the dispatcher can't handle it. Enqueue
	// should skip rather than create a dead pending row.
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	tn, err := tenants.Create(context.Background(), repository.Tenant{
		Name: "Acme", Slug: "acme",
		Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	withJira := integration.New(
		memory.NewIntegrationConnectorRepository(store),
		memory.NewIntegrationDeliveryRepository(store),
		memory.NewAuditLogRepository(store),
		integration.Registry{
			repository.IntegrationConnectorSyslog: &stubConnector{kind: repository.IntegrationConnectorSyslog},
			repository.IntegrationConnectorJira:   &stubConnector{kind: repository.IntegrationConnectorJira},
		},
		nil,
	)
	if _, err := withJira.CreateConnector(context.Background(), tn.ID,
		integration.CreateConnectorInput{
			Type:   repository.IntegrationConnectorJira,
			Name:   "jira-prod",
			Config: json.RawMessage(`{"site":"acme.atlassian.net"}`),
		}, nil); err != nil {
		t.Fatalf("seed jira: %v", err)
	}
	withoutJira := integration.New(
		memory.NewIntegrationConnectorRepository(store),
		memory.NewIntegrationDeliveryRepository(store),
		memory.NewAuditLogRepository(store),
		integration.Registry{
			repository.IntegrationConnectorSyslog: &stubConnector{kind: repository.IntegrationConnectorSyslog},
		},
		nil,
	)
	deliveries, err := withoutJira.Enqueue(context.Background(), tn.ID, "alert.created", nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if len(deliveries) != 0 {
		t.Fatalf("deliveries = %d, want 0 (orphan should be skipped)", len(deliveries))
	}
}

func TestService_SupportsKind(t *testing.T) {
	svc, _, _, _, _ := newSvc(t)
	if !svc.SupportsKind(repository.IntegrationConnectorSyslog) {
		t.Fatalf("expected syslog supported")
	}
	if svc.SupportsKind(repository.IntegrationConnectorJira) {
		t.Fatalf("expected jira not supported")
	}
}

func TestService_ListDeliveries_FilterByConnector(t *testing.T) {
	svc, _, _, tn, actor := newSvc(t)
	c1, err := svc.CreateConnector(context.Background(), tn,
		goodCreateInput(), &actor)
	if err != nil {
		t.Fatalf("create c1: %v", err)
	}
	// c2 with same event type but different name.
	in2 := goodCreateInput()
	in2.Name = "secondary"
	c2, err := svc.CreateConnector(context.Background(), tn, in2, &actor)
	if err != nil {
		t.Fatalf("create c2: %v", err)
	}
	if _, err := svc.Enqueue(context.Background(), tn, "alert.created",
		json.RawMessage(`{"k":"v"}`)); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	all, err := svc.ListDeliveries(context.Background(), tn, nil,
		repository.Page{Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all.Items) != 2 {
		t.Fatalf("all = %d, want 2", len(all.Items))
	}
	scoped, err := svc.ListDeliveries(context.Background(), tn, &c1.ID,
		repository.Page{Limit: 50})
	if err != nil {
		t.Fatalf("scoped: %v", err)
	}
	if len(scoped.Items) != 1 {
		t.Fatalf("scoped = %d, want 1", len(scoped.Items))
	}
	if scoped.Items[0].ConnectorID != c1.ID {
		t.Fatalf("scoped connector mismatch")
	}
	_ = c2
}

func TestService_ClockOverride(t *testing.T) {
	svc, _, _, tn, actor := newSvc(t)
	if _, err := svc.CreateConnector(context.Background(), tn, goodCreateInput(), &actor); err != nil {
		t.Fatalf("create: %v", err)
	}
	fixed := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	svc.SetClock(func() time.Time { return fixed })
	deliveries, err := svc.Enqueue(context.Background(), tn, "alert.created", nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if len(deliveries) != 1 {
		t.Fatalf("deliveries = %d", len(deliveries))
	}
	if !deliveries[0].NextRetryAt.Equal(fixed) {
		t.Fatalf("NextRetryAt = %v, want %v", deliveries[0].NextRetryAt, fixed)
	}
}
