package webhook_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/webhook"
)

func newSvc(t *testing.T) (*webhook.Service, *memory.Store, uuid.UUID, uuid.UUID) {
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
	svc := webhook.New(
		memory.NewWebhookEndpointRepository(store),
		memory.NewWebhookDeliveryRepository(store),
		memory.NewAuditLogRepository(store),
		nil,
	)
	actor := uuid.New()
	return svc, store, tn.ID, actor
}

func TestCreateEndpoint_GeneratesSecretReturnedOnce(t *testing.T) {
	t.Parallel()
	svc, store, tenantID, actor := newSvc(t)
	ctx := context.Background()

	res, err := svc.CreateEndpoint(ctx, tenantID, "https://example.com/hook",
		[]string{"tenant.created", "site.updated"}, &actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Secret == "" {
		t.Fatal("secret not returned on create")
	}
	// Decoded secret length must be 32 bytes (256-bit HMAC key).
	raw, err := base64.RawURLEncoding.DecodeString(res.Secret)
	if err != nil {
		t.Fatalf("decode secret: %v", err)
	}
	if len(raw) != 32 {
		t.Errorf("secret raw length = %d, want 32", len(raw))
	}
	// The repo must persist the same plaintext bytes (HMAC needs them).
	stored, err := memory.NewWebhookEndpointRepository(store).Get(ctx, tenantID, res.Endpoint.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if base64.RawURLEncoding.EncodeToString(stored.SigningSecret) != res.Secret {
		t.Errorf("persisted SigningSecret does not match returned secret")
	}
	// Subsequent Get-by-service must NOT echo the plaintext (api handler controls echo).
	gotAgain, err := svc.GetEndpoint(ctx, tenantID, res.Endpoint.ID)
	if err != nil {
		t.Fatalf("get again: %v", err)
	}
	// service returns the raw record including SigningSecret — handler is responsible for masking.
	if len(gotAgain.SigningSecret) != 32 {
		t.Errorf("expected SigningSecret stored, len = %d", len(gotAgain.SigningSecret))
	}
}

func TestCreateEndpoint_SecretEntropyDistinctPerCall(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, actor := newSvc(t)
	ctx := context.Background()
	seen := make(map[string]struct{}, 8)
	for i := 0; i < 8; i++ {
		res, err := svc.CreateEndpoint(ctx, tenantID, "https://example.com/hook",
			[]string{"tenant.created"}, &actor)
		if err != nil {
			t.Fatalf("create #%d: %v", i, err)
		}
		if _, dup := seen[res.Secret]; dup {
			t.Fatalf("duplicate secret across calls (entropy broken)")
		}
		seen[res.Secret] = struct{}{}
	}
}

func TestCreateEndpoint_RejectsInvalidURL(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, actor := newSvc(t)
	cases := []string{"", "::::", "ftp://example.com/hook", "no-scheme.example.com"}
	for _, raw := range cases {
		_, err := svc.CreateEndpoint(context.Background(), tenantID, raw,
			[]string{"tenant.created"}, &actor)
		if !errors.Is(err, repository.ErrInvalidArgument) {
			t.Errorf("CreateEndpoint(%q) err = %v, want ErrInvalidArgument", raw, err)
		}
	}
}

func TestCreateEndpoint_RejectsEmptyEvents(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, actor := newSvc(t)
	cases := [][]string{nil, {}, {"", "  ", "\t"}}
	for _, ev := range cases {
		_, err := svc.CreateEndpoint(context.Background(), tenantID,
			"https://example.com/hook", ev, &actor)
		if !errors.Is(err, repository.ErrInvalidArgument) {
			t.Errorf("CreateEndpoint(events=%v) err = %v", ev, err)
		}
	}
}

func TestCreateEndpoint_NormalisesEvents(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, actor := newSvc(t)
	res, err := svc.CreateEndpoint(context.Background(), tenantID,
		"https://example.com/hook",
		[]string{" Tenant.Created ", "site.UPDATED", "tenant.created", ""}, &actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	want := []string{"site.updated", "tenant.created"}
	if len(res.Endpoint.Events) != len(want) {
		t.Fatalf("events = %v, want %v", res.Endpoint.Events, want)
	}
	for i, w := range want {
		if res.Endpoint.Events[i] != w {
			t.Errorf("events[%d] = %q, want %q", i, res.Endpoint.Events[i], w)
		}
	}
}

func TestUpdateEndpoint_PartialFields(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, actor := newSvc(t)
	ctx := context.Background()
	res, err := svc.CreateEndpoint(ctx, tenantID, "https://a.example/hook",
		[]string{"tenant.created"}, &actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	upd, err := svc.UpdateEndpoint(ctx, tenantID, res.Endpoint.ID,
		"https://b.example/hook", nil, "", &actor)
	if err != nil {
		t.Fatalf("update url: %v", err)
	}
	if upd.URL != "https://b.example/hook" {
		t.Errorf("URL not updated: %s", upd.URL)
	}
	if len(upd.Events) != 1 || upd.Events[0] != "tenant.created" {
		t.Errorf("events lost on partial update: %v", upd.Events)
	}

	upd2, err := svc.UpdateEndpoint(ctx, tenantID, res.Endpoint.ID,
		"", nil, repository.WebhookEndpointStatusDisabled, &actor)
	if err != nil {
		t.Fatalf("update status: %v", err)
	}
	if upd2.Status != repository.WebhookEndpointStatusDisabled {
		t.Errorf("status not updated: %v", upd2.Status)
	}
	if upd2.URL != "https://b.example/hook" {
		t.Errorf("URL lost on status-only update: %s", upd2.URL)
	}
}

func TestUpdateEndpoint_RejectsInvalidStatus(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, actor := newSvc(t)
	ctx := context.Background()
	res, err := svc.CreateEndpoint(ctx, tenantID, "https://a.example/hook",
		[]string{"tenant.created"}, &actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_, err = svc.UpdateEndpoint(ctx, tenantID, res.Endpoint.ID,
		"", nil, "not-a-status", &actor)
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestDeleteEndpoint_RemovesAndAudits(t *testing.T) {
	t.Parallel()
	svc, store, tenantID, actor := newSvc(t)
	ctx := context.Background()
	res, err := svc.CreateEndpoint(ctx, tenantID, "https://a.example/hook",
		[]string{"tenant.created"}, &actor)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.DeleteEndpoint(ctx, tenantID, res.Endpoint.ID, &actor); err != nil {
		t.Fatalf("delete: %v", err)
	}
	_, err = svc.GetEndpoint(ctx, tenantID, res.Endpoint.ID)
	if !errors.Is(err, repository.ErrNotFound) {
		t.Errorf("Get after delete err = %v, want ErrNotFound", err)
	}
	// Audit log contains both create and delete entries scoped to this tenant.
	audit := memory.NewAuditLogRepository(store)
	log, err := audit.List(ctx, tenantID, repository.AuditFilter{}, repository.Page{Limit: 50})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	actions := make([]string, 0, len(log.Items))
	for _, e := range log.Items {
		actions = append(actions, e.Action)
	}
	sort.Strings(actions)
	if len(actions) != 2 || actions[0] != "webhook.endpoint_created" || actions[1] != "webhook.endpoint_deleted" {
		t.Errorf("audit actions = %v", actions)
	}
}

func TestListEndpoints_TenantScoping(t *testing.T) {
	t.Parallel()
	svc, store, tenantA, actor := newSvc(t)
	ctx := context.Background()
	// Second tenant
	tenants := memory.NewTenantRepository(store)
	tnB, err := tenants.Create(ctx, repository.Tenant{
		Name: "Other", Slug: "other",
		Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tnB: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.CreateEndpoint(ctx, tenantA, "https://a.example/hook",
			[]string{"tenant.created"}, &actor); err != nil {
			t.Fatalf("create A: %v", err)
		}
	}
	if _, err := svc.CreateEndpoint(ctx, tnB.ID, "https://b.example/hook",
		[]string{"tenant.created"}, nil); err != nil {
		t.Fatalf("create B: %v", err)
	}
	page, err := svc.ListEndpoints(ctx, tenantA, repository.Page{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(page.Items) != 3 {
		t.Errorf("tenant A got %d, want 3", len(page.Items))
	}
	for _, ep := range page.Items {
		if ep.TenantID != tenantA {
			t.Errorf("cross-tenant leak: %v", ep.TenantID)
		}
	}
}

func TestEnqueue_FansOutToMatchingActiveOnly(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, actor := newSvc(t)
	ctx := context.Background()

	// 1 active matching, 1 active non-matching, 1 disabled matching.
	matching, err := svc.CreateEndpoint(ctx, tenantID, "https://yes.example/hook",
		[]string{"tenant.created"}, &actor)
	if err != nil {
		t.Fatalf("create matching: %v", err)
	}
	if _, err := svc.CreateEndpoint(ctx, tenantID, "https://other.example/hook",
		[]string{"site.updated"}, &actor); err != nil {
		t.Fatalf("create non-matching: %v", err)
	}
	disabled, err := svc.CreateEndpoint(ctx, tenantID, "https://off.example/hook",
		[]string{"tenant.created"}, &actor)
	if err != nil {
		t.Fatalf("create disabled: %v", err)
	}
	if _, err := svc.UpdateEndpoint(ctx, tenantID, disabled.Endpoint.ID,
		"", nil, repository.WebhookEndpointStatusDisabled, &actor); err != nil {
		t.Fatalf("disable: %v", err)
	}

	got, err := svc.Enqueue(ctx, tenantID, "tenant.created", json.RawMessage(`{"x":1}`))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("created deliveries = %d, want 1", len(got))
	}
	if got[0].EndpointID != matching.Endpoint.ID {
		t.Errorf("delivery for endpoint %v, want %v", got[0].EndpointID, matching.Endpoint.ID)
	}
	if got[0].Status != repository.WebhookDeliveryStatusPending {
		t.Errorf("status = %v", got[0].Status)
	}
}

func TestEnqueue_NoActiveSubscribersReturnsEmpty(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, _ := newSvc(t)
	got, err := svc.Enqueue(context.Background(), tenantID,
		"tenant.created", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("deliveries = %d, want 0", len(got))
	}
}

func TestEnqueue_DefaultsEmptyPayloadToEmptyObject(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, actor := newSvc(t)
	ctx := context.Background()
	if _, err := svc.CreateEndpoint(ctx, tenantID, "https://a.example/hook",
		[]string{"tenant.created"}, &actor); err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := svc.Enqueue(ctx, tenantID, "tenant.created", nil)
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("deliveries = %d", len(got))
	}
	if string(got[0].Payload) != "{}" {
		t.Errorf("payload = %q, want {}", string(got[0].Payload))
	}
}

func TestEnqueue_RejectsInvalidJSONPayload(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, _ := newSvc(t)
	_, err := svc.Enqueue(context.Background(), tenantID, "tenant.created",
		json.RawMessage(`{bad json`))
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestEnqueue_RejectsEmptyEventType(t *testing.T) {
	t.Parallel()
	svc, _, tenantID, _ := newSvc(t)
	_, err := svc.Enqueue(context.Background(), tenantID, "", json.RawMessage(`{}`))
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
}
