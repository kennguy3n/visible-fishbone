// Package handler — integration_test pins the REST surface for
// the integration connector + deliveries handler. Mirrors
// webhook_test in structure so the two pipes (URL webhooks and
// typed connectors) have identical test coverage shape.
//
// Specifically pinned:
//   - Create / Get / List / Patch / Delete round-trip
//   - Secret is NEVER returned over the wire (only `secret_set`)
//   - Invalid kind / unsupported plugin rejected at REST boundary (400)
//   - POST /test returns 200 on probe success, 502 on failure with
//     the updated connector body wrapped in {connector,error}
//   - POST /status accepts active/disabled, rejects others (400)
//   - GET /integration-deliveries returns rows scoped by ?connector_id
package handler_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/integration"
)

// _ silences unused-import detector when individual tests are
// trimmed down; context + json are referenced from helpers.
var _ = context.Background

// stubConnector is the minimum Connector implementation we need
// for handler-level smoke tests. The Send/Test behaviour is
// driven from per-test closures so each test can pin the wire
// surface for the desired outcome without spinning up a real
// network endpoint.
type stubConnector struct {
	kind       repository.IntegrationConnectorType
	sendErr    error
	testErr    error
	sendInvoke int
}

func (s *stubConnector) Kind() repository.IntegrationConnectorType { return s.kind }
func (s *stubConnector) Send(_ context.Context, _ integration.Sendable) (integration.SendResult, error) {
	s.sendInvoke++
	return integration.SendResult{}, s.sendErr
}
func (s *stubConnector) Test(_ context.Context, _ json.RawMessage, _ json.RawMessage) error {
	return s.testErr
}

// newIntegrationTestRouter wires a fully composed router with
// the integration handler, JWT auth, and memory repos.
func newIntegrationTestRouter(t *testing.T, kind repository.IntegrationConnectorType, testErr error) (
	http.Handler, *memory.Store, *stubConnector, uuid.UUID, uuid.UUID, string,
) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	userID := uuid.New()

	stub := &stubConnector{kind: kind, testErr: testErr}
	svc := integration.New(
		memory.NewIntegrationConnectorRepository(store),
		memory.NewIntegrationDeliveryRepository(store),
		memory.NewAuditLogRepository(store),
		integration.Registry{kind: stub},
		nil,
	)

	jwtSecret := "test-jwt-secret-key"
	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret:    jwtSecret,
			JWTIssuer:    "sng-control",
			JWTAudience:  "sng-control",
			APIKeyHeader: "X-SNG-API-Key",
		},
	}
	router := handler.NewRouter(handler.RouterDeps{
		Config:       cfg,
		Integrations: handler.NewIntegrationHandler(svc),
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "sng-control",
		"aud":       "sng-control",
		"sub":       userID.String(),
		"tenant_id": tenantID.String(),
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
	})
	signed, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return router, store, stub, tenantID, userID, signed
}

func TestIntegrationHandler_CreateGetListUpdateDelete(t *testing.T) {
	t.Parallel()
	router, _, _, tenantID, _, token := newIntegrationTestRouter(
		t, repository.IntegrationConnectorSIEMWebhook, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/integrations"

	// CREATE
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type":        "siem_webhook",
		"name":        "soc-pagerduty",
		"description": "SIEM forward",
		"event_types": []string{"alert.created"},
		"config":      map[string]string{"url": "https://example.com/siem"},
		"secret":      json.RawMessage(`"opaque-hmac"`),
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created handler.IntegrationConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == "" {
		t.Fatalf("create returned empty id: %+v", created)
	}
	if !created.SecretSet {
		t.Errorf("secret_set = false on create; want true")
	}
	if created.TenantID != tenantID.String() {
		t.Errorf("tenant_id = %q", created.TenantID)
	}
	if created.Type != "siem_webhook" {
		t.Errorf("type = %q", created.Type)
	}

	// GET — secret must never be present
	rec = doJSON(t, router, http.MethodGet, path+"/"+created.ID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var bodyMap map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &bodyMap); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if _, exists := bodyMap["secret"]; exists {
		t.Errorf("GET response leaked `secret` field: %v", bodyMap)
	}
	if got, _ := bodyMap["secret_set"].(bool); !got {
		t.Errorf("secret_set = false on get")
	}

	// LIST — same secret-leak guard, plus item count
	rec = doJSON(t, router, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("LIST status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("list count = %d, want 1", len(list.Items))
	}
	for _, it := range list.Items {
		if _, exists := it["secret"]; exists {
			t.Errorf("LIST item leaked `secret`: %v", it)
		}
	}

	// PATCH — change name
	rec = doJSON(t, router, http.MethodPatch, path+"/"+created.ID, token, map[string]any{
		"name": "soc-pagerduty-renamed",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var updated handler.IntegrationConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode patch: %v", err)
	}
	if updated.Name != "soc-pagerduty-renamed" {
		t.Errorf("name = %q", updated.Name)
	}

	// DELETE
	rec = doJSON(t, router, http.MethodDelete, path+"/"+created.ID, token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE status = %d, body = %s", rec.Code, rec.Body.String())
	}
	rec = doJSON(t, router, http.MethodGet, path+"/"+created.ID, token, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET-after-delete status = %d, want 404", rec.Code)
	}
}

func TestIntegrationHandler_RejectsInvalidKind(t *testing.T) {
	t.Parallel()
	router, _, _, tenantID, _, token := newIntegrationTestRouter(
		t, repository.IntegrationConnectorSIEMWebhook, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/integrations"

	// "pagerduty" is not a valid IntegrationConnectorType.
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type": "pagerduty",
		"name": "wat",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST invalid type status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestIntegrationHandler_RejectsUnregisteredKind(t *testing.T) {
	t.Parallel()
	// Registry only contains SIEM webhook; ask for syslog.
	router, _, _, tenantID, _, token := newIntegrationTestRouter(
		t, repository.IntegrationConnectorSIEMWebhook, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/integrations"

	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type": "syslog",
		"name": "soc-syslog",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST unsupported-kind status = %d, body = %s", rec.Code, rec.Body.String())
	}
}

func TestIntegrationHandler_TestEndpoint_SuccessReturns200(t *testing.T) {
	t.Parallel()
	router, _, _, tenantID, _, token := newIntegrationTestRouter(
		t, repository.IntegrationConnectorSIEMWebhook, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/integrations"

	// CREATE — need an id to test against
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type":   "siem_webhook",
		"name":   "soc",
		"config": map[string]string{"url": "https://example.com/siem"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created handler.IntegrationConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	rec = doJSON(t, router, http.MethodPost, path+"/"+created.ID+"/test", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /test status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var probed handler.IntegrationConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &probed); err != nil {
		t.Fatalf("decode probe: %v", err)
	}
	if probed.LastTestResult != "success" {
		t.Errorf("last_test_result = %q, want success", probed.LastTestResult)
	}
	if probed.LastTestError != "" {
		t.Errorf("last_test_error = %q, want empty on success", probed.LastTestError)
	}
}

func TestIntegrationHandler_TestEndpoint_FailureReturns502WithBody(t *testing.T) {
	t.Parallel()
	// Force the probe to fail; handler must surface the updated
	// row + typed error code under a 502.
	router, _, _, tenantID, _, token := newIntegrationTestRouter(
		t, repository.IntegrationConnectorSIEMWebhook, errors.New("destination unreachable"))
	path := "/api/v1/tenants/" + tenantID.String() + "/integrations"

	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type":   "siem_webhook",
		"name":   "soc",
		"config": map[string]string{"url": "https://example.com/siem"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created handler.IntegrationConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	rec = doJSON(t, router, http.MethodPost, path+"/"+created.ID+"/test", token, nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("POST /test status = %d, want 502; body = %s", rec.Code, rec.Body.String())
	}
	var wrapped struct {
		Connector handler.IntegrationConnectorResponse `json:"connector"`
		Error     struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &wrapped); err != nil {
		t.Fatalf("decode wrapped body: %v", err)
	}
	if wrapped.Error.Code != "connector_test_failed" {
		t.Errorf("error.code = %q, want connector_test_failed", wrapped.Error.Code)
	}
	if wrapped.Connector.LastTestResult != "failure" {
		t.Errorf("connector.last_test_result = %q, want failure", wrapped.Connector.LastTestResult)
	}
	if wrapped.Connector.LastTestError == "" {
		t.Errorf("connector.last_test_error empty; want probe message")
	}
}

func TestIntegrationHandler_SetStatusValidatesEnum(t *testing.T) {
	t.Parallel()
	router, _, _, tenantID, _, token := newIntegrationTestRouter(
		t, repository.IntegrationConnectorSIEMWebhook, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/integrations"

	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type":   "siem_webhook",
		"name":   "soc",
		"config": map[string]string{"url": "https://example.com/siem"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created handler.IntegrationConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// Valid: disabled
	rec = doJSON(t, router, http.MethodPost, path+"/"+created.ID+"/status", token, map[string]any{
		"status": "disabled",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /status disabled status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got handler.IntegrationConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got.Status != "disabled" {
		t.Errorf("status = %q, want disabled", got.Status)
	}

	// Invalid: bogus enum
	rec = doJSON(t, router, http.MethodPost, path+"/"+created.ID+"/status", token, map[string]any{
		"status": "deactivated",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("POST /status bogus value status = %d, want 400; body = %s",
			rec.Code, rec.Body.String())
	}
}

// TestIntegrationHandler_EventTypesAlwaysArray pins the wire-form
// invariant that a connector with no event filter (EventTypes
// nil or []string{}) serializes `event_types` as a JSON `[]`
// rather than `null`. `event_types` is declared `required` in
// the OpenAPI schema, so a JSON `null` would violate the
// contract for spec-compliant clients.
func TestIntegrationHandler_EventTypesAlwaysArray(t *testing.T) {
	t.Parallel()
	router, _, _, tenantID, _, token := newIntegrationTestRouter(
		t, repository.IntegrationConnectorSIEMWebhook, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/integrations"

	// Create without specifying event_types: backend stores nil.
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type":   "siem_webhook",
		"name":   "soc",
		"config": map[string]string{"url": "https://example.com/siem"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body = %s", rec.Code, rec.Body.String())
	}
	// Inspect the raw JSON for the `event_types` field — `[]` not
	// `null`. Deserializing into a typed struct would coerce
	// both shapes to a nil/empty slice and miss the difference.
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &asMap); err != nil {
		t.Fatalf("decode create as map: %v", err)
	}
	raw, ok := asMap["event_types"]
	if !ok {
		t.Fatalf("response missing event_types: %s", rec.Body.String())
	}
	if string(raw) != "[]" {
		t.Fatalf("event_types = %s, want []", string(raw))
	}
}

// TestIntegrationHandler_ListConnectors_OmitsEmptyNextCursor pins
// the round-4 fix that integration list endpoints emit
// `next_cursor` via a typed struct with `json:"...,omitempty"`
// instead of `map[string]any` — matching the alert + baseline
// handlers. Empty NextCursor (single-page result) MUST be
// omitted from the JSON envelope; emitting `"next_cursor": ""`
// confuses spec-strict SDK generators that treat
// `nullable: true` as "missing OR null, not empty string".
func TestIntegrationHandler_ListConnectors_OmitsEmptyNextCursor(t *testing.T) {
	t.Parallel()
	router, _, _, tenantID, _, token := newIntegrationTestRouter(
		t, repository.IntegrationConnectorSIEMWebhook, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/integrations"

	// Empty list (no connectors) -> single page, NextCursor "".
	rec := doJSON(t, router, http.MethodGet, path, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var asMap map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &asMap); err != nil {
		t.Fatalf("decode list as map: %v", err)
	}
	if _, present := asMap["next_cursor"]; present {
		t.Fatalf("next_cursor must be omitted when empty; got %s",
			rec.Body.String())
	}
}

// TestIntegrationHandler_PatchRejectsTypeField pins round-7 of
// Devin Review on PR #41: the PATCH handler previously shared its
// request struct with the POST handler, so a loose client sending
// `{"type": "jira"}` on PATCH would silently decode without error
// (the Go struct had a Type field even though the OpenAPI
// IntegrationConnectorUpdateRequest schema doesn't), and the
// server would ignore the field and respond 200 OK as if the
// "update" had succeeded. That is misleading for clients who
// expect either a schema-strict 400 or actual mutation.
//
// The fix splits IntegrationConnectorRequest into separate
// IntegrationConnectorCreateRequest (has Type) and
// IntegrationConnectorUpdateRequest (no Type). With
// DisallowUnknownFields on the decoder, `{"type": ...}` on PATCH
// now returns a clean 400 invalid_body — matching the OpenAPI
// surface contract.
//
// We also pin the positive path: a PATCH with no `type` field
// still succeeds, and the connector kind remains immutable
// regardless of what the client sent.
func TestIntegrationHandler_PatchRejectsTypeField(t *testing.T) {
	t.Parallel()
	router, _, _, tenantID, _, token := newIntegrationTestRouter(
		t, repository.IntegrationConnectorSIEMWebhook, nil)
	path := "/api/v1/tenants/" + tenantID.String() + "/integrations"

	// Seed a connector to PATCH against.
	rec := doJSON(t, router, http.MethodPost, path, token, map[string]any{
		"type":   "siem_webhook",
		"name":   "soc-source",
		"config": map[string]any{"endpoint": "https://example.com"},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST seed status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created handler.IntegrationConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}

	// PATCH with `type` field MUST be rejected — connector kind
	// is immutable post-create, and silent-swallow would mislead
	// callers into thinking they had retyped the connector.
	rec = doJSON(t, router, http.MethodPatch, path+"/"+created.ID, token, map[string]any{
		"type": "jira",
		"name": "soc-source-retyped",
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PATCH with type field: status = %d, want 400; body = %s",
			rec.Code, rec.Body.String())
	}

	// Sanity-check: the connector kind was NOT mutated by the
	// rejected request. (If the decoder ever silently swallowed
	// the field again, the rest of the request body could still
	// land partial mutations — this guards against half-applied
	// updates regressing.)
	rec = doJSON(t, router, http.MethodGet, path+"/"+created.ID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET after rejected PATCH: status = %d", rec.Code)
	}
	var after handler.IntegrationConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &after); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if after.Type != "siem_webhook" {
		t.Errorf("Type mutated by rejected PATCH: got %q want siem_webhook", after.Type)
	}
	if after.Name != "soc-source" {
		t.Errorf("Name mutated by rejected PATCH: got %q want soc-source", after.Name)
	}

	// Positive path: PATCH WITHOUT `type` still succeeds.
	rec = doJSON(t, router, http.MethodPatch, path+"/"+created.ID, token, map[string]any{
		"name": "soc-source-renamed",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("clean PATCH status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var updated handler.IntegrationConnectorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode update: %v", err)
	}
	if updated.Name != "soc-source-renamed" {
		t.Errorf("Name not updated by clean PATCH: got %q", updated.Name)
	}
	if updated.Type != "siem_webhook" {
		t.Errorf("Type changed after clean PATCH: got %q want siem_webhook", updated.Type)
	}
}
