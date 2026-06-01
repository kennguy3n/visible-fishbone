// Package handler — integration.go owns the REST surface for
// integration connectors (syslog / SIEM webhook / Jira /
// ServiceNow) and their delivery audit trail.
//
// Shape mirrors webhook.go on purpose: the operator mental model
// is "webhooks are URL destinations, integrations are typed
// destinations" and the two pipes share the same Enqueue +
// DeliveryWorker lifecycle. Keeping the REST shape symmetric
// (POST / list / get / patch / delete + nested deliveries) means
// an operator who knows one pipe already knows the other.
//
// Wire-format invariants:
//   - The connector Secret is NEVER returned in JSON responses.
//     The Service stores it; the worker reads it; clients see only
//     a `secret_set` boolean indicating presence. This matches the
//     webhook signing-secret contract.
//   - List endpoints are cursor paginated via `?cursor=&limit=`.
//   - The Test endpoint synchronously invokes the connector's
//     Test() probe and returns the updated row (so the operator
//     portal can render last_test_at + last_test_result + error
//     in one round-trip). A failed probe still mutates the row
//     (so the failure is audited) and surfaces as HTTP 502 with
//     the typed error message.
package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/integration"
)

// IntegrationHandler exposes the integration connector CRUD +
// test + deliveries endpoints.
type IntegrationHandler struct {
	svc *integration.Service
}

// NewIntegrationHandler wires the handler.
func NewIntegrationHandler(svc *integration.Service) *IntegrationHandler {
	return &IntegrationHandler{svc: svc}
}

// Register attaches routes.
func (h *IntegrationHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/integrations", h.create)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/integrations", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/integrations/{id}", h.get)
	MountTenantScoped(mux, "PATCH /api/v1/tenants/{tenant_id}/integrations/{id}", h.update)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/integrations/{id}", h.delete)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/integrations/{id}/test", h.test)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/integrations/{id}/status", h.setStatus)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/integrations/{id}/deliveries", h.listDeliveries)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/integration-deliveries", h.listAllDeliveries)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/integration-deliveries/{id}", h.getDelivery)
}

// IntegrationConnectorRequest is the JSON body for POST/PATCH.
//
// POST: Type + Name are required, Config defaults to `{}` if
// omitted (the plugin's Validate() is what enforces a real
// shape).
//
// PATCH: every field is optional; omitting EventTypes leaves the
// existing slice untouched (mirrors the Service contract — a nil
// slice means "no change", an empty `[]` means "match
// everything"). Description follows the same rule as the Service
// layer: blank means no change, so clearing requires admin path
// (delete+recreate) for now — by design.
type IntegrationConnectorRequest struct {
	Type        string          `json:"type,omitempty"`
	Name        string          `json:"name,omitempty"`
	Description string          `json:"description,omitempty"`
	EventTypes  []string        `json:"event_types,omitempty"`
	Config      json.RawMessage `json:"config,omitempty"`
	Secret      json.RawMessage `json:"secret,omitempty"`
}

// IntegrationConnectorResponse is the JSON projection of a
// connector. SecretSet is the only signal clients get about the
// secret: presence is observable, contents are not. Mirrors the
// webhook endpoint shape (which has the same secret-on-create-
// only invariant).
type IntegrationConnectorResponse struct {
	ID             string   `json:"id"`
	TenantID       string   `json:"tenant_id"`
	Type           string   `json:"type"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	EventTypes     []string `json:"event_types"`
	Config         any      `json:"config,omitempty"`
	SecretSet      bool     `json:"secret_set"`
	Status         string   `json:"status"`
	LastTestResult string   `json:"last_test_result"`
	LastTestAt     string   `json:"last_test_at,omitempty"`
	LastTestError  string   `json:"last_test_error,omitempty"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

func toIntegrationConnectorResponse(c repository.IntegrationConnector) IntegrationConnectorResponse {
	resp := IntegrationConnectorResponse{
		ID:          c.ID.String(),
		TenantID:    c.TenantID.String(),
		Type:        string(c.Type),
		Name:        c.Name,
		Description: c.Description,
		// Force a non-nil slice so the JSON wire-form is always
		// `[]` for a connector with no event filter — EventTypes
		// is `required` in the OpenAPI schema and a JSON `null`
		// would violate the contract for spec-compliant clients.
		EventTypes:     append(make([]string, 0, len(c.EventTypes)), c.EventTypes...),
		SecretSet:      len(c.Secret) > 0,
		Status:         string(c.Status),
		LastTestResult: string(c.LastTestResult),
		LastTestError:  c.LastTestError,
		CreatedAt:      c.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:      c.UpdatedAt.Format(time.RFC3339Nano),
	}
	if c.LastTestAt != nil {
		resp.LastTestAt = c.LastTestAt.Format(time.RFC3339Nano)
	}
	if len(c.Config) > 0 {
		// Decode Config back into a structured field so the
		// operator portal can render typed forms; an invalid
		// blob falls back to the raw bytes as a JSON string so
		// nothing observably breaks.
		var v any
		if err := json.Unmarshal(c.Config, &v); err == nil {
			resp.Config = v
		} else {
			resp.Config = json.RawMessage(c.Config)
		}
	}
	return resp
}

// IntegrationDeliveryResponse is the JSON projection of a
// delivery row. ResponseStatus is omitted when zero — a zero
// would falsely imply HTTP 0 (no response received) for syslog
// which has no HTTP layer at all.
type IntegrationDeliveryResponse struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	ConnectorID       string `json:"connector_id"`
	EventType         string `json:"event_type"`
	Status            string `json:"status"`
	Attempts          int    `json:"attempts"`
	LastAttemptAt     string `json:"last_attempt_at,omitempty"`
	LastError         string `json:"last_error,omitempty"`
	NextRetryAt       string `json:"next_retry_at"`
	ResponseStatus    int    `json:"response_status,omitempty"`
	ExternalReference string `json:"external_reference,omitempty"`
	CreatedAt         string `json:"created_at"`
}

func toIntegrationDeliveryResponse(d repository.IntegrationDelivery) IntegrationDeliveryResponse {
	resp := IntegrationDeliveryResponse{
		ID:                d.ID.String(),
		TenantID:          d.TenantID.String(),
		ConnectorID:       d.ConnectorID.String(),
		EventType:         d.EventType,
		Status:            string(d.Status),
		Attempts:          d.Attempts,
		LastError:         d.LastError,
		NextRetryAt:       d.NextRetryAt.Format(time.RFC3339Nano),
		ResponseStatus:    d.ResponseStatus,
		ExternalReference: d.ExternalReference,
		CreatedAt:         d.CreatedAt.Format(time.RFC3339Nano),
	}
	if d.LastAttemptAt != nil {
		resp.LastAttemptAt = d.LastAttemptAt.Format(time.RFC3339Nano)
	}
	return resp
}

func (h *IntegrationHandler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req IntegrationConnectorRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	kind := repository.IntegrationConnectorType(req.Type)
	if !kind.IsValid() {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"type must be one of: syslog, siem_webhook, jira, servicenow")
		return
	}
	if !h.svc.SupportsKind(kind) {
		WriteError(w, http.StatusBadRequest, "unsupported_connector",
			"connector kind not registered in this deployment: "+string(kind))
		return
	}
	created, err := h.svc.CreateConnector(r.Context(), tenantID, integration.CreateConnectorInput{
		Type:        kind,
		Name:        req.Name,
		Description: req.Description,
		EventTypes:  req.EventTypes,
		Config:      req.Config,
		Secret:      req.Secret,
	}, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toIntegrationConnectorResponse(created))
}

func (h *IntegrationHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("cursor"),
	}
	res, err := h.svc.ListConnectors(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]IntegrationConnectorResponse, 0, len(res.Items))
	for _, c := range res.Items {
		items = append(items, toIntegrationConnectorResponse(c))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *IntegrationHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	c, err := h.svc.GetConnector(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toIntegrationConnectorResponse(c))
}

func (h *IntegrationHandler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req IntegrationConnectorRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	updated, err := h.svc.UpdateConnector(r.Context(), tenantID, id, integration.UpdateConnectorInput{
		Name:        req.Name,
		Description: req.Description,
		EventTypes:  req.EventTypes,
		Config:      req.Config,
		Secret:      req.Secret,
	}, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toIntegrationConnectorResponse(updated))
}

func (h *IntegrationHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteConnector(r.Context(), tenantID, id, actorFromCtx(r)); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// integrationStatusRequest is the body for POST /integrations/{id}/status —
// keep separate from IntegrationConnectorRequest so the
// payload contract for "set status" is small and obvious.
type integrationStatusRequest struct {
	Status string `json:"status"`
}

func (h *IntegrationHandler) setStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req integrationStatusRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	status := repository.IntegrationConnectorStatus(req.Status)
	switch status {
	case repository.IntegrationConnectorStatusActive,
		repository.IntegrationConnectorStatusDisabled:
	default:
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"status must be 'active' or 'disabled'")
		return
	}
	updated, err := h.svc.SetConnectorStatus(r.Context(), tenantID, id, status, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toIntegrationConnectorResponse(updated))
}

func (h *IntegrationHandler) test(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	updated, err := h.svc.TestConnector(r.Context(), tenantID, id, actorFromCtx(r))
	if err != nil {
		// TestConnector surfaces the probe error wrapped, after
		// successfully recording the failure on the row. We
		// return the updated row alongside a 502 so the operator
		// portal can show "we tried, here's what we recorded".
		// Non-probe errors (row not found, repo failure to record
		// the result) follow the standard repository->HTTP map.
		if updated.ID != uuid.Nil {
			WriteJSON(w, http.StatusBadGateway, map[string]any{
				"connector": toIntegrationConnectorResponse(updated),
				"error": map[string]string{
					"code":    "connector_test_failed",
					"message": err.Error(),
				},
			})
			return
		}
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toIntegrationConnectorResponse(updated))
}

func (h *IntegrationHandler) listDeliveries(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	connectorID, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("cursor"),
	}
	res, err := h.svc.ListDeliveries(r.Context(), tenantID, &connectorID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]IntegrationDeliveryResponse, 0, len(res.Items))
	for _, d := range res.Items {
		items = append(items, toIntegrationDeliveryResponse(d))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *IntegrationHandler) listAllDeliveries(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var connectorPtr *uuid.UUID
	if v := r.URL.Query().Get("connector_id"); v != "" {
		parsed, err := uuid.Parse(v)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_param", "connector_id is not a valid UUID")
			return
		}
		connectorPtr = &parsed
	}
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("cursor"),
	}
	res, err := h.svc.ListDeliveries(r.Context(), tenantID, connectorPtr, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]IntegrationDeliveryResponse, 0, len(res.Items))
	for _, d := range res.Items {
		items = append(items, toIntegrationDeliveryResponse(d))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *IntegrationHandler) getDelivery(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	d, err := h.svc.GetDelivery(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toIntegrationDeliveryResponse(d))
}
