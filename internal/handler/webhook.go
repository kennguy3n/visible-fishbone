package handler

import (
	"net/http"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/webhook"
)

// WebhookHandler exposes the webhook CRUD + delivery-list endpoints.
type WebhookHandler struct {
	svc *webhook.Service
}

// NewWebhookHandler wires the handler.
func NewWebhookHandler(svc *webhook.Service) *WebhookHandler {
	return &WebhookHandler{svc: svc}
}

// Register attaches routes.
func (h *WebhookHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/webhooks", h.create)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/webhooks", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/webhooks/{id}", h.get)
	MountTenantScoped(mux, "PATCH /api/v1/tenants/{tenant_id}/webhooks/{id}", h.update)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/webhooks/{id}", h.delete)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/webhooks/{id}/deliveries", h.listDeliveries)
}

// WebhookEndpointRequest is the JSON body for POST / PATCH.
type WebhookEndpointRequest struct {
	URL    string   `json:"url,omitempty"`
	Events []string `json:"events,omitempty"`
	Status string   `json:"status,omitempty"`
}

// WebhookEndpointResponse is the JSON projection of an endpoint.
type WebhookEndpointResponse struct {
	ID        string   `json:"id"`
	TenantID  string   `json:"tenant_id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Status    string   `json:"status"`
	Secret    string   `json:"secret,omitempty"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

func toEndpointResponse(ep repository.WebhookEndpoint, secret string) WebhookEndpointResponse {
	return WebhookEndpointResponse{
		ID:        ep.ID.String(),
		TenantID:  ep.TenantID.String(),
		URL:       ep.URL,
		Events:    ep.Events,
		Status:    string(ep.Status),
		Secret:    secret,
		CreatedAt: ep.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt: ep.UpdatedAt.Format(time.RFC3339Nano),
	}
}

// WebhookDeliveryResponse is the JSON projection of a delivery.
type WebhookDeliveryResponse struct {
	ID             string `json:"id"`
	TenantID       string `json:"tenant_id"`
	EndpointID     string `json:"endpoint_id"`
	EventType      string `json:"event_type"`
	Status         string `json:"status"`
	Attempts       int    `json:"attempts"`
	LastAttemptAt  string `json:"last_attempt_at,omitempty"`
	LastError      string `json:"last_error,omitempty"`
	NextRetryAt    string `json:"next_retry_at"`
	ResponseStatus int    `json:"response_status,omitempty"`
	CreatedAt      string `json:"created_at"`
}

func toDeliveryResponse(d repository.WebhookDelivery) WebhookDeliveryResponse {
	resp := WebhookDeliveryResponse{
		ID:             d.ID.String(),
		TenantID:       d.TenantID.String(),
		EndpointID:     d.EndpointID.String(),
		EventType:      d.EventType,
		Status:         string(d.Status),
		Attempts:       d.Attempts,
		LastError:      d.LastError,
		NextRetryAt:    d.NextRetryAt.Format(time.RFC3339Nano),
		ResponseStatus: d.ResponseStatus,
		CreatedAt:      d.CreatedAt.Format(time.RFC3339Nano),
	}
	if d.LastAttemptAt != nil {
		resp.LastAttemptAt = d.LastAttemptAt.Format(time.RFC3339Nano)
	}
	return resp
}

func (h *WebhookHandler) create(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req WebhookEndpointRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	actor := actorFromCtx(r)
	res, err := h.svc.CreateEndpoint(r.Context(), tenantID, req.URL, req.Events, actor)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toEndpointResponse(res.Endpoint, res.Secret))
}

func (h *WebhookHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		After: r.URL.Query().Get("after"),
		Limit: QueryLimit(r),
		Order: repository.SortOrder(r.URL.Query().Get("order")),
	}
	res, err := h.svc.ListEndpoints(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]WebhookEndpointResponse, 0, len(res.Items))
	for _, ep := range res.Items {
		items = append(items, toEndpointResponse(ep, ""))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *WebhookHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	ep, err := h.svc.GetEndpoint(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toEndpointResponse(ep, ""))
}

func (h *WebhookHandler) update(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req WebhookEndpointRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	actor := actorFromCtx(r)
	ep, err := h.svc.UpdateEndpoint(r.Context(), tenantID, id, req.URL, req.Events,
		repository.WebhookEndpointStatus(req.Status), actor)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toEndpointResponse(ep, ""))
}

func (h *WebhookHandler) delete(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	actor := actorFromCtx(r)
	if err := h.svc.DeleteEndpoint(r.Context(), tenantID, id, actor); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *WebhookHandler) listDeliveries(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	endpointID, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	page := repository.Page{
		After: r.URL.Query().Get("after"),
		Limit: QueryLimit(r),
		Order: repository.SortOrder(r.URL.Query().Get("order")),
	}
	res, err := h.svc.ListDeliveries(r.Context(), tenantID, &endpointID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]WebhookDeliveryResponse, 0, len(res.Items))
	for _, d := range res.Items {
		items = append(items, toDeliveryResponse(d))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}
