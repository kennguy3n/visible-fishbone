package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// CASBHandler exposes the CASB discovery REST surface: connector
// CRUD, test/sync triggers, discovered-apps listing, and posture
// reports.
type CASBHandler struct {
	svc *casb.Service
}

// NewCASBHandler wires the handler.
func NewCASBHandler(svc *casb.Service) *CASBHandler {
	return &CASBHandler{svc: svc}
}

// Register attaches routes.
func (h *CASBHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/connectors", h.listConnectors)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/casb/connectors", h.createConnector)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/connectors/{id}", h.getConnector)
	MountTenantScoped(mux, "PATCH /api/v1/tenants/{tenant_id}/casb/connectors/{id}", h.updateConnector)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/casb/connectors/{id}", h.deleteConnector)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/casb/connectors/{id}/test", h.testConnector)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/casb/connectors/{id}/sync", h.syncConnector)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/apps", h.listApps)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/apps/{app_id}/posture", h.getPosture)
}

// --- JSON request/response projections ---

type casbConnectorCreateRequest struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config,omitempty"`
	Secret json.RawMessage `json:"secret,omitempty"`
}

type casbConnectorUpdateRequest struct {
	Name   string          `json:"name,omitempty"`
	Config json.RawMessage `json:"config,omitempty"`
	Secret json.RawMessage `json:"secret,omitempty"`
	Status string          `json:"status,omitempty"`
}

type casbConnectorResponse struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	Type       string          `json:"type"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	Config     json.RawMessage `json:"config,omitempty"`
	SecretSet  bool            `json:"secret_set"`
	LastSyncAt *string         `json:"last_sync_at,omitempty"`
	CreatedAt  string          `json:"created_at"`
	UpdatedAt  string          `json:"updated_at"`
}

func toCASBConnectorResponse(c repository.CASBConnector) casbConnectorResponse {
	r := casbConnectorResponse{
		ID:        c.ID.String(),
		TenantID:  c.TenantID.String(),
		Type:      string(c.Type),
		Name:      c.Name,
		Status:    string(c.Status),
		Config:    c.Config,
		SecretSet: isSecretSet(c.Secret),
		CreatedAt: c.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: c.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if c.LastSyncAt != nil {
		s := c.LastSyncAt.Format("2006-01-02T15:04:05Z")
		r.LastSyncAt = &s
	}
	return r
}

type casbAppResponse struct {
	ID         string `json:"id"`
	TenantID   string `json:"tenant_id"`
	Name       string `json:"name"`
	Vendor     string `json:"vendor"`
	Category   string `json:"category"`
	RiskScore  int    `json:"risk_score"`
	UsersCount int    `json:"users_count"`
	FirstSeen  string `json:"first_seen"`
	LastSeen   string `json:"last_seen"`
}

func toCASBAppResponse(a repository.CASBDiscoveredApp) casbAppResponse {
	return casbAppResponse{
		ID:         a.ID.String(),
		TenantID:   a.TenantID.String(),
		Name:       a.Name,
		Vendor:     a.Vendor,
		Category:   a.Category,
		RiskScore:  a.RiskScore,
		UsersCount: a.UsersCount,
		FirstSeen:  a.FirstSeen.Format("2006-01-02T15:04:05Z"),
		LastSeen:   a.LastSeen.Format("2006-01-02T15:04:05Z"),
	}
}

// --- handlers ---

func (h *CASBHandler) listConnectors(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("cursor"),
	}
	result, err := h.svc.ListConnectors(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := struct {
		Items      []casbConnectorResponse `json:"items"`
		NextCursor string                  `json:"next_cursor,omitempty"`
	}{
		Items:      make([]casbConnectorResponse, 0, len(result.Items)),
		NextCursor: result.NextCursor,
	}
	for _, c := range result.Items {
		out.Items = append(out.Items, toCASBConnectorResponse(c))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (h *CASBHandler) createConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req casbConnectorCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Type == "" || req.Name == "" {
		WriteError(w, http.StatusBadRequest, "invalid_body", "type and name are required")
		return
	}
	created, err := h.svc.CreateConnector(r.Context(), tenantID, casb.CreateConnectorInput{
		Type:   repository.CASBConnectorType(req.Type),
		Name:   req.Name,
		Config: req.Config,
		Secret: req.Secret,
	}, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toCASBConnectorResponse(created))
}

func (h *CASBHandler) getConnector(w http.ResponseWriter, r *http.Request) {
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
	WriteJSON(w, http.StatusOK, toCASBConnectorResponse(c))
}

func (h *CASBHandler) updateConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req casbConnectorUpdateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	input := casb.UpdateConnectorInput{
		Name:   req.Name,
		Config: req.Config,
		Secret: req.Secret,
	}
	if req.Status != "" {
		s := repository.CASBConnectorStatus(req.Status)
		input.Status = &s
	}
	updated, err := h.svc.UpdateConnector(r.Context(), tenantID, id, input, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toCASBConnectorResponse(updated))
}

func (h *CASBHandler) deleteConnector(w http.ResponseWriter, r *http.Request) {
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

func (h *CASBHandler) testConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.TestConnector(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
			WriteRepositoryError(w, err)
			return
		}
		WriteError(w, http.StatusBadGateway, "connector_test_failed", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *CASBHandler) syncConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.SyncConnector(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
			WriteRepositoryError(w, err)
			return
		}
		WriteError(w, http.StatusBadGateway, "sync_failed", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "synced"})
}

func (h *CASBHandler) listApps(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	apps, err := h.svc.DiscoverSaaSApps(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]casbAppResponse, 0, len(apps))
	for _, a := range apps {
		items = append(items, toCASBAppResponse(a))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *CASBHandler) getPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	appID, ok := PathUUID(w, r, "app_id")
	if !ok {
		return
	}
	report, err := h.svc.GetSaaSPosture(r.Context(), tenantID, appID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, report)
}
