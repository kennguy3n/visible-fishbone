package handler

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/service/terraform"
)

// TerraformHandler exposes the config export/import endpoints.
type TerraformHandler struct {
	provider *terraform.Provider
}

// NewTerraformHandler wires the handler.
func NewTerraformHandler(provider *terraform.Provider) *TerraformHandler {
	return &TerraformHandler{provider: provider}
}

// Register attaches routes.
func (h *TerraformHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/config/export", h.export)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/config/import", h.importConfig)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/config/drift", h.drift)
}

func (h *TerraformHandler) export(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	config, err := h.provider.ExportTenantConfig(r.Context(), tenantID)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "export_failed", "internal server error")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(config)
}

func (h *TerraformHandler) importConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_body", "failed to read body")
		return
	}
	if !json.Valid(body) {
		WriteError(w, http.StatusBadRequest, "invalid_json", "body is not valid JSON")
		return
	}
	if err := h.provider.ImportTenantConfig(r.Context(), tenantID, body); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "imported"})
}

func (h *TerraformHandler) drift(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_body", "failed to read body")
		return
	}
	if !json.Valid(body) {
		WriteError(w, http.StatusBadRequest, "invalid_json", "body is not valid JSON")
		return
	}
	report, err := h.provider.DetectDrift(r.Context(), tenantID, body)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "drift_failed", "internal server error")
		return
	}
	WriteJSON(w, http.StatusOK, report)
}
