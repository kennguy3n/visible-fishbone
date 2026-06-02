package handler

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

// BulkEnrollHTTPRequest is the API body for bulk enrollment.
type BulkEnrollHTTPRequest struct {
	Count int    `json:"count"`
	TTL   string `json:"ttl,omitempty"`
}

// BulkRevokeHTTPRequest is the API body for bulk revocation.
type BulkRevokeHTTPRequest struct {
	DeviceIDs []uuid.UUID `json:"device_ids"`
}

// BulkDeviceHandler exposes REST endpoints for bulk device operations.
type BulkDeviceHandler struct {
	svc     *identity.BulkDeviceService
	devices repository.DeviceRepository
	logger  *slog.Logger
}

// NewBulkDeviceHandler returns a ready-to-use handler.
func NewBulkDeviceHandler(
	svc *identity.BulkDeviceService,
	devices repository.DeviceRepository,
	logger *slog.Logger,
) *BulkDeviceHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &BulkDeviceHandler{svc: svc, devices: devices, logger: logger}
}

// Register wires the handler routes onto the mux.
func (h *BulkDeviceHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/devices/bulk/enroll", h.bulkEnroll)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/devices/bulk/revoke", h.bulkRevoke)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/devices/import", h.importCSV)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/devices/export", h.exportCSV)
}

func (h *BulkDeviceHandler) bulkEnroll(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req BulkEnrollHTTPRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	ttl := 24 * time.Hour
	if req.TTL != "" {
		parsed, err := time.ParseDuration(req.TTL)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_argument", "invalid ttl duration")
			return
		}
		ttl = parsed
	}
	result, tokens, err := h.svc.BulkGenerateTokens(r.Context(), tenantID, req.Count, ttl)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	type tokenDTO struct {
		ID        uuid.UUID `json:"id"`
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	dtos := make([]tokenDTO, 0, len(tokens))
	for _, t := range tokens {
		dtos = append(dtos, tokenDTO{ID: t.Token.ID, Token: t.Plaintext, ExpiresAt: t.Token.ExpiresAt})
	}
	WriteJSON(w, http.StatusCreated, map[string]any{
		"result": result,
		"tokens": dtos,
	})
}

func (h *BulkDeviceHandler) bulkRevoke(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req BulkRevokeHTTPRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	result, err := h.svc.BulkRevoke(r.Context(), tenantID, req.DeviceIDs)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_argument", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, result)
}

func (h *BulkDeviceHandler) importCSV(w http.ResponseWriter, r *http.Request) {
	if _, ok := PathUUID(w, r, "tenant_id"); !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10 MB
	rows, err := h.svc.ImportCSV(r.Body)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"imported": len(rows),
		"rows":     rows,
	})
}

func (h *BulkDeviceHandler) exportCSV(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var all []repository.Device
	after := ""
	for {
		pg := repository.Page{Limit: repository.MaxPageLimit, After: after}
		result, err := h.devices.List(r.Context(), tenantID, repository.DeviceListFilter{}, pg)
		if err != nil {
			WriteRepositoryError(w, err)
			return
		}
		all = append(all, result.Items...)
		if result.NextCursor == "" || len(all) >= identity.MaxBulkDevices {
			break
		}
		after = result.NextCursor
	}
	data, err := h.svc.ExportCSV(r.Context(), tenantID, all)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=devices.csv")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
