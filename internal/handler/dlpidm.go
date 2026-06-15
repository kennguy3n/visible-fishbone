// Package handler — dlpidm.go owns the REST surface for WP4 DLP
// OCR/IDM control-plane state: per-tenant protected-document
// fingerprint sets (Indexed Document Matching) and the OCR/IDM
// configuration + status.
//
// Endpoints (all tenant-scoped):
//
//	POST   /api/v1/tenants/{tenant_id}/dlp/idm/fingerprint-sets
//	GET    /api/v1/tenants/{tenant_id}/dlp/idm/fingerprint-sets
//	GET    /api/v1/tenants/{tenant_id}/dlp/idm/fingerprint-sets/{id}
//	PATCH  /api/v1/tenants/{tenant_id}/dlp/idm/fingerprint-sets/{id}
//	DELETE /api/v1/tenants/{tenant_id}/dlp/idm/fingerprint-sets/{id}
//	GET    /api/v1/tenants/{tenant_id}/dlp/ocr-idm/config
//	PUT    /api/v1/tenants/{tenant_id}/dlp/ocr-idm/config
//	GET    /api/v1/tenants/{tenant_id}/dlp/ocr-idm/status
//
// A fingerprint set is created by uploading the raw protected-document
// text in `content`; the server fingerprints it once and persists only
// the resulting hashes. Raw content and the fingerprint hashes
// themselves are never returned over this API — only metadata, counts,
// and configuration.
package handler

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpidm"
)

// DLPIDMHandler exposes the DLP OCR/IDM control-plane REST surface.
type DLPIDMHandler struct {
	svc *dlpidm.Service
}

// NewDLPIDMHandler wires the handler.
func NewDLPIDMHandler(svc *dlpidm.Service) *DLPIDMHandler {
	return &DLPIDMHandler{svc: svc}
}

// Register attaches DLP OCR/IDM routes.
func (h *DLPIDMHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dlp/idm/fingerprint-sets", h.createSet)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/idm/fingerprint-sets", h.listSets)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/idm/fingerprint-sets/{id}", h.getSet)
	MountTenantScoped(mux, "PATCH /api/v1/tenants/{tenant_id}/dlp/idm/fingerprint-sets/{id}", h.updateSet)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/dlp/idm/fingerprint-sets/{id}", h.deleteSet)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/ocr-idm/config", h.getConfig)
	MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/dlp/ocr-idm/config", h.putConfig)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/ocr-idm/status", h.status)
}

// --- wire types -----------------------------------------------------------

type idmFingerprintSetResponse struct {
	ID               uuid.UUID `json:"id"`
	TenantID         uuid.UUID `json:"tenant_id"`
	Name             string    `json:"name"`
	Description      string    `json:"description"`
	ShingleSize      int       `json:"shingle_size"`
	WindowSize       int       `json:"window_size"`
	MaxFingerprints  int       `json:"max_fingerprints"`
	FingerprintCount int       `json:"fingerprint_count"`
	SourceBytes      int64     `json:"source_bytes"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func toIDMFingerprintSetResponse(s repository.IDMFingerprintSet) idmFingerprintSetResponse {
	return idmFingerprintSetResponse{
		ID:               s.ID,
		TenantID:         s.TenantID,
		Name:             s.Name,
		Description:      s.Description,
		ShingleSize:      s.ShingleSize,
		WindowSize:       s.WindowSize,
		MaxFingerprints:  s.MaxFingerprints,
		FingerprintCount: len(s.Fingerprints),
		SourceBytes:      s.SourceBytes,
		CreatedAt:        s.CreatedAt,
		UpdatedAt:        s.UpdatedAt,
	}
}

type idmFingerprintSetCreateRequest struct {
	Name            string `json:"name"`
	Description     string `json:"description"`
	Content         string `json:"content"`
	ShingleSize     *int   `json:"shingle_size,omitempty"`
	WindowSize      *int   `json:"window_size,omitempty"`
	MaxFingerprints *int   `json:"max_fingerprints,omitempty"`
}

type idmFingerprintSetUpdateRequest struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

type ocrIDMConfigResponse struct {
	TenantID               uuid.UUID `json:"tenant_id"`
	OCREnabled             bool      `json:"ocr_enabled"`
	OCRMaxInputBytes       int64     `json:"ocr_max_input_bytes"`
	OCRMaxDimension        int       `json:"ocr_max_dimension"`
	IDMEnabled             bool      `json:"idm_enabled"`
	IDMSimilarityThreshold float64   `json:"idm_similarity_threshold"`
	IDMShingleSize         int       `json:"idm_shingle_size"`
	IDMWindowSize          int       `json:"idm_window_size"`
	IDMMaxFingerprints     int       `json:"idm_max_fingerprints"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

func toOCRIDMConfigResponse(c repository.DLPOCRIDMConfig) ocrIDMConfigResponse {
	return ocrIDMConfigResponse{
		TenantID:               c.TenantID,
		OCREnabled:             c.OCREnabled,
		OCRMaxInputBytes:       c.OCRMaxInputBytes,
		OCRMaxDimension:        c.OCRMaxDimension,
		IDMEnabled:             c.IDMEnabled,
		IDMSimilarityThreshold: c.IDMSimilarityThreshold,
		IDMShingleSize:         c.IDMShingleSize,
		IDMWindowSize:          c.IDMWindowSize,
		IDMMaxFingerprints:     c.IDMMaxFingerprints,
		CreatedAt:              c.CreatedAt,
		UpdatedAt:              c.UpdatedAt,
	}
}

// ocrIDMConfigUpdateRequest is a partial update: omitted fields retain
// their current effective value (the stored config, or the compiled-in
// default when the tenant has never customized it).
type ocrIDMConfigUpdateRequest struct {
	OCREnabled             *bool    `json:"ocr_enabled,omitempty"`
	OCRMaxInputBytes       *int64   `json:"ocr_max_input_bytes,omitempty"`
	OCRMaxDimension        *int     `json:"ocr_max_dimension,omitempty"`
	IDMEnabled             *bool    `json:"idm_enabled,omitempty"`
	IDMSimilarityThreshold *float64 `json:"idm_similarity_threshold,omitempty"`
	IDMShingleSize         *int     `json:"idm_shingle_size,omitempty"`
	IDMWindowSize          *int     `json:"idm_window_size,omitempty"`
	IDMMaxFingerprints     *int     `json:"idm_max_fingerprints,omitempty"`
}

type ocrIDMStatusResponse struct {
	Config            ocrIDMConfigResponse `json:"config"`
	SetCount          int                  `json:"set_count"`
	TotalFingerprints int64                `json:"total_fingerprints"`
	TotalSourceBytes  int64                `json:"total_source_bytes"`
}

// --- handlers -------------------------------------------------------------

func (h *DLPIDMHandler) createSet(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req idmFingerprintSetCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	set, err := h.svc.RegisterDocument(r.Context(), tid, dlpidm.RegisterDocumentInput{
		Name:            req.Name,
		Description:     req.Description,
		Content:         req.Content,
		ShingleSize:     req.ShingleSize,
		WindowSize:      req.WindowSize,
		MaxFingerprints: req.MaxFingerprints,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toIDMFingerprintSetResponse(set))
}

func (h *DLPIDMHandler) listSets(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		After: r.URL.Query().Get("cursor"),
		Limit: QueryLimit(r),
	}
	result, err := h.svc.ListSets(r.Context(), tid, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]idmFingerprintSetResponse, len(result.Items))
	for i, s := range result.Items {
		items[i] = toIDMFingerprintSetResponse(s)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": result.NextCursor,
	})
}

func (h *DLPIDMHandler) getSet(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	set, err := h.svc.GetSet(r.Context(), tid, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toIDMFingerprintSetResponse(set))
}

func (h *DLPIDMHandler) updateSet(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req idmFingerprintSetUpdateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	set, err := h.svc.UpdateSet(r.Context(), tid, id, repository.IDMFingerprintSetPatch{
		Name:        req.Name,
		Description: req.Description,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toIDMFingerprintSetResponse(set))
}

func (h *DLPIDMHandler) deleteSet(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteSet(r.Context(), tid, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *DLPIDMHandler) getConfig(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	cfg, err := h.svc.GetConfig(r.Context(), tid)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toOCRIDMConfigResponse(cfg))
}

func (h *DLPIDMHandler) putConfig(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req ocrIDMConfigUpdateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	// Merge the partial request over the tenant's current effective
	// config so a no-ops client can change one field without resending
	// every setting.
	current, err := h.svc.GetConfig(r.Context(), tid)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	in := dlpidm.ConfigInput{
		OCREnabled:             current.OCREnabled,
		OCRMaxInputBytes:       current.OCRMaxInputBytes,
		OCRMaxDimension:        current.OCRMaxDimension,
		IDMEnabled:             current.IDMEnabled,
		IDMSimilarityThreshold: current.IDMSimilarityThreshold,
		IDMShingleSize:         current.IDMShingleSize,
		IDMWindowSize:          current.IDMWindowSize,
		IDMMaxFingerprints:     current.IDMMaxFingerprints,
	}
	if req.OCREnabled != nil {
		in.OCREnabled = *req.OCREnabled
	}
	if req.OCRMaxInputBytes != nil {
		in.OCRMaxInputBytes = *req.OCRMaxInputBytes
	}
	if req.OCRMaxDimension != nil {
		in.OCRMaxDimension = *req.OCRMaxDimension
	}
	if req.IDMEnabled != nil {
		in.IDMEnabled = *req.IDMEnabled
	}
	if req.IDMSimilarityThreshold != nil {
		in.IDMSimilarityThreshold = *req.IDMSimilarityThreshold
	}
	if req.IDMShingleSize != nil {
		in.IDMShingleSize = *req.IDMShingleSize
	}
	if req.IDMWindowSize != nil {
		in.IDMWindowSize = *req.IDMWindowSize
	}
	if req.IDMMaxFingerprints != nil {
		in.IDMMaxFingerprints = *req.IDMMaxFingerprints
	}
	cfg, err := h.svc.PutConfig(r.Context(), tid, in)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toOCRIDMConfigResponse(cfg))
}

func (h *DLPIDMHandler) status(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	st, err := h.svc.Status(r.Context(), tid)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, ocrIDMStatusResponse{
		Config:            toOCRIDMConfigResponse(st.Config),
		SetCount:          st.Stats.SetCount,
		TotalFingerprints: st.Stats.TotalFingerprints,
		TotalSourceBytes:  st.Stats.TotalSourceBytes,
	})
}
