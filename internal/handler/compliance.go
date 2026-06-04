package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/compliance"
)

// Platform-scoped permissions gating the admin SOC2 evidence surface.
// They follow the rbac "resource:action" grammar; platform_admin's
// wildcard grant satisfies both. Defined here (not in the rbac
// package) so this session does not edit shared rbac code.
const (
	permComplianceEvidenceRead  = "compliance:read"
	permComplianceEvidenceWrite = "compliance:write"
)

// ComplianceHandler exposes the Compliance Report REST surface plus,
// when an evidence service is wired, the platform-level SOC2 evidence
// automation admin endpoints.
type ComplianceHandler struct {
	svc *compliance.ReportService

	// Optional SOC2 evidence automation surface. When evidence is
	// nil the admin endpoints are not registered, keeping the handler
	// backward-compatible for callers that only need the report APIs.
	evidence  *compliance.EvidenceService
	scheduler *compliance.Scheduler
	authz     middleware.MSPAuthorizer
}

// ComplianceOption customises a ComplianceHandler.
type ComplianceOption func(*ComplianceHandler)

// WithEvidenceAutomation enables the admin SOC2 evidence endpoints.
// evidence and scheduler back the list/download and collect routes
// respectively; authz gates them with platform-scoped permission
// checks. If any argument is nil the admin routes are not registered.
func WithEvidenceAutomation(evidence *compliance.EvidenceService, scheduler *compliance.Scheduler, authz middleware.MSPAuthorizer) ComplianceOption {
	return func(h *ComplianceHandler) {
		h.evidence = evidence
		h.scheduler = scheduler
		h.authz = authz
	}
}

// NewComplianceHandler wires the handler.
func NewComplianceHandler(svc *compliance.ReportService, opts ...ComplianceOption) *ComplianceHandler {
	h := &ComplianceHandler{svc: svc}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// evidenceEnabled reports whether the admin SOC2 evidence surface is
// fully wired.
func (h *ComplianceHandler) evidenceEnabled() bool {
	return h.evidence != nil && h.scheduler != nil && h.authz != nil
}

// Register attaches compliance routes.
func (h *ComplianceHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/compliance/reports", h.listReports)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/compliance/reports/generate", h.generateReport)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/compliance/reports/{id}", h.getReport)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/compliance/reports/{id}/evidence", h.getEvidence)

	// Platform-level SOC2 evidence automation (admin-scoped). These
	// carry no {tenant_id}; authorization is a platform-permission
	// gate inside each handler, mirroring the MSP list/create routes.
	if h.evidenceEnabled() {
		mux.HandleFunc("GET /api/v1/admin/compliance/evidence", h.adminListEvidence)
		mux.HandleFunc("POST /api/v1/admin/compliance/evidence/collect", h.adminCollectEvidence)
		mux.HandleFunc("GET /api/v1/admin/compliance/evidence/{id}/download", h.adminDownloadEvidence)
	}
}

// --- wire types -----------------------------------------------------------

type complianceReportResponse struct {
	ID           uuid.UUID                  `json:"id"`
	TenantID     uuid.UUID                  `json:"tenant_id"`
	Framework    string                     `json:"framework"`
	Score        float64                    `json:"score"`
	MaxScore     float64                    `json:"max_score"`
	Controls     []compliance.ControlStatus `json:"controls"`
	EvidencePack json.RawMessage            `json:"evidence_pack,omitempty"`
	GeneratedAt  time.Time                  `json:"generated_at"`
	CreatedAt    time.Time                  `json:"created_at"`
}

func toComplianceReportResponse(r compliance.ComplianceReport) complianceReportResponse {
	return complianceReportResponse{
		ID:           r.ID,
		TenantID:     r.TenantID,
		Framework:    string(r.Framework),
		Score:        r.Score,
		MaxScore:     r.MaxScore,
		Controls:     r.Controls,
		EvidencePack: r.EvidencePack,
		GeneratedAt:  r.GeneratedAt,
		CreatedAt:    r.CreatedAt,
	}
}

type generateReportRequest struct {
	Framework     string `json:"framework"`
	DLP           bool   `json:"dlp"`
	Browser       bool   `json:"browser"`
	CASB          bool   `json:"casb"`
	Policy        bool   `json:"policy"`
	AccessControl bool   `json:"access_control"`
}

// --- handlers -------------------------------------------------------------

func (h *ComplianceHandler) listReports(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("after"),
	}
	result, err := h.svc.List(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]complianceReportResponse, len(result.Items))
	for i, item := range result.Items {
		items[i] = toComplianceReportResponse(item)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": result.NextCursor,
	})
}

func (h *ComplianceHandler) generateReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}

	var req generateReportRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Framework == "" {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "framework is required")
		return
	}

	report, err := h.svc.Generate(r.Context(), tenantID, compliance.ComplianceFramework(req.Framework), compliance.EnforcedPolicies{
		DLP:           req.DLP,
		Browser:       req.Browser,
		CASB:          req.CASB,
		Policy:        req.Policy,
		AccessControl: req.AccessControl,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toComplianceReportResponse(report))
}

func (h *ComplianceHandler) getReport(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	report, err := h.svc.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toComplianceReportResponse(report))
}

func (h *ComplianceHandler) getEvidence(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	evidence, err := h.svc.GetEvidence(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(evidence)
}

// --- platform SOC2 evidence automation -----------------------------------

// evidenceResponse is the wire shape for a compliance_evidence row.
type evidenceResponse struct {
	ID             uuid.UUID `json:"id"`
	CollectionType string    `json:"collection_type"`
	CollectedAt    time.Time `json:"collected_at"`
	S3Key          string    `json:"s3_key"`
	Signature      string    `json:"signature"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

func toEvidenceResponse(e repository.ComplianceEvidence) evidenceResponse {
	return evidenceResponse{
		ID:             e.ID,
		CollectionType: e.CollectionType,
		CollectedAt:    e.CollectedAt,
		S3Key:          e.S3Key,
		Signature:      e.Signature,
		Status:         e.Status,
		CreatedAt:      e.CreatedAt,
	}
}

// requireCompliancePlatform gates the platform-scoped evidence routes,
// mirroring MSPHandler.requirePlatformPermission. Returns true when the
// handler should proceed.
func (h *ComplianceHandler) requireCompliancePlatform(w http.ResponseWriter, r *http.Request, permission string) bool {
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"platform-scoped compliance routes require an authenticated user identity")
		return false
	}
	allowed, err := h.authz.AuthorizePlatform(r.Context(), userID, permission)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "authorization_failed",
			"failed to evaluate platform authorization")
		return false
	}
	if !allowed {
		WriteError(w, http.StatusForbidden, "platform_forbidden",
			"credentials do not authorise platform-scoped compliance operations")
		return false
	}
	return true
}

func (h *ComplianceHandler) adminListEvidence(w http.ResponseWriter, r *http.Request) {
	if !h.requireCompliancePlatform(w, r, permComplianceEvidenceRead) {
		return
	}
	filter := repository.ComplianceEvidenceFilter{
		CollectionType: r.URL.Query().Get("type"),
		Status:         r.URL.Query().Get("status"),
	}
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("after"),
	}
	result, err := h.evidence.List(r.Context(), filter, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]evidenceResponse, len(result.Items))
	for i, item := range result.Items {
		items[i] = toEvidenceResponse(item)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": result.NextCursor,
	})
}

func (h *ComplianceHandler) adminCollectEvidence(w http.ResponseWriter, r *http.Request) {
	if !h.requireCompliancePlatform(w, r, permComplianceEvidenceWrite) {
		return
	}
	row, err := h.scheduler.CollectManual(r.Context())
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toEvidenceResponse(row))
}

func (h *ComplianceHandler) adminDownloadEvidence(w http.ResponseWriter, r *http.Request) {
	if !h.requireCompliancePlatform(w, r, permComplianceEvidenceRead) {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	row, body, err := h.evidence.Download(r.Context(), id)
	if err != nil {
		// A signature mismatch is a tamper/corruption signal, not a
		// client error — surface it explicitly rather than letting the
		// default mapping mask it as a generic repository error.
		if errors.Is(err, compliance.ErrSignatureMismatch) {
			WriteError(w, http.StatusInternalServerError, "evidence_integrity_error",
				"stored evidence failed signature verification")
			return
		}
		WriteRepositoryError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Evidence-Signature", row.Signature)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", "evidence-"+row.ID.String()+".json"))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
