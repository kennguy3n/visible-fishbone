package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/compliance"
)

// ComplianceHandler exposes the Compliance Report REST surface.
type ComplianceHandler struct {
	svc *compliance.ReportService
}

// NewComplianceHandler wires the handler.
func NewComplianceHandler(svc *compliance.ReportService) *ComplianceHandler {
	return &ComplianceHandler{svc: svc}
}

// Register attaches compliance routes.
func (h *ComplianceHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/compliance/reports", h.listReports)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/compliance/reports/generate", h.generateReport)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/compliance/reports/{id}", h.getReport)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/compliance/reports/{id}/evidence", h.getEvidence)
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
