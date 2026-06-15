package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/complianceauto"
)

// ComplianceAutoHandler exposes the continuous compliance evidence REST
// surface (WP6): a tenant's live posture per framework/control with
// evidence references, an on-demand evidence-pack export (JSON or CSV),
// and an on-demand collection trigger. It is distinct from
// ComplianceHandler, which serves the point-in-time compliance reports.
type ComplianceAutoHandler struct {
	engine *complianceauto.Engine
}

// NewComplianceAutoHandler wires the handler over the engine.
func NewComplianceAutoHandler(engine *complianceauto.Engine) *ComplianceAutoHandler {
	return &ComplianceAutoHandler{engine: engine}
}

// Register attaches the continuous-compliance routes. All are
// tenant-scoped, so RequireTenant binds the path tenant to the caller's
// token via MountTenantScoped.
func (h *ComplianceAutoHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/compliance-auto/posture", h.getPosture)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/compliance-auto/collect", h.collect)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/compliance-auto/evidence-pack", h.exportPack)
}

// --- wire types -----------------------------------------------------------

type complianceAutoControlResponse struct {
	ControlID   string          `json:"control_id"`
	Framework   string          `json:"framework"`
	Title       string          `json:"title"`
	Statement   string          `json:"statement"`
	Category    string          `json:"category"`
	CollectorID string          `json:"collector_id"`
	Status      string          `json:"status"`
	Summary     string          `json:"summary"`
	Source      string          `json:"source"`
	ObservedAt  time.Time       `json:"observed_at"`
	Evidence    json.RawMessage `json:"evidence,omitempty"`
}

type complianceAutoFrameworkResponse struct {
	Framework     string                          `json:"framework"`
	Total         int                             `json:"total"`
	Pass          int                             `json:"pass"`
	Fail          int                             `json:"fail"`
	NotApplicable int                             `json:"not_applicable"`
	ScorePercent  int                             `json:"score_percent"`
	Controls      []complianceAutoControlResponse `json:"controls"`
}

type complianceAutoPostureResponse struct {
	TenantID    uuid.UUID                         `json:"tenant_id"`
	GeneratedAt time.Time                         `json:"generated_at"`
	Frameworks  []complianceAutoFrameworkResponse `json:"frameworks"`
}

func toPostureResponse(p complianceauto.TenantPosture) complianceAutoPostureResponse {
	resp := complianceAutoPostureResponse{
		TenantID:    p.TenantID,
		GeneratedAt: p.GeneratedAt,
		Frameworks:  make([]complianceAutoFrameworkResponse, 0, len(p.Frameworks)),
	}
	for _, fp := range p.Frameworks {
		fr := complianceAutoFrameworkResponse{
			Framework:     string(fp.Framework),
			Total:         fp.Total,
			Pass:          fp.Pass,
			Fail:          fp.Fail,
			NotApplicable: fp.NotApplicable,
			ScorePercent:  scorePercent(fp.Pass, fp.Total-fp.NotApplicable),
			Controls:      make([]complianceAutoControlResponse, 0, len(fp.Controls)),
		}
		for _, c := range fp.Controls {
			fr.Controls = append(fr.Controls, complianceAutoControlResponse{
				ControlID:   c.Control.ID,
				Framework:   string(c.Control.Framework),
				Title:       c.Control.Title,
				Statement:   c.Control.Statement,
				Category:    c.Control.Category,
				CollectorID: string(c.Control.CollectorID),
				Status:      string(c.Status),
				Summary:     c.Summary,
				Source:      c.Source,
				ObservedAt:  c.ObservedAt,
				Evidence:    c.Details,
			})
		}
		resp.Frameworks = append(resp.Frameworks, fr)
	}
	return resp
}

func scorePercent(pass, inScope int) int {
	if inScope <= 0 {
		return 100
	}
	return int(float64(pass) / float64(inScope) * 100)
}

// --- handlers -------------------------------------------------------------

// getPosture returns the tenant's stored posture. An optional
// ?framework= filters to one framework.
func (h *ComplianceAutoHandler) getPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	framework, ok := optionalFramework(w, r)
	if !ok {
		return
	}
	posture, err := h.engine.Posture(r.Context(), tenantID, framework)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toPostureResponse(posture))
}

// collect triggers an on-demand evaluation sweep for the tenant and
// returns the freshly computed posture. The scheduled background loop
// performs the same work fleet-wide; this lets an operator or the UI
// refresh a single tenant immediately.
func (h *ComplianceAutoHandler) collect(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	posture, err := h.engine.Evaluate(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toPostureResponse(posture))
}

// exportPack streams an on-demand evidence pack. ?framework= is required;
// ?format=json (default) or csv selects the encoding.
func (h *ComplianceAutoHandler) exportPack(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	raw := r.URL.Query().Get("framework")
	if raw == "" {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "framework query parameter is required")
		return
	}
	if !complianceauto.IsFramework(raw) {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "unknown framework: "+raw)
		return
	}
	framework := complianceauto.Framework(raw)

	posture, err := h.engine.Posture(r.Context(), tenantID, framework)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	if len(posture.Frameworks) == 0 {
		WriteError(w, http.StatusNotFound, "not_found",
			"no compliance evidence has been collected for this tenant and framework yet")
		return
	}
	pack, err := complianceauto.BuildPack(posture, framework)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "internal_error", "failed to build evidence pack")
		return
	}

	format := r.URL.Query().Get("format")
	switch format {
	case "", "json":
		body, err := pack.MarshalJSONIndent()
		if err != nil {
			WriteError(w, http.StatusInternalServerError, "internal_error", "failed to encode evidence pack")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", packFilename(raw, tenantID, "json")))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=%q", packFilename(raw, tenantID, "csv")))
		w.WriteHeader(http.StatusOK)
		if err := pack.WriteCSV(w); err != nil {
			// Header already written; nothing actionable left but to
			// stop. The truncated body signals the failure to the client.
			return
		}
	default:
		WriteError(w, http.StatusBadRequest, "invalid_argument", "format must be json or csv")
	}
}

func packFilename(framework string, tenantID uuid.UUID, ext string) string {
	return fmt.Sprintf("evidence-%s-%s.%s", framework, tenantID.String(), ext)
}

// optionalFramework reads and validates an optional ?framework= filter.
// An empty value means "all frameworks". An unknown value renders a 400
// and returns ok=false.
func optionalFramework(w http.ResponseWriter, r *http.Request) (complianceauto.Framework, bool) {
	raw := r.URL.Query().Get("framework")
	if raw == "" {
		return "", true
	}
	if !complianceauto.IsFramework(raw) {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "unknown framework: "+raw)
		return "", false
	}
	return complianceauto.Framework(raw), true
}
