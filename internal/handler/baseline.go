// Package handler — baseline.go exposes the read + tune REST
// surface for baseline statistical models (Phase 3 Block 3, Task 13).
//
// Endpoints (all tenant-scoped, JWT/API-key authenticated):
//
//   GET  /api/v1/tenants/{tenant_id}/baselines
//       Lists baseline models for the tenant in LastUpdatedAt
//       DESC order. Cursor pagination via the standard
//       ?limit= / ?cursor= query params.
//
//   GET  /api/v1/tenants/{tenant_id}/baselines/{dimension}/{window_seconds}
//       Returns the model for a specific (dimension, window).
//       404 when no model exists.
//
//   PUT  /api/v1/tenants/{tenant_id}/baselines/{dimension}/{window_seconds}/threshold
//       Overrides the per-(dimension, window) ZThreshold. The
//       feedback tuning loop respects operator overrides — see
//       alert.Feedback.TuneDimension for the bounds it stays
//       within.
//
// The handler is wired in router.go via deps.Baseline. A nil
// dep skips registration (the binary still serves the rest of
// the API). The repository pointer is the only dependency: read
// + threshold mutation both go straight to the repo so the
// handler doesn't need a separate "baseline service".

package handler

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// BaselineHandler exposes the baseline REST surface.
type BaselineHandler struct {
	baselines repository.BaselineModelRepository
	logger    *slog.Logger
}

// NewBaselineHandler bundles dependencies.
func NewBaselineHandler(r repository.BaselineModelRepository, logger *slog.Logger) *BaselineHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &BaselineHandler{baselines: r, logger: logger}
}

// Register wires every endpoint onto mux.
func (h *BaselineHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/baselines", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/baselines/{dimension}/{window_seconds}", h.get)
	MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/baselines/{dimension}/{window_seconds}/threshold", h.updateThreshold)
}

// baselineResponse is the wire shape for one baseline row.
// Hand-rolled (rather than embedding the repository struct
// directly) so the API contract is independent of internal
// evolution. Welford state (Samples / Mean / M2 / EWMA /
// EWMAVar) is exposed so the operator portal can render the
// self-explaining alert context.
type baselineResponse struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	Dimension      string    `json:"dimension"`
	WindowSeconds  int       `json:"window_seconds"`
	Samples        int64     `json:"samples"`
	Mean           float64   `json:"mean"`
	StdDev         float64   `json:"stddev"`
	EWMA           float64   `json:"ewma"`
	EWMAStdDev     float64   `json:"ewma_stddev"`
	Alpha          float64   `json:"alpha"`
	ZThreshold     float64   `json:"z_threshold"`
	LastObservedAt string    `json:"last_observed_at,omitempty"`
	LastUpdatedAt  string    `json:"last_updated_at,omitempty"`
	CreatedAt      string    `json:"created_at"`
	Version        int64     `json:"version"`
}

func toBaselineResponse(m repository.BaselineModel) baselineResponse {
	out := baselineResponse{
		ID:            m.ID,
		TenantID:      m.TenantID,
		Dimension:     m.Dimension,
		WindowSeconds: m.WindowSeconds,
		Samples:       m.Samples,
		Mean:          m.Mean,
		StdDev:        m.StdDev(),
		EWMA:          m.EWMA,
		EWMAStdDev:    m.EWMAStdDev(),
		Alpha:         m.Alpha,
		ZThreshold:    m.ZThreshold,
		CreatedAt:     m.CreatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
		Version:       m.Version,
	}
	if !m.LastObservedAt.IsZero() {
		out.LastObservedAt = m.LastObservedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	if !m.LastUpdatedAt.IsZero() {
		out.LastUpdatedAt = m.LastUpdatedAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	}
	return out
}

func (h *BaselineHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		Limit:  QueryLimit(r),
		After: r.URL.Query().Get("cursor"),
	}
	pg, err := h.baselines.List(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := struct {
		Items      []baselineResponse `json:"items"`
		NextCursor string             `json:"next_cursor,omitempty"`
	}{
		Items: make([]baselineResponse, 0, len(pg.Items)),
	}
	for _, m := range pg.Items {
		out.Items = append(out.Items, toBaselineResponse(m))
	}
	out.NextCursor = pg.NextCursor
	WriteJSON(w, http.StatusOK, out)
}

func (h *BaselineHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	dimension := r.PathValue("dimension")
	if dimension == "" {
		WriteError(w, http.StatusBadRequest, "missing_param", "dimension is required")
		return
	}
	wndRaw := r.PathValue("window_seconds")
	wnd, err := strconv.Atoi(wndRaw)
	if err != nil || wnd <= 0 {
		WriteError(w, http.StatusBadRequest, "invalid_param", "window_seconds must be a positive integer")
		return
	}
	m, err := h.baselines.GetForDimension(r.Context(), tenantID, dimension, wnd)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toBaselineResponse(m))
}

// updateThresholdRequest is the PUT body.
type updateThresholdRequest struct {
	ZThreshold float64 `json:"z_threshold"`
}

func (h *BaselineHandler) updateThreshold(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	dimension := r.PathValue("dimension")
	if dimension == "" {
		WriteError(w, http.StatusBadRequest, "missing_param", "dimension is required")
		return
	}
	wndRaw := r.PathValue("window_seconds")
	wnd, err := strconv.Atoi(wndRaw)
	if err != nil || wnd <= 0 {
		WriteError(w, http.StatusBadRequest, "invalid_param", "window_seconds must be a positive integer")
		return
	}
	var body updateThresholdRequest
	if !DecodeJSON(w, r, &body) {
		return
	}
	if body.ZThreshold <= 0 {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "z_threshold must be positive")
		return
	}
	m, err := h.baselines.UpdateThreshold(r.Context(), tenantID, dimension, wnd, body.ZThreshold)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "not_found", "no baseline model exists for (dimension, window_seconds)")
			return
		}
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toBaselineResponse(m))
}
