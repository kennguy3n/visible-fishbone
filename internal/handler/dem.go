// Package handler — dem.go exposes the Digital Experience Monitoring
// (DEM) REST surface: agents upload probe results, operators read
// per-target experience scores + timeseries, manage custom probe
// targets, and list degradation alerts.
//
// Endpoints (all tenant-scoped):
//
//	POST   /api/v1/tenants/{tenant_id}/dem/results
//	     Ingest a batch of edge probe results; recomputes scores.
//
//	GET    /api/v1/tenants/{tenant_id}/dem/targets
//	     The effective target set (managed defaults overlaid with the
//	     tenant's custom targets) — what an agent should probe.
//	POST   /api/v1/tenants/{tenant_id}/dem/targets
//	GET    /api/v1/tenants/{tenant_id}/dem/targets/{target_id}
//	PUT    /api/v1/tenants/{tenant_id}/dem/targets/{target_id}
//	DELETE /api/v1/tenants/{tenant_id}/dem/targets/{target_id}
//	     CRUD on the tenant's custom probe targets.
//
//	GET    /api/v1/tenants/{tenant_id}/dem/scores
//	     Latest experience score per target (dashboard view).
//	GET    /api/v1/tenants/{tenant_id}/dem/scores/timeseries
//	     Score timeseries; ?target_key= (repeatable), ?since=, ?until=
//	     (RFC3339), ?cursor=, ?limit=, ?order=asc|desc.
//
//	GET    /api/v1/tenants/{tenant_id}/dem/alerts
//	     DEM degradation alerts; ?state= (repeatable).

package handler

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/dem"
)

// DEMHandler exposes the DEM REST surface.
type DEMHandler struct {
	svc    *dem.Service
	logger *slog.Logger
}

// NewDEMHandler bundles dependencies. svc is required.
func NewDEMHandler(svc *dem.Service, logger *slog.Logger) *DEMHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &DEMHandler{svc: svc, logger: logger}
}

// Register wires endpoints onto mux.
func (h *DEMHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dem/results", h.ingest)

	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dem/targets", h.listTargets)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dem/targets", h.createTarget)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dem/targets/{target_id}", h.getTarget)
	MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/dem/targets/{target_id}", h.updateTarget)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/dem/targets/{target_id}", h.deleteTarget)

	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dem/scores", h.latestScores)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dem/scores/timeseries", h.scoreTimeseries)

	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dem/alerts", h.listAlerts)
}

// --- wire shapes --------------------------------------------------------

type targetResponse struct {
	ID              *uuid.UUID `json:"id,omitempty"`
	TenantID        *uuid.UUID `json:"tenant_id,omitempty"`
	TargetKey       string     `json:"target_key"`
	Name            string     `json:"name"`
	ProbeKind       string     `json:"probe_kind"`
	Address         string     `json:"address"`
	Port            *int       `json:"port,omitempty"`
	Enabled         bool       `json:"enabled"`
	IntervalSeconds int        `json:"interval_seconds"`
	TimeoutMs       int        `json:"timeout_ms"`
	// Managed is true for a code-defined default target (no config
	// row); such a target has no id and cannot be updated/deleted.
	Managed   bool       `json:"managed"`
	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

func toTargetResponse(t repository.DEMTarget) targetResponse {
	out := targetResponse{
		TargetKey:       t.TargetKey,
		Name:            t.Name,
		ProbeKind:       t.ProbeKind,
		Address:         t.Address,
		Port:            t.Port,
		Enabled:         t.Enabled,
		IntervalSeconds: t.IntervalSeconds,
		TimeoutMs:       t.TimeoutMs,
		Managed:         t.ID == uuid.Nil,
	}
	if t.ID != uuid.Nil {
		id := t.ID
		out.ID = &id
	}
	if t.TenantID != uuid.Nil {
		tid := t.TenantID
		out.TenantID = &tid
	}
	if !t.CreatedAt.IsZero() {
		ts := t.CreatedAt
		out.CreatedAt = &ts
	}
	if !t.UpdatedAt.IsZero() {
		ts := t.UpdatedAt
		out.UpdatedAt = &ts
	}
	return out
}

type targetRequest struct {
	TargetKey string `json:"target_key"`
	Name      string `json:"name"`
	ProbeKind string `json:"probe_kind"`
	Address   string `json:"address"`
	Port      *int   `json:"port,omitempty"`
	// Enabled defaults to true when omitted so adding a custom target
	// activates it; send false explicitly to disable a managed default
	// by reusing its target_key.
	Enabled         *bool `json:"enabled,omitempty"`
	IntervalSeconds int   `json:"interval_seconds,omitempty"`
	TimeoutMs       int   `json:"timeout_ms,omitempty"`
}

func (req targetRequest) toRow() repository.DEMTarget {
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	return repository.DEMTarget{
		TargetKey:       req.TargetKey,
		Name:            req.Name,
		ProbeKind:       req.ProbeKind,
		Address:         req.Address,
		Port:            req.Port,
		Enabled:         enabled,
		IntervalSeconds: req.IntervalSeconds,
		TimeoutMs:       req.TimeoutMs,
	}
}

type scoreResponse struct {
	ID            uuid.UUID `json:"id"`
	TenantID      uuid.UUID `json:"tenant_id"`
	TargetKey     string    `json:"target_key"`
	TargetName    string    `json:"target_name"`
	Score         float64   `json:"score"`
	Availability  float64   `json:"availability"`
	LatencyP50Ms  *float64  `json:"latency_p50_ms,omitempty"`
	LatencyP95Ms  *float64  `json:"latency_p95_ms,omitempty"`
	SampleCount   int       `json:"sample_count"`
	WindowSeconds int       `json:"window_seconds"`
	WindowStart   time.Time `json:"window_start"`
	WindowEnd     time.Time `json:"window_end"`
	CreatedAt     time.Time `json:"created_at"`
}

func toScoreResponse(s repository.DEMExperienceScore) scoreResponse {
	return scoreResponse{
		ID:            s.ID,
		TenantID:      s.TenantID,
		TargetKey:     s.TargetKey,
		TargetName:    s.TargetName,
		Score:         s.Score,
		Availability:  s.Availability,
		LatencyP50Ms:  s.LatencyP50Ms,
		LatencyP95Ms:  s.LatencyP95Ms,
		SampleCount:   s.SampleCount,
		WindowSeconds: s.WindowSeconds,
		WindowStart:   s.WindowStart,
		WindowEnd:     s.WindowEnd,
		CreatedAt:     s.CreatedAt,
	}
}

type ingestResult struct {
	TargetKey  string   `json:"target_key"`
	TargetName string   `json:"target_name"`
	ProbeKind  string   `json:"probe_kind"`
	Success    bool     `json:"success"`
	DNSMs      *float64 `json:"dns_ms,omitempty"`
	TCPMs      *float64 `json:"tcp_ms,omitempty"`
	TLSMs      *float64 `json:"tls_ms,omitempty"`
	TTFBMs     *float64 `json:"ttfb_ms,omitempty"`
	TotalMs    *float64 `json:"total_ms,omitempty"`
	HTTPStatus *int     `json:"http_status,omitempty"`
	ErrorKind  string   `json:"error_kind,omitempty"`
	// ErrorDetail is accepted (the edge crate emits it) but never
	// persisted: free-form failure text could carry sensitive host
	// data, so DEM keeps only the bucketed ErrorKind.
	ErrorDetail  string `json:"error_detail,omitempty"`
	ObservedAtMs uint64 `json:"observed_at_ms"`
}

type ingestRequest struct {
	Results []ingestResult `json:"results"`
}

type ingestResponse struct {
	Accepted int             `json:"accepted"`
	Scores   []scoreResponse `json:"scores"`
}

// --- handlers -----------------------------------------------------------

func (h *DEMHandler) ingest(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var body ingestRequest
	if !DecodeJSON(w, r, &body) {
		return
	}
	if len(body.Results) == 0 {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "results must be non-empty")
		return
	}
	results := make([]repository.DEMProbeResult, 0, len(body.Results))
	for _, in := range body.Results {
		results = append(results, repository.DEMProbeResult{
			TargetKey:  in.TargetKey,
			TargetName: in.TargetName,
			ProbeKind:  in.ProbeKind,
			Success:    in.Success,
			DNSMs:      in.DNSMs,
			TCPMs:      in.TCPMs,
			TLSMs:      in.TLSMs,
			TTFBMs:     in.TTFBMs,
			TotalMs:    in.TotalMs,
			HTTPStatus: in.HTTPStatus,
			ErrorKind:  in.ErrorKind,
			// Realistic Unix-millis (~1.7e12) are far below MaxInt64;
			// the edge crate derives this from SystemTime::now() so it
			// can never overflow. A crafted huge value would map to a
			// pre-epoch time that falls outside the rolling window and
			// is reaped by retention — a no-op, not a corruption.
			ObservedAt: time.UnixMilli(int64(in.ObservedAtMs)).UTC(),
		})
	}
	res, err := h.svc.Ingest(r.Context(), tenantID, results)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := ingestResponse{Accepted: res.Accepted, Scores: make([]scoreResponse, 0, len(res.Scores))}
	for _, s := range res.Scores {
		out.Scores = append(out.Scores, toScoreResponse(s))
	}
	WriteJSON(w, http.StatusAccepted, out)
}

func (h *DEMHandler) listTargets(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	targets, err := h.svc.ListEffectiveTargets(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := struct {
		Items []targetResponse `json:"items"`
	}{Items: make([]targetResponse, 0, len(targets))}
	for _, t := range targets {
		out.Items = append(out.Items, toTargetResponse(t))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (h *DEMHandler) createTarget(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var body targetRequest
	if !DecodeJSON(w, r, &body) {
		return
	}
	saved, err := h.svc.CreateTarget(r.Context(), tenantID, body.toRow())
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toTargetResponse(saved))
}

func (h *DEMHandler) getTarget(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "target_id")
	if !ok {
		return
	}
	t, err := h.svc.GetTarget(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toTargetResponse(t))
}

func (h *DEMHandler) updateTarget(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "target_id")
	if !ok {
		return
	}
	var body targetRequest
	if !DecodeJSON(w, r, &body) {
		return
	}
	row := body.toRow()
	row.ID = id
	saved, err := h.svc.UpdateTarget(r.Context(), tenantID, row)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toTargetResponse(saved))
}

func (h *DEMHandler) deleteTarget(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "target_id")
	if !ok {
		return
	}
	if err := h.svc.DeleteTarget(r.Context(), tenantID, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *DEMHandler) latestScores(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	scores, err := h.svc.LatestScores(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := struct {
		Items []scoreResponse `json:"items"`
	}{Items: make([]scoreResponse, 0, len(scores))}
	for _, s := range scores {
		out.Items = append(out.Items, toScoreResponse(s))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (h *DEMHandler) scoreTimeseries(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := repository.DEMScoreFilter{}
	for _, k := range q["target_key"] {
		if k != "" {
			filter.TargetKeys = append(filter.TargetKeys, k)
		}
	}
	if raw := q.Get("since"); raw != "" {
		ts, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_param", "since must be an RFC3339 timestamp")
			return
		}
		filter.Since = ts.UTC()
	}
	if raw := q.Get("until"); raw != "" {
		ts, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_param", "until must be an RFC3339 timestamp")
			return
		}
		filter.Until = ts.UTC()
	}
	page := repository.Page{
		Limit: QueryLimit(r),
		After: q.Get("cursor"),
		Order: repository.SortOrder(q.Get("order")),
	}
	pg, err := h.svc.ListScores(r.Context(), tenantID, filter, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := struct {
		Items      []scoreResponse `json:"items"`
		NextCursor string          `json:"next_cursor,omitempty"`
	}{Items: make([]scoreResponse, 0, len(pg.Items))}
	for _, s := range pg.Items {
		out.Items = append(out.Items, toScoreResponse(s))
	}
	out.NextCursor = pg.NextCursor
	WriteJSON(w, http.StatusOK, out)
}

func (h *DEMHandler) listAlerts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	q := r.URL.Query()
	var states []repository.AlertState
	for _, s := range q["state"] {
		state := repository.AlertState(s)
		if !state.IsValid() {
			WriteError(w, http.StatusBadRequest, "invalid_param", "unknown state: "+s)
			return
		}
		states = append(states, state)
	}
	page := repository.Page{Limit: QueryLimit(r), After: q.Get("cursor")}
	pg, err := h.svc.ListAlerts(r.Context(), tenantID, states, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := struct {
		Items      []alertResponse `json:"items"`
		NextCursor string          `json:"next_cursor,omitempty"`
	}{Items: make([]alertResponse, 0, len(pg.Items))}
	for _, a := range pg.Items {
		out.Items = append(out.Items, toAlertResponse(a))
	}
	out.NextCursor = pg.NextCursor
	WriteJSON(w, http.StatusOK, out)
}
