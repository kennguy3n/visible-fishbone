// Package handler — alert.go exposes the alert + suppression +
// feedback REST surface (Phase 3 Block 3, Tasks 14-15).
//
// Endpoints (tenant-scoped):
//
//   GET    /api/v1/tenants/{tenant_id}/alerts
//        Lists alerts in created_at DESC order. Filters via
//        repeatable ?state=, ?kind=, ?dimension= query params.
//
//   GET    /api/v1/tenants/{tenant_id}/alerts/{alert_id}
//        Returns one alert.
//
//   POST   /api/v1/tenants/{tenant_id}/alerts/{alert_id}/acknowledge
//        Transitions an alert to acknowledged.
//
//   POST   /api/v1/tenants/{tenant_id}/alerts/{alert_id}/resolve
//        Transitions an alert to resolved (from open or acknowledged).
//
//   GET    /api/v1/tenants/{tenant_id}/alert-suppressions
//   POST   /api/v1/tenants/{tenant_id}/alert-suppressions
//   GET    /api/v1/tenants/{tenant_id}/alert-suppressions/{rule_id}
//   DELETE /api/v1/tenants/{tenant_id}/alert-suppressions/{rule_id}
//        CRUD on suppression rules.
//
//   GET    /api/v1/tenants/{tenant_id}/alerts/{alert_id}/feedback
//   POST   /api/v1/tenants/{tenant_id}/alerts/{alert_id}/feedback
//   DELETE /api/v1/tenants/{tenant_id}/alerts/{alert_id}/feedback
//        Submit / read / delete operator feedback per alert.

package handler

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/alert"
)

// AlertHandler exposes the alert REST surface.
type AlertHandler struct {
	router   *alert.Router
	feedback *alert.Feedback
	logger   *slog.Logger
}

// NewAlertHandler bundles dependencies. feedback may be nil
// (the feedback endpoints will be skipped on registration).
func NewAlertHandler(r *alert.Router, fb *alert.Feedback, logger *slog.Logger) *AlertHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &AlertHandler{router: r, feedback: fb, logger: logger}
}

// Register wires endpoints onto mux.
func (h *AlertHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/alerts", h.listAlerts)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/alerts/{alert_id}", h.getAlert)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/alerts/{alert_id}/acknowledge", h.acknowledge)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/alerts/{alert_id}/resolve", h.resolve)

	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/alert-suppressions", h.listSuppressions)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/alert-suppressions", h.createSuppression)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/alert-suppressions/{rule_id}", h.getSuppression)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/alert-suppressions/{rule_id}", h.deleteSuppression)

	if h.feedback != nil {
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/alerts/{alert_id}/feedback", h.getFeedback)
		MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/alerts/{alert_id}/feedback", h.submitFeedback)
		MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/alerts/{alert_id}/feedback", h.deleteFeedback)
	}
}

// alertResponse is the canonical wire shape of repository.Alert.
type alertResponse struct {
	ID             uuid.UUID       `json:"id"`
	TenantID       uuid.UUID       `json:"tenant_id"`
	Kind           string          `json:"kind"`
	Severity       string          `json:"severity"`
	Dimension      string          `json:"dimension"`
	ObservedValue  float64         `json:"observed_value"`
	BaselineMean   float64         `json:"baseline_mean"`
	BaselineStdDev float64         `json:"baseline_stddev"`
	ZScore         float64         `json:"z_score"`
	WindowStart    time.Time       `json:"window_start"`
	WindowEnd      time.Time       `json:"window_end"`
	Summary        string          `json:"summary"`
	Evidence       json.RawMessage `json:"evidence,omitempty"`
	State          string          `json:"state"`
	SuppressedBy   *uuid.UUID      `json:"suppressed_by,omitempty"`
	AcknowledgedBy *uuid.UUID      `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at,omitempty"`
	ResolvedBy     *uuid.UUID      `json:"resolved_by,omitempty"`
	ResolvedAt     *time.Time      `json:"resolved_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func toAlertResponse(a repository.Alert) alertResponse {
	out := alertResponse{
		ID:             a.ID,
		TenantID:       a.TenantID,
		Kind:           a.Kind,
		Severity:       string(a.Severity),
		Dimension:      a.Dimension,
		ObservedValue:  a.ObservedValue,
		BaselineMean:   a.BaselineMean,
		BaselineStdDev: a.BaselineStdDev,
		ZScore:         a.ZScore,
		WindowStart:    a.WindowStart,
		WindowEnd:      a.WindowEnd,
		Summary:        a.Summary,
		State:          string(a.State),
		SuppressedBy:   a.SuppressedBy,
		AcknowledgedBy: a.AcknowledgedBy,
		AcknowledgedAt: a.AcknowledgedAt,
		ResolvedBy:     a.ResolvedBy,
		ResolvedAt:     a.ResolvedAt,
		CreatedAt:      a.CreatedAt,
		UpdatedAt:      a.UpdatedAt,
	}
	if len(a.Evidence) > 0 {
		out.Evidence = a.Evidence
	}
	return out
}

func (h *AlertHandler) listAlerts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := repository.AlertListFilter{}
	for _, s := range q["state"] {
		state := repository.AlertState(s)
		if !state.IsValid() {
			WriteError(w, http.StatusBadRequest, "invalid_param", "unknown state: "+s)
			return
		}
		filter.States = append(filter.States, state)
	}
	for _, k := range q["kind"] {
		if k != "" {
			filter.Kinds = append(filter.Kinds, k)
		}
	}
	for _, d := range q["dimension"] {
		if d != "" {
			filter.Dimensions = append(filter.Dimensions, d)
		}
	}
	page := repository.Page{Limit: QueryLimit(r), After: q.Get("cursor")}
	pg, err := h.router.List(r.Context(), tenantID, filter, page)
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

func (h *AlertHandler) getAlert(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "alert_id")
	if !ok {
		return
	}
	a, err := h.router.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toAlertResponse(a))
}

func (h *AlertHandler) acknowledge(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "alert_id")
	if !ok {
		return
	}
	a, err := h.router.Acknowledge(r.Context(), tenantID, id, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toAlertResponse(a))
}

func (h *AlertHandler) resolve(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "alert_id")
	if !ok {
		return
	}
	a, err := h.router.Resolve(r.Context(), tenantID, id, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toAlertResponse(a))
}

// --- suppressions -------------------------------------------------------

type suppressionResponse struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  uuid.UUID  `json:"tenant_id"`
	Kind      *string    `json:"kind,omitempty"`
	Dimension *string    `json:"dimension,omitempty"`
	Reason    string     `json:"reason"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func toSuppressionResponse(s repository.AlertSuppression) suppressionResponse {
	return suppressionResponse{
		ID: s.ID, TenantID: s.TenantID,
		Kind: s.Kind, Dimension: s.Dimension,
		Reason: s.Reason, CreatedBy: s.CreatedBy,
		CreatedAt: s.CreatedAt, ExpiresAt: s.ExpiresAt,
	}
}

type createSuppressionRequest struct {
	Kind      *string    `json:"kind,omitempty"`
	Dimension *string    `json:"dimension,omitempty"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (h *AlertHandler) createSuppression(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var body createSuppressionRequest
	if !DecodeJSON(w, r, &body) {
		return
	}
	if body.Reason == "" {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "reason is required")
		return
	}
	if body.Kind == nil && body.Dimension == nil {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "at least one of kind / dimension must be provided")
		return
	}
	saved, err := h.router.CreateSuppression(r.Context(), tenantID, repository.AlertSuppression{
		Kind:      body.Kind,
		Dimension: body.Dimension,
		Reason:    body.Reason,
		CreatedBy: actorFromCtx(r),
		ExpiresAt: body.ExpiresAt,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toSuppressionResponse(saved))
}

func (h *AlertHandler) listSuppressions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{Limit: QueryLimit(r), After: r.URL.Query().Get("cursor")}
	pg, err := h.router.ListSuppressions(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := struct {
		Items      []suppressionResponse `json:"items"`
		NextCursor string                `json:"next_cursor,omitempty"`
	}{Items: make([]suppressionResponse, 0, len(pg.Items))}
	for _, s := range pg.Items {
		out.Items = append(out.Items, toSuppressionResponse(s))
	}
	out.NextCursor = pg.NextCursor
	WriteJSON(w, http.StatusOK, out)
}

func (h *AlertHandler) getSuppression(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "rule_id")
	if !ok {
		return
	}
	s, err := h.router.GetSuppression(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toSuppressionResponse(s))
}

func (h *AlertHandler) deleteSuppression(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "rule_id")
	if !ok {
		return
	}
	if err := h.router.DeleteSuppression(r.Context(), tenantID, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- feedback -----------------------------------------------------------

type feedbackResponse struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  uuid.UUID  `json:"tenant_id"`
	AlertID   uuid.UUID  `json:"alert_id"`
	Decision  string     `json:"decision"`
	Notes     string     `json:"notes,omitempty"`
	CreatedBy *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

func toFeedbackResponse(f repository.AlertFeedback) feedbackResponse {
	return feedbackResponse{
		ID: f.ID, TenantID: f.TenantID, AlertID: f.AlertID,
		Decision: string(f.Decision), Notes: f.Notes,
		CreatedBy: f.CreatedBy, CreatedAt: f.CreatedAt,
	}
}

type submitFeedbackRequest struct {
	Decision string `json:"decision"`
	Notes    string `json:"notes,omitempty"`
}

func (h *AlertHandler) submitFeedback(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "alert_id")
	if !ok {
		return
	}
	var body submitFeedbackRequest
	if !DecodeJSON(w, r, &body) {
		return
	}
	decision := repository.AlertFeedbackDecision(body.Decision)
	if !decision.IsValid() {
		WriteError(w, http.StatusBadRequest, "invalid_argument",
			"decision must be one of true_positive | false_positive | noise")
		return
	}
	f, err := h.feedback.Submit(r.Context(), tenantID, id, decision, body.Notes, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toFeedbackResponse(f))
}

func (h *AlertHandler) getFeedback(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "alert_id")
	if !ok {
		return
	}
	f, err := h.feedback.GetForAlert(r.Context(), tenantID, id)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			WriteError(w, http.StatusNotFound, "not_found", "no feedback for this alert")
			return
		}
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toFeedbackResponse(f))
}

func (h *AlertHandler) deleteFeedback(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "alert_id")
	if !ok {
		return
	}
	if err := h.feedback.Delete(r.Context(), tenantID, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
