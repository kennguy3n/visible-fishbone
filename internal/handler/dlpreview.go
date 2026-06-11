package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

// DLPReviewHandler exposes the operator REST surface for the
// human-in-the-loop DLP review queue (internal/service/dlpreview): list
// the backlog, fetch one event, take the three terminal decisions
// (approve / block / dismiss), and read a non-blocking digest.
//
// The endpoint AI-app exfiltration signal is coach-first — it flags but
// does not block — so everything it surfaces lands here for a human to
// decide. Without this handler the queue had a durable store, a service,
// and a migration but no way for an operator to reach it; this wires the
// last mile.
type DLPReviewHandler struct {
	svc *dlpreview.Service
}

// NewDLPReviewHandler wires the handler.
func NewDLPReviewHandler(svc *dlpreview.Service) *DLPReviewHandler {
	return &DLPReviewHandler{svc: svc}
}

// defaultDigestWindow is used when the caller omits ?window=.
const defaultDigestWindow = 24 * time.Hour

// maxDigestWindow caps ?window= so a caller cannot ask the repository to
// aggregate an unbounded history in one request.
const maxDigestWindow = 90 * 24 * time.Hour

// Register attaches routes. The literal `digest` segment is registered
// alongside `{id}`; Go's ServeMux prefers the more specific literal, so
// GET .../review-queue/digest never collides with GET .../{id}.
func (h *DLPReviewHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/review-queue", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/review-queue/digest", h.digest)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/review-queue/{id}", h.get)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dlp/review-queue/{id}/approve", h.approve)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dlp/review-queue/{id}/block", h.block)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dlp/review-queue/{id}/dismiss", h.dismiss)
}

// --- JSON projections ---

type dlpReviewEventResponse struct {
	ID             string                       `json:"id"`
	TenantID       string                       `json:"tenant_id"`
	Signal         string                       `json:"signal"`
	DestinationApp string                       `json:"destination_app"`
	Severity       string                       `json:"severity"`
	Confidence     float64                      `json:"confidence"`
	State          string                       `json:"state"`
	Findings       []dlpreview.FindingAggregate `json:"findings"`
	CreatedAt      string                       `json:"created_at"`
	DecidedAt      *string                      `json:"decided_at,omitempty"`
	DecidedBy      *string                      `json:"decided_by,omitempty"`
}

func toDLPReviewEventResponse(e dlpreview.ReviewEvent) dlpReviewEventResponse {
	findings := e.Findings
	if findings == nil {
		findings = []dlpreview.FindingAggregate{}
	}
	r := dlpReviewEventResponse{
		ID:             e.ID.String(),
		TenantID:       e.TenantID.String(),
		Signal:         e.Signal,
		DestinationApp: e.DestinationApp,
		Severity:       string(e.Severity),
		Confidence:     e.Confidence,
		State:          string(e.State),
		Findings:       findings,
		CreatedAt:      e.CreatedAt.Format(time.RFC3339),
	}
	if e.DecidedAt != nil {
		s := e.DecidedAt.Format(time.RFC3339)
		r.DecidedAt = &s
	}
	if e.DecidedBy != nil {
		s := *e.DecidedBy
		r.DecidedBy = &s
	}
	return r
}

type dlpReviewDigestResponse struct {
	TenantID     string         `json:"tenant_id"`
	Window       string         `json:"window"`
	Since        string         `json:"since"`
	GeneratedAt  string         `json:"generated_at"`
	Total        int            `json:"total"`
	Pending      int            `json:"pending"`
	ByState      map[string]int `json:"by_state"`
	BySeverity   map[string]int `json:"by_severity"`
	PendingByApp map[string]int `json:"pending_by_app"`
}

func toDLPReviewDigestResponse(d dlpreview.Digest) dlpReviewDigestResponse {
	byState := make(map[string]int, len(d.Summary.ByState))
	for k, v := range d.Summary.ByState {
		byState[string(k)] = v
	}
	bySeverity := make(map[string]int, len(d.Summary.BySeverity))
	for k, v := range d.Summary.BySeverity {
		bySeverity[string(k)] = v
	}
	pendingByApp := d.Summary.PendingByApp
	if pendingByApp == nil {
		pendingByApp = map[string]int{}
	}
	return dlpReviewDigestResponse{
		TenantID:     d.TenantID.String(),
		Window:       d.Window.String(),
		Since:        d.Since.Format(time.RFC3339),
		GeneratedAt:  d.GeneratedAt.Format(time.RFC3339),
		Total:        d.Summary.Total,
		Pending:      d.Summary.Pending,
		ByState:      byState,
		BySeverity:   bySeverity,
		PendingByApp: pendingByApp,
	}
}

// --- handlers ---

func (h *DLPReviewHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	filter := dlpreview.ListFilter{Limit: QueryLimit(r)}
	if raw := r.URL.Query().Get("state"); raw != "" {
		state := dlpreview.ReviewState(raw)
		if !state.Valid() {
			WriteError(w, http.StatusBadRequest, "invalid_param",
				"state must be one of: pending, approved, blocked, dismissed")
			return
		}
		filter.State = &state
	}
	events, err := h.svc.List(r.Context(), tenantID, filter)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := struct {
		Items []dlpReviewEventResponse `json:"items"`
	}{Items: make([]dlpReviewEventResponse, 0, len(events))}
	for _, e := range events {
		out.Items = append(out.Items, toDLPReviewEventResponse(e))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (h *DLPReviewHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	ev, err := h.svc.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDLPReviewEventResponse(ev))
}

func (h *DLPReviewHandler) approve(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, h.svc.Approve)
}

func (h *DLPReviewHandler) block(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, h.svc.Block)
}

func (h *DLPReviewHandler) dismiss(w http.ResponseWriter, r *http.Request) {
	h.decide(w, r, h.svc.Dismiss)
}

// decideFunc is the shared signature of Service.Approve/Block/Dismiss.
type decideFunc func(ctx context.Context, tenantID, id uuid.UUID, actor string) (dlpreview.ReviewEvent, error)

func (h *DLPReviewHandler) decide(w http.ResponseWriter, r *http.Request, fn decideFunc) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	actor := reviewActor(r)
	if actor == "" {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"a decision requires an authenticated reviewer")
		return
	}
	updated, err := fn(r.Context(), tenantID, id, actor)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDLPReviewEventResponse(updated))
}

func (h *DLPReviewHandler) digest(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	window := defaultDigestWindow
	if raw := r.URL.Query().Get("window"); raw != "" {
		parsed, err := time.ParseDuration(raw)
		if err != nil || parsed <= 0 {
			WriteError(w, http.StatusBadRequest, "invalid_param",
				"window must be a positive Go duration (e.g. 24h, 168h)")
			return
		}
		if parsed > maxDigestWindow {
			parsed = maxDigestWindow
		}
		window = parsed
	}
	d, err := h.svc.Digest(r.Context(), tenantID, window)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDLPReviewDigestResponse(d))
}

// reviewActor derives a stable, non-PII actor id for the decision audit
// trail (the queue's decided_by column). It prefers the authenticated
// user's UUID, falling back to the auth subject (JWT `sub` or API-key
// name) so a service-account caller still produces a traceable id.
// Returns "" when the request carries no identity at all.
func reviewActor(r *http.Request) string {
	if u := middleware.UserIDFromContext(r.Context()); u != uuid.Nil {
		return u.String()
	}
	return middleware.AuthSubjectFromContext(r.Context())
}
