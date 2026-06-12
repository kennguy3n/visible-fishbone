package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// Permissions gating the operator rollout surface. They follow the rbac
// "resource:action" grammar (a platform/tenant admin's wildcard grant
// satisfies both); a transition flips a security control's enforcement
// posture, so it is a write-scoped, admin-level operation. Defined here
// (not in the rbac package) so this session does not edit shared rbac
// code.
const (
	permRolloutRead  = "rollout:read"
	permRolloutWrite = "rollout:write"
)

// RolloutAuthorizer is the narrow RBAC seam the rollout handler gates on.
// It is satisfied by *rbac.Service.HasPermission. Optional: a nil
// authorizer leaves the routes ungated (minimum-wiring/tests); production
// wires it so only operators holding the rollout permissions can read or
// transition a capability.
type RolloutAuthorizer interface {
	HasPermission(ctx context.Context, userID uuid.UUID, permission string) (bool, error)
}

// RolloutHandler exposes the operator REST surface for the per-tenant
// staged-enablement (rollout) framework (internal/service/rollout): read
// the current rollout state of every default-OFF capability for a
// tenant, read one capability, and POST a transition that advances
// (off -> monitor -> enforce) or rolls a capability back.
//
// The framework is the guardrail that turns flipping a capability gate
// from a binary on/off flip into a rehearsed monitor -> enforce
// progression. Without this handler the state machine, store, and
// migration exist but an operator has no way to drive a tenant through
// the progression; this wires that last mile.
type RolloutHandler struct {
	svc   *rollout.Service
	authz RolloutAuthorizer
}

// RolloutOption customises a RolloutHandler.
type RolloutOption func(*RolloutHandler)

// WithRolloutAuthorizer gates every rollout route behind an RBAC
// permission check: rollout:read for the GETs and rollout:write for a
// transition. Without it the routes are tenant-scoped but not
// role-gated. Production wiring always supplies one.
func WithRolloutAuthorizer(authz RolloutAuthorizer) RolloutOption {
	return func(h *RolloutHandler) {
		if authz != nil {
			h.authz = authz
		}
	}
}

// NewRolloutHandler wires the handler.
func NewRolloutHandler(svc *rollout.Service, opts ...RolloutOption) *RolloutHandler {
	h := &RolloutHandler{svc: svc}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// authorize enforces the RBAC permission for a rollout route. It returns
// true (proceed) when no authorizer is wired. With one wired it requires
// an authenticated user identity (401) holding the permission (403),
// mirroring the MSP/compliance permission gates.
func (h *RolloutHandler) authorize(w http.ResponseWriter, r *http.Request, permission string) bool {
	if h.authz == nil {
		return true
	}
	userID := middleware.UserIDFromContext(r.Context())
	if userID == uuid.Nil {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"rollout routes require an authenticated user identity")
		return false
	}
	allowed, err := h.authz.HasPermission(r.Context(), userID, permission)
	if err != nil {
		WriteError(w, http.StatusInternalServerError, "authorization_failed",
			"failed to evaluate rollout authorization")
		return false
	}
	if !allowed {
		WriteError(w, http.StatusForbidden, "forbidden",
			"credentials do not authorise this rollout operation")
		return false
	}
	return true
}

// Register attaches routes. The transition is a POST on a sub-path of
// the capability resource so the literal `transition` segment never
// collides with the `{capability}` GET (Go's ServeMux prefers the more
// specific pattern).
func (h *RolloutHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/rollout", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/rollout/{capability}", h.get)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/rollout/{capability}/transition", h.transition)
}

// --- JSON projections ---

type rolloutStateResponse struct {
	TenantID   string `json:"tenant_id"`
	Capability string `json:"capability"`
	State      string `json:"state"`
	// Enforces / Evaluates expose the derived semantics so a console
	// does not have to hard-code the state ladder: only `enforce`
	// enforces, and both `monitor` and `enforce` evaluate.
	Enforces  bool    `json:"enforces"`
	Evaluates bool    `json:"evaluates"`
	Reason    string  `json:"reason,omitempty"`
	UpdatedBy string  `json:"updated_by,omitempty"`
	CreatedAt *string `json:"created_at,omitempty"`
	UpdatedAt *string `json:"updated_at,omitempty"`
}

func toRolloutStateResponse(r rollout.Record) rolloutStateResponse {
	resp := rolloutStateResponse{
		TenantID:   r.TenantID.String(),
		Capability: string(r.Capability),
		State:      string(r.State),
		Enforces:   r.State.Enforces(),
		Evaluates:  r.State.Evaluates(),
		Reason:     r.Reason,
		UpdatedBy:  r.UpdatedBy,
	}
	// A never-transitioned default record carries no timestamps; only
	// surface them when the row actually exists.
	if !r.CreatedAt.IsZero() {
		s := r.CreatedAt.Format(time.RFC3339)
		resp.CreatedAt = &s
	}
	if !r.UpdatedAt.IsZero() {
		s := r.UpdatedAt.Format(time.RFC3339)
		resp.UpdatedAt = &s
	}
	return resp
}

// rolloutTransitionRequest is the POST body for a transition.
type rolloutTransitionRequest struct {
	// To is the target state: "off", "monitor", or "enforce".
	To string `json:"to"`
	// AllowSkip permits an advance that skips the monitor phase
	// (off -> enforce). Defaults false; ignored for rollbacks and
	// single-step advances.
	AllowSkip bool `json:"allow_skip"`
	// Reason is the operator note recorded with the transition.
	Reason string `json:"reason"`
}

// --- handlers ---

func (h *RolloutHandler) list(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, permRolloutRead) {
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	records, err := h.svc.List(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := struct {
		Items []rolloutStateResponse `json:"items"`
	}{Items: make([]rolloutStateResponse, 0, len(records))}
	for _, rec := range records {
		out.Items = append(out.Items, toRolloutStateResponse(rec))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (h *RolloutHandler) get(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, permRolloutRead) {
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	capID, ok := pathCapability(w, r)
	if !ok {
		return
	}
	rec, err := h.svc.Get(r.Context(), tenantID, capID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toRolloutStateResponse(rec))
}

func (h *RolloutHandler) transition(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r, permRolloutWrite) {
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	capID, ok := pathCapability(w, r)
	if !ok {
		return
	}
	var req rolloutTransitionRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	to := rollout.State(req.To)
	if !to.Valid() {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"to must be one of: off, monitor, enforce")
		return
	}
	actor := rolloutActor(r)
	if actor == "" {
		WriteError(w, http.StatusUnauthorized, "unauthenticated",
			"a rollout transition requires an authenticated operator")
		return
	}
	updated, err := h.svc.Transition(r.Context(), tenantID, capID, rollout.TransitionInput{
		To:        to,
		AllowSkip: req.AllowSkip,
		Reason:    req.Reason,
		Actor:     actor,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toRolloutStateResponse(updated))
}

// pathCapability extracts and validates the {capability} path segment,
// writing a 400 and returning false when it is missing or unknown.
func pathCapability(w http.ResponseWriter, r *http.Request) (rollout.Capability, bool) {
	raw := r.PathValue("capability")
	if raw == "" {
		WriteError(w, http.StatusBadRequest, "missing_param", "capability is required")
		return "", false
	}
	c := rollout.Capability(raw)
	if !c.Valid() {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"capability must be one of: clamav_swg, noops_autoenforce, idp_directory_sync")
		return "", false
	}
	return c, true
}

// rolloutActor derives a stable, non-PII actor id for the transition
// audit trail (the row's updated_by column). It prefers the
// authenticated user's UUID, falling back to the auth subject (JWT `sub`
// or API-key name) so a service-account caller still produces a
// traceable id. Returns "" when the request carries no identity.
func rolloutActor(r *http.Request) string {
	if u := middleware.UserIDFromContext(r.Context()); u != uuid.Nil {
		return u.String()
	}
	return middleware.AuthSubjectFromContext(r.Context())
}
