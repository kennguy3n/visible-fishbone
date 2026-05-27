package handler

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

// claimTokenMinTTLSeconds is the minimum value accepted for
// `ttl_seconds` on POST /claim-tokens. It must stay in sync with
// the `minimum: 60` constraint declared in api/openapi.yaml — the
// previous handler accepted any positive value, silently violating
// the published contract.
const claimTokenMinTTLSeconds = 60

// DeviceHandler exposes the device enrolment and listing endpoints.
type DeviceHandler struct {
	identity *identity.Service
	devices  repository.DeviceRepository

	// claimTokenTTL is the default lifetime of a claim token when
	// the request body omits it.
	claimTokenTTL time.Duration
}

// NewDeviceHandler wires the handler.
func NewDeviceHandler(identitySvc *identity.Service, devices repository.DeviceRepository, defaultClaimTTL time.Duration) *DeviceHandler {
	if defaultClaimTTL <= 0 {
		defaultClaimTTL = 24 * time.Hour
	}
	return &DeviceHandler{identity: identitySvc, devices: devices, claimTokenTTL: defaultClaimTTL}
}

// Register attaches routes.
func (h *DeviceHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/claim-tokens", h.createClaimToken)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/devices/enroll", h.enroll)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/devices", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/devices/{id}", h.get)
}

// ClaimTokenCreateRequest is the JSON body for POST /claim-tokens.
type ClaimTokenCreateRequest struct {
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

// ClaimTokenCreateResponse is the JSON response for POST /claim-tokens.
type ClaimTokenCreateResponse struct {
	ID        string `json:"id"`
	Token     string `json:"token"` // plaintext, shown ONCE
	ExpiresAt string `json:"expires_at"`
}

func (h *DeviceHandler) createClaimToken(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req ClaimTokenCreateRequest
	// Body is optional for this endpoint.
	if r.ContentLength > 0 {
		if !DecodeJSON(w, r, &req) {
			return
		}
	}
	ttl := h.claimTokenTTL
	if req.TTLSeconds > 0 {
		// Enforce the OpenAPI-published minimum (60s) here so the
		// handler matches the documented contract. The lower bound
		// exists for operational sanity — sub-minute tokens are
		// practically useless (the operator can't reasonably install
		// the agent and have it call /devices/enroll before the
		// token expires) and would just generate noise in the audit
		// log without ever producing a successful enrollment.
		if req.TTLSeconds < claimTokenMinTTLSeconds {
			WriteError(w, http.StatusBadRequest, "invalid_argument",
				"ttl_seconds must be >= 60 (OpenAPI contract)")
			return
		}
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	res, err := h.identity.GenerateClaimToken(r.Context(), tenantID, ttl, nil)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, ClaimTokenCreateResponse{
		ID:        res.Token.ID.String(),
		Token:     res.Plaintext,
		ExpiresAt: res.Token.ExpiresAt.Format(time.RFC3339Nano),
	})
}

// DeviceEnrollRequest is the JSON body for POST /devices/enroll.
type DeviceEnrollRequest struct {
	ClaimToken       string             `json:"claim_token"`
	Name             string             `json:"name"`
	Platform         string             `json:"platform"`
	PublicKeyEd25519 string             `json:"public_key_ed25519"`
	Posture          repository.Posture `json:"posture,omitempty"`
}

func (h *DeviceHandler) enroll(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req DeviceEnrollRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.ClaimToken == "" || req.Platform == "" || req.PublicKeyEd25519 == "" || req.Name == "" {
		WriteError(w, http.StatusBadRequest, "missing_field", "claim_token, name, platform, public_key_ed25519 are required")
		return
	}
	dev, err := h.identity.RedeemClaimToken(r.Context(), tenantID, req.ClaimToken, req.Name, repository.DevicePlatform(req.Platform), req.PublicKeyEd25519, req.Posture)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toDeviceResponse(dev))
}

func (h *DeviceHandler) list(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	q := r.URL.Query()
	filter := repository.DeviceListFilter{
		Platform: repository.DevicePlatform(q.Get("platform")),
		Status:   repository.DeviceStatus(q.Get("status")),
	}
	if sid := q.Get("site_id"); sid != "" {
		u, err := uuid.Parse(sid)
		if err != nil {
			WriteError(w, http.StatusBadRequest, "invalid_param", "site_id is not a valid UUID")
			return
		}
		filter.SiteID = &u
	}
	page := repository.Page{
		After: q.Get("after"),
		Limit: QueryLimit(r),
		Order: repository.SortOrder(q.Get("order")),
	}
	res, err := h.devices.List(r.Context(), tenantID, filter, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]DeviceResponse, 0, len(res.Items))
	for _, d := range res.Items {
		items = append(items, toDeviceResponse(d))
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": res.NextCursor,
	})
}

func (h *DeviceHandler) get(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	d, err := h.devices.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDeviceResponse(d))
}

// DeviceResponse is the JSON projection of repository.Device.
type DeviceResponse struct {
	ID               string             `json:"id"`
	TenantID         string             `json:"tenant_id"`
	SiteID           *string            `json:"site_id,omitempty"`
	Name             string             `json:"name"`
	Platform         string             `json:"platform"`
	PublicKeyEd25519 string             `json:"public_key_ed25519,omitempty"`
	EnrolledAt       *string            `json:"enrolled_at,omitempty"`
	LastSeenAt       *string            `json:"last_seen_at,omitempty"`
	Status           string             `json:"status"`
	Posture          repository.Posture `json:"posture"`
	CreatedAt        string             `json:"created_at"`
	UpdatedAt        string             `json:"updated_at"`
}

func toDeviceResponse(d repository.Device) DeviceResponse {
	resp := DeviceResponse{
		ID: d.ID.String(), TenantID: d.TenantID.String(), Name: d.Name,
		Platform: string(d.Platform), PublicKeyEd25519: d.PublicKeyEd25519,
		Status: string(d.Status), Posture: d.Posture,
		CreatedAt: d.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt: d.UpdatedAt.Format(time.RFC3339Nano),
	}
	if d.SiteID != nil {
		sid := d.SiteID.String()
		resp.SiteID = &sid
	}
	if d.EnrolledAt != nil {
		s := d.EnrolledAt.Format(time.RFC3339Nano)
		resp.EnrolledAt = &s
	}
	if d.LastSeenAt != nil {
		s := d.LastSeenAt.Format(time.RFC3339Nano)
		resp.LastSeenAt = &s
	}
	return resp
}
