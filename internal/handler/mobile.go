package handler

// mobile.go is the HTTP surface for the device-bound mobile
// self-service flows (service logic in
// internal/service/identity/mobile_enrollment.go). Both endpoints are
// authenticated by the mobile session JWT minted by the OIDC
// native-SSO token endpoint (oidc.go): that JWT carries
// `token_type: "mobile"` and the base64 Ed25519 `device_key`, which
// the auth middleware surfaces as middleware.MobileClaims on the
// request context. The handler trusts those claims (signature + iss /
// aud / exp already verified by middleware.Auth) and uses the
// device_key as the authoritative device identity — request-body
// fields never override it. A non-mobile credential (operator console
// / API key) is rejected with 403: only a mobile session may
// self-enroll or self-report for its own device.

import (
	"net/http"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

// MobileHandler exposes the authenticated mobile enrolment and
// posture-reporting endpoints. It reuses the identity.Service that
// owns device lifecycle + audit.
type MobileHandler struct {
	identity *identity.Service
}

// NewMobileHandler wires the handler.
func NewMobileHandler(identitySvc *identity.Service) *MobileHandler {
	return &MobileHandler{identity: identitySvc}
}

// Register attaches the authenticated, tenant-scoped mobile routes.
// They sit behind the standard auth + tenant-scope middleware (the
// session JWT is the credential). The fixed `/devices/mobile/...`
// prefix does not collide with `/devices/{id}` — that pattern matches
// a single trailing segment, whereas these carry two.
func (h *MobileHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/devices/mobile/enroll", h.enroll)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/devices/mobile/posture", h.reportPosture)
}

// MobileEnrollRequest is the JSON body for mobile self-enrolment. The
// device key is taken from the session token, NOT this body;
// DevicePublicKey is accepted only so a client may assert the key it
// believes it is bound to — a mismatch is rejected.
type MobileEnrollRequest struct {
	// Platform is the mobile OS to enroll as: "ios" or "android".
	Platform string `json:"platform"`
	// Name is an optional human-friendly device label.
	Name string `json:"name,omitempty"`
	// DevicePublicKey, when present, MUST equal the session token's
	// device_key. It exists for clients that want to assert the
	// binding explicitly; it never overrides the token.
	DevicePublicKey string `json:"device_public_key,omitempty"`
	// Posture is an optional initial posture snapshot.
	Posture *repository.Posture `json:"posture,omitempty"`
}

// MobileEnrollResponse is returned by the enrolment endpoint.
type MobileEnrollResponse struct {
	Device DeviceResponse `json:"device"`
	// Created is true when the device was freshly created (HTTP 201)
	// and false on an idempotent re-enrolment (HTTP 200).
	Created bool `json:"created"`
}

func (h *MobileHandler) enroll(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	claims, ok := requireMobileSession(w, r)
	if !ok {
		return
	}

	var req MobileEnrollRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Platform == "" {
		WriteError(w, http.StatusBadRequest, "invalid_param", "platform is required")
		return
	}
	platform := repository.DevicePlatform(req.Platform)
	if !platform.IsMobile() {
		WriteError(w, http.StatusBadRequest, "invalid_param", "platform must be one of: ios, android")
		return
	}
	// A body-supplied device_public_key is optional, but if present it
	// must agree with the token's device_key — the client cannot
	// enroll a device other than the one its session is bound to.
	if req.DevicePublicKey != "" && req.DevicePublicKey != claims.DeviceKey {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			"device_public_key does not match the session's device_key")
		return
	}

	result, err := h.identity.EnrollMobileDevice(r.Context(), tenantID, identity.MobileEnrollInput{
		DeviceKey:   claims.DeviceKey,
		Platform:    platform,
		Name:        req.Name,
		OIDCSubject: claims.OIDCSubject,
		Actor:       actorFromContext(r),
		Posture:     req.Posture,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}

	status := http.StatusOK
	if result.Created {
		status = http.StatusCreated
	}
	WriteJSON(w, status, MobileEnrollResponse{
		Device:  toDeviceResponse(result.Device),
		Created: result.Created,
	})
}

// MobilePostureRequest is the JSON body for a posture report. The
// device is resolved from the session token's device_key, so the body
// carries only posture signals.
type MobilePostureRequest struct {
	Posture repository.Posture `json:"posture"`
}

func (h *MobileHandler) reportPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	claims, ok := requireMobileSession(w, r)
	if !ok {
		return
	}

	var req MobilePostureRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	dev, err := h.identity.ReportMobilePosture(r.Context(), tenantID, identity.MobilePostureInput{
		DeviceKey:   claims.DeviceKey,
		Posture:     req.Posture,
		OIDCSubject: claims.OIDCSubject,
		Actor:       actorFromContext(r),
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDeviceResponse(dev))
}

// requireMobileSession enforces that the request is authenticated by a
// device-bound mobile session JWT and that the session actually
// carries a device_key. A non-mobile credential (operator console /
// API key) or a malformed mobile token is rejected with 403 — only a
// mobile session may act on its own device.
func requireMobileSession(w http.ResponseWriter, r *http.Request) (middleware.MobileClaims, bool) {
	claims, ok := middleware.MobileClaimsFromContext(r.Context())
	if !ok || !claims.IsMobile() {
		WriteError(w, http.StatusForbidden, "forbidden",
			"a mobile device session is required for this endpoint")
		return middleware.MobileClaims{}, false
	}
	if claims.DeviceKey == "" {
		// A mobile token without a device_key is malformed; it cannot
		// be bound to a device, so it may not self-enroll/report.
		WriteError(w, http.StatusForbidden, "forbidden",
			"mobile session is not bound to a device key")
		return middleware.MobileClaims{}, false
	}
	return claims, true
}

// actorFromContext returns the authenticated SNG user UUID for audit
// attribution, or nil when the session has no SNG user binding.
func actorFromContext(r *http.Request) *uuid.UUID {
	if uid := middleware.UserIDFromContext(r.Context()); uid != uuid.Nil {
		return &uid
	}
	return nil
}
