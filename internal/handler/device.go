package handler

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
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
	identity   *identity.Service
	devices    repository.DeviceRepository
	enrollment *identity.EnrollmentService

	// claimTokenTTL is the default lifetime of a claim token when
	// the request body omits it.
	claimTokenTTL time.Duration

	// enrollGuard, when set, throttles failed device enrolments per
	// source IP on the public POST /api/v1/enroll endpoint: after a
	// threshold of failed claim-token redemptions one IP is locked out
	// for a cooldown. Nil disables the lockout.
	enrollGuard *middleware.AttemptLimiter
	// logger, when set, records failed enrolment attempts (source IP,
	// tenant, device, reason). Nil suppresses the log.
	logger *slog.Logger
}

// NewDeviceHandler wires the handler.
func NewDeviceHandler(identitySvc *identity.Service, devices repository.DeviceRepository, defaultClaimTTL time.Duration) *DeviceHandler {
	if defaultClaimTTL <= 0 {
		defaultClaimTTL = 24 * time.Hour
	}
	return &DeviceHandler{identity: identitySvc, devices: devices, claimTokenTTL: defaultClaimTTL}
}

// SetEnrollmentService attaches the enrollment service.
func (h *DeviceHandler) SetEnrollmentService(es *identity.EnrollmentService) {
	h.enrollment = es
}

// SetBruteForceGuard attaches the IP-keyed brute-force guard and
// logger used to throttle and audit failed device enrolments on the
// public enroll endpoint. Either argument may be nil.
func (h *DeviceHandler) SetBruteForceGuard(guard *middleware.AttemptLimiter, logger *slog.Logger) {
	h.enrollGuard = guard
	h.logger = logger
}

// Register attaches routes.
func (h *DeviceHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/claim-tokens", h.createClaimToken)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/devices/enroll", h.enroll)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/devices", h.list)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/devices/{id}", h.get)

	// Enrollment endpoints (Task 30).
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/devices/{id}/refresh-cert", h.refreshCert)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/devices/{id}/revoke", h.revokeDevice)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/devices/{id}/status", h.enrollmentStatus)
}

// RegisterPublic attaches unauthenticated enrollment routes.
// POST /api/v1/enroll does not require auth — the claim token is the credential.
func (h *DeviceHandler) RegisterPublic(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/enroll", h.enrollDevice)
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
	// Body is optional for this endpoint, but we MUST attempt to
	// decode whenever the client may have sent one.
	//
	// r.ContentLength is:
	//   *  > 0  for fixed-length bodies (Content-Length header set)
	//   *  0    when the client explicitly sent no body
	//   * -1    when the body is sent with Transfer-Encoding: chunked
	//          (Content-Length unknown until the chunk stream ends)
	//
	// The previous guard `r.ContentLength > 0` silently ignored the
	// chunked case — a client streaming `{"ttl_seconds": 120}` over
	// chunked encoding would get the compiled-in default TTL applied
	// silently, with NO error and no log line. `!= 0` covers both
	// fixed-length and chunked bodies; an empty chunked body is then
	// handled by treating io.EOF from the JSON decoder as
	// "client sent no body" rather than as a 400 malformed-body
	// error (which would break the "body is optional" contract).
	if r.ContentLength != 0 {
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			if errors.Is(err, io.EOF) {
				// chunked transfer with zero bytes — treat as
				// "no body", apply server defaults.
			} else {
				WriteError(w, http.StatusBadRequest, "invalid_body", err.Error())
				return
			}
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

	// Stamp the audited actor on the issued token. The
	// identity service threads this through to both
	// `ClaimToken.CreatedBy` (so the row carries provenance) and
	// the `claim_token.created` audit log entry. Passing `nil`
	// here silently drops the link between the request's
	// authenticated principal and the credential they minted,
	// breaking forensic trace of "who issued this enrolment
	// token" — exactly the question an investigator asks when an
	// enrolment is later abused.
	res, err := h.identity.GenerateClaimToken(r.Context(), tenantID, ttl, actorFromCtx(r))
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

// --- Enrollment endpoints (Task 30) --------------------------------------

// EnrollDeviceRequest is the JSON body for POST /api/v1/enroll.
type EnrollDeviceRequest struct {
	ClaimToken string `json:"claim_token"`
	TenantID   string `json:"tenant_id"`
	DeviceID   string `json:"device_id"`
	PublicKey  string `json:"public_key_ed25519"`
}

// EnrollDeviceResponse is the JSON response for POST /api/v1/enroll.
type EnrollDeviceResponse struct {
	DeviceID  string `json:"device_id"`
	TenantID  string `json:"tenant_id"`
	Status    string `json:"status"`
	CertPEM   string `json:"cert_pem"`
	ExpiresAt string `json:"expires_at"`
}

func (h *DeviceHandler) enrollDevice(w http.ResponseWriter, r *http.Request) {
	if h.enrollment == nil {
		WriteError(w, http.StatusNotImplemented, "not_implemented", "enrollment service not configured")
		return
	}
	// Brute-force gate: a flood of failed claim-token redemptions from
	// one IP (e.g. guessing claim tokens) trips a cooldown before any
	// crypto runs. Malformed requests below are NOT counted — only a
	// failed redemption, which is the actual credential check.
	var ip string
	if h.enrollGuard != nil {
		ip = h.enrollGuard.ClientIP(r)
		if retryAfter, blocked := h.enrollGuard.Blocked(ip); blocked {
			w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
			WriteError(w, http.StatusTooManyRequests, "too_many_failed_enrollments",
				"too many failed enrollment attempts; try again later")
			return
		}
	}
	var req EnrollDeviceRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.ClaimToken == "" || req.PublicKey == "" || req.TenantID == "" || req.DeviceID == "" {
		WriteError(w, http.StatusBadRequest, "missing_field", "claim_token, tenant_id, device_id, public_key_ed25519 are required")
		return
	}
	tenantID, err := uuid.Parse(req.TenantID)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_param", "tenant_id is not a valid UUID")
		return
	}
	deviceID, err := uuid.Parse(req.DeviceID)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_param", "device_id is not a valid UUID")
		return
	}
	pubKeyBytes, err := decodePublicKey(req.PublicKey)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_param", "invalid Ed25519 public key: "+err.Error())
		return
	}

	result, err := h.enrollment.RedeemClaimToken(r.Context(), tenantID, deviceID, req.ClaimToken, pubKeyBytes)
	if err != nil {
		h.recordEnrollFailure(ip, tenantID, deviceID, err)
		WriteRepositoryError(w, err)
		return
	}
	if h.enrollGuard != nil && ip != "" {
		h.enrollGuard.RecordSuccess(ip)
	}
	WriteJSON(w, http.StatusCreated, EnrollDeviceResponse{
		DeviceID:  result.Enrollment.DeviceID.String(),
		TenantID:  result.Enrollment.TenantID.String(),
		Status:    string(result.Enrollment.Status),
		CertPEM:   result.Certificate.CertPEM,
		ExpiresAt: result.Certificate.ExpiresAt.Format(time.RFC3339Nano),
	})
}

// recordEnrollFailure feeds a failed claim-token redemption to the
// brute-force guard (when configured) and logs it. Only genuine
// redemption failures reach here — malformed requests are rejected
// earlier and never counted, so a client sending bad JSON cannot lock
// out its own IP.
func (h *DeviceHandler) recordEnrollFailure(ip string, tenantID, deviceID uuid.UUID, cause error) {
	if h.enrollGuard != nil && ip != "" {
		h.enrollGuard.RecordFailure(ip)
	}
	if h.logger != nil {
		attrs := []any{
			slog.String("event", "enroll_failed"),
			slog.String("tenant_id", tenantID.String()),
			slog.String("device_id", deviceID.String()),
		}
		if ip != "" {
			attrs = append(attrs, slog.String("source_ip", ip))
		}
		if cause != nil {
			attrs = append(attrs, slog.String("reason", cause.Error()))
		}
		h.logger.Warn("device enrollment failed", attrs...)
	}
}

// RefreshCertResponse is the JSON response for cert refresh.
type RefreshCertResponse struct {
	CertPEM   string `json:"cert_pem"`
	ExpiresAt string `json:"expires_at"`
}

func (h *DeviceHandler) refreshCert(w http.ResponseWriter, r *http.Request) {
	if h.enrollment == nil {
		WriteError(w, http.StatusNotImplemented, "not_implemented", "enrollment service not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	deviceID, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	cert, err := h.enrollment.RefreshCertificate(r.Context(), tenantID, deviceID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, RefreshCertResponse{
		CertPEM:   cert.CertPEM,
		ExpiresAt: cert.ExpiresAt.Format(time.RFC3339Nano),
	})
}

func (h *DeviceHandler) revokeDevice(w http.ResponseWriter, r *http.Request) {
	if h.enrollment == nil {
		WriteError(w, http.StatusNotImplemented, "not_implemented", "enrollment service not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	deviceID, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.enrollment.RevokeDevice(r.Context(), tenantID, deviceID); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// EnrollmentStatusResponse is the JSON response for enrollment status.
type EnrollmentStatusResponse struct {
	DeviceID       string  `json:"device_id"`
	TenantID       string  `json:"tenant_id"`
	Status         string  `json:"status"`
	EnrolledAt     string  `json:"enrolled_at"`
	LastCertIssued *string `json:"last_cert_issued_at,omitempty"`
	RevokedAt      *string `json:"revoked_at,omitempty"`
}

func (h *DeviceHandler) enrollmentStatus(w http.ResponseWriter, r *http.Request) {
	if h.enrollment == nil {
		WriteError(w, http.StatusNotImplemented, "not_implemented", "enrollment service not configured")
		return
	}
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	deviceID, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	e, err := h.enrollment.GetEnrollmentStatus(r.Context(), tenantID, deviceID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	resp := EnrollmentStatusResponse{
		DeviceID:   e.DeviceID.String(),
		TenantID:   e.TenantID.String(),
		Status:     string(e.Status),
		EnrolledAt: e.EnrolledAt.Format(time.RFC3339Nano),
	}
	if e.LastCertIssuedAt != nil {
		s := e.LastCertIssuedAt.Format(time.RFC3339Nano)
		resp.LastCertIssued = &s
	}
	if e.RevokedAt != nil {
		s := e.RevokedAt.Format(time.RFC3339Nano)
		resp.RevokedAt = &s
	}
	WriteJSON(w, http.StatusOK, resp)
}

func decodePublicKey(s string) ([]byte, error) {
	if len(s) == 0 {
		return nil, errors.New("empty public key")
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid base64")
}
