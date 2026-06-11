package handler

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

// OIDCHandler implements the IdP-federation REST surface: tenant CRUD
// for OIDC provider configs plus the public mobile native-SSO token
// and refresh endpoints.
type OIDCHandler struct {
	configs      repository.IDPConfigRepository
	oidc         *identity.OIDCService
	maxProviders int
	// dirCreds is the optional directory-credential vault. When set
	// (WithDirectoryCredentials), the handler exposes the per-config
	// directory-credential sub-resource that feeds the IdP SyncService.
	// Nil when directory sync is not wired, in which case those routes
	// are not registered at all.
	dirCreds *identity.CredentialVault
}

// NewOIDCHandler returns a ready-to-use OIDC handler. maxProviders
// caps how many provider configs a tenant may register (<= 0 means
// unlimited).
func NewOIDCHandler(configs repository.IDPConfigRepository, oidc *identity.OIDCService, maxProviders int) *OIDCHandler {
	return &OIDCHandler{configs: configs, oidc: oidc, maxProviders: maxProviders}
}

// WithDirectoryCredentials attaches the directory-credential vault,
// enabling the per-config directory-credential admin sub-resource. A
// nil vault is a no-op (the routes stay unregistered), so wiring is
// fail-safe. Returns the receiver for chaining.
func (h *OIDCHandler) WithDirectoryCredentials(vault *identity.CredentialVault) *OIDCHandler {
	if vault != nil {
		h.dirCreds = vault
	}
	return h
}

// Register attaches the authenticated idp-configs CRUD routes. These
// sit behind the standard auth + tenant-scope middleware.
func (h *OIDCHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/idp-configs", h.createConfig)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/idp-configs", h.listConfigs)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/idp-configs/{id}", h.getConfig)
	MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/idp-configs/{id}", h.updateConfig)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/idp-configs/{id}", h.deleteConfig)

	// Directory-credential sub-resource: the sealed per-provider
	// secret the IdP SyncService unseals to call the directory API.
	// Only mounted when a vault is wired (directory sync enabled).
	if h.dirCreds != nil {
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/idp-configs/{id}/directory-credential", h.getDirectoryCredential)
		MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/idp-configs/{id}/directory-credential", h.setDirectoryCredential)
		MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/idp-configs/{id}/directory-credential", h.deleteDirectoryCredential)
	}
}

// RegisterPublic attaches the unauthenticated mobile native-SSO
// endpoints. They are public because the mobile agent has no SNG
// session yet — it is bootstrapping one by presenting a
// cryptographically-verified OIDC ID token (mirrors the public
// /enroll endpoint, which validates a one-time claim token).
func (h *OIDCHandler) RegisterPublic(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/auth/mobile/token", h.mobileToken)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/auth/mobile/refresh", h.mobileRefresh)
}

// --- idp-configs CRUD ----------------------------------------------------

// IDPConfigRequest is the JSON body for create/update of a provider
// config.
type IDPConfigRequest struct {
	ProviderType   string   `json:"provider_type"`
	IssuerURL      string   `json:"issuer_url"`
	ClientID       string   `json:"client_id"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	GroupClaimPath string   `json:"group_claim_path,omitempty"`
	// Enabled defaults to true on create when omitted.
	Enabled *bool `json:"enabled,omitempty"`
}

// IDPConfigResponse is the JSON representation of a provider config.
type IDPConfigResponse struct {
	ID             string   `json:"id"`
	TenantID       string   `json:"tenant_id"`
	ProviderType   string   `json:"provider_type"`
	IssuerURL      string   `json:"issuer_url"`
	ClientID       string   `json:"client_id"`
	AllowedDomains []string `json:"allowed_domains"`
	GroupClaimPath string   `json:"group_claim_path"`
	Enabled        bool     `json:"enabled"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

func toIDPConfigResponse(c repository.IDPConfig) IDPConfigResponse {
	domains := c.AllowedDomains
	if domains == nil {
		domains = []string{}
	}
	return IDPConfigResponse{
		ID:             c.ID.String(),
		TenantID:       c.TenantID.String(),
		ProviderType:   string(c.ProviderType),
		IssuerURL:      c.IssuerURL,
		ClientID:       c.ClientID,
		AllowedDomains: domains,
		GroupClaimPath: c.GroupClaimPath,
		Enabled:        c.Enabled,
		CreatedAt:      c.CreatedAt.Format(time.RFC3339Nano),
		UpdatedAt:      c.UpdatedAt.Format(time.RFC3339Nano),
	}
}

func (h *OIDCHandler) createConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req IDPConfigRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	// Normalize the issuer to its canonical (no trailing slash) form
	// before any validation or storage so that e.g.
	// "https://accounts.google.com/" and "https://accounts.google.com"
	// collapse to one entry. resolveConfig compares issuers the same
	// way, and the unique (tenant_id, issuer_url) index then actually
	// blocks duplicates instead of being bypassable via a trailing slash.
	req.IssuerURL = strings.TrimRight(strings.TrimSpace(req.IssuerURL), "/")
	if req.IssuerURL == "" || req.ClientID == "" || req.ProviderType == "" {
		WriteError(w, http.StatusBadRequest, "missing_field", "provider_type, issuer_url, client_id are required")
		return
	}
	if err := repository.ValidateIDPProviderType(repository.IDPProviderType(req.ProviderType)); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	// Enforce the per-tenant provider cap. The count→create check is
	// not atomic, but this mirrors the deliberate tradeoff documented
	// for the analogous API-key cap (apikey.Service.Create): IdP
	// configs are created at human/admin rate, so the only effect of a
	// race is briefly exceeding the cap by N-1 for N concurrent
	// requests, and the next create rejects. The unique
	// (tenant_id, issuer_url) index still prevents duplicate providers.
	if h.maxProviders > 0 {
		existing, err := h.configs.List(r.Context(), tenantID)
		if err != nil {
			WriteRepositoryError(w, err)
			return
		}
		if len(existing) >= h.maxProviders {
			WriteError(w, http.StatusTooManyRequests, "resource_exhausted",
				"tenant has reached the maximum number of IdP configs")
			return
		}
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	created, err := h.configs.Create(r.Context(), tenantID, repository.IDPConfig{
		ProviderType:   repository.IDPProviderType(req.ProviderType),
		IssuerURL:      req.IssuerURL,
		ClientID:       req.ClientID,
		AllowedDomains: req.AllowedDomains,
		GroupClaimPath: req.GroupClaimPath,
		Enabled:        enabled,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toIDPConfigResponse(created))
}

func (h *OIDCHandler) listConfigs(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	configs, err := h.configs.List(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]IDPConfigResponse, 0, len(configs))
	for _, c := range configs {
		items = append(items, toIDPConfigResponse(c))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *OIDCHandler) getConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	c, err := h.configs.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toIDPConfigResponse(c))
}

func (h *OIDCHandler) updateConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req IDPConfigRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	// Normalize the issuer the same way createConfig does so updates
	// can't reintroduce a trailing-slash variant of an existing config.
	req.IssuerURL = strings.TrimRight(strings.TrimSpace(req.IssuerURL), "/")
	if req.IssuerURL == "" || req.ClientID == "" || req.ProviderType == "" {
		WriteError(w, http.StatusBadRequest, "missing_field", "provider_type, issuer_url, client_id are required")
		return
	}
	if err := repository.ValidateIDPProviderType(repository.IDPProviderType(req.ProviderType)); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	updated, err := h.configs.Update(r.Context(), tenantID, repository.IDPConfig{
		ID:             id,
		ProviderType:   repository.IDPProviderType(req.ProviderType),
		IssuerURL:      req.IssuerURL,
		ClientID:       req.ClientID,
		AllowedDomains: req.AllowedDomains,
		GroupClaimPath: req.GroupClaimPath,
		Enabled:        enabled,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toIDPConfigResponse(updated))
}

func (h *OIDCHandler) deleteConfig(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.configs.Delete(r.Context(), tenantID, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- directory-credential sub-resource -----------------------------------

// DirectoryCredentialRequest is the JSON body for setting a provider's
// directory-API credential. Token is the bearer secret; base_url and
// subject are provider-specific (see identity.DirectoryCredential). The
// credential is sealed at rest and never returned by any endpoint.
type DirectoryCredentialRequest struct {
	BaseURL string `json:"base_url,omitempty"`
	Token   string `json:"token"`
	Subject string `json:"subject,omitempty"`
}

// DirectoryCredentialStatusResponse reports whether a credential is
// configured WITHOUT echoing any secret material.
type DirectoryCredentialStatusResponse struct {
	ConfigID   string `json:"config_id"`
	Configured bool   `json:"configured"`
}

func (h *OIDCHandler) getDirectoryCredential(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	// Confirm the config exists within the tenant first so an unknown
	// id is a 404 rather than silently reporting configured:false.
	if _, err := h.configs.Get(r.Context(), tenantID, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	configured, err := h.dirCreds.Has(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, DirectoryCredentialStatusResponse{ConfigID: id.String(), Configured: configured})
}

func (h *OIDCHandler) setDirectoryCredential(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req DirectoryCredentialRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" {
		WriteError(w, http.StatusBadRequest, "missing_field", "token is required")
		return
	}
	// The config must exist within the tenant. This both yields a clean
	// 404 for an unknown id and prevents seeding a credential against
	// another tenant's config id (the store FK only checks existence,
	// not ownership).
	if _, err := h.configs.Get(r.Context(), tenantID, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	err := h.dirCreds.Put(r.Context(), tenantID, id, identity.DirectoryCredential{
		BaseURL: strings.TrimSpace(req.BaseURL),
		Token:   token,
		Subject: strings.TrimSpace(req.Subject),
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, DirectoryCredentialStatusResponse{ConfigID: id.String(), Configured: true})
}

func (h *OIDCHandler) deleteDirectoryCredential(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.dirCreds.Clear(r.Context(), tenantID, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- mobile native SSO ---------------------------------------------------

// MobileTokenRequest is the JSON body for POST /auth/mobile/token.
type MobileTokenRequest struct {
	// IDToken is the OIDC ID token obtained by the mobile agent's
	// native sign-in.
	IDToken string `json:"id_token"`
	// Issuer optionally pins which registered provider to validate
	// against; when omitted it is derived from the token's iss claim.
	Issuer string `json:"issuer,omitempty"`
	// DevicePublicKey is the base64 Ed25519 device key the resulting
	// SNG session is bound to.
	DevicePublicKey string `json:"device_public_key"`
}

// MobileRefreshRequest is the JSON body for POST /auth/mobile/refresh.
type MobileRefreshRequest struct {
	RefreshToken    string `json:"refresh_token"`
	Issuer          string `json:"issuer"`
	DevicePublicKey string `json:"device_public_key"`
}

// MobileIdentity is the validated user identity returned alongside an
// SNG session.
type MobileIdentity struct {
	UserID   string   `json:"user_id"`
	TenantID string   `json:"tenant_id"`
	Email    string   `json:"email"`
	Subject  string   `json:"subject"`
	Provider string   `json:"provider"`
	Issuer   string   `json:"issuer"`
	Groups   []string `json:"groups,omitempty"`
}

// MobileBinding documents what the minted SNG session is cryptographically
// bound to: the device's Ed25519 public key AND the user's OIDC subject.
type MobileBinding struct {
	DevicePublicKey string `json:"device_public_key"`
	UserSubject     string `json:"user_subject"`
}

// MobileSessionResponse is the response for both the token-exchange and
// refresh endpoints.
type MobileSessionResponse struct {
	AccessToken string         `json:"access_token"`
	TokenType   string         `json:"token_type"`
	ExpiresIn   int            `json:"expires_in"`
	ExpiresAt   string         `json:"expires_at"`
	Identity    MobileIdentity `json:"identity"`
	Binding     MobileBinding  `json:"binding"`
}

func toMobileSessionResponse(res identity.SessionResult) MobileSessionResponse {
	return MobileSessionResponse{
		AccessToken: res.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(res.TTL.Seconds()),
		ExpiresAt:   res.ExpiresAt.Format(time.RFC3339Nano),
		Identity: MobileIdentity{
			UserID:   idOrEmpty(res.Identity.UserID),
			TenantID: idOrEmpty(res.Identity.TenantID),
			Email:    res.Identity.Email,
			Subject:  res.Identity.Subject,
			Provider: string(res.Identity.Provider),
			Issuer:   res.Identity.Issuer,
			Groups:   res.Identity.Groups,
		},
		Binding: MobileBinding{
			DevicePublicKey: res.DevicePublicKey,
			UserSubject:     res.Identity.Subject,
		},
	}
}

func idOrEmpty(id uuid.UUID) string {
	if id == uuid.Nil {
		return ""
	}
	return id.String()
}

// validateDeviceKey fails fast on a device_public_key that is not a
// base64-encoded 32-byte Ed25519 public key. Without this the value
// would be embedded verbatim as an opaque session claim and only
// rejected (if at all) by downstream ZTNA enforcement. decodePublicKey
// is shared with the claim-token enrollment path so the accepted base64
// variants stay consistent across enrollment surfaces.
func validateDeviceKey(w http.ResponseWriter, key string) bool {
	b, err := decodePublicKey(key)
	if err != nil {
		WriteError(w, http.StatusBadRequest, "invalid_param", "invalid device_public_key: "+err.Error())
		return false
	}
	if len(b) != ed25519.PublicKeySize {
		WriteError(w, http.StatusBadRequest, "invalid_param",
			fmt.Sprintf("device_public_key must be a %d-byte Ed25519 key, got %d bytes", ed25519.PublicKeySize, len(b)))
		return false
	}
	return true
}

func (h *OIDCHandler) mobileToken(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req MobileTokenRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.IDToken == "" || req.DevicePublicKey == "" {
		WriteError(w, http.StatusBadRequest, "missing_field", "id_token and device_public_key are required")
		return
	}
	if !validateDeviceKey(w, req.DevicePublicKey) {
		return
	}
	res, err := h.oidc.IssueSessionFromIDToken(r.Context(), tenantID, identity.TokenExchangeInput{
		IDToken:         req.IDToken,
		Issuer:          req.Issuer,
		DevicePublicKey: req.DevicePublicKey,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toMobileSessionResponse(res))
}

func (h *OIDCHandler) mobileRefresh(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req MobileRefreshRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.RefreshToken == "" || req.Issuer == "" || req.DevicePublicKey == "" {
		WriteError(w, http.StatusBadRequest, "missing_field", "refresh_token, issuer and device_public_key are required")
		return
	}
	if !validateDeviceKey(w, req.DevicePublicKey) {
		return
	}
	res, err := h.oidc.RefreshSession(r.Context(), tenantID, identity.RefreshInput{
		RefreshToken:    req.RefreshToken,
		Issuer:          req.Issuer,
		DevicePublicKey: req.DevicePublicKey,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toMobileSessionResponse(res))
}
