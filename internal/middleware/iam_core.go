package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/iamcore"
	"github.com/kennguy3n/visible-fishbone/internal/repository/postgres"
)

// IAMCoreValidator validates an incoming iam-core access token. It is
// satisfied by *iamcore.Client; the interface keeps the middleware
// unit-testable with a fake.
type IAMCoreValidator interface {
	// Issuer is the canonical iam-core issuer. Auth routes a Bearer
	// token to this validator only when the token's unverified `iss`
	// matches, so iam-core and the legacy operator-console / HMAC
	// tokens can coexist on the same Authorization header.
	Issuer() string
	// VerifyAccessToken fully validates the token (signature via JWKS,
	// iss/aud/exp/nbf) and returns its normalised claims, or an error
	// (fail-closed).
	VerifyAccessToken(ctx context.Context, raw string) (iamcore.Claims, error)
}

// TenantResolver maps an iam-core tenant identifier (the `tenant_id`
// claim, an opaque iam-core string) onto the local SNG tenant UUID so
// the rest of the control plane — and the Postgres RLS GUC — operate
// on the native tenant model. Implementations live in the tenant
// service.
type TenantResolver interface {
	// ResolveTenant returns the SNG tenant UUID for an iam-core
	// tenant_id, or an error when no SNG tenant is mapped (the request
	// is then rejected — an authenticated user whose tenant we cannot
	// place must not fall through to an unscoped context).
	ResolveTenant(ctx context.Context, iamCoreTenantID string) (uuid.UUID, error)
}

// IAMCoreIdentity is the request-scoped view of a caller authenticated
// by an iam-core access token. It is stamped onto the context only
// after full verification, so handlers may trust every field.
type IAMCoreIdentity struct {
	// Subject is the iam-core user_id (`sub`).
	Subject string
	// TenantID is the iam-core tenant identifier (`tenant_id` claim,
	// before mapping to the SNG tenant UUID).
	TenantID string
	// SNGTenantID is the resolved local tenant UUID (uuid.Nil when no
	// resolver was configured).
	SNGTenantID uuid.UUID
	// Roles are the user's iam-core roles.
	Roles []string
	// Scopes are the OAuth2 scopes on the token.
	Scopes []string
	// Email is the user's email (when the token carried it).
	Email string
	// MFASatisfied reports whether the token evidences MFA (see
	// iamcore.Claims). The step-up gate (RequireMFA) consults it.
	MFASatisfied bool
}

// HasRole reports whether the identity carries the given role.
func (i IAMCoreIdentity) HasRole(role string) bool {
	for _, r := range i.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// withIAMCoreIdentity stamps the verified iam-core identity onto the
// context. Called by Auth only after VerifyAccessToken succeeds.
func withIAMCoreIdentity(ctx context.Context, id IAMCoreIdentity) context.Context {
	return context.WithValue(ctx, keyIAMCoreID, id)
}

// IAMCoreIdentityFromContext returns the iam-core identity surfaced by
// Auth, and false when the request was not authenticated by an
// iam-core token (legacy operator-console / API-key / mobile auth).
func IAMCoreIdentityFromContext(ctx context.Context) (IAMCoreIdentity, bool) {
	v, ok := ctx.Value(keyIAMCoreID).(IAMCoreIdentity)
	return v, ok
}

// WithIAMCoreIdentityForTest stamps an iam-core identity onto a
// context for tests that exercise downstream handlers/middleware
// (e.g. RequireMFA) without minting and verifying a real token.
func WithIAMCoreIdentityForTest(ctx context.Context, id IAMCoreIdentity) context.Context {
	return withIAMCoreIdentity(ctx, id)
}

// WithIAMCore enables validation of upstream iam-core access tokens in
// the Auth middleware. It is additive: when the option is omitted Auth
// behaves exactly as before. When set, a Bearer token whose `iss`
// matches the validator's issuer is validated against iam-core
// (fail-closed) instead of the legacy HMAC path; all other tokens are
// unaffected.
//
// resolver may be nil, in which case the iam-core identity is surfaced
// but no SNG tenant UUID / RLS GUC is bound (useful for endpoints that
// do not touch tenant-scoped storage). When resolver is non-nil, a
// tenant that cannot be mapped causes a 403.
func WithIAMCore(v IAMCoreValidator, resolver TenantResolver) AuthOption {
	return func(o *authOptions) {
		o.iamCore = v
		o.tenantResolver = resolver
	}
}

// authenticateIAMCore validates an iam-core Bearer token and, on
// success, returns the request context enriched with the iam-core
// identity (and the resolved SNG tenant + RLS GUC). It fully owns the
// HTTP response on failure (writing the appropriate 401/403) and
// reports handled=true so the caller stops processing.
func (o *authOptions) authenticateIAMCore(w http.ResponseWriter, r *http.Request, raw string) (context.Context, bool) {
	claims, err := o.iamCore.VerifyAccessToken(r.Context(), raw)
	if err != nil {
		// Fail-closed: any verification problem is a 401. We do not
		// fall back to the HMAC path — the token claimed the iam-core
		// issuer, so accepting it any other way would be a downgrade.
		writeAuthError(w, "invalid_token")
		return nil, true
	}

	// Tenant binding (Task 2). The `tenant_id` claim is authoritative;
	// when an X-Tenant-ID header is also present it MUST match, else
	// 403 — a token minted for tenant A must never act on tenant B.
	if hdr := strings.TrimSpace(r.Header.Get("X-Tenant-ID")); hdr != "" && hdr != claims.TenantID {
		writeAuthErrorStatus(w, http.StatusForbidden, "tenant_mismatch",
			"X-Tenant-ID header does not match token tenant")
		return nil, true
	}

	ctx := r.Context()
	meta := RequestMetaFromContext(ctx)

	identity := IAMCoreIdentity{
		Subject:      claims.Subject,
		TenantID:     claims.TenantID,
		Roles:        claims.Roles,
		Scopes:       claims.Scopes,
		Email:        claims.Email,
		MFASatisfied: claims.MFASatisfied,
	}

	// Map the iam-core tenant onto the SNG tenant model + RLS GUC.
	if o.tenantResolver != nil {
		sngTenant, resolveErr := o.tenantResolver.ResolveTenant(ctx, claims.TenantID)
		if resolveErr != nil || sngTenant == uuid.Nil {
			writeAuthErrorStatus(w, http.StatusForbidden, "tenant_not_mapped",
				"no ShieldNet tenant is mapped to the token's iam-core tenant")
			return nil, true
		}
		identity.SNGTenantID = sngTenant
		ctx = withTenantID(ctx, sngTenant)
		meta.SetTenantID(sngTenant)
		// Bind the RLS GUC expectation so the repository layer scopes
		// every query to this tenant — identical to the operator-console
		// and RequireTenant paths.
		ctx = postgres.WithExpectedTenant(ctx, sngTenant.String())
	}

	// Surface the iam-core user id as the auth subject for audit/logging
	// parity with the other auth paths.
	if claims.Subject != "" {
		ctx = withAuthSubject(ctx, claims.Subject)
	}
	ctx = withIAMCoreIdentity(ctx, identity)
	return ctx, true
}

// unverifiedIssuer extracts the `iss` claim from a JWT WITHOUT
// verifying its signature. It is used solely to ROUTE a Bearer token
// to the right verifier (iam-core vs legacy HMAC); the routed verifier
// then performs the real cryptographic + claim validation, so reading
// an unverified claim here is safe. Returns "" when the token is
// malformed.
func unverifiedIssuer(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Iss
}
