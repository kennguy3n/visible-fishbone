package middleware

import (
	"context"
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/iamcore"
)

// StepUpIntrospector confirms, server-side, that the caller's session
// satisfies MFA — the authoritative fallback when the access token
// itself carries no MFA marker. Satisfied by *iamcore.Client via
// Introspect. The middleware passes the caller's raw bearer token.
type StepUpIntrospector interface {
	Introspect(ctx context.Context, token string) (iamcore.Introspection, error)
}

// RequireMFA gates sensitive control-plane operations (policy changes,
// device enrollment, API-key creation) behind a multi-factor
// authentication check, per the iam-core MFA-enforcement contract
// (Session 2A, Task 5).
//
// It MUST be mounted INSIDE the Auth chain so the verified iam-core
// identity is already on the context. Decision order:
//
//  1. No iam-core identity on the context → the request was
//     authenticated some other way (operator-console / API-key /
//     mobile). RequireMFA does not apply; pass through. (iam-core MFA
//     enforcement only governs iam-core-authenticated callers.)
//  2. The access token already evidences MFA (amr / custom mfa claim)
//     → pass through.
//  3. Otherwise, when an introspector is configured, confirm via
//     iam-core /oauth2/introspect that the live session is
//     MFA-satisfied. iam-core does NOT expose a verify endpoint, so
//     introspection (or a fresh OIDC re-auth driven by the client) is
//     the correct step-up signal.
//  4. If none of the above is satisfied → 401 mfa_required, signalling
//     the client to re-authenticate with MFA.
//
// introspector may be nil; then only the token-claim evidence (step 2)
// can satisfy the gate.
func RequireMFA(introspector StepUpIntrospector) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := IAMCoreIdentityFromContext(r.Context())
			if !ok {
				// Not an iam-core caller — this gate doesn't govern it.
				next.ServeHTTP(w, r)
				return
			}
			if identity.MFASatisfied {
				next.ServeHTTP(w, r)
				return
			}
			if introspector != nil {
				if token := bearerToken(r); token != "" {
					res, err := introspector.Introspect(r.Context(), token)
					if err == nil && res.Active && res.MFASatisfied {
						next.ServeHTTP(w, r)
						return
					}
				}
			}
			// Fail-closed: require step-up. 401 (not 403) so the client
			// knows to re-authenticate rather than treating it as a
			// permanent authorization denial.
			writeAuthErrorStatus(w, http.StatusUnauthorized, "mfa_required",
				"multi-factor authentication is required for this operation")
		})
	}
}

// bearerToken returns the raw bearer token from the Authorization
// header, or "" when absent/!Bearer.
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	authz := r.Header.Get("Authorization")
	if len(authz) <= len(prefix) || authz[:len(prefix)] != prefix {
		return ""
	}
	return authz[len(prefix):]
}
