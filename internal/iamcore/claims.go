package iamcore

import (
	"sort"
	"strings"
)

// Claims is the validated, normalised view of an iam-core access
// token that ShieldNet cares about. It is produced only after the
// signature, issuer, audience, and time-window checks have passed, so
// downstream code may trust every field.
type Claims struct {
	// Subject is the iam-core user_id (`sub`).
	Subject string
	// TenantID is the iam-core tenant identifier (`tenant_id` claim).
	TenantID string
	// Roles are the user's roles, read from the namespaced
	// {issuer}/roles claim (Auth0/iam-core convention) with a plain
	// "roles" fallback.
	Roles []string
	// Scopes are the space-delimited OAuth2 scopes (`scope`).
	Scopes []string
	// Email is the user's email when the token carried the OIDC email
	// scope.
	Email string
	// AMR is the Authentication Methods References array (`amr`) when
	// present.
	AMR []string
	// MFASatisfied reports whether the token evidences a
	// multi-factor authentication: a truthy custom `mfa` claim, or an
	// `amr` value naming a second factor. See mfaFromClaims.
	MFASatisfied bool
}

// HasRole reports whether the token carries the given role
// (case-sensitive, matching iam-core's role naming).
func (c Claims) HasRole(role string) bool {
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// mfaMethods are the amr values iam-core / OIDC providers emit for a
// second authentication factor. Presence of any of them means the
// session is MFA-satisfied. "mfa" itself is included because some
// providers emit a coarse marker rather than the specific method.
var mfaMethods = map[string]bool{
	"mfa":      true,
	"otp":      true,
	"totp":     true,
	"hwk":      true, // hardware key
	"swk":      true, // software key
	"webauthn": true,
	"fido":     true,
	"u2f":      true,
	"sms":      true,
	"phr":      true, // phishing-resistant
	"phrh":     true, // phishing-resistant hardware
}

// claimsFromMap projects a verified JWT claim map onto Claims. issuer
// is the canonical issuer, used to read the namespaced
// {issuer}/roles claim.
func claimsFromMap(m map[string]any, issuer string) Claims {
	c := Claims{
		Subject:  stringClaim(m["sub"]),
		TenantID: stringClaim(m["tenant_id"]),
		Email:    stringClaim(m["email"]),
	}
	c.Scopes = splitScopes(stringClaim(m["scope"]))
	c.Roles = rolesFromClaims(m, issuer)
	c.AMR = stringSlice(m["amr"])
	c.MFASatisfied = mfaFromClaims(m, c.AMR)
	return c
}

// rolesFromClaims reads roles from the namespaced {issuer}/roles
// claim first (iam-core's authoritative location), then falls back to
// a bare "roles" claim. Duplicates are removed and order normalised so
// the result is stable.
func rolesFromClaims(m map[string]any, issuer string) []string {
	var roles []string
	if issuer != "" {
		roles = stringSlice(m[strings.TrimRight(issuer, "/")+"/roles"])
	}
	if len(roles) == 0 {
		roles = stringSlice(m["roles"])
	}
	return dedupeSorted(roles)
}

// mfaFromClaims decides whether the token evidences MFA. A truthy
// custom `mfa` claim (bool true or the strings "true"/"1") wins; else
// any recognised second-factor method in `amr` satisfies it.
func mfaFromClaims(m map[string]any, amr []string) bool {
	switch v := m["mfa"].(type) {
	case bool:
		if v {
			return true
		}
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes":
			return true
		}
	}
	for _, a := range amr {
		if mfaMethods[strings.ToLower(strings.TrimSpace(a))] {
			return true
		}
	}
	return false
}

// stringClaim coerces a claim value to a string, tolerating the
// any-typed values produced by JSON decoding.
func stringClaim(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

// stringSlice coerces a claim value to a []string, accepting either a
// JSON array of strings or a single string (some providers emit a
// scalar when there is one entry).
func stringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		return []string{strings.TrimSpace(t)}
	default:
		return nil
	}
}

// splitScopes splits a space-delimited OAuth2 scope string.
func splitScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	return strings.Fields(scope)
}

func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
