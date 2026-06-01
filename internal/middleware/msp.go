package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// MSPAuthorizer is the narrow interface RequireMSPScope depends on.
// Implemented by *rbac.Service — defined here as a small interface
// so the middleware package does not import the service package
// (which would otherwise be an import cycle since the service
// package depends on middleware for context accessors).
type MSPAuthorizer interface {
	// AuthorizeMSP reports whether the user holds an msp-scoped
	// (or platform-wildcard) grant carrying the given permission
	// against the given MSP.
	AuthorizeMSP(ctx context.Context, userID, mspID uuid.UUID, permission string) (bool, error)

	// AuthorizePlatform reports whether the user holds a
	// platform-scoped grant carrying the given permission. Used
	// by routes that operate above any specific MSP (notably
	// `GET /api/v1/msps` and `POST /api/v1/msps`, where no
	// msp_id is in the URL). MSP-scoped grants do NOT satisfy
	// this check — an operator with msp_admin on one MSP must
	// not be able to enumerate or create others.
	AuthorizePlatform(ctx context.Context, userID uuid.UUID, permission string) (bool, error)
}

// RequireMSP ensures the resolved MSP ID matches the `msp_id` path
// parameter on every protected MSP route. Mirrors RequireTenant but
// for the MSP hierarchy. Stamps the parsed MSP UUID onto the
// request context so downstream handlers can call
// MSPIDFromContext without re-parsing.
//
// Use this when an endpoint already has a higher-level authorization
// gate (e.g. a platform-admin-only path) and only needs the path
// param sanity-checked. For permission-gated endpoints, wrap with
// RequireMSPScope which combines the path bind + an
// AuthorizeMSP check.
func RequireMSP(pathParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mspID, ok := parseMSPID(w, r, pathParam)
			if !ok {
				return
			}
			ctx := withMSPID(r.Context(), mspID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireMSPScope is the permission-gated counterpart to RequireMSP.
// It parses the `msp_id` path parameter, calls
// MSPAuthorizer.AuthorizeMSP for the request's user against the
// given permission, and either passes through (after stamping the
// context) or returns 403.
//
// The MSP authorizer is injected so the middleware stays a thin
// shim over service-layer policy: tests can pass a stub, and the
// production wiring binds *rbac.Service.
func RequireMSPScope(authz MSPAuthorizer, permission string, pathParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mspID, ok := parseMSPID(w, r, pathParam)
			if !ok {
				return
			}
			userID := UserIDFromContext(r.Context())
			if userID == uuid.Nil {
				writeMSPError(w, http.StatusUnauthorized, "unauthenticated",
					"msp-scoped routes require an authenticated user identity")
				return
			}
			allowed, err := authz.AuthorizeMSP(r.Context(), userID, mspID, permission)
			if err != nil {
				writeMSPError(w, http.StatusInternalServerError, "authorization_failed",
					"failed to evaluate msp authorization")
				return
			}
			if !allowed {
				writeMSPError(w, http.StatusForbidden, "msp_forbidden",
					"credentials do not authorise this msp scope")
				return
			}
			ctx := withMSPID(r.Context(), mspID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func parseMSPID(w http.ResponseWriter, r *http.Request, pathParam string) (uuid.UUID, bool) {
	raw := r.PathValue(pathParam)
	if raw == "" {
		writeMSPError(w, http.StatusBadRequest, "missing_msp", "msp_id path parameter is required")
		return uuid.Nil, false
	}
	mspID, err := uuid.Parse(strings.TrimSpace(raw))
	if err != nil {
		writeMSPError(w, http.StatusBadRequest, "invalid_msp", "msp_id is not a valid UUID")
		return uuid.Nil, false
	}
	return mspID, true
}

func writeMSPError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
