package middleware

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

// RequireTenant ensures the resolved tenant ID matches the
// `tenant_id` path parameter on every protected route. It is used
// to prevent JWT-A from operating on tenant-B's resources by
// forging a path parameter.
//
// pathParam is the name of the path parameter (e.g. "tenant_id").
// The middleware is mounted *inside* the auth chain so it can rely
// on the tenant ID already being in context. Per-route mounting
// (not a single apiMux wrapper) is required because
// r.PathValue is only populated after the mux has matched the
// pattern; a wrapper around the bare mux would always see empty.
// The handler.MountTenantScoped helper applies this automatically
// for any pattern containing "{tenant_id}".
func RequireTenant(pathParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pathTenant := r.PathValue(pathParam)
			if pathTenant == "" {
				writeTenantError(w, http.StatusBadRequest, "missing_tenant", "tenant_id path parameter is required")
				return
			}
			pid, err := uuid.Parse(strings.TrimSpace(pathTenant))
			if err != nil {
				writeTenantError(w, http.StatusBadRequest, "invalid_tenant", "tenant_id is not a valid UUID")
				return
			}
			ctxTenant := TenantIDFromContext(r.Context())
			if ctxTenant != uuid.Nil && ctxTenant != pid {
				writeTenantError(w, http.StatusForbidden, "tenant_mismatch", "credentials do not authorise this tenant")
				return
			}
			// Either credentials carry a tenant matching the path,
			// or they were global (platform_admin) — in both
			// cases we bind the path tenant onto the context so
			// downstream handlers can scope queries.
			ctx := withTenantID(r.Context(), pid)
			// Defense-in-depth: record the path tenant (now proven to
			// match the JWT claim for tenant-bound credentials) as the
			// authoritative RLS tenant. The repository layer asserts the
			// live sng.tenant_id GUC equals this value before running any
			// tenant-scoped query (see postgres.setTenantGUC), so a
			// divergence between the resolved tenant and the connection
			// state fails closed instead of crossing a tenant boundary.
			ctx = withExpectedTenant(ctx, pid)
			// Late-bind onto the outer Logging meta too — for
			// platform_admin requests the JWT had no tenant_id
			// claim, so Auth left the meta's tenant_id empty;
			// this is the first place we know it.
			RequestMetaFromContext(ctx).SetTenantID(pid)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func writeTenantError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
