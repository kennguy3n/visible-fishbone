package middleware

import (
	"net/http"

	"github.com/google/uuid"
)

// AssertTenantContext is a defense-in-depth tenant-isolation
// middleware. RLS (Postgres row-level security) is the PRIMARY
// boundary; this middleware adds a second, independent layer at the
// request edge so a routing or handler bug cannot let a request run
// without an authoritatively-resolved tenant.
//
// It is meant for tenant-scoped routes that derive their tenant from
// the authenticated principal (the JWT `tenant_id` claim) rather than
// from a `{tenant_id}` path segment — for those, RequireTenant already
// pins the path tenant to the claim. AssertTenantContext:
//
//   - rejects (403) any wrapped request that reaches it WITHOUT a
//     tenant bound by Auth, i.e. an unscoped credential trying to use
//     a tenant-scoped endpoint (fail closed);
//   - stamps the resolved tenant as the request's "expected RLS
//     tenant" (ExpectedRLSTenantFromContext) so the data layer's GUC
//     read-back assertion (internal/repository/postgres.setTenantGUC)
//     has a single trusted value to verify the live `sng.tenant_id`
//     connection state against.
//
// Together with that read-back, the full chain is: JWT claim →
// resolved tenant (asserted here) → repository GUC (asserted there),
// so a divergence at any hop fails the request rather than silently
// crossing a tenant boundary.
func AssertTenantContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tid := TenantIDFromContext(r.Context())
		if tid == uuid.Nil {
			// A tenant-scoped endpoint reached with a credential that
			// carries no tenant (e.g. a platform-admin or API key not
			// bound to a tenant). Without a tenant the RLS GUC would be
			// unset and every query would silently return zero rows;
			// surface that as an explicit authorization failure instead.
			writeTenantError(w, http.StatusForbidden, "tenant_required",
				"this endpoint requires a tenant-scoped credential")
			return
		}
		ctx := withExpectedTenant(r.Context(), tid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
