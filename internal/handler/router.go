package handler

import (
	"log/slog"
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/metrics"
	"github.com/kennguy3n/visible-fishbone/internal/middleware"
)

// RouterDeps bundles the dependencies needed to compose the API
// router. Each handler is injected separately so callers can swap
// real implementations for in-memory ones in tests.
type RouterDeps struct {
	Config           *config.Config
	Logger           *slog.Logger
	Tenants          *TenantHandler
	TenantMigration  *TenantMigrationHandler
	Sites            *SiteHandler
	Devices          *DeviceHandler
	RBAC             *RBACHandler
	Policy           *PolicyHandler
	PolicySimulation *PolicySimulationHandler
	Audit            *AuditHandler
	Webhooks         *WebhookHandler
	APIKeys          *APIKeyHandler
	Telemetry        *TelemetryHandler
	AppRegistry      *AppRegistryHandler
	Baseline         *BaselineHandler
	Alert            *AlertHandler
	Integrations     *IntegrationHandler
	CASB             *CASBHandler
	PolicyTemplates  *PolicyTemplateHandler
	MSP              *MSPHandler
	Browser          *BrowserHandler
	Terraform        *TerraformHandler
	AI               *AIHandler
	DLP              *DLPHandler
	DLPReview        *DLPReviewHandler
	Rollout          *RolloutHandler
	SCIM             *SCIMHandler
	Compliance       *ComplianceHandler
	Playbook         *PlaybookHandler
	Troubleshoot     *TroubleshootHandler
	OIDC             *OIDCHandler
	Mobile           *MobileHandler
	// AdminSSO, when set, exposes the public iam-core OAuth2 admin
	// login + callback endpoints (Session 2A, Task 3).
	AdminSSO     *AdminSSOHandler
	Metering     *MeteringHandler
	PoP          *PoPHandler
	ThreatFeed   *ThreatFeedHandler
	Sandbox      *SandboxHandler
	RBI          *RBIHandler
	OpenAPISpec  *OpenAPIHandler
	APIKeyLookup middleware.APIKeyLookup
	// MobileDeviceStatus, when set, enables the auth-middleware
	// device kill-switch for mobile session JWTs: a token bound to a
	// suspended/deleted device is refused on every endpoint, not just
	// the mobile self-service ones.
	MobileDeviceStatus middleware.MobileDeviceStatusResolver
	// IAMCore, when set, enables validation of upstream iam-core
	// access tokens in the auth middleware (additive — legacy
	// API-key / mobile / HMAC auth is unaffected). IAMCoreTenant maps
	// the iam-core tenant_id claim onto the SNG tenant UUID (and binds
	// the RLS GUC); nil surfaces the identity without tenant scoping.
	IAMCore       middleware.IAMCoreValidator
	IAMCoreTenant middleware.TenantResolver
	RateLimiter   *middleware.RateLimiter
	// TenantRateLimiter, when set, enforces a per-tenant token-bucket
	// request budget AFTER authentication (so the resolved tenant is in
	// context). Nil disables it (the chain degrades to a pass-through),
	// leaving only the outer per-IP RateLimiter in place.
	TenantRateLimiter *middleware.TenantRateLimiter
	// AuthBruteForce, when set, throttles credential-validation
	// failures per source IP in the auth middleware: after a threshold
	// of failures one IP is locked out for a cooldown. Nil disables the
	// lockout (failed attempts are still logged when Logger is set).
	AuthBruteForce *middleware.AttemptLimiter
	// ActivityRecorder, when set, records the resolved tenant of every
	// authenticated API request as active so the dormancy planner has a
	// control-plane activity signal alongside the data-plane one fed by
	// the telemetry consumer. Nil degrades the middleware to a
	// transparent pass-through.
	ActivityRecorder middleware.ActivityObserver
	Health           *Health
	OpsHealth        *OpsHealthHandler
	BulkDevice       *BulkDeviceHandler
	// Metrics, when non-nil, installs the Prometheus HTTP
	// instrumentation middleware (request count / duration /
	// in-flight) at the top of the chain. Nil disables it (the
	// middleware degrades to a transparent pass-through), so tests
	// that don't care about metrics can leave it unset.
	Metrics *metrics.Metrics
	// ManagedThreatContent, when set, exposes the managed (curated)
	// threat-content surface (WP3): a tenant-scoped read of the
	// fleet-wide curated bundle a tenant receives and a system-scoped
	// manual refresh trigger. Distinct from ThreatFeed, which serves
	// the operator-configured ai feed-coverage view.
	ManagedThreatContent *ManagedThreatContentHandler
}

// NewRouter composes the full API mux + middleware chain.
//
// The route layout is:
//
//	/healthz, /readyz           — public, no auth
//	/api/v1/docs                — public (operator console fetches it)
//	/api/v1/*                   — auth (JWT or API key) + tenant scoping
//
// We expose two separate sub-muxes so the auth/tenant middleware
// applies only to the protected API.
func NewRouter(deps RouterDeps) http.Handler {
	publicMux := http.NewServeMux()
	if deps.Health != nil {
		publicMux.HandleFunc("GET /healthz", deps.Health.Liveness)
		publicMux.HandleFunc("GET /readyz", deps.Health.Readiness)
	}
	if deps.OpenAPISpec != nil {
		deps.OpenAPISpec.Register(publicMux)
	}
	if deps.Devices != nil {
		deps.Devices.RegisterPublic(publicMux)
	}
	if deps.OIDC != nil {
		deps.OIDC.RegisterPublic(publicMux)
	}
	if deps.PoP != nil {
		deps.PoP.RegisterPublic(publicMux)
	}
	if deps.AdminSSO != nil {
		deps.AdminSSO.RegisterPublic(publicMux)
	}

	apiMux := http.NewServeMux()
	if deps.Tenants != nil {
		deps.Tenants.Register(apiMux)
	}
	if deps.TenantMigration != nil {
		deps.TenantMigration.Register(apiMux)
	}
	if deps.Sites != nil {
		deps.Sites.Register(apiMux)
	}
	if deps.Devices != nil {
		deps.Devices.Register(apiMux)
	}
	if deps.RBAC != nil {
		deps.RBAC.Register(apiMux)
	}
	if deps.Policy != nil {
		deps.Policy.Register(apiMux)
	}
	if deps.PolicySimulation != nil {
		deps.PolicySimulation.Register(apiMux)
	}
	if deps.Audit != nil {
		deps.Audit.Register(apiMux)
	}
	if deps.Webhooks != nil {
		deps.Webhooks.Register(apiMux)
	}
	if deps.APIKeys != nil {
		deps.APIKeys.Register(apiMux)
	}
	if deps.Telemetry != nil {
		deps.Telemetry.Register(apiMux)
	}
	if deps.AppRegistry != nil {
		deps.AppRegistry.Register(apiMux)
	}
	if deps.Baseline != nil {
		deps.Baseline.Register(apiMux)
	}
	if deps.Alert != nil {
		deps.Alert.Register(apiMux)
	}
	if deps.Integrations != nil {
		deps.Integrations.Register(apiMux)
	}
	if deps.CASB != nil {
		deps.CASB.Register(apiMux)
	}
	if deps.PolicyTemplates != nil {
		deps.PolicyTemplates.Register(apiMux)
	}
	if deps.MSP != nil {
		deps.MSP.Register(apiMux)
	}
	if deps.Browser != nil {
		deps.Browser.Register(apiMux)
	}
	if deps.Terraform != nil {
		deps.Terraform.Register(apiMux)
	}
	if deps.AI != nil {
		deps.AI.Register(apiMux)
	}
	if deps.DLP != nil {
		deps.DLP.Register(apiMux)
	}
	if deps.DLPReview != nil {
		deps.DLPReview.Register(apiMux)
	}
	if deps.Rollout != nil {
		deps.Rollout.Register(apiMux)
	}
	if deps.SCIM != nil {
		deps.SCIM.Register(apiMux)
	}
	if deps.Compliance != nil {
		deps.Compliance.Register(apiMux)
	}
	if deps.Playbook != nil {
		deps.Playbook.Register(apiMux)
	}
	if deps.OpsHealth != nil {
		deps.OpsHealth.Register(apiMux)
	}
	if deps.BulkDevice != nil {
		deps.BulkDevice.Register(apiMux)
	}
	if deps.Troubleshoot != nil {
		deps.Troubleshoot.Register(apiMux)
	}
	if deps.OIDC != nil {
		deps.OIDC.Register(apiMux)
	}
	if deps.Mobile != nil {
		deps.Mobile.Register(apiMux)
	}
	if deps.Metering != nil {
		deps.Metering.Register(apiMux)
	}
	if deps.PoP != nil {
		deps.PoP.Register(apiMux)
	}
	if deps.ThreatFeed != nil {
		deps.ThreatFeed.Register(apiMux)
	}
	if deps.Sandbox != nil {
		deps.Sandbox.Register(apiMux)
	}
	if deps.RBI != nil {
		deps.RBI.Register(apiMux)
	}
	if deps.ManagedThreatContent != nil {
		deps.ManagedThreatContent.Register(apiMux)
	}

	authOpts := []middleware.AuthOption{}
	if deps.MobileDeviceStatus != nil {
		authOpts = append(authOpts, middleware.WithMobileDeviceStatus(deps.MobileDeviceStatus))
	}
	if deps.IAMCore != nil {
		authOpts = append(authOpts, middleware.WithIAMCore(deps.IAMCore, deps.IAMCoreTenant))
	}
	// Brute-force protection + failed-auth logging. The guard may be
	// nil (lockout disabled) while Logger is set (still audit every
	// failure), or both set; WithBruteForceGuard handles either.
	if deps.AuthBruteForce != nil || deps.Logger != nil {
		authOpts = append(authOpts,
			middleware.WithBruteForceGuard(deps.AuthBruteForce, deps.Logger),
			// Give the failure-logging path the same trusted-proxy list
			// the guard uses so the logged source_ip is the real client
			// (not the load balancer) even when the guard is disabled.
			middleware.WithTrustedProxies(deps.Config.BruteForce.TrustedProxies),
		)
	}
	// Per-tenant rate limiting runs immediately AFTER Auth so the
	// tenant identity Auth resolves (from the API-key / JWT claim) is in
	// context when the limiter keys on it. Placed before the per-route
	// RequireTenant so a flooding tenant is shed before any handler
	// work. When unset it degrades to a transparent pass-through.
	apiMWs := []func(http.Handler) http.Handler{
		middleware.Auth(&deps.Config.Auth, deps.APIKeyLookup, authOpts...),
	}
	if deps.TenantRateLimiter != nil {
		apiMWs = append(apiMWs, deps.TenantRateLimiter.Middleware())
	}
	// Record per-tenant activity after auth + rate limiting so the
	// resolved tenant is in context and a flooding tenant shed by the
	// limiter never reaches the recorder. Nil recorder is a
	// pass-through.
	if deps.ActivityRecorder != nil {
		apiMWs = append(apiMWs, middleware.RecordActivity(deps.ActivityRecorder))
	}
	apiChain := middleware.Chain(apiMWs...)
	authedAPI := apiChain(apiMux)

	root := http.NewServeMux()
	root.Handle("/healthz", publicMux)
	root.Handle("/readyz", publicMux)
	root.Handle("/api/v1/docs", publicMux)
	root.Handle("/api/v1/openapi.yaml", publicMux)
	root.Handle("/api/v1/enroll", publicMux)
	// Public PoP bootstrap: a not-yet-enrolled client lists the PoP
	// fleet to resolve the steering hostname. Only GET is public —
	// POST /api/v1/pops (admin register) falls through to the authed
	// catch-all below, which is more specific than this method-scoped
	// pattern only for GET.
	if deps.PoP != nil {
		root.Handle("GET /api/v1/pops", publicMux)
	}
	// Mobile native-SSO bootstrap endpoints are public (the agent has
	// no SNG session yet); these specific patterns take precedence
	// over the catch-all authed /api/v1/ handler below.
	root.Handle("/api/v1/tenants/{tenant_id}/auth/mobile/token", publicMux)
	root.Handle("/api/v1/tenants/{tenant_id}/auth/mobile/refresh", publicMux)
	// Admin SSO bootstrap endpoints are public (the operator has no
	// SNG session yet); these specific patterns take precedence over
	// the catch-all authed /api/v1/ handler below.
	if deps.AdminSSO != nil {
		root.Handle("GET /api/v1/auth/sso/login", publicMux)
		root.Handle("GET /api/v1/auth/sso/callback", publicMux)
	}
	root.Handle("/api/v1/", authedAPI)
	root.Handle("/scim/", authedAPI)

	// Top-level middleware applied to every request.
	var rlmw func(http.Handler) http.Handler
	if deps.RateLimiter != nil {
		rlmw = deps.RateLimiter.Middleware()
	} else {
		rlmw = func(next http.Handler) http.Handler { return next }
	}
	// Metrics and Logging are placed OUTSIDE Recovery so a handler
	// panic — which Recovery converts to a 500 — is still observed
	// by both: counted in Prometheus and emitted as an access-log
	// line with its 500 status. A middleware placed INSIDE Recovery
	// has its post-handler code skipped when the panic unwinds
	// through it, which is why Logging used to miss panicked
	// requests. Tracing is kept inside Recovery and AFTER Logging so
	// (a) the late-bound RequestMeta installed by Logging is present
	// when the span records tenant_id, and (b) its deferred span
	// annotation can re-raise the panic for Recovery to convert to a
	// 500. All three degrade to pass-throughs when their dependency
	// is absent.
	chain := middleware.Chain(
		middleware.RequestID(),
		deps.Metrics.Middleware(),
		middleware.Logging(deps.Logger),
		middleware.Recovery(deps.Logger),
		middleware.Tracing(),
		middleware.CORS(&deps.Config.CORS),
		rlmw,
		// LocaleMiddleware is the innermost middleware so the
		// localizedResponseWriter it installs is the writer the
		// handlers (and their Write* helpers) observe directly,
		// negotiating Accept-Language and stamping Content-Language
		// on every response.
		LocaleMiddleware,
	)
	return chain(root)
}
