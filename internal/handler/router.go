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
	MSP              *MSPHandler
	Browser          *BrowserHandler
	Terraform        *TerraformHandler
	AI               *AIHandler
	DLP              *DLPHandler
	SCIM             *SCIMHandler
	Compliance       *ComplianceHandler
	Playbook         *PlaybookHandler
	Troubleshoot     *TroubleshootHandler
	OIDC             *OIDCHandler
	OpenAPISpec      *OpenAPIHandler
	APIKeyLookup     middleware.APIKeyLookup
	RateLimiter      *middleware.RateLimiter
	Health           *Health
	OpsHealth        *OpsHealthHandler
	BulkDevice       *BulkDeviceHandler
	// Metrics, when non-nil, installs the Prometheus HTTP
	// instrumentation middleware (request count / duration /
	// in-flight) at the top of the chain. Nil disables it (the
	// middleware degrades to a transparent pass-through), so tests
	// that don't care about metrics can leave it unset.
	Metrics *metrics.Metrics
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

	apiMux := http.NewServeMux()
	if deps.Tenants != nil {
		deps.Tenants.Register(apiMux)
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

	apiChain := middleware.Chain(
		middleware.Auth(&deps.Config.Auth, deps.APIKeyLookup),
	)
	authedAPI := apiChain(apiMux)

	root := http.NewServeMux()
	root.Handle("/healthz", publicMux)
	root.Handle("/readyz", publicMux)
	root.Handle("/api/v1/docs", publicMux)
	root.Handle("/api/v1/openapi.yaml", publicMux)
	root.Handle("/api/v1/enroll", publicMux)
	// Mobile native-SSO bootstrap endpoints are public (the agent has
	// no SNG session yet); these specific patterns take precedence
	// over the catch-all authed /api/v1/ handler below.
	root.Handle("/api/v1/tenants/{tenant_id}/auth/mobile/token", publicMux)
	root.Handle("/api/v1/tenants/{tenant_id}/auth/mobile/refresh", publicMux)
	root.Handle("/api/v1/", authedAPI)
	root.Handle("/scim/", authedAPI)

	// Top-level middleware applied to every request.
	var rlmw func(http.Handler) http.Handler
	if deps.RateLimiter != nil {
		rlmw = deps.RateLimiter.Middleware()
	} else {
		rlmw = func(next http.Handler) http.Handler { return next }
	}
	// Metrics is placed OUTSIDE Recovery so a handler panic — which
	// Recovery converts to a 500 — is still counted (with its 500
	// status) rather than lost. Tracing is placed AFTER Logging so
	// the late-bound RequestMeta (installed by Logging) is present
	// when the span records tenant_id. Both degrade to
	// pass-throughs when their dependency is absent.
	chain := middleware.Chain(
		middleware.RequestID(),
		deps.Metrics.Middleware(),
		middleware.Recovery(deps.Logger),
		middleware.Logging(deps.Logger),
		middleware.Tracing(),
		middleware.CORS(&deps.Config.CORS),
		rlmw,
	)
	return chain(root)
}
