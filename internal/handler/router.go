package handler

import (
	"log/slog"
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/config"
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
	OpenAPISpec      *OpenAPIHandler
	APIKeyLookup     middleware.APIKeyLookup
	RateLimiter      *middleware.RateLimiter
	Health           *Health
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
	root.Handle("/api/v1/", authedAPI)
	root.Handle("/scim/", authedAPI)

	// Top-level middleware applied to every request.
	var rlmw func(http.Handler) http.Handler
	if deps.RateLimiter != nil {
		rlmw = deps.RateLimiter.Middleware()
	} else {
		rlmw = func(next http.Handler) http.Handler { return next }
	}
	chain := middleware.Chain(
		middleware.RequestID(),
		middleware.Recovery(deps.Logger),
		middleware.Logging(deps.Logger),
		middleware.CORS(&deps.Config.CORS),
		rlmw,
	)
	return chain(root)
}
