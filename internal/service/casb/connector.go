package casb

import (
	"context"
	"encoding/json"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// CASBConnectorPlugin is the interface every CASB SaaS connector
// must implement. Implementations are stateless: per-tenant
// configuration is passed on every call via the config/secret
// parameters so the same plugin instance can serve multiple tenants
// concurrently.
type CASBConnectorPlugin interface {
	// Connect validates the supplied configuration and establishes
	// a connection (or verifies one can be established).
	Connect(ctx context.Context, config json.RawMessage, secret []byte) error

	// ListUsers enumerates SaaS users visible to the connector.
	ListUsers(ctx context.Context, config json.RawMessage, secret []byte) ([]SaaSUser, error)

	// ListActivity returns audit/activity events since the given
	// cutoff.
	ListActivity(ctx context.Context, config json.RawMessage, secret []byte, since string) ([]ActivityEvent, error)

	// AssessPosture runs configuration posture checks and returns
	// a report.
	AssessPosture(ctx context.Context, config json.RawMessage, secret []byte) (PostureReport, error)

	// Test probes connectivity and config validity. Returns nil
	// on success.
	Test(ctx context.Context, config json.RawMessage, secret []byte) error

	// Type returns the connector kind this plugin handles.
	Type() repository.CASBConnectorType
}

// PluginRegistry maps connector types to their plugin
// implementations.
type PluginRegistry map[repository.CASBConnectorType]CASBConnectorPlugin
