package complianceauto

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// PlatformSource produces the real per-tenant Snapshot the collectors
// evaluate. It is an interface so the engine can be driven by the real
// PlatformAdapter in production and by deterministic fakes in tests
// (the "flip a setting → control flips" property is tested against a
// fake source).
type PlatformSource interface {
	// Tenants enumerates the tenant ids to evaluate in a sweep. The
	// implementation must be cheap — a single indexed read — because it
	// runs every cycle across the whole fleet.
	Tenants(ctx context.Context) ([]uuid.UUID, error)
	// Snapshot reads the current platform state for one tenant. It
	// performs a bounded, fixed number of read-only repository calls.
	Snapshot(ctx context.Context, tenantID uuid.UUID) (Snapshot, error)
}

// The reader interfaces below are deliberately narrow projections of the
// real repositories — each names only the methods the adapter calls — so
// the real repos satisfy them directly while tests can supply minimal
// fakes. Method sets mirror internal/repository exactly.

type tenantReader interface {
	Get(ctx context.Context, id uuid.UUID) (repository.Tenant, error)
	ListTenantActivity(ctx context.Context) ([]repository.TenantActivity, error)
}

type policyReader interface {
	GetCurrentGraph(ctx context.Context, tenantID uuid.UUID) (repository.PolicyGraph, error)
}

type signingKeyReader interface {
	GetActive(ctx context.Context, tenantID uuid.UUID) (repository.PolicySigningKey, error)
}

type idpReader interface {
	List(ctx context.Context, tenantID uuid.UUID) ([]repository.IDPConfig, error)
}

type auditReader interface {
	List(ctx context.Context, tenantID uuid.UUID, filter repository.AuditFilter, page repository.Page) (repository.PageResult[repository.AuditEntry], error)
}

// ManagedDefaults are the platform-wide security facts the SaaS operator
// guarantees for every tenant, derived once from control-plane config.
// They satisfy the zero-tenant-configuration requirement: an SME gets a
// correct posture for these controls without touching any setting.
type ManagedDefaults struct {
	// RLSEnforced is true when the control plane runs under the
	// RLS-bound application role (config Database.AppRole set).
	RLSEnforced bool
	// EncryptionAtRest is true when a key-wrap master is configured
	// (config Policy.KeyWrapMasterB64 / KeyWrapMasterFile set).
	EncryptionAtRest bool
	// PostgresSSLMode is the control plane's libpq sslmode (config
	// PG_SSLMODE). It is the real, config-visible signal for transport
	// encryption: production validation hard-requires one of
	// require/verify-ca/verify-full, while a dev/test deployment behind
	// a plaintext proxy leaves it at the "disable" default. The
	// encryption-in-transit control derives its verdict from this rather
	// than a hardcoded pass, so it actually fails when transport is not
	// encrypted (see TLSEnforcedFromSSLMode).
	PostgresSSLMode string
}

// tlsEnforcingSSLModes are the libpq sslmode values that REQUIRE an
// encrypted connection. "disable"/"allow" permit plaintext and "prefer"
// silently falls back to it, so none of them enforce TLS.
var tlsEnforcingSSLModes = map[string]bool{
	"require":     true,
	"verify-ca":   true,
	"verify-full": true,
}

// TLSEnforcedFromSSLMode reports whether a libpq sslmode guarantees an
// encrypted transport. It is the single mapping from raw config to the
// encryption-in-transit evidence, exported so the wiring layer and tests
// share one definition.
func TLSEnforcedFromSSLMode(mode string) bool {
	return tlsEnforcingSSLModes[mode]
}

// PlatformAdapter is the production PlatformSource. It assembles a
// Snapshot from real repository reads plus the managed defaults.
type PlatformAdapter struct {
	tenants  tenantReader
	policy   policyReader
	signing  signingKeyReader
	idp      idpReader
	audit    auditReader
	defaults ManagedDefaults
	clock    func() time.Time
}

// NewPlatformAdapter wires the adapter. clock may be nil (defaults to
// time.Now). The reader arguments are the real repositories.
func NewPlatformAdapter(
	tenants tenantReader,
	policy policyReader,
	signing signingKeyReader,
	idp idpReader,
	audit auditReader,
	defaults ManagedDefaults,
	clock func() time.Time,
) *PlatformAdapter {
	if clock == nil {
		clock = time.Now
	}
	return &PlatformAdapter{
		tenants:  tenants,
		policy:   policy,
		signing:  signing,
		idp:      idp,
		audit:    audit,
		defaults: defaults,
		clock:    clock,
	}
}

var _ PlatformSource = (*PlatformAdapter)(nil)

// Tenants enumerates tenant ids via the cheap activity projection.
// ListTenantActivity returns every live tenant (it is a LEFT JOIN over
// the tenants table: a tenant with no recorded activity is still
// returned, with a nil last-active timestamp), so a brand-new tenant is
// swept on the very next cycle without waiting for first activity. The
// projection is used only because it is the single cheapest indexed read
// of the full tenant set; the engine needs only the ids.
func (a *PlatformAdapter) Tenants(ctx context.Context) ([]uuid.UUID, error) {
	activity, err := a.tenants.ListTenantActivity(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]uuid.UUID, 0, len(activity))
	for _, t := range activity {
		out = append(out, t.ID)
	}
	return out, nil
}

// graphDefaultAction is the minimal projection of a compiled policy
// graph the default-deny collector needs.
type graphDefaultAction struct {
	DefaultAction string `json:"default_action"`
}

// tenantRetentionSettings is the minimal projection of tenant settings
// the retention collector needs.
type tenantRetentionSettings struct {
	DataRetentionDays int `json:"data_retention_days"`
}

// Snapshot performs the bounded set of reads for one tenant. Optional
// resources (policy graph, active signing key) that are simply absent
// resolve to "not configured" rather than an error; any other read
// error aborts the snapshot so the engine can record the failure.
func (a *PlatformAdapter) Snapshot(ctx context.Context, tenantID uuid.UUID) (Snapshot, error) {
	now := a.clock().UTC()
	snap := Snapshot{
		TenantID:         tenantID,
		ObservedAt:       now,
		RLSEnforced:      a.defaults.RLSEnforced,
		EncryptionAtRest: a.defaults.EncryptionAtRest,
		TLSMode:          a.defaults.PostgresSSLMode,
		TLSEnforced:      TLSEnforcedFromSSLMode(a.defaults.PostgresSSLMode),
	}

	tenant, err := a.tenants.Get(ctx, tenantID)
	if err != nil {
		return Snapshot{}, err
	}
	snap.Region = tenant.Region
	if len(tenant.Settings) > 0 {
		var rs tenantRetentionSettings
		if json.Unmarshal(tenant.Settings, &rs) == nil {
			snap.RetentionDays = rs.DataRetentionDays
		}
	}

	idps, err := a.idp.List(ctx, tenantID)
	if err != nil {
		return Snapshot{}, err
	}
	snap.IDPConfigured = len(idps)
	for _, c := range idps {
		if c.Enabled {
			snap.IDPEnabled++
		}
	}

	key, err := a.signing.GetActive(ctx, tenantID)
	switch {
	case err == nil:
		snap.HasActiveSigningKey = true
		snap.SigningKeyActivatedAt = key.ActivatedAt
	case errors.Is(err, repository.ErrNotFound):
		// No active key — leave HasActiveSigningKey false.
	default:
		return Snapshot{}, err
	}

	graph, err := a.policy.GetCurrentGraph(ctx, tenantID)
	switch {
	case err == nil:
		snap.HasPolicyGraph = true
		snap.PolicyGraphVersion = graph.Version
		var gda graphDefaultAction
		if json.Unmarshal(graph.Graph, &gda) == nil {
			snap.PolicyDefaultDeny = gda.DefaultAction == "deny"
		}
	case errors.Is(err, repository.ErrNotFound):
		// No compiled graph yet — collector reports not-applicable.
	default:
		return Snapshot{}, err
	}

	audit, err := a.audit.List(ctx, tenantID, repository.AuditFilter{}, repository.Page{Limit: 1})
	if err != nil {
		return Snapshot{}, err
	}
	if len(audit.Items) > 0 {
		snap.HasAuditActivity = true
		snap.LastAuditAt = audit.Items[0].CreatedAt
	}

	return snap, nil
}
