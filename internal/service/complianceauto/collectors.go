package complianceauto

import (
	"time"

	"github.com/google/uuid"
)

// KeyRotationMaxAge is the managed rotation window: an active signing key
// older than this is considered overdue for rotation. SOC 2 / ISO 27001
// expect a defined, enforced rotation cadence; the platform default is
// one year.
const KeyRotationMaxAge = 365 * 24 * time.Hour

// Snapshot is the real platform state for a single tenant, read ONCE per
// evaluation sweep by a PlatformSource. Collectors are pure functions
// over this struct — they never perform I/O — which keeps evaluation
// cheap, deterministic, and trivially testable (flip a field, observe the
// control flip). Every field is sourced from a real repository read or a
// managed platform-configuration fact; none is hardcoded to "pass".
type Snapshot struct {
	TenantID   uuid.UUID
	ObservedAt time.Time

	// Policy graph (read from PolicyRepository.GetCurrentGraph).
	HasPolicyGraph     bool
	PolicyDefaultDeny  bool
	PolicyGraphVersion int

	// Managed platform defaults derived from control-plane config.
	RLSEnforced      bool
	EncryptionAtRest bool
	// TLSEnforced is the computed verdict for transport encryption;
	// TLSMode is the raw libpq sslmode it was derived from, recorded as
	// evidence so the posture shows WHY the control passed or failed.
	TLSEnforced bool
	TLSMode     string

	// Identity federation (read from IDPConfigRepository.List).
	IDPConfigured int
	IDPEnabled    int

	// Policy bundle signing key (read from PolicySigningKeyRepository).
	HasActiveSigningKey   bool
	SigningKeyActivatedAt time.Time

	// Data residency (read from Tenant.Region).
	Region string

	// Audit activity (read from AuditLogRepository.List).
	HasAuditActivity bool
	LastAuditAt      time.Time

	// Data retention (read from Tenant.Settings.data_retention_days).
	RetentionDays int
}

// Observation is the result of evaluating one collector against a
// Snapshot: the computed status plus the concrete evidence reference
// (what was observed, when, and from which source).
type Observation struct {
	CollectorID CollectorID
	Status      Status
	// Summary is a one-line human explanation of the verdict.
	Summary string
	// Source identifies the platform subsystem the evidence came from.
	Source string
	// ObservedAt is when the underlying state was read (Snapshot time).
	ObservedAt time.Time
	// Details carries collector-specific structured facts that back the
	// verdict. Serialized to the evidence record's JSONB column.
	Details map[string]any
}

// Collector evaluates one platform invariant against a Snapshot.
type Collector func(Snapshot) Observation

// collectors is the registry mapping each CollectorID to its pure
// evaluation function. Defined once; never mutated.
var collectors = map[CollectorID]Collector{
	CollectorPolicyDefaultDeny: collectPolicyDefaultDeny,
	CollectorTenantIsolation:   collectTenantIsolation,
	CollectorSSOEnforcement:    collectSSOEnforcement,
	CollectorEncryptionAtRest:  collectEncryptionAtRest,
	CollectorEncryptionTransit: collectEncryptionTransit,
	CollectorBundleSigning:     collectBundleSigning,
	CollectorKeyRotation:       collectKeyRotation,
	CollectorAuditTrail:        collectAuditTrail,
	CollectorDataResidency:     collectDataResidency,
	CollectorDataRetention:     collectDataRetention,
}

// CollectorFor returns the collector for an id, or false if unknown.
func CollectorFor(id CollectorID) (Collector, bool) {
	c, ok := collectors[id]
	return c, ok
}

// newObservation seeds an Observation with the fields every collector
// shares, so each collector body only sets status/summary/details.
func newObservation(id CollectorID, s Snapshot, source string) Observation {
	return Observation{
		CollectorID: id,
		Source:      source,
		ObservedAt:  s.ObservedAt,
		Details:     map[string]any{},
	}
}

func collectPolicyDefaultDeny(s Snapshot) Observation {
	obs := newObservation(CollectorPolicyDefaultDeny, s, "policy_graph")
	switch {
	case !s.HasPolicyGraph:
		obs.Status = StatusNotApplicable
		obs.Summary = "no policy graph has been compiled for the tenant yet"
	case s.PolicyDefaultDeny:
		obs.Status = StatusPass
		obs.Summary = "active policy graph enforces default-deny"
	default:
		obs.Status = StatusFail
		obs.Summary = "active policy graph default action is allow, not deny"
	}
	obs.Details["has_policy_graph"] = s.HasPolicyGraph
	obs.Details["default_deny"] = s.PolicyDefaultDeny
	obs.Details["graph_version"] = s.PolicyGraphVersion
	return obs
}

func collectTenantIsolation(s Snapshot) Observation {
	obs := newObservation(CollectorTenantIsolation, s, "platform_config")
	if s.RLSEnforced {
		obs.Status = StatusPass
		obs.Summary = "row-level security is enforced for tenant data isolation"
	} else {
		obs.Status = StatusFail
		obs.Summary = "row-level security is not enforced"
	}
	obs.Details["rls_enforced"] = s.RLSEnforced
	return obs
}

func collectSSOEnforcement(s Snapshot) Observation {
	obs := newObservation(CollectorSSOEnforcement, s, "idp_configs")
	switch {
	case s.IDPEnabled > 0:
		obs.Status = StatusPass
		obs.Summary = "at least one identity provider is configured and enabled"
	case s.IDPConfigured > 0:
		obs.Status = StatusFail
		obs.Summary = "identity providers are configured but none are enabled"
	default:
		obs.Status = StatusFail
		obs.Summary = "no identity provider is configured for federated access"
	}
	obs.Details["idp_configured"] = s.IDPConfigured
	obs.Details["idp_enabled"] = s.IDPEnabled
	return obs
}

func collectEncryptionAtRest(s Snapshot) Observation {
	obs := newObservation(CollectorEncryptionAtRest, s, "platform_config")
	if s.EncryptionAtRest {
		obs.Status = StatusPass
		obs.Summary = "managed envelope encryption is configured for data at rest"
	} else {
		obs.Status = StatusFail
		obs.Summary = "no key-wrap master is configured; data-at-rest encryption is disabled"
	}
	obs.Details["encryption_at_rest"] = s.EncryptionAtRest
	return obs
}

func collectEncryptionTransit(s Snapshot) Observation {
	obs := newObservation(CollectorEncryptionTransit, s, "platform_config")
	if s.TLSEnforced {
		obs.Status = StatusPass
		obs.Summary = "TLS is enforced for data in transit"
	} else {
		obs.Status = StatusFail
		obs.Summary = "TLS is not enforced for data in transit"
	}
	obs.Details["tls_enforced"] = s.TLSEnforced
	if s.TLSMode != "" {
		obs.Details["tls_mode"] = s.TLSMode
	}
	return obs
}

func collectBundleSigning(s Snapshot) Observation {
	obs := newObservation(CollectorBundleSigning, s, "policy_signing_keys")
	if s.HasActiveSigningKey {
		obs.Status = StatusPass
		obs.Summary = "an active policy bundle signing key is present"
	} else {
		obs.Status = StatusFail
		obs.Summary = "no active policy bundle signing key is present"
	}
	obs.Details["has_active_signing_key"] = s.HasActiveSigningKey
	return obs
}

func collectKeyRotation(s Snapshot) Observation {
	obs := newObservation(CollectorKeyRotation, s, "policy_signing_keys")
	if !s.HasActiveSigningKey {
		obs.Status = StatusNotApplicable
		obs.Summary = "no active signing key to evaluate for rotation"
		obs.Details["has_active_signing_key"] = false
		return obs
	}
	age := s.ObservedAt.Sub(s.SigningKeyActivatedAt)
	ageDays := int(age.Hours() / 24)
	if age <= KeyRotationMaxAge {
		obs.Status = StatusPass
		obs.Summary = "active signing key is within the managed rotation window"
	} else {
		obs.Status = StatusFail
		obs.Summary = "active signing key is overdue for rotation"
	}
	obs.Details["has_active_signing_key"] = true
	obs.Details["key_age_days"] = ageDays
	obs.Details["max_age_days"] = int(KeyRotationMaxAge.Hours() / 24)
	obs.Details["activated_at"] = s.SigningKeyActivatedAt.UTC().Format(time.RFC3339)
	return obs
}

func collectAuditTrail(s Snapshot) Observation {
	obs := newObservation(CollectorAuditTrail, s, "audit_log")
	if s.HasAuditActivity {
		obs.Status = StatusPass
		obs.Summary = "append-only audit trail has recorded activity"
	} else {
		obs.Status = StatusFail
		obs.Summary = "no audit trail activity has been recorded"
	}
	obs.Details["has_audit_activity"] = s.HasAuditActivity
	if !s.LastAuditAt.IsZero() {
		obs.Details["last_audit_at"] = s.LastAuditAt.UTC().Format(time.RFC3339)
	}
	return obs
}

func collectDataResidency(s Snapshot) Observation {
	obs := newObservation(CollectorDataResidency, s, "tenant_record")
	if s.Region != "" {
		obs.Status = StatusPass
		obs.Summary = "tenant data is pinned to a declared residency region"
	} else {
		obs.Status = StatusFail
		obs.Summary = "tenant has no declared residency region"
	}
	obs.Details["region"] = s.Region
	return obs
}

func collectDataRetention(s Snapshot) Observation {
	obs := newObservation(CollectorDataRetention, s, "tenant_settings")
	if s.RetentionDays > 0 {
		obs.Status = StatusPass
		obs.Summary = "a data-retention period is configured"
	} else {
		obs.Status = StatusFail
		obs.Summary = "no data-retention period is configured"
	}
	obs.Details["retention_days"] = s.RetentionDays
	return obs
}
