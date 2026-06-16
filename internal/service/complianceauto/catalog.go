// Package complianceauto is the continuous compliance evidence service
// (WP6). It maps real ShieldNet Gateway platform state — policy-graph
// posture, tenant-isolation config, identity federation, encryption and
// key-rotation settings, audit activity, and data residency/retention —
// onto a catalog of SOC 2 and ISO 27001 controls, evaluates each control
// to pass/fail/not-applicable with concrete evidence references on a
// bounded leader-gated schedule, persists the results, and produces
// framework-mapped, exportable evidence packs on demand.
//
// It runs ALONGSIDE the existing internal/service/compliance package and
// is intentionally distinct: `compliance` produces point-in-time reports
// from caller-supplied booleans and archives signed SOC 2 bundles to S3,
// whereas `complianceauto` continuously reads ACTUAL platform state via
// the repository layer and computes posture itself. It consumes no
// private state from `compliance`.
package complianceauto

// Framework identifies a control framework the service maps evidence to.
type Framework string

const (
	// FrameworkSOC2 is the AICPA SOC 2 Trust Services Criteria.
	FrameworkSOC2 Framework = "SOC2"
	// FrameworkISO27001 is ISO/IEC 27001:2022 Annex A.
	FrameworkISO27001 Framework = "ISO_27001"
)

// Status is the computed posture of a single control.
type Status string

const (
	// StatusPass means the observed platform state satisfies the control.
	StatusPass Status = "pass"
	// StatusFail means the control is in scope but the observed state
	// does not satisfy it — a genuine compliance gap.
	StatusFail Status = "fail"
	// StatusNotApplicable means the control is out of scope for the
	// tenant's current configuration (e.g. no policy graph compiled
	// yet), so no pass/fail judgement is made.
	StatusNotApplicable Status = "not_applicable"
)

// CollectorID names the evidence collector that evaluates a control.
// Multiple controls (often one per framework) may share a collector
// when they assert the same underlying platform invariant.
type CollectorID string

const (
	CollectorPolicyDefaultDeny CollectorID = "policy_default_deny"
	CollectorTenantIsolation   CollectorID = "tenant_isolation_rls"
	CollectorSSOEnforcement    CollectorID = "sso_enforcement"
	CollectorEncryptionAtRest  CollectorID = "encryption_at_rest"
	CollectorEncryptionTransit CollectorID = "encryption_in_transit"
	CollectorBundleSigning     CollectorID = "policy_bundle_signing"
	CollectorKeyRotation       CollectorID = "key_rotation"
	CollectorAuditTrail        CollectorID = "audit_trail"
	CollectorDataResidency     CollectorID = "data_residency"
	CollectorDataRetention     CollectorID = "data_retention"
)

// Control is one catalog entry: a framework control mapped to the
// collector that produces its evidence.
type Control struct {
	// ID is the framework-native control identifier (e.g. "CC6.1",
	// "A.8.24"). Unique within a framework.
	ID string
	// Framework is the owning framework.
	Framework Framework
	// Title is a short human label.
	Title string
	// Statement is what the control requires, in one sentence.
	Statement string
	// Category groups related controls (e.g. "Logical Access").
	Category string
	// CollectorID is the evidence collector evaluated for this control.
	CollectorID CollectorID
}

// catalog is the full control set. It is defined once and never mutated.
// A meaningful subset of SOC 2 Trust Services Criteria and ISO 27001:2022
// Annex A controls is covered, each backed by a collector that reads real
// platform state (see collectors.go). Several invariants (default-deny,
// encryption, key rotation, SSO, audit logging, residency) map to a
// control in BOTH frameworks via a shared collector, demonstrating
// one-collector-to-many-controls mapping.
var catalog = []Control{
	// --- SOC 2 -------------------------------------------------------
	{
		ID:          "CC6.1",
		Framework:   FrameworkSOC2,
		Title:       "Logical access — default-deny policy",
		Statement:   "Logical access is restricted by a deny-by-default authorization policy.",
		Category:    "Logical Access",
		CollectorID: CollectorPolicyDefaultDeny,
	},
	{
		ID:          "CC6.1-ISO",
		Framework:   FrameworkSOC2,
		Title:       "Tenant isolation (row-level security)",
		Statement:   "Tenant data is isolated by enforced row-level security.",
		Category:    "Logical Access",
		CollectorID: CollectorTenantIsolation,
	},
	{
		ID:          "CC6.6",
		Framework:   FrameworkSOC2,
		Title:       "Federated authentication (SSO)",
		Statement:   "External access is authenticated through a configured identity provider.",
		Category:    "Logical Access",
		CollectorID: CollectorSSOEnforcement,
	},
	{
		ID:          "CC6.7",
		Framework:   FrameworkSOC2,
		Title:       "Encryption at rest",
		Statement:   "Data at rest is protected with managed envelope encryption.",
		Category:    "Cryptography",
		CollectorID: CollectorEncryptionAtRest,
	},
	{
		ID:          "CC6.8",
		Framework:   FrameworkSOC2,
		Title:       "Encryption in transit",
		Statement:   "Data in transit is protected with enforced TLS.",
		Category:    "Cryptography",
		CollectorID: CollectorEncryptionTransit,
	},
	{
		ID:          "CC7.1",
		Framework:   FrameworkSOC2,
		Title:       "Policy bundle integrity",
		Statement:   "Distributed policy bundles are signed by an active signing key.",
		Category:    "System Integrity",
		CollectorID: CollectorBundleSigning,
	},
	{
		ID:          "CC7.2",
		Framework:   FrameworkSOC2,
		Title:       "Audit logging",
		Statement:   "Security-relevant actions are recorded in an append-only audit trail.",
		Category:    "Monitoring",
		CollectorID: CollectorAuditTrail,
	},
	{
		ID:          "C1.1",
		Framework:   FrameworkSOC2,
		Title:       "Cryptographic key rotation",
		Statement:   "Signing keys are rotated within the managed rotation window.",
		Category:    "Cryptography",
		CollectorID: CollectorKeyRotation,
	},
	{
		ID:          "C1.2",
		Framework:   FrameworkSOC2,
		Title:       "Data retention",
		Statement:   "A data-retention period is configured for tenant data.",
		Category:    "Confidentiality",
		CollectorID: CollectorDataRetention,
	},
	{
		ID:          "P1.1",
		Framework:   FrameworkSOC2,
		Title:       "Data residency",
		Statement:   "Tenant data is pinned to a declared residency region.",
		Category:    "Privacy",
		CollectorID: CollectorDataResidency,
	},

	// --- ISO/IEC 27001:2022 Annex A ----------------------------------
	{
		ID:          "A.8.2",
		Framework:   FrameworkISO27001,
		Title:       "Privileged access rights",
		Statement:   "Access is governed by a deny-by-default authorization policy.",
		Category:    "Access Control",
		CollectorID: CollectorPolicyDefaultDeny,
	},
	{
		ID:          "A.5.16",
		Framework:   FrameworkISO27001,
		Title:       "Identity management",
		Statement:   "Identities are federated through a configured identity provider.",
		Category:    "Identity",
		CollectorID: CollectorSSOEnforcement,
	},
	{
		ID:          "A.8.24",
		Framework:   FrameworkISO27001,
		Title:       "Use of cryptography",
		Statement:   "Data at rest is protected with managed envelope encryption.",
		Category:    "Cryptography",
		CollectorID: CollectorEncryptionAtRest,
	},
	{
		ID:          "A.8.24-KR",
		Framework:   FrameworkISO27001,
		Title:       "Key management",
		Statement:   "Cryptographic keys are rotated within the managed rotation window.",
		Category:    "Cryptography",
		CollectorID: CollectorKeyRotation,
	},
	{
		ID:          "A.8.15",
		Framework:   FrameworkISO27001,
		Title:       "Logging",
		Statement:   "Security events are recorded in an append-only audit trail.",
		Category:    "Operations",
		CollectorID: CollectorAuditTrail,
	},
	{
		ID:          "A.5.31",
		Framework:   FrameworkISO27001,
		Title:       "Legal and residency requirements",
		Statement:   "Tenant data is pinned to a declared residency region.",
		Category:    "Compliance",
		CollectorID: CollectorDataResidency,
	},
}

// Catalog returns a copy of the full control catalog in stable order.
func Catalog() []Control {
	out := make([]Control, len(catalog))
	copy(out, catalog)
	return out
}

// Frameworks returns the distinct frameworks present in the catalog, in
// first-seen order.
func Frameworks() []Framework {
	seen := map[Framework]bool{}
	var out []Framework
	for _, c := range catalog {
		if !seen[c.Framework] {
			seen[c.Framework] = true
			out = append(out, c.Framework)
		}
	}
	return out
}

// ControlsForFramework returns the catalog entries for one framework.
func ControlsForFramework(fw Framework) []Control {
	var out []Control
	for _, c := range catalog {
		if c.Framework == fw {
			out = append(out, c)
		}
	}
	return out
}

// IsFramework reports whether s names a catalog framework.
func IsFramework(s string) bool {
	for _, fw := range Frameworks() {
		if string(fw) == s {
			return true
		}
	}
	return false
}
