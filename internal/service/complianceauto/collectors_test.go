package complianceauto

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// baseObservedAt is a fixed evaluation time so collector assertions are
// deterministic.
var baseObservedAt = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func snap() Snapshot {
	return Snapshot{TenantID: uuid.New(), ObservedAt: baseObservedAt}
}

// run evaluates one collector by id against s, failing the test if the
// id is unknown.
func run(t *testing.T, id CollectorID, s Snapshot) Observation {
	t.Helper()
	c, ok := CollectorFor(id)
	if !ok {
		t.Fatalf("no collector registered for %q", id)
	}
	return c(s)
}

func TestCollectors_FlipState(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		id     CollectorID
		mutate func(*Snapshot)
		want   Status
	}{
		{"default_deny/no_graph", CollectorPolicyDefaultDeny, func(s *Snapshot) { s.HasPolicyGraph = false }, StatusNotApplicable},
		{"default_deny/deny", CollectorPolicyDefaultDeny, func(s *Snapshot) { s.HasPolicyGraph = true; s.PolicyDefaultDeny = true }, StatusPass},
		{"default_deny/allow", CollectorPolicyDefaultDeny, func(s *Snapshot) { s.HasPolicyGraph = true; s.PolicyDefaultDeny = false }, StatusFail},

		{"isolation/on", CollectorTenantIsolation, func(s *Snapshot) { s.RLSEnforced = true }, StatusPass},
		{"isolation/off", CollectorTenantIsolation, func(s *Snapshot) { s.RLSEnforced = false }, StatusFail},

		{"sso/enabled", CollectorSSOEnforcement, func(s *Snapshot) { s.IDPConfigured = 2; s.IDPEnabled = 1 }, StatusPass},
		{"sso/configured_none_enabled", CollectorSSOEnforcement, func(s *Snapshot) { s.IDPConfigured = 1; s.IDPEnabled = 0 }, StatusFail},
		{"sso/none", CollectorSSOEnforcement, func(s *Snapshot) { s.IDPConfigured = 0; s.IDPEnabled = 0 }, StatusFail},

		{"enc_rest/on", CollectorEncryptionAtRest, func(s *Snapshot) { s.EncryptionAtRest = true }, StatusPass},
		{"enc_rest/off", CollectorEncryptionAtRest, func(s *Snapshot) { s.EncryptionAtRest = false }, StatusFail},

		{"enc_transit/on", CollectorEncryptionTransit, func(s *Snapshot) { s.TLSEnforced = true }, StatusPass},
		{"enc_transit/off", CollectorEncryptionTransit, func(s *Snapshot) { s.TLSEnforced = false }, StatusFail},

		{"signing/present", CollectorBundleSigning, func(s *Snapshot) { s.HasActiveSigningKey = true }, StatusPass},
		{"signing/absent", CollectorBundleSigning, func(s *Snapshot) { s.HasActiveSigningKey = false }, StatusFail},

		{"rotation/no_key", CollectorKeyRotation, func(s *Snapshot) { s.HasActiveSigningKey = false }, StatusNotApplicable},
		{"rotation/fresh", CollectorKeyRotation, func(s *Snapshot) {
			s.HasActiveSigningKey = true
			s.SigningKeyActivatedAt = baseObservedAt.Add(-30 * 24 * time.Hour)
		}, StatusPass},
		{"rotation/overdue", CollectorKeyRotation, func(s *Snapshot) {
			s.HasActiveSigningKey = true
			s.SigningKeyActivatedAt = baseObservedAt.Add(-400 * 24 * time.Hour)
		}, StatusFail},

		{"audit/active", CollectorAuditTrail, func(s *Snapshot) { s.HasAuditActivity = true; s.LastAuditAt = baseObservedAt }, StatusPass},
		{"audit/silent", CollectorAuditTrail, func(s *Snapshot) { s.HasAuditActivity = false }, StatusFail},

		{"residency/set", CollectorDataResidency, func(s *Snapshot) { s.Region = "eu-west-1" }, StatusPass},
		{"residency/unset", CollectorDataResidency, func(s *Snapshot) { s.Region = "" }, StatusFail},

		{"retention/set", CollectorDataRetention, func(s *Snapshot) { s.RetentionDays = 90 }, StatusPass},
		{"retention/unset", CollectorDataRetention, func(s *Snapshot) { s.RetentionDays = 0 }, StatusFail},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := snap()
			tc.mutate(&s)
			obs := run(t, tc.id, s)

			if obs.Status != tc.want {
				t.Fatalf("status = %q, want %q", obs.Status, tc.want)
			}
			if obs.CollectorID != tc.id {
				t.Fatalf("collector id = %q, want %q", obs.CollectorID, tc.id)
			}
			if obs.Source == "" {
				t.Fatal("evidence source must be populated")
			}
			if !obs.ObservedAt.Equal(s.ObservedAt) {
				t.Fatalf("observed_at = %v, want %v", obs.ObservedAt, s.ObservedAt)
			}
			if len(obs.Details) == 0 {
				t.Fatal("evidence details must be populated")
			}
		})
	}
}

// TestCollectors_RegistryCoversCatalog proves every catalog control maps
// to a registered collector — no orphaned control can silently never be
// evaluated.
func TestCollectors_RegistryCoversCatalog(t *testing.T) {
	t.Parallel()
	for _, ctrl := range Catalog() {
		if _, ok := CollectorFor(ctrl.CollectorID); !ok {
			t.Errorf("control %s/%s references unregistered collector %q",
				ctrl.Framework, ctrl.ID, ctrl.CollectorID)
		}
	}
}

// TestTLSEnforcedFromSSLMode pins the mapping from libpq sslmode to the
// encryption-in-transit verdict: only the modes that require an encrypted
// connection count as enforced.
func TestTLSEnforcedFromSSLMode(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"require":     true,
		"verify-ca":   true,
		"verify-full": true,
		"disable":     false,
		"allow":       false,
		"prefer":      false,
		"":            false,
		"REQUIRE":     false, // case-sensitive: libpq values are lowercase
	}
	for mode, want := range cases {
		if got := TLSEnforcedFromSSLMode(mode); got != want {
			t.Errorf("TLSEnforcedFromSSLMode(%q) = %v, want %v", mode, got, want)
		}
	}
}

// TestEncryptionTransit_RecordsMode proves the sslmode flows into the
// evidence and drives the verdict — a plaintext mode fails and surfaces
// the mode that caused it.
func TestEncryptionTransit_RecordsMode(t *testing.T) {
	t.Parallel()

	enforced := snap()
	enforced.TLSEnforced = true
	enforced.TLSMode = "require"
	obs := run(t, CollectorEncryptionTransit, enforced)
	if obs.Status != StatusPass {
		t.Fatalf("require: status = %q, want pass", obs.Status)
	}
	if obs.Details["tls_mode"] != "require" {
		t.Fatalf("require: tls_mode detail = %v, want require", obs.Details["tls_mode"])
	}

	plaintext := snap()
	plaintext.TLSEnforced = false
	plaintext.TLSMode = "disable"
	obs = run(t, CollectorEncryptionTransit, plaintext)
	if obs.Status != StatusFail {
		t.Fatalf("disable: status = %q, want fail", obs.Status)
	}
	if obs.Details["tls_mode"] != "disable" {
		t.Fatalf("disable: tls_mode detail = %v, want disable", obs.Details["tls_mode"])
	}
}

// TestKeyRotation_Boundary pins the rotation window boundary: a key
// exactly at the max age still passes; one second older fails.
func TestKeyRotation_Boundary(t *testing.T) {
	t.Parallel()
	s := snap()
	s.HasActiveSigningKey = true

	s.SigningKeyActivatedAt = baseObservedAt.Add(-KeyRotationMaxAge)
	if obs := run(t, CollectorKeyRotation, s); obs.Status != StatusPass {
		t.Fatalf("at max age: status = %q, want pass", obs.Status)
	}

	s.SigningKeyActivatedAt = baseObservedAt.Add(-KeyRotationMaxAge - time.Second)
	if obs := run(t, CollectorKeyRotation, s); obs.Status != StatusFail {
		t.Fatalf("past max age: status = %q, want fail", obs.Status)
	}
}
