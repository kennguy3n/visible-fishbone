package repository

import (
	"encoding/json"
	"testing"
)

func u32ptr(v uint32) *uint32 { return &v }
func boolptr(b bool) *bool    { return &b }

// TestPostureExpandedSignalsJSONRoundTrip pins the wire contract for the
// WS4 expanded posture signals: they must serialize under the same
// snake_case keys the ZTNA evaluator's DevicePosture uses
// (crates/sng-ztna/src/device.rs), and an older agent that omits them
// must still round-trip cleanly (omitempty), deserializing back to the
// "unreported" (nil / empty) state rather than a spurious zero value.
func TestPostureExpandedSignalsJSONRoundTrip(t *testing.T) {
	t.Parallel()

	full := Posture{
		EDRHealthy:                   boolptr(true),
		OSPatchDaysSince:             u32ptr(3),
		AntivirusEnabled:             boolptr(true),
		AntivirusDefinitionsAgeHours: u32ptr(12),
		CertificateHealth:            CertificateHealthExpiring,
	}
	raw, err := json.Marshal(full)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Evaluator-aligned wire keys must be present.
	for _, key := range []string{
		"edr_healthy", "os_patch_days_since", "antivirus_enabled",
		"antivirus_definitions_age_hours", "certificate_health",
	} {
		if !json.Valid(raw) {
			t.Fatalf("invalid json: %s", raw)
		}
		if !containsKey(raw, key) {
			t.Fatalf("expected key %q in %s", key, raw)
		}
	}

	var back Posture
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.EDRHealthy == nil || !*back.EDRHealthy ||
		back.OSPatchDaysSince == nil || *back.OSPatchDaysSince != 3 ||
		back.AntivirusDefinitionsAgeHours == nil || *back.AntivirusDefinitionsAgeHours != 12 ||
		back.CertificateHealth != CertificateHealthExpiring {
		t.Fatalf("round-trip lost data: %+v", back)
	}

	// Older agent: none of the expanded keys present.
	emptyRaw, err := json.Marshal(Posture{OSVersion: "old"})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	for _, key := range []string{"edr_healthy", "os_patch_days_since", "certificate_health"} {
		if containsKey(emptyRaw, key) {
			t.Fatalf("omitempty violated: key %q present in %s", key, emptyRaw)
		}
	}
}

func containsKey(raw []byte, key string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

// TestPostureFailClosedReads asserts the control-plane-side reads
// collapse an unreported signal to its fail-closed value, mirroring the
// evaluator's serde defaults (false / u32::MAX). A missing signal must
// never read as healthy / fresh.
func TestPostureFailClosedReads(t *testing.T) {
	t.Parallel()

	var unreported Posture // every expanded signal nil / empty
	if unreported.EDRHealthyOrFailClosed() {
		t.Error("unreported EDR must read unhealthy")
	}
	if unreported.AntivirusEnabledOrFailClosed() {
		t.Error("unreported AV must read disabled")
	}
	if got := unreported.OSPatchDaysSinceOrStale(); got != staleAgeSentinel {
		t.Errorf("unreported patch age = %d, want %d (maximally stale)", got, staleAgeSentinel)
	}
	if got := unreported.AntivirusDefinitionsAgeHoursOrStale(); got != staleAgeSentinel {
		t.Errorf("unreported AV age = %d, want %d (maximally stale)", got, staleAgeSentinel)
	}
	if got := unreported.CertificateHealth.Normalized(); got != CertificateHealthUnknown {
		t.Errorf("unreported cert health normalized to %q, want %q", got, CertificateHealthUnknown)
	}

	reported := Posture{
		EDRHealthy:                   boolptr(true),
		AntivirusEnabled:             boolptr(true),
		OSPatchDaysSince:             u32ptr(0),
		AntivirusDefinitionsAgeHours: u32ptr(0),
		CertificateHealth:            CertificateHealthHealthy,
	}
	if !reported.EDRHealthyOrFailClosed() || !reported.AntivirusEnabledOrFailClosed() ||
		reported.OSPatchDaysSinceOrStale() != 0 || reported.AntivirusDefinitionsAgeHoursOrStale() != 0 ||
		reported.CertificateHealth.Normalized() != CertificateHealthHealthy {
		t.Errorf("reported-healthy posture misread: %+v", reported)
	}

	// An unrecognized cert-health string must also fail closed.
	if got := CertificateHealth("bogus").Normalized(); got != CertificateHealthUnknown {
		t.Errorf("unrecognized cert health normalized to %q, want %q", got, CertificateHealthUnknown)
	}
}
