package threatintel

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

// TestIPSRuleService_RefreshOncePublishesSignedBundle drives the
// producer end to end: the injected provider's rule text is signed,
// published on the IPS subject, and the envelope verifies+decodes back
// to the same rules under the signer's key.
func TestIPSRuleService_RefreshOncePublishesSignedBundle(t *testing.T) {
	pub := &fakePublisher{}
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	rules := "alert tls any any -> any any (msg:\"SNG THREATINTEL C2 ja3 client fingerprint\"; sid:3200000000; rev:1;)\n"
	provider := func() (string, int) { return rules, 1 }

	svc, err := NewIPSRuleService(provider, signer, pub, WithIPSLogger(quietLogger()))
	if err != nil {
		t.Fatalf("NewIPSRuleService: %v", err)
	}
	res, err := svc.RefreshOnce(context.Background())
	if err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if res.RuleCount != 1 || res.Version == 0 {
		t.Fatalf("result = %+v", res)
	}

	count, data, sub := pub.snapshot()
	if count != 1 {
		t.Fatalf("publish count = %d, want 1", count)
	}
	if sub != DefaultIPSRuleSubject {
		t.Fatalf("subject = %q, want %q", sub, DefaultIPSRuleSubject)
	}

	var env SignedIPSRuleBundle
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("unmarshal published envelope: %v", err)
	}
	claims, err := env.VerifyWith(signer.Public())
	if err != nil {
		t.Fatalf("VerifyWith: %v", err)
	}
	if claims.RulesText != rules {
		t.Fatalf("published rules = %q, want %q", claims.RulesText, rules)
	}
	if claims.Source != IPSRuleSourceCustomOrg || claims.SchemaVersion != IPSRuleSchemaVersion {
		t.Fatalf("claims = %+v", claims)
	}
}

// TestIPSRuleService_PublishesEmptyToDrain verifies an empty rule set
// is published (draining the edge) rather than skipped — the
// in-process store is authoritative, unlike the DNS fetch path.
func TestIPSRuleService_PublishesEmptyToDrain(t *testing.T) {
	pub := &fakePublisher{}
	signer, _ := GenerateSigner()
	svc, err := NewIPSRuleService(func() (string, int) { return "", 0 }, signer, pub, WithIPSLogger(quietLogger()))
	if err != nil {
		t.Fatalf("NewIPSRuleService: %v", err)
	}
	if _, err := svc.RefreshOnce(context.Background()); err != nil {
		t.Fatalf("RefreshOnce: %v", err)
	}
	if count, _, _ := pub.snapshot(); count != 1 {
		t.Fatalf("empty rule set should still publish, count = %d", count)
	}
}

// TestIPSRuleService_VersionMonotonic verifies the bundle revision
// never regresses across two same-second refreshes.
func TestIPSRuleService_VersionMonotonic(t *testing.T) {
	pub := &fakePublisher{}
	signer, _ := GenerateSigner()
	frozen := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	svc, err := NewIPSRuleService(func() (string, int) { return "", 0 }, signer, pub,
		WithIPSLogger(quietLogger()), withIPSClock(func() time.Time { return frozen }))
	if err != nil {
		t.Fatalf("NewIPSRuleService: %v", err)
	}
	r1, _ := svc.RefreshOnce(context.Background())
	r2, _ := svc.RefreshOnce(context.Background())
	if r2.Version <= r1.Version {
		t.Fatalf("version not monotonic: %d then %d", r1.Version, r2.Version)
	}
}

func TestNewIPSRuleService_Validation(t *testing.T) {
	signer, _ := GenerateSigner()
	pub := &fakePublisher{}
	provider := func() (string, int) { return "", 0 }
	cases := []struct {
		name     string
		provider IPSRuleProvider
		signer   *Signer
		pub      BundlePublisher
	}{
		{"nil provider", nil, signer, pub},
		{"nil signer", provider, nil, pub},
		{"nil publisher", provider, signer, nil},
	}
	for _, tc := range cases {
		if _, err := NewIPSRuleService(tc.provider, tc.signer, tc.pub); err == nil {
			t.Errorf("%s: expected error", tc.name)
		}
	}
}
