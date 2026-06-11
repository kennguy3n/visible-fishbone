package dlp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlp"
)

func TestService_EndpointRules_CompilesEnabledPolicies(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "PCI",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: `\d{16}`}},
		Action:  repository.DLPActionBlock,
		Enabled: true,
	}); err != nil {
		t.Fatalf("create enabled: %v", err)
	}
	// A disabled policy must not contribute any rules.
	if _, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "Disabled",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeKeyword, Pattern: "secret"}},
		Action:  repository.DLPActionLog,
		Enabled: false,
	}); err != nil {
		t.Fatalf("create disabled: %v", err)
	}

	rules, err := svc.EndpointRules(ctx, tid)
	if err != nil {
		t.Fatalf("endpoint rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 endpoint rule, got %d", len(rules))
	}
	r := rules[0]
	if r.PatternType != repository.DLPRuleTypeRegex {
		t.Errorf("pattern_type = %q, want regex", r.PatternType)
	}
	if r.PatternData != `\d{16}` {
		t.Errorf("pattern_data = %q", r.PatternData)
	}
	if r.Action != dlp.EndpointActionBlock {
		t.Errorf("action = %q, want block", r.Action)
	}
	if r.Severity != dlp.EndpointSeverityCritical {
		t.Errorf("severity = %q, want critical", r.Severity)
	}
	if len(r.Channels) != 0 {
		t.Errorf("expected all-channels (empty list), got %v", r.Channels)
	}
}

func TestService_CompileEndpointBundle_WireShape(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "Redact PII",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeMIPLabel, SensitivityLevel: "confidential"}},
		Action:  repository.DLPActionRedact,
		Enabled: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	blob, err := svc.CompileEndpointBundle(ctx, tid, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	// Decode into a generic map and assert the keys/values match the
	// shape sng-dlp's DlpPolicy / DlpRule deserialize.
	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc["schema_version"].(float64) != 1 {
		t.Errorf("schema_version = %v, want 1", doc["schema_version"])
	}
	if doc["target"] != "endpoint" {
		t.Errorf("target = %v, want endpoint", doc["target"])
	}
	if doc["domain"] != "dlp" {
		t.Errorf("domain = %v, want dlp", doc["domain"])
	}

	rules, ok := doc["rules"].([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("rules = %v", doc["rules"])
	}
	rule := rules[0].(map[string]any)
	if rule["pattern_type"] != "mip_label" {
		t.Errorf("pattern_type = %v, want mip_label", rule["pattern_type"])
	}
	// Redact maps to a user warning on the endpoint.
	if rule["action"] != "warn" {
		t.Errorf("action = %v, want warn", rule["action"])
	}
	if rule["pattern_data"] != "confidential" {
		t.Errorf("pattern_data = %v, want confidential (from SensitivityLevel)", rule["pattern_data"])
	}

	channels, ok := doc["channels"].(map[string]any)
	if !ok || len(channels) != 5 {
		t.Fatalf("channels = %v", doc["channels"])
	}
	clip, ok := channels["clipboard"].(map[string]any)
	if !ok || clip["enabled"] != true {
		t.Errorf("clipboard channel = %v", channels["clipboard"])
	}
}

func TestCompileEndpointBundle_ActionFloorOverride(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "Log only",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeKeyword, Pattern: "internal"}},
		Action:  repository.DLPActionLog,
		Enabled: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	channels := dlp.DefaultEndpointChannelConfig()
	block := dlp.EndpointActionBlock
	channels[dlp.EndpointChannelUSBTransfer] = dlp.EndpointChannelConfig{
		Enabled:        true,
		ActionOverride: &block,
	}

	blob, err := svc.CompileEndpointBundle(ctx, tid, channels)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	usb := doc["channels"].(map[string]any)["usb_transfer"].(map[string]any)
	if usb["action_override"] != "block" {
		t.Errorf("usb action_override = %v, want block", usb["action_override"])
	}
	// A channel with no floor must omit action_override entirely.
	clip := doc["channels"].(map[string]any)["clipboard"].(map[string]any)
	if _, present := clip["action_override"]; present {
		t.Errorf("clipboard must omit action_override, got %v", clip["action_override"])
	}
}

func TestValidateEndpointPolicy_RejectsBadDocuments(t *testing.T) {
	base := func() dlp.EndpointDLPPolicy {
		return dlp.EndpointDLPPolicy{
			SchemaVersion: 1,
			Target:        repository.PolicyBundleTargetEndpoint,
			Domain:        "dlp",
			Rules: []dlp.EndpointDLPRule{
				{ID: "p:0", Name: "n", PatternType: repository.DLPRuleTypeRegex, PatternData: "x",
					Severity: dlp.EndpointSeverityHigh, Action: dlp.EndpointActionLog},
			},
			Channels: dlp.DefaultEndpointChannelConfig(),
		}
	}

	if err := dlp.ValidateEndpointPolicy(base()); err != nil {
		t.Fatalf("base policy should be valid: %v", err)
	}

	wrongTarget := base()
	wrongTarget.Target = repository.PolicyBundleTargetEdge
	if err := dlp.ValidateEndpointPolicy(wrongTarget); err == nil {
		t.Error("expected error for non-endpoint target")
	}

	wrongDomain := base()
	wrongDomain.Domain = "swg"
	if err := dlp.ValidateEndpointPolicy(wrongDomain); err == nil {
		t.Error("expected error for non-dlp domain")
	}

	newer := base()
	newer.SchemaVersion = 2
	if err := dlp.ValidateEndpointPolicy(newer); err == nil {
		t.Error("expected error for unsupported schema version")
	}

	dup := base()
	dup.Rules = append(dup.Rules, dup.Rules[0])
	if err := dlp.ValidateEndpointPolicy(dup); err == nil {
		t.Error("expected error for duplicate rule id")
	}
}

// TestCompileEndpointBundle_EmitsCoachFirstAiApp locks in the wiring
// that makes the HITL review-queue producer live: every endpoint
// bundle arms the AI-app exfiltration detector coach-first (enabled,
// never blocking). Without this block the agent leaves the detector
// disarmed and the producer can never fire in prod.
func TestCompileEndpointBundle_EmitsCoachFirstAiApp(t *testing.T) {
	svc, tid := setup(t)
	blob, err := svc.CompileEndpointBundle(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var policy dlp.EndpointDLPPolicy
	if err := json.Unmarshal(blob, &policy); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if policy.AiApp == nil {
		t.Fatal("endpoint bundle missing ai_app block; detector would stay disarmed")
	}
	if !policy.AiApp.Enabled {
		t.Error("ai_app.enabled = false; detector disarmed")
	}
	if policy.AiApp.BlockOptIn {
		t.Error("ai_app.block_opt_in = true; default must be coach-first (non-blocking)")
	}
	if policy.AiApp.CoachSeverityFloor != dlp.EndpointSeverityHigh {
		t.Errorf("ai_app.coach_severity_floor = %q, want high", policy.AiApp.CoachSeverityFloor)
	}
	// The block must serialise with snake_case keys sng-dlp's
	// AiAppPolicy decodes.
	if !bytes.Contains(blob, []byte(`"ai_app"`)) ||
		!bytes.Contains(blob, []byte(`"block_opt_in"`)) ||
		!bytes.Contains(blob, []byte(`"min_report_confidence"`)) {
		t.Errorf("ai_app wire keys missing: %s", blob)
	}
}

func TestCompileEndpointBundle_EmptyTenantIsValid(t *testing.T) {
	svc, tid := setup(t)
	blob, err := svc.CompileEndpointBundle(context.Background(), tid, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var policy dlp.EndpointDLPPolicy
	if err := json.Unmarshal(blob, &policy); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(policy.Rules) != 0 {
		t.Errorf("expected no rules, got %d", len(policy.Rules))
	}
	if policy.Target != repository.PolicyBundleTargetEndpoint {
		t.Errorf("target = %q", policy.Target)
	}

	// Wire-shape regression: an empty tenant must emit `"rules": []`,
	// never `"rules": null`. sng-dlp's `rules` uses `#[serde(default)]`,
	// which fills only a *missing* key — a present null would fail to
	// decode into Vec<DlpRule> and break the bundle for every tenant
	// without enabled policies. Decoding into a Go struct can't catch
	// this (Go maps both null and [] to a zero-length slice), so assert
	// on the raw bytes the Rust agent actually sees.
	if bytes.Contains(blob, []byte(`"rules":null`)) {
		t.Fatalf("bundle emitted \"rules\":null, which sng-dlp cannot decode: %s", blob)
	}
	if !bytes.Contains(blob, []byte(`"rules":[]`)) {
		t.Errorf("expected \"rules\":[] in bundle, got %s", blob)
	}
}

// An MIP-label rule with both a label id and a sensitivity level is an
// OR match in web DLP. The endpoint rule's single pattern_data can hold
// only one of them, so the compiler splits such a rule into two
// endpoint rules — `<id>:label` and `<id>:sens` — that both attribute
// back to the same source policy, preserving the OR-semantics without
// widening the wire schema.
func TestCompileEndpointBundle_MIPLabelDualMatchEmitsTwoRules(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	created, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name: "MIP both fields",
		Rules: []repository.DLPRule{{
			Type:             repository.DLPRuleTypeMIPLabel,
			Pattern:          "label-1234",
			SensitivityLevel: "confidential",
		}},
		Action:  repository.DLPActionBlock,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	blob, err := svc.CompileEndpointBundle(ctx, tid, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rawRules, ok := doc["rules"].([]any)
	if !ok || len(rawRules) != 2 {
		t.Fatalf("expected 2 endpoint rules for a dual-field MIP rule, got %v", doc["rules"])
	}

	byID := make(map[string]map[string]any, len(rawRules))
	for _, r := range rawRules {
		rule := r.(map[string]any)
		byID[rule["id"].(string)] = rule
	}

	base := created.ID.String() + ":0"
	label, ok := byID[base+":label"]
	if !ok {
		t.Fatalf("missing %s:label rule; got rules %s", base, blob)
	}
	if label["pattern_data"] != "label-1234" {
		t.Errorf("label pattern_data = %v, want label-1234", label["pattern_data"])
	}
	sens, ok := byID[base+":sens"]
	if !ok {
		t.Fatalf("missing %s:sens rule; got rules %s", base, blob)
	}
	if sens["pattern_data"] != "confidential" {
		t.Errorf("sens pattern_data = %v, want confidential", sens["pattern_data"])
	}

	// Both paths carry the same source policy's type and action, so a
	// match on either fires the same verdict.
	for name, rule := range map[string]map[string]any{"label": label, "sens": sens} {
		if rule["pattern_type"] != "mip_label" {
			t.Errorf("%s pattern_type = %v, want mip_label", name, rule["pattern_type"])
		}
		if rule["action"] != "block" {
			t.Errorf("%s action = %v, want block", name, rule["action"])
		}
	}
}

// A rule whose compiled pattern_data is empty (here an MIP-label rule
// with neither a label id nor a sensitivity level) is a dead match path:
// it can never match, and an empty fingerprint payload would make the
// agent reject the entire bundle. compileEndpointRules drops the dead
// path while keeping the rest of the policy's rules — and the surviving
// rules keep their original `:<index>` id so audit attribution is
// stable.
func TestCompileEndpointBundle_EmptyPatternRuleIsDropped(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	created, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name: "mixed",
		Rules: []repository.DLPRule{
			// index 0: no payload at all — must be dropped.
			{Type: repository.DLPRuleTypeMIPLabel},
			// index 1: a real rule — must survive with its :1 id.
			{Type: repository.DLPRuleTypeRegex, Pattern: "ssn_us"},
		},
		Action:  repository.DLPActionBlock,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	blob, err := svc.CompileEndpointBundle(ctx, tid, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rawRules, ok := doc["rules"].([]any)
	if !ok || len(rawRules) != 1 {
		t.Fatalf("expected exactly 1 endpoint rule (dead path dropped), got %s", blob)
	}
	rule := rawRules[0].(map[string]any)
	if want := created.ID.String() + ":1"; rule["id"] != want {
		t.Errorf("surviving rule id = %v, want %s (index preserved)", rule["id"], want)
	}
	if rule["pattern_data"] != "ssn_us" {
		t.Errorf("pattern_data = %v, want ssn_us", rule["pattern_data"])
	}
}

// Web fingerprint matching is repository-driven, so a fingerprint
// DLPRule's Pattern is not guaranteed to be the 16-char hex SimHash the
// endpoint agent expects. A non-hex fingerprint payload would make
// sng-dlp fail the WHOLE-bundle compile (parse_simhash_hex rejects it),
// dropping every rule for the tenant. compileEndpointRules must drop just
// the offending fingerprint rule and keep the rest — while a fingerprint
// rule that does carry a valid 16-char hex hash is preserved verbatim.
func TestCompileEndpointBundle_InvalidFingerprintRuleIsDropped(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	created, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name: "fingerprints",
		Rules: []repository.DLPRule{
			// index 0: fingerprint whose Pattern is a human-readable
			// name, not a hex SimHash — would poison the bundle, so drop.
			{Type: repository.DLPRuleTypeFingerprint, Pattern: "Q3 board deck"},
			// index 1: fingerprint carrying a valid 16-char hex hash —
			// must survive verbatim with its :1 id.
			{Type: repository.DLPRuleTypeFingerprint, Pattern: "0123456789abcdef"},
			// index 2: a regex rule — must survive with its :2 id,
			// proving the bad fingerprint didn't take the bundle down.
			{Type: repository.DLPRuleTypeRegex, Pattern: "ssn_us"},
		},
		Action:  repository.DLPActionBlock,
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	blob, err := svc.CompileEndpointBundle(ctx, tid, nil)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rawRules, ok := doc["rules"].([]any)
	if !ok || len(rawRules) != 2 {
		t.Fatalf("expected exactly 2 endpoint rules (bad fingerprint dropped), got %s", blob)
	}

	byID := make(map[string]map[string]any, len(rawRules))
	for _, raw := range rawRules {
		r := raw.(map[string]any)
		byID[r["id"].(string)] = r
	}
	// The bad fingerprint (index 0) must be absent.
	if _, present := byID[created.ID.String()+":0"]; present {
		t.Errorf("non-hex fingerprint rule :0 should have been dropped, got %s", blob)
	}
	// The valid hex fingerprint (index 1) survives verbatim.
	fp := byID[created.ID.String()+":1"]
	if fp == nil {
		t.Fatalf("valid fingerprint rule :1 missing, got %s", blob)
	}
	if fp["pattern_data"] != "0123456789abcdef" {
		t.Errorf("fingerprint pattern_data = %v, want 0123456789abcdef", fp["pattern_data"])
	}
	// The regex rule (index 2) survives — the bad fingerprint did not
	// poison the bundle.
	if rx := byID[created.ID.String()+":2"]; rx == nil || rx["pattern_data"] != "ssn_us" {
		t.Errorf("regex rule :2 should survive with pattern_data ssn_us, got %s", blob)
	}
}
