package dlp_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
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

// A registered document fingerprint must be projected into the endpoint
// bundle as a fingerprint rule so the on-device near-duplicate detector
// sees the same corpus the control plane matches against. Without this
// the registered fingerprint only matched server-side and endpoints
// stayed blind to the very document an operator registered to protect.
func TestCompileEndpointBundle_RegisteredFingerprintBecomesEndpointRule(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	fp, err := svc.RegisterFingerprint(ctx, tid, "Q3 Board Deck", "text/plain",
		[]byte("strictly confidential board material for the third quarter review"))
	if err != nil {
		t.Fatalf("register fingerprint: %v", err)
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
		t.Fatalf("expected exactly 1 endpoint rule (the fingerprint), got %s", blob)
	}
	r := rawRules[0].(map[string]any)

	if got, want := r["id"], "fingerprint:"+fp.ID.String(); got != want {
		t.Errorf("id = %v, want %v", got, want)
	}
	if r["pattern_type"] != "fingerprint" {
		t.Errorf("pattern_type = %v, want fingerprint", r["pattern_type"])
	}
	// The pattern_data must be the 16-char hex of the stored 64-bit
	// SimHash — the exact shape sng-dlp's parse_simhash_hex accepts.
	wantHex := hex.EncodeToString(fp.Hash[:8])
	if r["pattern_data"] != wantHex {
		t.Errorf("pattern_data = %v, want %v", r["pattern_data"], wantHex)
	}
	if len(wantHex) != 16 {
		t.Fatalf("expected 16-char hex pattern_data, got %q", wantHex)
	}
	// Registered fingerprints default to coach-first warn at high severity.
	if r["action"] != "warn" {
		t.Errorf("action = %v, want warn (coach-first)", r["action"])
	}
	if r["severity"] != "high" {
		t.Errorf("severity = %v, want high", r["severity"])
	}
	if r["name"] != "Q3 Board Deck" {
		t.Errorf("name = %v, want Q3 Board Deck", r["name"])
	}
	// Empty channel list = all channels on the endpoint.
	if ch, _ := r["channels"].([]any); len(ch) != 0 {
		t.Errorf("channels = %v, want all (empty list)", r["channels"])
	}
}

// A tenant with no registered fingerprints must contribute no
// fingerprint rules — the projection is additive, never synthetic.
func TestCompileEndpointBundle_NoFingerprintsNoFingerprintRules(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "PCI",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeRegex, Pattern: `\d{16}`}},
		Action:  repository.DLPActionBlock,
		Enabled: true,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	rules, err := svc.EndpointRules(ctx, tid)
	if err != nil {
		t.Fatalf("endpoint rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected only the 1 policy rule, got %d", len(rules))
	}
	if rules[0].PatternType == repository.DLPRuleTypeFingerprint {
		t.Errorf("no fingerprint rule expected, got %+v", rules[0])
	}
}

// A corrupt fingerprint row (stored hash shorter than the 8 bytes a
// 64-bit SimHash needs) must be skipped, not emitted as a pattern_data
// that would fail the agent's whole-bundle decode and strip every rule.
func TestCompileEndpointBundle_CorruptFingerprintHashSkipped(t *testing.T) {
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	tenant, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "Test", Slug: "corrupt-fp", Tier: repository.TenantTierStarter,
		Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	fpRepo := memory.NewDLPFingerprintRepository(store)
	svc := dlp.New(
		memory.NewDLPPolicyRepository(store),
		fpRepo,
		memory.NewDLPMatchRepository(store),
		memory.NewDLPModelRepository(store),
		nil,
	)
	ctx := context.Background()

	// Inject a corrupt row directly: a 2-byte hash can't form a u64.
	if _, err := fpRepo.Create(ctx, tenant.ID, repository.DLPFingerprint{
		Name: "truncated", Hash: []byte{0x01, 0x02}, ContentType: "text/plain",
	}); err != nil {
		t.Fatalf("inject corrupt fingerprint: %v", err)
	}

	rules, err := svc.EndpointRules(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("endpoint rules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("corrupt fingerprint must be skipped, got %d rules: %+v", len(rules), rules)
	}
}

// A stored hash that is *longer* than 8 bytes is not a 64-bit SimHash
// (e.g. a SHA-256 written by some future digest path). Truncating it to
// its first 8 bytes would emit a pattern_data that decodes fine but
// matches the wrong document on the edge, so the projection must skip
// it fail-closed rather than silently truncate.
func TestCompileEndpointBundle_OverlongFingerprintHashSkipped(t *testing.T) {
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	tenant, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "Test", Slug: "overlong-fp", Tier: repository.TenantTierStarter,
		Status: repository.TenantStatusActive,
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	fpRepo := memory.NewDLPFingerprintRepository(store)
	svc := dlp.New(
		memory.NewDLPPolicyRepository(store),
		fpRepo,
		memory.NewDLPMatchRepository(store),
		memory.NewDLPModelRepository(store),
		nil,
	)
	ctx := context.Background()

	// A 16-byte hash: longer than a SimHash, so the first 8 bytes are
	// not a meaningful SimHash to project.
	if _, err := fpRepo.Create(ctx, tenant.ID, repository.DLPFingerprint{
		Name: "sha256-shaped", ContentType: "text/plain",
		Hash: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	}); err != nil {
		t.Fatalf("inject overlong fingerprint: %v", err)
	}

	rules, err := svc.EndpointRules(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("endpoint rules: %v", err)
	}
	if len(rules) != 0 {
		t.Fatalf("overlong fingerprint must be skipped, got %d rules: %+v", len(rules), rules)
	}
}

// When a policy already carries an explicit fingerprint rule over the
// same SimHash that an operator separately registered, the endpoint
// bundle must emit exactly one rule for that SimHash — the agent matches
// each fingerprint rule independently, so two would double-flag one
// upload. The explicit policy rule (with its operator-chosen action)
// wins over the registered rule's coach-first default.
func TestCompileEndpointBundle_FingerprintDedupPolicyWins(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	fp, err := svc.RegisterFingerprint(ctx, tid, "Merger Memo", "text/plain",
		[]byte("project titan merger memo — material non-public information"))
	if err != nil {
		t.Fatalf("register fingerprint: %v", err)
	}
	sameHash := hex.EncodeToString(fp.Hash)

	// A policy fingerprint rule over the identical SimHash, hard-block.
	if _, err := svc.CreatePolicy(ctx, tid, repository.DLPPolicy{
		Name:    "Merger memo (hard block)",
		Rules:   []repository.DLPRule{{Type: repository.DLPRuleTypeFingerprint, Pattern: sameHash}},
		Action:  repository.DLPActionBlock,
		Enabled: true,
	}); err != nil {
		t.Fatalf("create policy: %v", err)
	}

	rules, err := svc.EndpointRules(ctx, tid)
	if err != nil {
		t.Fatalf("endpoint rules: %v", err)
	}

	matched := 0
	var winner dlp.EndpointDLPRule
	for _, r := range rules {
		if r.PatternData == sameHash {
			matched++
			winner = r
		}
	}
	if matched != 1 {
		t.Fatalf("expected exactly 1 rule for the shared SimHash, got %d: %+v", matched, rules)
	}
	// The surviving rule is the explicit policy one, not the registered
	// coach-first duplicate.
	if winner.Action != dlp.EndpointActionBlock {
		t.Errorf("action = %v, want block (policy rule wins over registered warn)", winner.Action)
	}
	if strings.HasPrefix(winner.ID, "fingerprint:") {
		t.Errorf("id = %q, want the policy-derived rule, not the registered fingerprint", winner.ID)
	}
}

// Two registrations of the same content yield the same SimHash; the
// projection must collapse them to a single endpoint rule so one upload
// raises one detection, not one per duplicate registration.
func TestCompileEndpointBundle_DuplicateRegisteredFingerprintsCollapse(t *testing.T) {
	svc, tid := setup(t)
	ctx := context.Background()

	content := []byte("identical sensitive content registered twice by mistake")
	if _, err := svc.RegisterFingerprint(ctx, tid, "First", "text/plain", content); err != nil {
		t.Fatalf("register first: %v", err)
	}
	if _, err := svc.RegisterFingerprint(ctx, tid, "Second", "text/plain", content); err != nil {
		t.Fatalf("register second: %v", err)
	}

	rules, err := svc.EndpointRules(ctx, tid)
	if err != nil {
		t.Fatalf("endpoint rules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("duplicate registrations must collapse to 1 rule, got %d: %+v", len(rules), rules)
	}
}
