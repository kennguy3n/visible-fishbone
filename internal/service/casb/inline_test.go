package casb

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

func newTestService(t *testing.T) *InlineCASBService {
	t.Helper()
	svc := NewInline(NewInMemoryInlineRuleStore(), nil, nil)
	// Deterministic ids so ordering assertions are stable.
	var n uint32
	svc.SetIDGenerator(func() uuid.UUID {
		n++
		var u uuid.UUID
		u[15] = byte(n)
		return u
	})
	return svc
}

func TestCreateInlineRule_ValidatesInput(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()

	cases := map[string]CreateInlineRuleInput{
		"empty app":       {AppID: "", Action: InlineActionUpload, Verdict: InlineVerdictLog},
		"unknown app":     {AppID: "definitely_not_a_real_app", Action: InlineActionUpload, Verdict: InlineVerdictLog},
		"invalid action":  {AppID: "m365", Action: InlineAction("rename"), Verdict: InlineVerdictLog},
		"invalid verdict": {AppID: "m365", Action: InlineActionUpload, Verdict: InlineVerdict("quarantine")},
		"negative size": {
			AppID: "m365", Action: InlineActionUpload, Verdict: InlineVerdictLog,
			Conditions: InlineConditions{SizeThreshold: -1},
		},
	}
	for name, in := range cases {
		in := in
		t.Run(name, func(t *testing.T) {
			_, err := svc.CreateInlineRule(ctx, tenant, in, nil)
			if !errors.Is(err, ErrInvalidArgument) {
				t.Fatalf("want ErrInvalidArgument, got %v", err)
			}
		})
	}
}

// TestKnownApps_CoverConnectorCatalog locks the inline catalog to
// the connector catalog: every CASB connector type the control
// plane ships must be a creatable inline-rule app_id, and the
// wildcard must never leak into the enumerated set. This is the
// guard that keeps an operator from being unable to write an inline
// rule for an app they have a connector for.
func TestKnownApps_CoverConnectorCatalog(t *testing.T) {
	t.Parallel()

	// "google" is the connector type; the inline/data-plane catalog
	// spells the same vendor "google_workspace" (its Drive/Workspace
	// detection id). Map the one divergent name so the rest can be
	// asserted verbatim.
	connectorToApp := func(ct repository.CASBConnectorType) string {
		if ct == repository.CASBConnectorGoogle {
			return "google_workspace"
		}
		return string(ct)
	}

	connectorTypes := []repository.CASBConnectorType{
		repository.CASBConnectorM365, repository.CASBConnectorGoogle,
		repository.CASBConnectorSlack, repository.CASBConnectorSalesforce,
		repository.CASBConnectorBox, repository.CASBConnectorDropbox,
		repository.CASBConnectorGitHub, repository.CASBConnectorGitLab,
		repository.CASBConnectorJira, repository.CASBConnectorConfluence,
		repository.CASBConnectorServiceNow, repository.CASBConnectorZendesk,
		repository.CASBConnectorHubSpot, repository.CASBConnectorZoom,
		repository.CASBConnectorTeams, repository.CASBConnectorAWSConsole,
		repository.CASBConnectorGCPConsole, repository.CASBConnectorAzurePortal,
		repository.CASBConnectorOkta, repository.CASBConnectorWorkday,
	}

	known := make(map[string]struct{}, len(KnownApps()))
	for _, a := range KnownApps() {
		if a == AnyApp {
			t.Fatalf("KnownApps must not include the %q wildcard", AnyApp)
		}
		known[a] = struct{}{}
	}
	if len(known) != len(connectorTypes) {
		t.Fatalf("catalog size mismatch: %d known apps, %d connector types",
			len(known), len(connectorTypes))
	}

	svc := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()
	for _, ct := range connectorTypes {
		app := connectorToApp(ct)
		if _, ok := known[app]; !ok {
			t.Errorf("connector %q has no inline catalog app %q", ct, app)
			continue
		}
		// The app must also be creatable end-to-end, not merely
		// present in the map.
		if _, err := svc.CreateInlineRule(ctx, tenant, CreateInlineRuleInput{
			AppID: app, Action: InlineActionUpload, Verdict: InlineVerdictLog, Enabled: true,
		}, nil); err != nil {
			t.Errorf("create inline rule for %q: %v", app, err)
		}
	}
}

func TestCreateInlineRule_NormalizesConditions(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()

	rule, err := svc.CreateInlineRule(ctx, tenant, CreateInlineRuleInput{
		AppID:   "M365",
		Action:  InlineActionUpload,
		Verdict: InlineVerdictBlock,
		Enabled: true,
		Conditions: InlineConditions{
			FileType:   ".DOCX",
			LabelMatch: "  Confidential  ",
		},
	}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rule.AppID != "m365" {
		t.Errorf("app_id not lowercased: %q", rule.AppID)
	}
	if rule.Conditions.FileType != "docx" {
		t.Errorf("file_type not normalized: %q", rule.Conditions.FileType)
	}
	if rule.Conditions.LabelMatch != "Confidential" {
		t.Errorf("label_match not trimmed: %q", rule.Conditions.LabelMatch)
	}
	if rule.CreatedAt.IsZero() || rule.UpdatedAt.IsZero() {
		t.Error("timestamps not set")
	}
}

func TestInlineConditionsNormalize(t *testing.T) {
	t.Parallel()
	// The leading dot must be stripped regardless of surrounding
	// whitespace: the data plane's file_type_from_path yields a
	// dot-less, lowercase extension, so a stored ".docx" would never
	// match and the file-type-gated rule would silently never fire.
	cases := []struct {
		in   string
		want string
	}{
		{".DOCX", "docx"},
		{" .DOCX", "docx"},
		{"  .pdf  ", "pdf"},
		{"XLSX", "xlsx"},
		{"", ""},
	}
	for _, tc := range cases {
		c := InlineConditions{FileType: tc.in}
		c.normalize()
		if c.FileType != tc.want {
			t.Errorf("normalize(%q): file_type = %q, want %q", tc.in, c.FileType, tc.want)
		}
	}
}

func TestInlineRuleCRUDLifecycle(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()

	created, err := svc.CreateInlineRule(ctx, tenant, CreateInlineRuleInput{
		AppID:   "slack",
		Action:  InlineActionShare,
		Verdict: InlineVerdictBlock,
		Enabled: true,
	}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := svc.GetInlineRule(ctx, tenant, created.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.AppID != "slack" || got.Verdict != InlineVerdictBlock {
		t.Errorf("unexpected rule: %+v", got)
	}

	enabled := false
	newVerdict := InlineVerdictLog
	updated, err := svc.UpdateInlineRule(ctx, tenant, created.ID, UpdateInlineRuleInput{
		Verdict: &newVerdict,
		Enabled: &enabled,
	}, nil)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Verdict != InlineVerdictLog || updated.Enabled {
		t.Errorf("update not applied: %+v", updated)
	}

	if err := svc.DeleteInlineRule(ctx, tenant, created.ID, nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.GetInlineRule(ctx, tenant, created.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("want ErrNotFound after delete, got %v", err)
	}
}

func TestUpdateInlineRule_RejectsBadValues(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()
	created, err := svc.CreateInlineRule(ctx, tenant, CreateInlineRuleInput{
		AppID: "m365", Action: InlineActionUpload, Verdict: InlineVerdictLog, Enabled: true,
	}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	badApp := "definitely_not_a_real_app"
	if _, err := svc.UpdateInlineRule(ctx, tenant, created.ID, UpdateInlineRuleInput{AppID: &badApp}, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("want ErrInvalidArgument for bad app, got %v", err)
	}
	badSize := InlineConditions{SizeThreshold: -5}
	if _, err := svc.UpdateInlineRule(ctx, tenant, created.ID, UpdateInlineRuleInput{Conditions: &badSize}, nil); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("want ErrInvalidArgument for bad size, got %v", err)
	}
}

func TestListInlineRules_OrderedByPriorityDesc(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()
	for _, p := range []int32{10, 100, 50} {
		if _, err := svc.CreateInlineRule(ctx, tenant, CreateInlineRuleInput{
			AppID: "m365", Action: InlineActionUpload, Verdict: InlineVerdictLog, Enabled: true, Priority: p,
		}, nil); err != nil {
			t.Fatalf("create: %v", err)
		}
	}
	rules, err := svc.ListInlineRules(ctx, tenant)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	got := []int32{rules[0].Priority, rules[1].Priority, rules[2].Priority}
	want := []int32{100, 50, 10}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("priority order: want %v, got %v", want, got)
		}
	}
}

func TestCompileRules_SkipsDisabledAndTagsDomain(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()

	if _, err := svc.CreateInlineRule(ctx, tenant, CreateInlineRuleInput{
		AppID: "m365", Action: InlineActionShare, Verdict: InlineVerdictBlock, Enabled: true, Priority: 100,
	}, nil); err != nil {
		t.Fatalf("create enabled: %v", err)
	}
	if _, err := svc.CreateInlineRule(ctx, tenant, CreateInlineRuleInput{
		AppID: "slack", Action: InlineActionUpload, Verdict: InlineVerdictLog, Enabled: false, Priority: 200,
	}, nil); err != nil {
		t.Fatalf("create disabled: %v", err)
	}

	compiled, err := svc.CompileRules(ctx, tenant)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if len(compiled) != 1 {
		t.Fatalf("want 1 compiled rule (disabled skipped), got %d", len(compiled))
	}
	r := compiled[0]
	if r.Domain != policy.DomainInlineCASB {
		t.Errorf("domain: want %q, got %q", policy.DomainInlineCASB, r.Domain)
	}
	if r.Verb != policy.VerbDeny {
		t.Errorf("verb: want deny for block verdict, got %q", r.Verb)
	}

	// The CASB payload round-trips through Extra in the Rust
	// CasbRule shape.
	raw, ok := r.Extra["casb"]
	if !ok {
		t.Fatal("missing casb payload in Extra")
	}
	var payload casbBundlePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.AppID != "m365" || payload.Action != InlineActionShare || payload.Verdict != InlineVerdictBlock {
		t.Errorf("unexpected payload: %+v", payload)
	}
}

func TestCompileRules_PriorityFitsInt32WireContract(t *testing.T) {
	t.Parallel()
	// Priority is int32 end-to-end (Go struct, Postgres INTEGER, Rust
	// i32). A max-int32 priority must round-trip through the compiled
	// bundle payload unchanged so the data plane's i32 deserialisation
	// never overflows. A wider Go type would have let an out-of-range
	// value reach the bundle and silently break installation.
	svc := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()
	const maxI32 int32 = math.MaxInt32
	if _, err := svc.CreateInlineRule(ctx, tenant, CreateInlineRuleInput{
		AppID: "m365", Action: InlineActionShare, Verdict: InlineVerdictBlock, Enabled: true, Priority: maxI32,
	}, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	compiled, err := svc.CompileRules(ctx, tenant)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	var payload casbBundlePayload
	if err := json.Unmarshal(compiled[0].Extra["casb"], &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.Priority != maxI32 {
		t.Errorf("priority: want %d, got %d", maxI32, payload.Priority)
	}
}

func TestCompiledRulesRouteToEdgeAndCloudOnly(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()
	if _, err := svc.CreateInlineRule(ctx, tenant, CreateInlineRuleInput{
		AppID: "m365", Action: InlineActionShare, Verdict: InlineVerdictBlock, Enabled: true,
	}, nil); err != nil {
		t.Fatalf("create: %v", err)
	}
	compiled, err := svc.CompileRules(ctx, tenant)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Fold the compiled inline-CASB rules into a graph and verify
	// CompileTarget routes them exactly like the SWG bundle slice.
	g := policy.Graph{DefaultAction: policy.VerbDeny, Rules: compiled}
	if err := g.Validate(); err != nil {
		t.Fatalf("graph validate: %v", err)
	}
	for target, want := range map[repository.PolicyBundleTarget]int{
		repository.PolicyBundleTargetEdge:     1,
		repository.PolicyBundleTargetCloud:    1,
		repository.PolicyBundleTargetEndpoint: 0,
		repository.PolicyBundleTargetMobile:   0,
	} {
		if got := len(g.CompileTarget(target)); got != want {
			t.Errorf("target %s: want %d rules, got %d", target, want, got)
		}
	}
}

func TestSeedDefaultTemplates(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()
	tenant := uuid.New()

	seeded, err := svc.SeedDefaultTemplates(ctx, tenant, nil)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if len(seeded) != 2 {
		t.Fatalf("want 2 seeded templates, got %d", len(seeded))
	}

	// Idempotent: a second call returns the existing rules without
	// creating duplicates.
	again, err := svc.SeedDefaultTemplates(ctx, tenant, nil)
	if err != nil {
		t.Fatalf("re-seed: %v", err)
	}
	if len(again) != 2 {
		t.Fatalf("re-seed created duplicates: got %d", len(again))
	}

	// Verify the reference policies are present.
	var haveShareBlock, haveUploadLog bool
	for _, r := range again {
		if r.AppID == "m365" && r.Action == InlineActionShare && r.Verdict == InlineVerdictBlock {
			haveShareBlock = true
		}
		if r.AppID == "salesforce" && r.Action == InlineActionUpload && r.Verdict == InlineVerdictLog &&
			r.Conditions.SizeThreshold == 10*1024*1024 {
			haveUploadLog = true
		}
	}
	if !haveShareBlock || !haveUploadLog {
		t.Errorf("default templates missing: shareBlock=%v uploadLog=%v", haveShareBlock, haveUploadLog)
	}
}

func TestInlineRuleStore_TenantIsolation(t *testing.T) {
	t.Parallel()
	svc := newTestService(t)
	ctx := context.Background()
	tenantA := uuid.New()
	tenantB := uuid.New()

	ruleA, err := svc.CreateInlineRule(ctx, tenantA, CreateInlineRuleInput{
		AppID: "m365", Action: InlineActionUpload, Verdict: InlineVerdictBlock, Enabled: true,
	}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Tenant B must not see tenant A's rule.
	if _, err := svc.GetInlineRule(ctx, tenantB, ruleA.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant isolation breached on Get: %v", err)
	}
	listB, err := svc.ListInlineRules(ctx, tenantB)
	if err != nil {
		t.Fatalf("list B: %v", err)
	}
	if len(listB) != 0 {
		t.Fatalf("tenant B sees %d rules, want 0", len(listB))
	}
}
