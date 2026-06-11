package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

func TestNLQueryEngine_EmptyQuestion(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	// Both an empty and a whitespace-only question must be rejected at
	// the same guard so Query and ParseIntent share one contract (a
	// blank question never reaches classification).
	for _, q := range []string{"", "   ", "\t\n "} {
		if _, err := engine.Query(context.Background(), NLQueryRequest{
			Question: q,
			TenantID: uuid.New(),
		}); err == nil {
			t.Fatalf("expected error for blank question %q", q)
		}
	}
}

// TestMergeIntent_EmptyKindContract locks the documented contract that
// an empty Kind is treated as IntentPolicyVerdict: the LLM's action is
// still merged in (verdict path) when the deterministic Kind is unset,
// while a non-verdict analytics Kind never accepts an LLM action.
func TestMergeIntent_EmptyKindContract(t *testing.T) {
	t.Parallel()
	// Empty deterministic Kind => verdict semantics => LLM action merged.
	got := mergeIntent(ParsedIntent{}, ParsedIntent{Action: "block"})
	if got.Action != "block" {
		t.Errorf("empty-Kind merge: Action = %q, want %q", got.Action, "block")
	}
	// Analytics Kind => read-only => LLM action dropped.
	got = mergeIntent(ParsedIntent{Kind: IntentBlockedTraffic}, ParsedIntent{Action: "block"})
	if got.Action != "" {
		t.Errorf("analytics merge: Action = %q, want empty", got.Action)
	}
}

// TestMergeEntityRef covers the extend-only contract: the model can
// fill an empty reference and extend an anchored single token to a
// multi-word name, but can never swap an anchored reference for an
// unrelated entity. The accepted reference is lowercased to match the
// all-lowercase deterministic tokenizer.
func TestMergeEntityRef(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		det    string
		llmRaw string
		want   string
	}{
		{"fill empty", "", "Salesforce", "salesforce"},
		{"fill empty multiword", "", "Google Drive", "google drive"},
		{"fill empty trims punctuation+space", "", "  salesforce? ", "salesforce"},
		{"extend anchored token", "google", "Google Drive", "google drive"},
		{"extend case-insensitive", "john", "John Smith", "john smith"},
		{"keep det when llm empty", "alice", "", "alice"},
		{"keep det when same single token", "salesforce", "salesforce", "salesforce"},
		{"reject swap to unrelated entity", "alice", "attacker", "alice"},
		{"reject multiword that does not start with anchor", "alice", "bob smith", "alice"},
		{"reject when only first word differs", "drive", "google drive", "drive"},
	}
	for _, tc := range cases {
		if got := mergeEntityRef(tc.det, tc.llmRaw); got != tc.want {
			t.Errorf("%s: mergeEntityRef(%q, %q) = %q, want %q", tc.name, tc.det, tc.llmRaw, got, tc.want)
		}
	}
}

// TestNLQueryEngine_LLMExtendsMultiWordEntity verifies the model
// materially improves entity resolution end-to-end: a question whose
// deterministic tokenizer anchors a single-token app ref ("google")
// is extended to the model's "google drive", while a hostile attempt
// to swap the user is rejected and routing stays deterministic.
func TestNLQueryEngine_LLMExtendsMultiWordEntity(t *testing.T) {
	t.Parallel()
	llm := &nlQueryStubLLM{
		text:    `{"user_ref":"attacker","app_ref":"Google Drive","device_ref":"laptop1"}`,
		modelID: "test-model",
	}
	engine := NewNLQueryEngine(llm)
	parse, err := engine.ParseIntent(context.Background(), "can user alice access app google from device laptop1?")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parse.AIGenerated || !parse.LLMValidJSON {
		t.Fatalf("expected ai_generated+valid JSON, got %+v", parse)
	}
	// Anchored "google" is extended to the model's multi-word name.
	if parse.Intent.AppRef != "google drive" {
		t.Fatalf("AppRef = %q, want %q (model extends the anchored token)", parse.Intent.AppRef, "google drive")
	}
	// The model cannot swap the deterministically anchored user.
	if parse.Intent.UserRef != "alice" {
		t.Fatalf("UserRef = %q, want alice (anchored ref must not be swapped)", parse.Intent.UserRef)
	}
	// Routing stays deterministic.
	if !parse.Intent.isVerdictKind() {
		t.Fatalf("kind = %q, want a verdict kind", parse.Intent.Kind)
	}
}

func TestNLQueryEngine_StructuredParsing(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user alice access app salesforce from device laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "allow" {
		t.Fatalf("expected allow verdict, got %s", resp.Verdict)
	}
	if resp.AIGenerated {
		t.Fatal("no LLM: ai_generated must be false")
	}
	if len(resp.MatchedRules) == 0 {
		t.Fatal("expected matched rules")
	}
}

func TestNLQueryEngine_StructuredParsingBlock(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "block user admin from app internal",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "deny" {
		t.Fatalf("expected deny verdict, got %s", resp.Verdict)
	}
}

func TestNLQueryEngine_NoEntities(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "what is the weather?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "unknown" {
		t.Fatalf("expected unknown verdict, got %s", resp.Verdict)
	}
	if resp.Confidence >= 0.5 {
		t.Fatalf("expected low confidence, got %f", resp.Confidence)
	}
}

func TestNLQueryEngine_WithLLM(t *testing.T) {
	t.Parallel()
	llm := &nlQueryStubLLM{
		text:    `{"user_ref": "alice", "app_ref": "salesforce", "device_ref": "laptop1", "action": "access"}`,
		modelID: "test-model",
	}
	engine := NewNLQueryEngine(llm)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can alice access salesforce from laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "allow" {
		t.Fatalf("expected allow, got %s", resp.Verdict)
	}
	if !resp.AIGenerated {
		t.Fatal("expected ai_generated=true with LLM")
	}
	if resp.ModelID != "test-model" {
		t.Fatalf("expected model_id=test-model, got %s", resp.ModelID)
	}
	if resp.Confidence < 0.7 {
		t.Fatalf("expected high confidence with LLM, got %f", resp.Confidence)
	}
}

func TestNLQueryEngine_LLMFallback(t *testing.T) {
	t.Parallel()
	llm := &nlQueryStubLLM{
		err: context.DeadlineExceeded,
	}
	engine := NewNLQueryEngine(llm)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user bob access app github?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should fall back to structured parsing.
	if resp.AIGenerated {
		t.Fatal("LLM failed: ai_generated should be false")
	}
	if resp.Verdict != "allow" {
		t.Fatalf("expected allow from structured fallback, got %s", resp.Verdict)
	}
}

func TestNLQueryEngine_DefaultHeuristicModeWhenNoSource(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user alice access app salesforce.com from device laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.EvaluationMode != evalModeDefaultHeuristic {
		t.Fatalf("expected mode %q, got %q", evalModeDefaultHeuristic, resp.EvaluationMode)
	}
	if resp.MatchedRules[0] != "default-policy" {
		t.Fatalf("expected default-policy matched rule, got %v", resp.MatchedRules)
	}
}

func TestNLQueryEngine_CompiledBundleAllow(t *testing.T) {
	t.Parallel()
	// SWG rule that allows the salesforce.com host; default deny.
	graph := `{"default_action":"deny","rules":[{"id":"allow-sf","domain":"swg","verb":"allow","predicates":[{"name":"h","match":{"host":"salesforce.com"}}]}]}`
	src := &fakeGraphSource{graph: repository.PolicyGraph{ID: uuid.New(), Version: 3, Graph: json.RawMessage(graph)}}
	engine := NewNLQueryEngine(nil, WithPolicyGraphSource(src))

	// No user ref: the verdict is fully representable in the access
	// envelope, so it carries full compiled-bundle authority.
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can app salesforce.com be reached from device laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "allow" {
		t.Fatalf("expected allow from compiled bundle, got %q", resp.Verdict)
	}
	if resp.EvaluationMode != evalModeCompiledBundle {
		t.Fatalf("expected mode %q, got %q", evalModeCompiledBundle, resp.EvaluationMode)
	}
	if len(resp.MatchedRules) == 0 || resp.MatchedRules[0] == "default-policy" {
		t.Fatalf("expected a policy-graph matched rule reference, got %v", resp.MatchedRules)
	}
	if resp.Confidence < 0.9 {
		t.Fatalf("expected high confidence for authoritative verdict, got %f", resp.Confidence)
	}
}

func TestNLQueryEngine_CompiledBundleUserRefPartialConfidence(t *testing.T) {
	t.Parallel()
	// The question names a user, but user identity cannot be carried
	// on the synthesized access envelope — so user-subject rules are
	// not evaluated. The verdict must NOT be reported with full
	// authority: confidence is reduced and the explanation says so.
	graph := `{"default_action":"deny","rules":[{"id":"allow-sf","domain":"swg","verb":"allow","predicates":[{"name":"h","match":{"host":"salesforce.com"}}]}]}`
	src := &fakeGraphSource{graph: repository.PolicyGraph{ID: uuid.New(), Version: 4, Graph: json.RawMessage(graph)}}
	engine := NewNLQueryEngine(nil, WithPolicyGraphSource(src))

	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user alice access app salesforce.com from device laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.EvaluationMode != evalModeCompiledBundle {
		t.Fatalf("expected mode %q, got %q", evalModeCompiledBundle, resp.EvaluationMode)
	}
	if resp.Confidence >= 0.95 {
		t.Fatalf("expected reduced confidence when user-subject rules can't be evaluated, got %f", resp.Confidence)
	}
	if !strings.Contains(resp.Explanation, "user-subject rules were not evaluated") {
		t.Fatalf("expected explanation caveat about unevaluated user rules, got %q", resp.Explanation)
	}
}

func TestNLQueryEngine_TrailingPunctuationDoesNotCorruptHost(t *testing.T) {
	t.Parallel()
	// The app ref is the final word before a "?". Before punctuation
	// stripping this produced AppRef="salesforce.com?", which matched
	// no SWG host rule and fell through to the default deny — yet was
	// still reported as an authoritative compiled-bundle verdict. The
	// ref must be cleaned so the allow rule matches.
	graph := `{"default_action":"deny","rules":[{"id":"allow-sf","domain":"swg","verb":"allow","predicates":[{"name":"h","match":{"host":"salesforce.com"}}]}]}`
	src := &fakeGraphSource{graph: repository.PolicyGraph{ID: uuid.New(), Version: 7, Graph: json.RawMessage(graph)}}
	engine := NewNLQueryEngine(nil, WithPolicyGraphSource(src))

	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user alice access app salesforce.com?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.EvaluationMode != evalModeCompiledBundle {
		t.Fatalf("expected mode %q, got %q", evalModeCompiledBundle, resp.EvaluationMode)
	}
	if resp.Verdict != "allow" {
		t.Fatalf("expected allow (punctuation stripped so host matches), got %q", resp.Verdict)
	}
}

func TestNLQueryEngine_StructuredParsingStripsPunctuation(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	intent := engine.parseStructured("Can user alice, access app salesforce? from device laptop1.")
	if intent.UserRef != "alice" {
		t.Fatalf("UserRef = %q, want alice", intent.UserRef)
	}
	if intent.AppRef != "salesforce" {
		t.Fatalf("AppRef = %q, want salesforce", intent.AppRef)
	}
	if intent.DeviceRef != "laptop1" {
		t.Fatalf("DeviceRef = %q, want laptop1", intent.DeviceRef)
	}
}

func TestNLQueryEngine_CompiledBundleDefaultDeny(t *testing.T) {
	t.Parallel()
	// Same graph, but the queried app doesn't match the allow rule,
	// so the graph's default action (deny) governs.
	graph := `{"default_action":"deny","rules":[{"id":"allow-sf","domain":"swg","verb":"allow","predicates":[{"name":"h","match":{"host":"salesforce.com"}}]}]}`
	src := &fakeGraphSource{graph: repository.PolicyGraph{ID: uuid.New(), Version: 1, Graph: json.RawMessage(graph)}}
	engine := NewNLQueryEngine(nil, WithPolicyGraphSource(src))

	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user bob access app evil.com from device laptop2?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Verdict != "deny" {
		t.Fatalf("expected deny from default action, got %q", resp.Verdict)
	}
	if resp.EvaluationMode != evalModeCompiledBundle {
		t.Fatalf("expected mode %q, got %q", evalModeCompiledBundle, resp.EvaluationMode)
	}
}

func TestNLQueryEngine_NoLivePolicyFallsBack(t *testing.T) {
	t.Parallel()
	src := &fakeGraphSource{err: repository.ErrNotFound}
	engine := NewNLQueryEngine(nil, WithPolicyGraphSource(src))

	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "Can user alice access app salesforce.com from device laptop1?",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.EvaluationMode != evalModeNoPolicy {
		t.Fatalf("expected mode %q, got %q", evalModeNoPolicy, resp.EvaluationMode)
	}
	// Heuristic default applies (allow unless explicit block).
	if resp.Verdict != "allow" {
		t.Fatalf("expected heuristic allow, got %q", resp.Verdict)
	}
}

// --- expanded grammar: analytics intent kinds ---

// TestNLQueryEngine_ClassifyKind locks the deterministic classifier
// for each new analytics phrasing plus the policy-verdict default,
// including the near-miss cases that must NOT be reclassified (a bare
// "block ... " verdict question is not blocked-traffic analytics).
func TestNLQueryEngine_ClassifyKind(t *testing.T) {
	t.Parallel()
	cases := []struct {
		question string
		want     IntentKind
	}{
		{"show blocked traffic for user alice", IntentBlockedTraffic},
		{"list blocked connections in the last 24h", IntentBlockedTraffic},
		{"what changed since last week", IntentChangeSummary},
		{"what has changed in the policy since yesterday", IntentChangeSummary},
		{"what is changing in the rules since friday", IntentChangeSummary},
		{"compare policy versions", IntentPolicyVersionCompare},
		{"compare v2 and v5 of the policy", IntentPolicyVersionCompare},
		{"which devices failed posture in 24h", IntentPostureFailure},
		{"show devices failing posture checks today", IntentPostureFailure},
		// Verdict questions and near-misses must stay policy_verdict.
		{"Can user alice access app salesforce from device laptop1?", IntentPolicyVerdict},
		{"block user admin from app internal", IntentPolicyVerdict},
		{"is traffic to evil.com blocked?", IntentPolicyVerdict},
		// "exchange" contains the substring "chang" but a reachability
		// verdict question must not be routed to the change-summary path.
		{"Can app exchange be reached since yesterday?", IntentPolicyVerdict},
		// "exchanged"/"unchanged"/"exchanges" embed "changed"/"changes"
		// but are not change-summary questions — word-boundary matching
		// keeps them on the verdict path even with a "since" clause.
		{"what has exchanged since yesterday?", IntentPolicyVerdict},
		{"are the rules unchanged since last week?", IntentPolicyVerdict},
		{"can bob access the data exchanges since monday?", IntentPolicyVerdict},
		{"what is the weather?", IntentPolicyVerdict},
	}
	for _, tc := range cases {
		if got := classifyKind(strings.ToLower(tc.question)); got != tc.want {
			t.Errorf("classifyKind(%q) = %q, want %q", tc.question, got, tc.want)
		}
	}
}

// TestNLQueryEngine_ParseTimeWindow checks relative-window
// normalization to seconds across numeric and named phrasings.
func TestNLQueryEngine_ParseTimeWindow(t *testing.T) {
	t.Parallel()
	const day = int64(86400)
	cases := []struct {
		question string
		wantNil  bool
		wantSecs int64
	}{
		{"which devices failed posture in 24h", false, day},
		{"blocked traffic in the last 48 hours", false, 2 * day},
		{"what changed since last week", false, 7 * day},
		{"changes in the past 2 weeks", false, 14 * day},
		{"posture failures today", false, day},
		{"changes since yesterday", false, day},
		{"changes in the last month", false, 30 * day},
		{"Can user alice access app salesforce?", true, 0},
	}
	for _, tc := range cases {
		w := parseTimeWindow(strings.ToLower(tc.question))
		if tc.wantNil {
			if w != nil {
				t.Errorf("parseTimeWindow(%q) = %+v, want nil", tc.question, w)
			}
			continue
		}
		if w == nil {
			t.Errorf("parseTimeWindow(%q) = nil, want %d seconds", tc.question, tc.wantSecs)
			continue
		}
		if w.Seconds != tc.wantSecs {
			t.Errorf("parseTimeWindow(%q).Seconds = %d, want %d", tc.question, w.Seconds, tc.wantSecs)
		}
	}
}

// TestNLQueryEngine_ParseVersionRefs checks version extraction from
// both "vN" and bare-integer phrasings, with de-dup and sorting.
func TestNLQueryEngine_ParseVersionRefs(t *testing.T) {
	t.Parallel()
	cases := []struct {
		question string
		want     []int
	}{
		{"compare v2 and v5", []int{2, 5}},
		{"compare policy versions 3 and 5", []int{3, 5}},
		{"compare policy v5 and v2 and v5", []int{2, 5}},
		{"compare policy versions", nil},
		// A relative-time magnitude must not be read as a version number.
		{"compare policy versions in the last 7 days", nil},
		{"compare versions 3 and 5 over the last 24h", []int{3, 5}},
	}
	for _, tc := range cases {
		got := parseVersionRefs(strings.ToLower(tc.question))
		if len(got) != len(tc.want) {
			t.Errorf("parseVersionRefs(%q) = %v, want %v", tc.question, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseVersionRefs(%q) = %v, want %v", tc.question, got, tc.want)
				break
			}
		}
	}
}

// TestNLQueryEngine_BlockedTrafficSubject verifies the user subject is
// extracted both via the "user X" keyword and the bare "for X" form.
func TestNLQueryEngine_BlockedTrafficSubject(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	for _, q := range []string{
		"show blocked traffic for user alice in the last 24h",
		"show blocked traffic for alice in the last 24h",
	} {
		intent := engine.parseStructured(q)
		if intent.Kind != IntentBlockedTraffic {
			t.Fatalf("%q: kind = %q, want blocked_traffic", q, intent.Kind)
		}
		if intent.UserRef != "alice" {
			t.Fatalf("%q: UserRef = %q, want alice", q, intent.UserRef)
		}
		if intent.Window == nil || intent.Window.Seconds != 86400 {
			t.Fatalf("%q: window = %+v, want 24h", q, intent.Window)
		}
	}
}

// TestNLQueryEngine_AnalyticsIntentCarriesNoAction asserts that the
// word "blocked" in a read-only analytics query is never promoted to
// an enforcement Action, while a genuine verdict question still is.
func TestNLQueryEngine_AnalyticsIntentCarriesNoAction(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	cases := []struct {
		question   string
		wantKind   IntentKind
		wantAction string
	}{
		{"show blocked traffic for user alice in the last 24h", IntentBlockedTraffic, ""},
		{"list blocked connections today", IntentBlockedTraffic, ""},
		{"should user admin be blocked from app internal?", IntentPolicyVerdict, "block"},
		{"can user alice access app salesforce?", IntentPolicyVerdict, "access"},
	}
	for _, tc := range cases {
		intent := engine.parseStructured(tc.question)
		if intent.Kind != tc.wantKind {
			t.Errorf("%q: kind = %q, want %q", tc.question, intent.Kind, tc.wantKind)
		}
		if intent.Action != tc.wantAction {
			t.Errorf("%q: action = %q, want %q", tc.question, intent.Action, tc.wantAction)
		}
	}
}

// TestNLQueryEngine_AnalyticsResponse asserts analytics questions
// return an informational (non-enforcement) response carrying the
// structured intent and never a fabricated verdict.
func TestNLQueryEngine_AnalyticsResponse(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	cases := []struct {
		question string
		kind     IntentKind
	}{
		{"show blocked traffic for user alice in the last 24h", IntentBlockedTraffic},
		{"what changed since last week", IntentChangeSummary},
		{"compare policy versions", IntentPolicyVersionCompare},
		{"which devices failed posture in 24h", IntentPostureFailure},
	}
	for _, tc := range cases {
		resp, err := engine.Query(context.Background(), NLQueryRequest{
			Question: tc.question,
			TenantID: uuid.New(),
		})
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", tc.question, err)
		}
		if resp.Verdict != verdictInformational {
			t.Errorf("%q: verdict = %q, want %q", tc.question, resp.Verdict, verdictInformational)
		}
		if resp.EvaluationMode != evalModeIntentClassified {
			t.Errorf("%q: mode = %q, want %q", tc.question, resp.EvaluationMode, evalModeIntentClassified)
		}
		if resp.QueryKind != string(tc.kind) {
			t.Errorf("%q: query_kind = %q, want %q", tc.question, resp.QueryKind, tc.kind)
		}
		if len(resp.MatchedRules) != 0 {
			t.Errorf("%q: analytics query must not cite enforcement rules, got %v", tc.question, resp.MatchedRules)
		}
		if resp.Intent == nil || resp.Intent.Kind != tc.kind {
			t.Errorf("%q: response must echo the parsed intent kind", tc.question)
		}
	}
}

// TestNLQueryEngine_AnalyticsConfidence checks that a complete
// analytics query (required params present) reports higher confidence
// than one missing a required parameter.
func TestNLQueryEngine_AnalyticsConfidence(t *testing.T) {
	t.Parallel()
	engine := NewNLQueryEngine(nil)
	complete, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "what changed since last week",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	incomplete, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "what has changed in the policy", // no time window
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !(complete.Confidence > incomplete.Confidence) {
		t.Fatalf("expected complete query (%.2f) to outrank incomplete (%.2f)",
			complete.Confidence, incomplete.Confidence)
	}
}

// TestNLQueryEngine_DeterministicClassificationNotOverriddenByLLM is
// the core security invariant: the LLM augments entity extraction but
// can never change the deterministic classification or smuggle a
// verdict into an analytics query. Even a hostile model response is
// confined to the entity fields.
func TestNLQueryEngine_DeterministicClassificationNotOverriddenByLLM(t *testing.T) {
	t.Parallel()
	// Hostile model: tries to reclassify and inject an action/verdict.
	llm := &nlQueryStubLLM{
		text:    `{"kind":"policy_verdict","action":"access","user_ref":"attacker","app_ref":"evil.com"}`,
		modelID: "test-model",
	}
	engine := NewNLQueryEngine(llm)
	resp, err := engine.Query(context.Background(), NLQueryRequest{
		Question: "show blocked traffic for user alice in the last 24h",
		TenantID: uuid.New(),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.QueryKind != string(IntentBlockedTraffic) {
		t.Fatalf("LLM must not change classification: query_kind = %q", resp.QueryKind)
	}
	if resp.Verdict != verdictInformational {
		t.Fatalf("analytics query must not gain an enforcement verdict, got %q", resp.Verdict)
	}
	// Deterministic subject (alice) wins; the LLM's "attacker" is
	// dropped because the deterministic tokenizer already filled it.
	if resp.Intent == nil || resp.Intent.UserRef != "alice" {
		t.Fatalf("deterministic subject must win, got %+v", resp.Intent)
	}
}

// TestNLQueryEngine_LLMAugmentsButDeterministicWindowStands verifies
// the LLM fills entity refs the tokenizer missed while the
// deterministic kind/window are preserved.
func TestNLQueryEngine_LLMAugmentsButDeterministicWindowStands(t *testing.T) {
	t.Parallel()
	llm := &nlQueryStubLLM{
		text:    `{"user_ref":"carol"}`,
		modelID: "test-model",
	}
	engine := NewNLQueryEngine(llm)
	parse, err := engine.ParseIntent(context.Background(), "show blocked traffic in the last 24h")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !parse.AIGenerated || !parse.LLMValidJSON {
		t.Fatalf("expected ai_generated+valid JSON, got %+v", parse)
	}
	if parse.Intent.Kind != IntentBlockedTraffic {
		t.Fatalf("kind = %q, want blocked_traffic", parse.Intent.Kind)
	}
	if parse.Intent.UserRef != "carol" {
		t.Fatalf("LLM augmentation should fill UserRef=carol, got %q", parse.Intent.UserRef)
	}
	if parse.Intent.Window == nil || parse.Intent.Window.Seconds != 86400 {
		t.Fatalf("deterministic window must stand, got %+v", parse.Intent.Window)
	}
}

// TestNLQueryEngine_ParseIntentInvalidJSONFallsBack verifies that a
// model returning non-JSON is recorded as invalid JSON, ai_generated
// stays false, and the deterministic parse is used.
func TestNLQueryEngine_ParseIntentInvalidJSONFallsBack(t *testing.T) {
	t.Parallel()
	llm := &nlQueryStubLLM{text: "I cannot answer that.", modelID: "test-model"}
	engine := NewNLQueryEngine(llm)
	parse, err := engine.ParseIntent(context.Background(), "what changed since last week")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parse.AIGenerated {
		t.Fatal("invalid JSON: ai_generated must be false")
	}
	if !parse.LLMConsulted || parse.LLMValidJSON {
		t.Fatalf("expected LLMConsulted=true, LLMValidJSON=false, got %+v", parse)
	}
	if parse.LLMRawOutput != "I cannot answer that." {
		t.Fatalf("raw output not recorded, got %q", parse.LLMRawOutput)
	}
	if parse.Intent.Kind != IntentChangeSummary {
		t.Fatalf("deterministic classification must stand, got %q", parse.Intent.Kind)
	}
}

// TestNLQueryEngine_LLMAndDeterministicAgree is the agreement check
// the CI validation job relies on: for the same question, an
// LLM-augmented parse and a deterministic-only parse must agree on the
// security-relevant fields (kind, window, versions) and on the
// resulting verdict path.
func TestNLQueryEngine_LLMAndDeterministicAgree(t *testing.T) {
	t.Parallel()
	graph := `{"default_action":"deny","rules":[{"id":"allow-sf","domain":"swg","verb":"allow","predicates":[{"name":"h","match":{"host":"salesforce.com"}}]}]}`
	questions := []string{
		"Can app salesforce.com be reached from device laptop1?",
		"show blocked traffic for user alice in the last 24h",
		"what changed since last week",
		"compare v2 and v5",
		"which devices failed posture in 24h",
	}
	for _, q := range questions {
		det := NewNLQueryEngine(nil, WithPolicyGraphSource(&fakeGraphSource{
			graph: repository.PolicyGraph{ID: uuid.New(), Version: 9, Graph: json.RawMessage(graph)},
		}))
		llm := NewNLQueryEngine(
			&nlQueryStubLLM{text: `{"app_ref":"salesforce.com","device_ref":"laptop1"}`, modelID: "test-model"},
			WithPolicyGraphSource(&fakeGraphSource{
				graph: repository.PolicyGraph{ID: uuid.New(), Version: 9, Graph: json.RawMessage(graph)},
			}),
		)
		tenant := uuid.New()
		dResp, err := det.Query(context.Background(), NLQueryRequest{Question: q, TenantID: tenant})
		if err != nil {
			t.Fatalf("%q: deterministic: %v", q, err)
		}
		lResp, err := llm.Query(context.Background(), NLQueryRequest{Question: q, TenantID: tenant})
		if err != nil {
			t.Fatalf("%q: llm: %v", q, err)
		}
		if dResp.Verdict != lResp.Verdict {
			t.Errorf("%q: verdict disagreement det=%q llm=%q", q, dResp.Verdict, lResp.Verdict)
		}
		if dResp.QueryKind != lResp.QueryKind {
			t.Errorf("%q: kind disagreement det=%q llm=%q", q, dResp.QueryKind, lResp.QueryKind)
		}
		if dResp.EvaluationMode != lResp.EvaluationMode {
			t.Errorf("%q: mode disagreement det=%q llm=%q", q, dResp.EvaluationMode, lResp.EvaluationMode)
		}
	}
}

// --- test stubs ---

type fakeGraphSource struct {
	graph repository.PolicyGraph
	err   error
}

func (f *fakeGraphSource) GetCurrentGraph(_ context.Context, _ uuid.UUID) (repository.PolicyGraph, error) {
	if f.err != nil {
		return repository.PolicyGraph{}, f.err
	}
	return f.graph, nil
}

type nlQueryStubLLM struct {
	text    string
	modelID string
	err     error
}

func (s *nlQueryStubLLM) Complete(_ context.Context, _ LLMRequest) (LLMResponse, error) {
	if s.err != nil {
		return LLMResponse{}, s.err
	}
	return LLMResponse{Text: s.text, ModelID: s.modelID, TokenCount: 30}, nil
}
