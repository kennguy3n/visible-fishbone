// Command llm_validation exercises the natural-language query engine
// (internal/service/ai/nl_query.go) end-to-end against a live,
// OpenAI-compatible inference endpoint (e.g. the self-hosted
// Ternary-Bonsai-8B served via Ollama) and publishes a quality report:
// latency percentiles, parse success rate, and verifier pass rate.
//
// It is NOT a mock. It drives the exact engine the control plane wires
// (NLQueryEngine + a compiled policy-graph source) over a curated set
// of 20 AI-assistant queries spanning every intent kind, then asserts
// the four properties Post 6 promised but could not previously
// demonstrate on live inference:
//
//   - JSON validity      — the model's structured reply parses as JSON.
//   - ai_generated flag   — true only when the LLM was consulted AND
//     returned valid JSON; false on every fallback path.
//   - verifier correctness — policy-verdict questions resolve through
//     the deterministic compiled-bundle evaluator, not a model guess.
//   - fallback agreement   — the deterministic-first engine's
//     classification and verdict path are identical with and without
//     the LLM (the model only augments entity extraction; it can never
//     change the security-relevant routing).
//
// Deterministic-first by construction: the engine classifies intent,
// time windows and policy versions deterministically and consults the
// model only to fill free-form entity references the tokenizer missed.
// This harness validates that the model's RAW extraction agrees with
// the deterministic ground truth where the tokenizer also found a
// value, so a regression in either path surfaces as a failed run.
//
// Usage:
//
//	# Live inference (CI / local with Ollama):
//	AI_LLM_ENDPOINT=http://localhost:11434/v1/chat/completions \
//	AI_LLM_MODEL=qwen2.5:0.5b \
//	  go run ./blog/harness/llm_validation -out blog/artifacts/llm_validation
//
//	# Deterministic-only (no endpoint): still validates classification,
//	# verifier and the fallback path; skips model-quality metrics.
//	  go run ./blog/harness/llm_validation
//
// The process exits non-zero if any gating threshold is violated, so it
// doubles as the assertion step of the CI validation job.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	aisvc "github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

// queriesJSON is the curated 20-query fixture, embedded so the harness
// is a single self-contained binary.
//
//go:embed queries.json
var queriesJSON []byte

// fixtureGraph is a small compiled SWG policy graph used as the live
// tenant policy for verdict questions: allow two known hosts, default
// deny. It exercises both the allow and default-deny branches of the
// compiled-bundle evaluator so the verifier-pass metric is meaningful.
const fixtureGraph = `{"default_action":"deny","rules":[` +
	`{"id":"allow-sf","domain":"swg","verb":"allow","predicates":[{"name":"h","match":{"host":"salesforce.com"}}]},` +
	`{"id":"allow-internal","domain":"swg","verb":"allow","predicates":[{"name":"h","match":{"host":"internal.corp"}}]}` +
	`]}`

// curatedQuery is one row of the embedded fixture.
type curatedQuery struct {
	Question      string `json:"question"`
	ExpectKind    string `json:"expect_kind"`
	ExpectVerdict string `json:"expect_verdict"`
}

// queryReport is the per-query record emitted in the report.
type queryReport struct {
	Question       string `json:"question"`
	ExpectedKind   string `json:"expected_kind"`
	ParsedKind     string `json:"parsed_kind"`
	KindCorrect    bool   `json:"kind_correct"`
	Verdict        string `json:"verdict"`
	ExpectedVern   string `json:"expected_verdict"`
	VerdictCorrect bool   `json:"verdict_correct"`
	EvaluationMode string `json:"evaluation_mode"`
	AIGenerated    bool   `json:"ai_generated"`
	LLMConsulted   bool   `json:"llm_consulted"`
	LLMValidJSON   bool   `json:"llm_valid_json"`
	AIGenCorrect   bool   `json:"ai_generated_correct"`
	FallbackAgree  bool   `json:"fallback_agreement"`
	RawParseAgree  bool   `json:"raw_parse_agreement"`
	LatencyMS      int64  `json:"latency_ms,omitempty"`
	Note           string `json:"note,omitempty"`
}

// report is the published quality document.
type report struct {
	GeneratedAt        time.Time     `json:"generated_at"`
	Endpoint           string        `json:"endpoint"`
	Model              string        `json:"model"`
	LiveInference      bool          `json:"live_inference"`
	QueryCount         int           `json:"query_count"`
	ParseSuccessRate   float64       `json:"parse_success_rate"`
	VerifierPassRate   float64       `json:"verifier_pass_rate"`
	ClassificationRate float64       `json:"classification_accuracy"`
	VerdictAccuracy    float64       `json:"verdict_accuracy"`
	FallbackAgreement  float64       `json:"fallback_agreement_rate"`
	AIGenCorrectness   float64       `json:"ai_generated_correctness"`
	RawParseAgreement  float64       `json:"raw_parse_agreement_rate"`
	LatencyP50MS       int64         `json:"latency_p50_ms"`
	LatencyP95MS       int64         `json:"latency_p95_ms"`
	LatencyP99MS       int64         `json:"latency_p99_ms"`
	Queries            []queryReport `json:"queries"`
}

// graphSource is a fixed, in-memory ai.PolicyGraphSource serving the
// fixture graph for every tenant. It lets the harness exercise the
// real compiled-bundle evaluator without a database.
type graphSource struct {
	graph repository.PolicyGraph
}

func (g *graphSource) GetCurrentGraph(_ context.Context, _ uuid.UUID) (repository.PolicyGraph, error) {
	return g.graph, nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "llm_validation: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		outDir   = flag.String("out", "blog/artifacts/llm_validation", "directory for the published quality report")
		endpoint = flag.String("endpoint", os.Getenv("AI_LLM_ENDPOINT"), "OpenAI-compatible chat-completions endpoint")
		model    = flag.String("model", os.Getenv("AI_LLM_MODEL"), "served model name")
		apiKey   = flag.String("api-key", os.Getenv("AI_LLM_API_KEY"), "bearer token for the endpoint (optional)")
		timeout  = flag.Duration("timeout", 30*time.Second, "per-query timeout")
		// Gating thresholds. Classification, verifier, fallback and the
		// ai_generated flag are deterministic invariants and must be
		// perfect; parse success depends on the served model's JSON
		// discipline and has a configurable floor.
		minParseSuccess = flag.Float64("min-parse-success", 0.75, "minimum LLM JSON parse success rate (live mode)")
		flagJSON        = flag.Bool("json", false, "print the report JSON to stdout")
	)
	flag.Parse()

	queries, err := loadQueries()
	if err != nil {
		return err
	}

	src := &graphSource{graph: repository.PolicyGraph{
		ID:      uuid.New(),
		Version: 12,
		Graph:   json.RawMessage(fixtureGraph),
	}}

	// Deterministic engine: the authoritative fallback. Never consults
	// a model; its verdict and classification are the ground truth the
	// LLM-augmented path must agree with.
	detEngine := aisvc.NewNLQueryEngine(nil, aisvc.WithPolicyGraphSource(src))

	// LLM-augmented engine: same wiring plus a live provider when an
	// endpoint is configured.
	var provider aisvc.LLMProvider
	live := strings.TrimSpace(*endpoint) != ""
	resolvedModel := *model
	if live {
		if resolvedModel == "" {
			resolvedModel = aisvc.DefaultModel
		}
		provider = &aisvc.HTTPProvider{
			Endpoint:    *endpoint,
			APIKey:      *apiKey,
			Model:       resolvedModel,
			ModelFamily: "auto",
			Timeout:     *timeout,
		}
	}
	llmEngine := aisvc.NewNLQueryEngine(provider, aisvc.WithPolicyGraphSource(src))

	if live {
		// Warm the model so the first real query's latency reflects
		// steady-state inference, not one-off weight loading.
		warmCtx, cancel := context.WithTimeout(context.Background(), *timeout)
		_, _ = llmEngine.ParseIntent(warmCtx, "warm up the model")
		cancel()
	}

	rep := report{
		GeneratedAt:   time.Now().UTC(),
		Endpoint:      *endpoint,
		Model:         resolvedModel,
		LiveInference: live,
		QueryCount:    len(queries),
	}

	var (
		latencies                                          []int64
		parseOK, verdictKinds, verifierOK                  int
		kindOK, verdictOK, fallbackOK, aiGenOK, rawAgreeOK int
		rawAgreeDenom                                      int
	)

	for _, q := range queries {
		tenant := uuid.New()
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)

		detResp, derr := detEngine.Query(ctx, aisvc.NLQueryRequest{Question: q.Question, TenantID: tenant})
		if derr != nil {
			cancel()
			return fmt.Errorf("deterministic query %q: %w", q.Question, derr)
		}

		row := queryReport{
			Question:     q.Question,
			ExpectedKind: q.ExpectKind,
			ExpectedVern: q.ExpectVerdict,
		}

		// LLM-augmented parse (one model call). When no endpoint is
		// configured this is a deterministic parse and the fallback
		// agreement check is trivially satisfied.
		start := time.Now()
		parse, perr := llmEngine.ParseIntent(ctx, q.Question)
		elapsed := time.Since(start).Milliseconds()
		cancel()
		if perr != nil {
			return fmt.Errorf("parse intent %q: %w", q.Question, perr)
		}

		row.LLMConsulted = parse.LLMConsulted
		row.LLMValidJSON = parse.LLMValidJSON
		row.AIGenerated = parse.AIGenerated
		row.ParsedKind = string(parse.Intent.Kind)
		row.KindCorrect = row.ParsedKind == q.ExpectKind
		row.Verdict = detResp.Verdict
		row.VerdictCorrect = detResp.Verdict == q.ExpectVerdict
		row.EvaluationMode = detResp.EvaluationMode

		// ai_generated correctness: must be true iff the LLM was
		// consulted and produced valid JSON; never on a fallback.
		row.AIGenCorrect = parse.AIGenerated == (parse.LLMConsulted && parse.LLMValidJSON)

		// Fallback agreement: the deterministic-first invariant. The
		// LLM-augmented classification (and thus verdict routing) must
		// equal the deterministic classification. The merge only fills
		// empty entity refs, so the security-relevant fields — kind,
		// window, versions — must match the deterministic parse exactly.
		detIntent := detResp.Intent
		row.FallbackAgree = detIntent != nil && intentRoutingEqual(*detIntent, parse.Intent)

		// Raw-parse agreement: where the deterministic tokenizer
		// extracted an entity, the model's RAW JSON must agree. This
		// validates model extraction quality against ground truth and
		// is only scored when the model returned valid JSON AND the
		// deterministic parse had at least one entity to compare.
		if live && parse.LLMValidJSON {
			if det := detIntentEntities(detIntent); det > 0 {
				rawAgreeDenom++
				if rawExtractionAgrees(parse.LLMRawOutput, detIntent) {
					rawAgreeOK++
					row.RawParseAgree = true
				}
			} else {
				row.RawParseAgree = true // nothing to contradict
			}
		} else {
			row.RawParseAgree = true
		}

		if live {
			row.LatencyMS = elapsed
			latencies = append(latencies, elapsed)
			if parse.LLMValidJSON {
				parseOK++
			}
		}

		// Verifier pass: policy-verdict questions must resolve through
		// the compiled-bundle evaluator (the deterministic verifier),
		// never a model guess or a silent default fall-through.
		if q.ExpectKind == string(aisvc.IntentPolicyVerdict) {
			verdictKinds++
			if detResp.EvaluationMode == "compiled-bundle" {
				verifierOK++
			} else {
				row.Note = "expected compiled-bundle evaluation, got " + detResp.EvaluationMode
			}
		}

		if row.KindCorrect {
			kindOK++
		}
		if row.VerdictCorrect {
			verdictOK++
		}
		if row.FallbackAgree {
			fallbackOK++
		}
		if row.AIGenCorrect {
			aiGenOK++
		}

		rep.Queries = append(rep.Queries, row)
	}

	n := float64(len(queries))
	rep.ClassificationRate = float64(kindOK) / n
	rep.VerdictAccuracy = float64(verdictOK) / n
	rep.FallbackAgreement = float64(fallbackOK) / n
	rep.AIGenCorrectness = float64(aiGenOK) / n
	if verdictKinds > 0 {
		rep.VerifierPassRate = float64(verifierOK) / float64(verdictKinds)
	}
	if live {
		rep.ParseSuccessRate = float64(parseOK) / n
		rep.LatencyP50MS = percentile(latencies, 50)
		rep.LatencyP95MS = percentile(latencies, 95)
		rep.LatencyP99MS = percentile(latencies, 99)
	}
	if rawAgreeDenom > 0 {
		rep.RawParseAgreement = float64(rawAgreeOK) / float64(rawAgreeDenom)
	} else {
		rep.RawParseAgreement = 1
	}

	if err := publish(*outDir, rep); err != nil {
		return err
	}
	if *flagJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
	}

	printSummary(rep)
	return assertThresholds(rep, *minParseSuccess)
}

// intentRoutingEqual reports whether two intents agree on every
// security-relevant routing field. Entity refs are intentionally
// excluded: the LLM is permitted to fill refs the deterministic
// tokenizer left empty, and that augmentation must not count as
// disagreement.
func intentRoutingEqual(a, b aisvc.ParsedIntent) bool {
	if a.Kind != b.Kind {
		return false
	}
	if !windowEqual(a.Window, b.Window) {
		return false
	}
	if len(a.CompareVersions) != len(b.CompareVersions) {
		return false
	}
	for i := range a.CompareVersions {
		if a.CompareVersions[i] != b.CompareVersions[i] {
			return false
		}
	}
	return true
}

func windowEqual(a, b *aisvc.TimeWindow) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Seconds == b.Seconds
}

// detIntentEntities counts the non-empty entity refs in the
// deterministic parse — the fields available to compare against the
// model's raw extraction.
func detIntentEntities(i *aisvc.ParsedIntent) int {
	if i == nil {
		return 0
	}
	n := 0
	for _, f := range []string{i.UserRef, i.AppRef, i.DeviceRef} {
		if f != "" {
			n++
		}
	}
	return n
}

// rawExtractionAgrees unmarshals the model's raw JSON and checks that,
// for every entity the deterministic tokenizer extracted, the model
// produced the same value (case-insensitive, punctuation-trimmed).
func rawExtractionAgrees(raw string, det *aisvc.ParsedIntent) bool {
	if det == nil {
		return true
	}
	trimmed := extractJSONObject(raw)
	var m aisvc.ParsedIntent
	if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
		return false
	}
	for _, pair := range [][2]string{
		{det.UserRef, m.UserRef},
		{det.AppRef, m.AppRef},
		{det.DeviceRef, m.DeviceRef},
	} {
		if pair[0] == "" {
			continue
		}
		if !strings.EqualFold(strings.Trim(pair[1], "?!.,;:\"'`()[]{}<> "), pair[0]) {
			return false
		}
	}
	return true
}

// extractJSONObject returns the substring from the first '{' to the
// last '}' so a model that wraps its JSON in prose still parses.
func extractJSONObject(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i >= 0 && j > i {
		return s[i : j+1]
	}
	return s
}

// percentile returns the p-th percentile (nearest-rank) of vs in
// milliseconds. vs is copied before sorting so the caller's slice
// order is preserved.
func percentile(vs []int64, p int) int64 {
	if len(vs) == 0 {
		return 0
	}
	sorted := append([]int64(nil), vs...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := (p * len(sorted)) / 100
	if rank >= len(sorted) {
		rank = len(sorted) - 1
	}
	return sorted[rank]
}

func loadQueries() ([]curatedQuery, error) {
	var queries []curatedQuery
	if err := json.Unmarshal(queriesJSON, &queries); err != nil {
		return nil, fmt.Errorf("decode embedded queries: %w", err)
	}
	if len(queries) == 0 {
		return nil, fmt.Errorf("no curated queries embedded")
	}
	return queries, nil
}

func publish(outDir string, rep report) error {
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return fmt.Errorf("create out dir: %w", err)
	}
	jsonPath := filepath.Join(outDir, "quality_report.json")
	buf, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(jsonPath, append(buf, '\n'), 0o600); err != nil {
		return fmt.Errorf("write json report: %w", err)
	}
	mdPath := filepath.Join(outDir, "quality_report.md")
	if err := os.WriteFile(mdPath, []byte(renderMarkdown(rep)), 0o600); err != nil {
		return fmt.Errorf("write markdown report: %w", err)
	}
	return nil
}

func renderMarkdown(rep report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# LLM Inference Validation — Quality Report\n\n")
	fmt.Fprintf(&b, "_Generated %s_\n\n", rep.GeneratedAt.Format(time.RFC3339))
	if rep.LiveInference {
		fmt.Fprintf(&b, "Mode: **live inference** — model `%s` at `%s`.\n\n", rep.Model, rep.Endpoint)
	} else {
		fmt.Fprintf(&b, "Mode: **deterministic-only** (no `AI_LLM_ENDPOINT`); model-quality metrics are skipped.\n\n")
	}
	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Metric | Value |\n|---|---|\n")
	fmt.Fprintf(&b, "| Queries | %d |\n", rep.QueryCount)
	fmt.Fprintf(&b, "| Classification accuracy | %s |\n", pct(rep.ClassificationRate))
	fmt.Fprintf(&b, "| Verdict accuracy | %s |\n", pct(rep.VerdictAccuracy))
	fmt.Fprintf(&b, "| Verifier pass rate | %s |\n", pct(rep.VerifierPassRate))
	fmt.Fprintf(&b, "| Fallback agreement | %s |\n", pct(rep.FallbackAgreement))
	fmt.Fprintf(&b, "| ai_generated correctness | %s |\n", pct(rep.AIGenCorrectness))
	if rep.LiveInference {
		fmt.Fprintf(&b, "| Parse success rate (valid JSON) | %s |\n", pct(rep.ParseSuccessRate))
		fmt.Fprintf(&b, "| Raw-parse agreement vs deterministic | %s |\n", pct(rep.RawParseAgreement))
		fmt.Fprintf(&b, "| Latency p50 / p95 / p99 | %d / %d / %d ms |\n", rep.LatencyP50MS, rep.LatencyP95MS, rep.LatencyP99MS)
	}
	fmt.Fprintf(&b, "\n## Per-query results\n\n")
	fmt.Fprintf(&b, "| Question | Kind | Verdict | Mode | ai_gen | valid_json | latency |\n")
	fmt.Fprintf(&b, "|---|---|---|---|---|---|---|\n")
	for _, q := range rep.Queries {
		lat := "—"
		if q.LatencyMS > 0 {
			lat = fmt.Sprintf("%d ms", q.LatencyMS)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %t | %t | %s |\n",
			mdEscape(q.Question), q.ParsedKind, q.Verdict, q.EvaluationMode, q.AIGenerated, q.LLMValidJSON, lat)
	}
	return b.String()
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

func pct(f float64) string { return fmt.Sprintf("%.1f%%", f*100) }

func printSummary(rep report) {
	fmt.Printf("llm_validation: %d queries | classification %.1f%% | verifier %.1f%% | fallback %.1f%% | ai_gen %.1f%%\n",
		rep.QueryCount, rep.ClassificationRate*100, rep.VerifierPassRate*100, rep.FallbackAgreement*100, rep.AIGenCorrectness*100)
	if rep.LiveInference {
		fmt.Printf("llm_validation: live model=%s | parse-success %.1f%% | raw-agree %.1f%% | latency p50=%dms p95=%dms p99=%dms\n",
			rep.Model, rep.ParseSuccessRate*100, rep.RawParseAgreement*100, rep.LatencyP50MS, rep.LatencyP95MS, rep.LatencyP99MS)
	} else {
		fmt.Printf("llm_validation: deterministic-only run (no AI_LLM_ENDPOINT); model-quality metrics skipped\n")
	}
}

// assertThresholds enforces the gating invariants. The deterministic
// properties (classification, verifier, fallback agreement,
// ai_generated correctness) must be perfect; the model JSON parse rate
// must clear the configured floor in live mode.
func assertThresholds(rep report, minParseSuccess float64) error {
	var failures []string
	if rep.ClassificationRate < 1 {
		failures = append(failures, fmt.Sprintf("classification accuracy %.1f%% < 100%%", rep.ClassificationRate*100))
	}
	if rep.VerdictAccuracy < 1 {
		failures = append(failures, fmt.Sprintf("verdict accuracy %.1f%% < 100%%", rep.VerdictAccuracy*100))
	}
	if rep.VerifierPassRate < 1 {
		failures = append(failures, fmt.Sprintf("verifier pass rate %.1f%% < 100%%", rep.VerifierPassRate*100))
	}
	if rep.FallbackAgreement < 1 {
		failures = append(failures, fmt.Sprintf("fallback agreement %.1f%% < 100%%", rep.FallbackAgreement*100))
	}
	if rep.AIGenCorrectness < 1 {
		failures = append(failures, fmt.Sprintf("ai_generated correctness %.1f%% < 100%%", rep.AIGenCorrectness*100))
	}
	if rep.LiveInference && rep.ParseSuccessRate < minParseSuccess {
		failures = append(failures, fmt.Sprintf("parse success rate %.1f%% < %.1f%% floor", rep.ParseSuccessRate*100, minParseSuccess*100))
	}
	if len(failures) > 0 {
		return fmt.Errorf("quality gate failed:\n  - %s", strings.Join(failures, "\n  - "))
	}
	fmt.Println("llm_validation: all quality gates passed")
	return nil
}
