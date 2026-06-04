// Command controlplane-bench is the SNG control-plane scale benchmark
// harness. This file holds the report model: the JSON artifact the
// weekly workflow archives, the markdown summary it surfaces, the
// per-metric verdict logic, and the run-over-run regression detector.
//
// Everything here is a pure transform over plain data so the report
// shape, the verdict maths, and the regression detector are unit-tested
// without a socket, a container, or a clock. The container-requiring
// measurement code lives behind the `integration` build tag.
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// SchemaVersion is the report schema version. Bump it whenever the
// JSON shape changes so a stale artifact is never silently compared
// against a new one by the regression detector.
const SchemaVersion = 1

// Mode labels the benchmark that produced a report. They mirror the
// CLI subcommands.
const (
	ModeAPILatency    = "api-latency"
	ModePolicyCompile = "policy-compile"
	ModeTenantScale   = "tenant-scale"
	ModeFullSuite     = "full-suite"
)

// Verdict status values.
const (
	StatusPass = "PASS"
	StatusWarn = "WARN"
	StatusFail = "FAIL"
)

// warnFraction is how far past a theoretical target a metric may drift
// before it flips from PASS to WARN. Beyond `1 + warnFraction`x the
// target the verdict is FAIL. 0.20 == 20%, matching the regression bar
// the scale-bench workflow alerts on.
const warnFraction = 0.20

// BusinessBenchmarkReport is the full artifact for one harness run.
type BusinessBenchmarkReport struct {
	// SchemaVersion guards cross-version comparison.
	SchemaVersion int `json:"schema_version"`
	// Mode is the subcommand that produced this report.
	Mode string `json:"mode"`
	// UnixTimeSecs is the run timestamp, Unix epoch seconds.
	UnixTimeSecs int64 `json:"unix_time_secs"`
	// GitSHA is the commit the run was built from, when known.
	GitSHA string `json:"git_sha,omitempty"`
	// DryRun records whether the numbers came from the synthetic
	// in-process pipeline (no live control plane / Postgres) rather
	// than a real workload. A dry-run report is for pipeline
	// self-test only and must never be archived as a baseline.
	DryRun bool `json:"dry_run"`

	// APILatency is present for the api-latency and full-suite modes.
	APILatency *APILatencySection `json:"api_latency,omitempty"`
	// PolicyCompile is present for the policy-compile and full-suite
	// modes.
	PolicyCompile *PolicyCompileSection `json:"policy_compile,omitempty"`
	// PostgresScale is present for the tenant-scale and full-suite
	// modes.
	PostgresScale *PostgresScaleSection `json:"postgres_scale,omitempty"`

	// Theoretical holds the design targets the verdicts are graded
	// against (sourced from PROPOSAL.md / ARCHITECTURE.md).
	Theoretical TheoreticalTargets `json:"theoretical"`
	// Competitor holds the published competitor numbers, with the
	// honesty caveat that makes the comparison fair.
	Competitor CompetitorBaselines `json:"competitor"`
	// Verdicts is the per-metric PASS/WARN/FAIL grading with gap
	// analysis. Derived from the sections + targets by Grade.
	Verdicts []Verdict `json:"verdicts"`
}

// EndpointLatency is the measured latency distribution for one
// API endpoint at one tenant-count tier. Latencies are milliseconds.
type EndpointLatency struct {
	// Method is the HTTP verb (GET, POST, PATCH).
	Method string `json:"method"`
	// Route is the OpenAPI route template (e.g.
	// "/api/v1/tenants/{tenant_id}").
	Route string `json:"route"`
	// Count is the number of completed requests.
	Count int64 `json:"count"`
	// Errors is the number of non-2xx / transport-failed requests.
	Errors int64 `json:"errors"`
	// RequestsPerSec is the achieved throughput for this endpoint.
	RequestsPerSec float64 `json:"requests_per_sec"`
	// P50Ms, P95Ms, P99Ms, MaxMs are latency percentiles in ms.
	P50Ms float64 `json:"p50_ms"`
	P95Ms float64 `json:"p95_ms"`
	P99Ms float64 `json:"p99_ms"`
	MaxMs float64 `json:"max_ms"`
}

// APILatencyTier is the aggregate result of running the mixed API
// workload against a control plane seeded with TenantCount tenants.
type APILatencyTier struct {
	// TenantCount is how many tenants were pre-seeded for this tier.
	TenantCount int `json:"tenant_count"`
	// DurationSecs is the measurement window per tier.
	DurationSecs int `json:"duration_secs"`
	// Concurrency is the number of concurrent virtual clients.
	Concurrency int `json:"concurrency"`
	// Endpoints holds the per-endpoint breakdown.
	Endpoints []EndpointLatency `json:"endpoints"`
	// OverallP99Ms is the p99 across every request in the tier.
	OverallP99Ms float64 `json:"overall_p99_ms"`
	// OverallRequestsPerSec is the aggregate throughput.
	OverallRequestsPerSec float64 `json:"overall_requests_per_sec"`
	// ErrorRate is errors/total across the tier, in [0,1].
	ErrorRate float64 `json:"error_rate"`
}

// APILatencySection collects every tenant-count tier measured.
type APILatencySection struct {
	Tiers []APILatencyTier `json:"tiers"`
}

// p99ForTenantCount returns the OverallP99Ms of the tier seeded with
// exactly n tenants, and whether such a tier exists. The regression
// detector uses it to compare like-for-like tiers across two reports.
func (s *APILatencySection) p99ForTenantCount(n int) (float64, bool) {
	for i := range s.Tiers {
		if s.Tiers[i].TenantCount == n {
			return s.Tiers[i].OverallP99Ms, true
		}
	}
	return 0, false
}

// largestCommonTenantCount returns the largest TenantCount measured in
// both sections, and whether any tier count is shared. The regression
// detector keys off this so it always compares the same tenant tier on
// each side rather than each report's own (possibly different) max tier.
func largestCommonTenantCount(a, b *APILatencySection) (int, bool) {
	best, found := 0, false
	for i := range a.Tiers {
		n := a.Tiers[i].TenantCount
		if _, ok := b.p99ForTenantCount(n); ok && (!found || n > best) {
			best, found = n, true
		}
	}
	return best, found
}

// maxTenantTier returns the tier with the largest TenantCount, or nil
// when the section has no tiers.
func (s *APILatencySection) maxTenantTier() *APILatencyTier {
	var best *APILatencyTier
	for i := range s.Tiers {
		if best == nil || s.Tiers[i].TenantCount > best.TenantCount {
			best = &s.Tiers[i]
		}
	}
	return best
}

// PolicyCompileResult is one policy-graph compilation measurement.
type PolicyCompileResult struct {
	// RuleCount is the number of rules in the compiled graph.
	RuleCount int `json:"rule_count"`
	// Target is the bundle target ("edge"|"endpoint"|"cloud"|
	// "mobile") or "all" when the result covers a full compile that
	// emits every target.
	Target string `json:"target"`
	// CompileMs is the wall-clock compile time in milliseconds.
	CompileMs float64 `json:"compile_ms"`
	// BundleBytes is the size of the emitted bundle payload.
	BundleBytes int `json:"bundle_bytes"`
	// AllocBytes is the heap bytes allocated during the compile, as
	// observed via runtime.MemStats deltas.
	AllocBytes uint64 `json:"alloc_bytes"`
}

// ConcurrentCompileResult measures N tenants compiling in parallel.
type ConcurrentCompileResult struct {
	// Tenants is the parallelism level.
	Tenants int `json:"tenants"`
	// RuleCount is the per-graph rule count used for the fan-out.
	RuleCount int `json:"rule_count"`
	// WallMs is the wall-clock time to finish all compiles.
	WallMs float64 `json:"wall_ms"`
	// MeanMs / P99Ms are the per-compile time distribution.
	MeanMs float64 `json:"mean_ms"`
	P99Ms  float64 `json:"p99_ms"`
}

// PolicyCompileSection collects the policy-compile measurements.
type PolicyCompileSection struct {
	// PerGraphSize is a single full-compile per graph size (the
	// CompileMs is the all-targets compile time).
	PerGraphSize []PolicyCompileResult `json:"per_graph_size"`
	// PerTarget breaks one representative graph size down per bundle
	// target so per-target bundle sizes are visible.
	PerTarget []PolicyCompileResult `json:"per_target"`
	// Concurrent holds the parallel-tenant fan-out results.
	Concurrent []ConcurrentCompileResult `json:"concurrent"`
}

// compileMsForRules returns the all-targets CompileMs for the given
// rule count, and whether a matching result was found.
func (s *PolicyCompileSection) compileMsForRules(rules int) (float64, bool) {
	for i := range s.PerGraphSize {
		if s.PerGraphSize[i].RuleCount == rules {
			return s.PerGraphSize[i].CompileMs, true
		}
	}
	return 0, false
}

// RLSOverhead captures the cost of Postgres row-level security.
type RLSOverhead struct {
	// WithRLSP99Ms is the tenant-scoped query p99 with the
	// `sng.tenant_id` GUC set (RLS enforced).
	WithRLSP99Ms float64 `json:"with_rls_p99_ms"`
	// WithoutRLSP99Ms is the same query run as a superuser bypassing
	// RLS (the GUC unset / FORCE RLS not applying).
	WithoutRLSP99Ms float64 `json:"without_rls_p99_ms"`
	// OverheadPct is (with-without)/without as a percentage.
	OverheadPct float64 `json:"overhead_pct"`
}

// PoolSaturation captures where the connection pool tops out.
type PoolSaturation struct {
	// PoolSize is the configured max connections.
	PoolSize int `json:"pool_size"`
	// SaturationConcurrency is the concurrent-query level past which
	// throughput stops rising (queries queue on the pool).
	SaturationConcurrency int `json:"saturation_concurrency"`
	// MaxQueriesPerSec is the peak achieved query throughput.
	MaxQueriesPerSec float64 `json:"max_queries_per_sec"`
}

// MigrationSpeed captures an online DDL timing at scale.
type MigrationSpeed struct {
	// RowCount is the number of rows in the altered table.
	RowCount int64 `json:"row_count"`
	// Statement is the DDL measured (e.g. "ALTER TABLE ... ADD
	// COLUMN").
	Statement string `json:"statement"`
	// ElapsedMs is the wall-clock time the statement took.
	ElapsedMs float64 `json:"elapsed_ms"`
}

// PostgresScaleSection collects the Postgres-at-scale measurements.
type PostgresScaleSection struct {
	// TenantCount is how many tenants were seeded for the run.
	TenantCount int `json:"tenant_count"`
	// RLS is the RLS overhead measurement.
	RLS RLSOverhead `json:"rls"`
	// Pool is the connection-pool saturation measurement.
	Pool PoolSaturation `json:"pool"`
	// Migration is the online-DDL timing.
	Migration MigrationSpeed `json:"migration"`
	// RowCounts maps logical table name -> total rows seeded.
	RowCounts map[string]int64 `json:"row_counts"`
	// IndexSizeBytes maps index name -> on-disk size.
	IndexSizeBytes map[string]int64 `json:"index_size_bytes"`
}

// TheoreticalTargets are the design goals the verdicts grade against.
// Sourced from PROPOSAL.md / ARCHITECTURE.md; see field docs.
type TheoreticalTargets struct {
	// APIP99Ms is the control-plane API p99 target at scale.
	APIP99Ms float64 `json:"api_p99_ms"`
	// PolicyCompile100RuleMs is the <100ms target for a 100-rule
	// graph.
	PolicyCompile100RuleMs float64 `json:"policy_compile_100_rule_ms"`
	// PolicyCompile1000RuleMs is the <1s target for a 1000-rule
	// graph.
	PolicyCompile1000RuleMs float64 `json:"policy_compile_1000_rule_ms"`
	// RLSOverheadPct is the tolerated RLS overhead ceiling.
	RLSOverheadPct float64 `json:"rls_overhead_pct"`
}

// DefaultTheoreticalTargets returns the design targets baked into the
// proposal. Centralised so the verdicts and the markdown header agree.
func DefaultTheoreticalTargets() TheoreticalTargets {
	return TheoreticalTargets{
		APIP99Ms:                200,
		PolicyCompile100RuleMs:  100,
		PolicyCompile1000RuleMs: 1000,
		RLSOverheadPct:          15,
	}
}

// CompetitorBaselines are published competitor numbers. They are NOT
// apples-to-apples (see Caveat); they frame the SaaS control plane
// against management-plane / appliance products.
type CompetitorBaselines struct {
	// FortinetPolicyPushP99Ms is FortiManager's policy-push p99 at
	// ~1000 managed devices (management plane).
	FortinetPolicyPushP99Ms float64 `json:"fortinet_policy_push_p99_ms"`
	// ZscalerTenantCRUDP99Ms is the Zscaler Admin API tenant-CRUD
	// p99 (cloud-native — the most directly comparable).
	ZscalerTenantCRUDP99Ms float64 `json:"zscaler_tenant_crud_p99_ms"`
	// PaloAltoPolicyCompileP99Ms is Panorama's policy-compilation
	// p99 (appliance management plane).
	PaloAltoPolicyCompileP99Ms float64 `json:"palo_alto_policy_compile_p99_ms"`
	// Caveat states why the comparison is not apples-to-apples.
	Caveat string `json:"caveat"`
}

// DefaultCompetitorBaselines returns the hardcoded published numbers
// with their honesty caveat. Values are the midpoint of the
// published ranges noted in the field docs.
func DefaultCompetitorBaselines() CompetitorBaselines {
	return CompetitorBaselines{
		FortinetPolicyPushP99Ms:    500, // FortiManager ~200-500ms policy push @ 1000 devices
		ZscalerTenantCRUDP99Ms:     300, // Zscaler Admin API ~100-300ms tenant CRUD
		PaloAltoPolicyCompileP99Ms: 800, // Panorama ~300-800ms policy compile
		Caveat: "Fortinet (FortiManager) and Palo Alto (Panorama) numbers are " +
			"management-plane / ASIC-appliance figures, NOT apples-to-apples with " +
			"a multi-tenant SaaS control plane. Zscaler (cloud-native) is the most " +
			"directly comparable. Treat the cross-vendor column as directional only.",
	}
}

// Verdict is one graded metric with gap analysis.
type Verdict struct {
	// Metric is the human-readable metric name.
	Metric string `json:"metric"`
	// Theoretical / Actual are formatted display strings (units
	// included) so the markdown table renders without re-deriving.
	Theoretical string `json:"theoretical"`
	Actual      string `json:"actual"`
	// Fortinet / Zscaler / PaloAlto are the competitor display
	// cells; "n/a" when the metric has no comparable figure.
	Fortinet string `json:"fortinet"`
	Zscaler  string `json:"zscaler"`
	PaloAlto string `json:"palo_alto"`
	// Status is PASS, WARN, or FAIL.
	Status string `json:"status"`
	// Gap describes the actual-vs-theoretical delta.
	Gap string `json:"gap"`
}

// gradeAgainstTarget grades a lower-is-better metric against a
// theoretical ceiling and returns (status, gap-description).
//
// PASS when actual <= target. WARN when actual is within warnFraction
// over the target. FAIL beyond that. A non-positive target means "no
// target defined" and yields a PASS with an explanatory gap.
func gradeAgainstTarget(actual, target float64) (string, string) {
	if target <= 0 {
		return StatusPass, "no target defined"
	}
	overFrac := (actual - target) / target
	switch {
	case actual <= target:
		return StatusPass, fmt.Sprintf("%.0f%% under target", -overFrac*100)
	case overFrac <= warnFraction:
		return StatusWarn, fmt.Sprintf("%.0f%% over target", overFrac*100)
	default:
		return StatusFail, fmt.Sprintf("%.0f%% over target", overFrac*100)
	}
}

// Grade derives the per-metric verdicts from the report's sections
// and targets, and stores them on r.Verdicts. Idempotent: it replaces
// any previously-computed verdicts. Sections that were not measured
// contribute no verdicts.
func (r *BusinessBenchmarkReport) Grade() {
	verdicts := make([]Verdict, 0, 4)

	if r.APILatency != nil {
		if tier := r.APILatency.maxTenantTier(); tier != nil {
			actual := tier.OverallP99Ms
			status, gap := gradeAgainstTarget(actual, r.Theoretical.APIP99Ms)
			verdicts = append(verdicts, Verdict{
				Metric:      fmt.Sprintf("API p99 @ %d tenants", tier.TenantCount),
				Theoretical: fmt.Sprintf("<%.0fms", r.Theoretical.APIP99Ms),
				Actual:      fmt.Sprintf("%.0fms", actual),
				Fortinet:    fmt.Sprintf("~%.0fms", r.Competitor.FortinetPolicyPushP99Ms),
				Zscaler:     fmt.Sprintf("~%.0fms", r.Competitor.ZscalerTenantCRUDP99Ms),
				PaloAlto:    fmt.Sprintf("~%.0fms", r.Competitor.PaloAltoPolicyCompileP99Ms),
				Status:      status,
				Gap:         gap,
			})
		}
	}

	if r.PolicyCompile != nil {
		if ms, ok := r.PolicyCompile.compileMsForRules(100); ok {
			status, gap := gradeAgainstTarget(ms, r.Theoretical.PolicyCompile100RuleMs)
			verdicts = append(verdicts, Verdict{
				Metric:      "Policy compile (100 rules)",
				Theoretical: fmt.Sprintf("<%.0fms", r.Theoretical.PolicyCompile100RuleMs),
				Actual:      fmt.Sprintf("%.1fms", ms),
				Fortinet:    "n/a",
				Zscaler:     "n/a",
				PaloAlto:    fmt.Sprintf("~%.0fms", r.Competitor.PaloAltoPolicyCompileP99Ms),
				Status:      status,
				Gap:         gap,
			})
		}
		if ms, ok := r.PolicyCompile.compileMsForRules(1000); ok {
			status, gap := gradeAgainstTarget(ms, r.Theoretical.PolicyCompile1000RuleMs)
			verdicts = append(verdicts, Verdict{
				Metric:      "Policy compile (1000 rules)",
				Theoretical: fmt.Sprintf("<%.0fms", r.Theoretical.PolicyCompile1000RuleMs),
				Actual:      fmt.Sprintf("%.1fms", ms),
				Fortinet:    "n/a",
				Zscaler:     "n/a",
				PaloAlto:    fmt.Sprintf("~%.0fms", r.Competitor.PaloAltoPolicyCompileP99Ms),
				Status:      status,
				Gap:         gap,
			})
		}
	}

	if r.PostgresScale != nil {
		actual := r.PostgresScale.RLS.OverheadPct
		status, gap := gradeAgainstTarget(actual, r.Theoretical.RLSOverheadPct)
		verdicts = append(verdicts, Verdict{
			Metric:      "Postgres RLS overhead",
			Theoretical: fmt.Sprintf("<%.0f%%", r.Theoretical.RLSOverheadPct),
			Actual:      fmt.Sprintf("%.1f%%", actual),
			Fortinet:    "n/a",
			Zscaler:     "n/a",
			PaloAlto:    "n/a",
			Status:      status,
			Gap:         gap,
		})
	}

	r.Verdicts = verdicts
}

// ToJSON serialises the report to pretty JSON.
func (r *BusinessBenchmarkReport) ToJSON() (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal report: %w", err)
	}
	return string(b), nil
}

// ReportFromJSON parses a report previously written by ToJSON.
func ReportFromJSON(s string) (*BusinessBenchmarkReport, error) {
	var r BusinessBenchmarkReport
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		return nil, fmt.Errorf("unmarshal report: %w", err)
	}
	return &r, nil
}

// ToMarkdown renders the human-readable summary, leading with the
// cross-vendor comparison table the verdicts feed.
func (r *BusinessBenchmarkReport) ToMarkdown() string {
	var b strings.Builder
	fmt.Fprintf(&b, "## SNG control-plane scale benchmark — %s\n\n", r.Mode)
	fmt.Fprintf(&b, "- run (unix): `%d`\n", r.UnixTimeSecs)
	if r.GitSHA != "" {
		fmt.Fprintf(&b, "- commit: `%s`\n", r.GitSHA)
	}
	if r.DryRun {
		b.WriteString("- **dry-run**: synthetic in-process numbers — NOT a real workload; do not archive as a baseline.\n")
	}
	b.WriteString("\n")

	b.WriteString("### Verdict\n\n")
	b.WriteString("| Metric | Theoretical | Actual | Fortinet | Zscaler | Palo Alto | Verdict |\n")
	b.WriteString("|--------|-------------|--------|----------|---------|-----------|---------|\n")
	for _, v := range r.Verdicts {
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s (%s) |\n",
			v.Metric, v.Theoretical, v.Actual, v.Fortinet, v.Zscaler, v.PaloAlto, v.Status, v.Gap)
	}
	b.WriteString("\n> ")
	b.WriteString(r.Competitor.Caveat)
	b.WriteString("\n\n")

	if r.APILatency != nil {
		r.writeAPILatencyMarkdown(&b)
	}
	if r.PolicyCompile != nil {
		r.writePolicyCompileMarkdown(&b)
	}
	if r.PostgresScale != nil {
		r.writePostgresScaleMarkdown(&b)
	}
	return b.String()
}

func (r *BusinessBenchmarkReport) writeAPILatencyMarkdown(b *strings.Builder) {
	b.WriteString("### API latency by tenant tier\n\n")
	b.WriteString("| Tenants | Concurrency | RPS | p99 (ms) | error rate |\n")
	b.WriteString("|--------:|------------:|----:|---------:|-----------:|\n")
	for i := range r.APILatency.Tiers {
		t := &r.APILatency.Tiers[i]
		fmt.Fprintf(b, "| %d | %d | %.0f | %.1f | %.2f%% |\n",
			t.TenantCount, t.Concurrency, t.OverallRequestsPerSec, t.OverallP99Ms, t.ErrorRate*100)
	}
	b.WriteString("\n")
}

func (r *BusinessBenchmarkReport) writePolicyCompileMarkdown(b *strings.Builder) {
	b.WriteString("### Policy compile by graph size\n\n")
	b.WriteString("| Rules | Compile (ms) | Bundle (bytes) | Alloc (bytes) |\n")
	b.WriteString("|------:|-------------:|---------------:|--------------:|\n")
	for _, c := range r.PolicyCompile.PerGraphSize {
		fmt.Fprintf(b, "| %d | %.2f | %d | %d |\n", c.RuleCount, c.CompileMs, c.BundleBytes, c.AllocBytes)
	}
	b.WriteString("\n")
	if len(r.PolicyCompile.Concurrent) > 0 {
		b.WriteString("### Concurrent compile fan-out\n\n")
		b.WriteString("| Tenants | Rules | Wall (ms) | mean (ms) | p99 (ms) |\n")
		b.WriteString("|--------:|------:|----------:|----------:|---------:|\n")
		for _, c := range r.PolicyCompile.Concurrent {
			fmt.Fprintf(b, "| %d | %d | %.2f | %.2f | %.2f |\n",
				c.Tenants, c.RuleCount, c.WallMs, c.MeanMs, c.P99Ms)
		}
		b.WriteString("\n")
	}
}

func (r *BusinessBenchmarkReport) writePostgresScaleMarkdown(b *strings.Builder) {
	s := r.PostgresScale
	b.WriteString("### Postgres at scale\n\n")
	fmt.Fprintf(b, "- seeded tenants: **%d**\n", s.TenantCount)
	fmt.Fprintf(b, "- RLS overhead: **%.1f%%** (with %.2fms vs without %.2fms, p99)\n",
		s.RLS.OverheadPct, s.RLS.WithRLSP99Ms, s.RLS.WithoutRLSP99Ms)
	fmt.Fprintf(b, "- pool saturation: **%d** concurrent queries at pool size %d (peak %.0f q/s)\n",
		s.Pool.SaturationConcurrency, s.Pool.PoolSize, s.Pool.MaxQueriesPerSec)
	fmt.Fprintf(b, "- migration: `%s` over %d rows took **%.1fms**\n",
		s.Migration.Statement, s.Migration.RowCount, s.Migration.ElapsedMs)
	if len(s.RowCounts) > 0 {
		b.WriteString("- row counts: ")
		b.WriteString(formatCountMap(s.RowCounts))
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

// formatCountMap renders a map deterministically (keys sorted) so the
// markdown is stable across runs.
func formatCountMap(m map[string]int64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// RegressionThreshold is the fractional metric movement past which the
// scale-bench workflow fails the run. 0.20 == 20%.
const RegressionThreshold = 0.20

// Regression is one flagged metric movement between two runs.
type Regression struct {
	Metric         string  `json:"metric"`
	Previous       float64 `json:"previous"`
	Current        float64 `json:"current"`
	ChangeFraction float64 `json:"change_fraction"`
}

// DetectRegressions compares a current report against a baseline and
// returns the metrics that moved in the wrong direction by more than
// `threshold`. For these latency / overhead metrics, an INCREASE is
// the regression.
//
// Comparison is only meaningful between reports of the same schema
// version and mode; a mismatch is an error so a caller never compares
// an api-latency run against a policy-compile run and "finds" a
// regression.
func DetectRegressions(baseline, current *BusinessBenchmarkReport, threshold float64) ([]Regression, error) {
	if baseline.SchemaVersion != current.SchemaVersion {
		return nil, fmt.Errorf("schema version mismatch: baseline %d vs current %d",
			baseline.SchemaVersion, current.SchemaVersion)
	}
	if baseline.Mode != current.Mode {
		return nil, fmt.Errorf("mode mismatch: baseline %q vs current %q", baseline.Mode, current.Mode)
	}

	var regressions []Regression
	add := func(metric string, prev, cur float64) {
		if frac, ok := fractionalIncrease(prev, cur); ok && frac > threshold {
			regressions = append(regressions, Regression{
				Metric: metric, Previous: prev, Current: cur, ChangeFraction: frac,
			})
		}
	}

	if baseline.APILatency != nil && current.APILatency != nil {
		// Compare like-for-like: the p99 of the largest tenant tier present
		// in BOTH reports. Comparing each report's own max tier could pit a
		// 1000-tenant baseline against a 5000-tenant current and flag scale,
		// not regression.
		if n, ok := largestCommonTenantCount(baseline.APILatency, current.APILatency); ok {
			bp, _ := baseline.APILatency.p99ForTenantCount(n)
			cp, _ := current.APILatency.p99ForTenantCount(n)
			add(fmt.Sprintf("api_p99_ms@%d_tenants", n), bp, cp)
		}
	}
	if baseline.PolicyCompile != nil && current.PolicyCompile != nil {
		for _, target := range []int{100, 1000} {
			bp, bok := baseline.PolicyCompile.compileMsForRules(target)
			cp, cok := current.PolicyCompile.compileMsForRules(target)
			if bok && cok {
				add(fmt.Sprintf("policy_compile_%d_rule_ms", target), bp, cp)
			}
		}
	}
	if baseline.PostgresScale != nil && current.PostgresScale != nil {
		add("rls_overhead_pct", baseline.PostgresScale.RLS.OverheadPct, current.PostgresScale.RLS.OverheadPct)
	}
	return regressions, nil
}

// fractionalIncrease returns (current-previous)/previous, or
// (_, false) when previous is non-positive (no defined baseline).
func fractionalIncrease(previous, current float64) (float64, bool) {
	if previous <= 0 {
		return 0, false
	}
	return (current - previous) / previous, true
}
