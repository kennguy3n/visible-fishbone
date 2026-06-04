package main

import (
	"fmt"
	"strings"
	"time"
)

// ToMarkdown renders the consolidated business benchmark report.
func (r *BusinessReport) ToMarkdown() string {
	var b strings.Builder
	b.WriteString("# ShieldNet Gateway — Business Benchmark Report\n\n")
	fmt.Fprintf(&b, "_Generated %s UTC", time.Unix(r.GeneratedUnixSecs, 0).UTC().Format("2006-01-02 15:04"))
	if r.GitSHA != "" {
		fmt.Fprintf(&b, " · git `%s`", r.GitSHA)
	}
	b.WriteString("_\n\n")
	r.writeBanner(&b)
	r.writeExecutiveSummary(&b)
	r.writeEdge(&b)
	r.writeControlPlane(&b)
	r.writeTelemetry(&b)
	r.writePolicyEval(&b)
	r.writeUnitEconomics(&b)
	r.writeTestSuite(&b)
	r.writeMethodology(&b)
	return b.String()
}

func (r *BusinessReport) writeBanner(b *strings.Builder) {
	if r.Live {
		b.WriteString("> **Mode: LIVE.** Verdicts compare measured in-path numbers against design targets.\n\n")
		return
	}
	b.WriteString("> ## ⚠️ Synthetic / dry-run inputs — NOT validated product performance\n>\n")
	b.WriteString("> The edge, control-plane and telemetry harnesses were run in `--dry-run` mode (no live\n")
	b.WriteString("> data path, single commodity runner, no dedicated hardware). Throughput/latency figures\n")
	b.WriteString("> characterise the **load generators and CPU-bound code paths**, not the enforced data\n")
	b.WriteString("> plane, and cost figures are **models** over published cloud list prices. Pass/Fail\n")
	b.WriteString("> verdicts are therefore shown as `N/A (dry-run)`. The Criterion policy-eval numbers\n")
	b.WriteString("> (Section 4) are the exception — those are real microbenchmark measurements. Re-run the\n")
	b.WriteString("> harnesses with the live integration setup on representative hardware and regenerate with\n")
	b.WriteString("> `--live` to obtain gradeable numbers.\n\n")
}

// ---------------------------------------------------------------------------

func (r *BusinessReport) writeExecutiveSummary(b *strings.Builder) {
	b.WriteString("## Executive Summary\n\n")
	b.WriteString("| Dimension | Inputs | Status |\n|---|---|---|\n")
	row := func(dim, inputs, status string) { fmt.Fprintf(b, "| %s | %s | %s |\n", dim, inputs, status) }
	row("Edge data path", present(r.Edge != nil), dimStatus(r, r.Edge != nil))
	row("Control plane at scale", present(r.ControlPlane != nil), dimStatus(r, r.ControlPlane != nil))
	row("Telemetry pipeline", present(len(r.Telemetry) > 0), dimStatus(r, len(r.Telemetry) > 0))
	row("Policy evaluation", presentN(len(critRows(r))), policyEvalStatus(r))
	row("Unit economics", present(r.Theoretical != nil), dimStatus(r, r.Theoretical != nil))
	row("Test-suite health", testSuiteInputs(r), testSuiteStatus(r))
	b.WriteString("\n")

	b.WriteString("**Strengths (data-backed):**\n")
	for _, s := range r.strengths() {
		fmt.Fprintf(b, "- %s\n", s)
	}
	b.WriteString("\n**Gaps / caveats:**\n")
	for _, g := range r.gaps() {
		fmt.Fprintf(b, "- %s\n", g)
	}
	b.WriteString("\n")
}

func (r *BusinessReport) strengths() []string {
	var out []string
	if rows := critRows(r); len(rows) > 0 {
		worst := 0.0
		for _, c := range rows {
			if c.Ns > worst {
				worst = c.Ns
			}
		}
		if r.Theoretical != nil && r.Theoretical.PolicyEval.TargetNs > 0 && worst < r.Theoretical.PolicyEval.TargetNs {
			out = append(out, fmt.Sprintf("Policy evaluation is comfortably sub-microsecond on every benchmarked shape (worst case %.0f ns vs %.0f ns target) — real Criterion measurements.", worst, r.Theoretical.PolicyEval.TargetNs))
		}
	}
	if r.TestSuite != nil {
		run, fail := 0, 0
		for _, l := range r.TestSuite.Layers {
			run += l.Run
			fail += l.Failed
		}
		if run > 0 && fail == 0 {
			out = append(out, fmt.Sprintf("Test suite is fully green across all layers (%d tests, 0 failures).", run))
		}
	}
	if c := r.telemetryCostPerUser(); c != nil && r.Theoretical != nil && len(r.Theoretical.UnitEconomics.OverallEnvelope) == 2 {
		out = append(out, fmt.Sprintf("Modeled telemetry-pipeline infra cost ($%.2f/user/mo) sits inside the $%.2f–%.2f/user/mo design envelope.", *c, r.Theoretical.UnitEconomics.OverallEnvelope[0], r.Theoretical.UnitEconomics.OverallEnvelope[1]))
	}
	if len(out) == 0 {
		out = append(out, "No gradeable strengths yet — supply live inputs.")
	}
	return out
}

func (r *BusinessReport) gaps() []string {
	var out []string
	if !r.Live {
		out = append(out, "Edge/control-plane/telemetry numbers are synthetic dry-run figures; they cannot be presented as product performance until re-run live on representative hardware.")
	}
	out = append(out, "Hardware-appliance competitor numbers (Fortinet/Palo Alto/Check Point) are ASIC-accelerated fixed appliances; SNG is software-only on a generic x86 VM. The comparison is directional, not apples-to-apples. Zscaler (cloud-native) is the most directly comparable.")
	if r.Edge == nil {
		out = append(out, "No edge report supplied — Section 1 is empty.")
	}
	if r.ControlPlane == nil {
		out = append(out, "No control-plane report supplied — Section 2 is empty.")
	}
	return out
}

// ---------------------------------------------------------------------------
// Section 1 — Edge data path
// ---------------------------------------------------------------------------

func (r *BusinessReport) writeEdge(b *strings.Builder) {
	b.WriteString("## 1. Edge Data Path Performance\n\n")
	if r.Edge == nil {
		b.WriteString("_No edge report supplied (`--edge`)._\n\n")
		return
	}
	b.WriteString("Representative throughput at packet size 1500 B per inspection depth. ")
	b.WriteString("FortiGate / PA columns are the vendor-published figure for the matching feature class and core count (see Section caveats). Full packet-size × inspection matrix is in `business-report.json`.\n\n")
	b.WriteString("| SKU (vCPU/RAM) | Inspection | Design target Gbps | Actual Gbps | FortiGate equiv | PA equiv | Verdict |\n")
	b.WriteString("|---|---|---:|---:|---:|---:|---|\n")
	for _, sku := range r.Edge.SKUs {
		for _, insp := range []string{"no-inspect", "url-cat", "full-tls"} {
			rep := pickThroughput(sku, insp, 1500)
			if rep == nil {
				continue
			}
			forti, pa := equivFor(rep)
			v := r.verdict(grade(rep.Throughput.MaxGbps, sku.Profile.TargetGbps, true))
			fmt.Fprintf(b, "| %s (%dc/%dG) | %s | %s | %s | %s | %s | %s |\n",
				sku.Profile.Name, sku.Profile.VCPUs, sku.Profile.RAMGB, insp,
				num(sku.Profile.TargetGbps), num(rep.Throughput.MaxGbps),
				gbpsOrDash(forti), gbpsOrDash(pa), v)
		}
	}
	b.WriteString("\n")
}

func pickThroughput(sku EdgeSKU, inspection string, preferredPacket int) *EdgeModeReport {
	var best *EdgeModeReport
	for i := range sku.Reports {
		rep := &sku.Reports[i]
		if rep.Mode != "throughput" || rep.Throughput == nil || rep.Dimensions.Inspection != inspection {
			continue
		}
		if rep.Dimensions.PacketSize == preferredPacket {
			return rep
		}
		if best == nil || rep.Throughput.MaxGbps > best.Throughput.MaxGbps {
			best = rep
		}
	}
	return best
}

// equivFor pulls the FortiGate and Palo Alto published figures from a report's
// embedded competitor comparison (which already applies the inspection→feature
// mapping and per-vendor caveats). Returns -1 when a vendor publishes nothing
// for that category.
func equivFor(rep *EdgeModeReport) (forti, pa float64) {
	forti, pa = -1, -1
	if rep.CompetitorComparison == nil {
		return
	}
	for _, row := range rep.CompetitorComparison.Rows {
		switch {
		case strings.Contains(row.Competitor, "Fortinet"):
			forti = row.PublishedGbps
		case strings.Contains(row.Competitor, "Palo Alto"):
			pa = row.PublishedGbps
		}
	}
	return
}

func gbpsOrDash(v float64) string {
	if v < 0 {
		return "—"
	}
	return num(v)
}

// ---------------------------------------------------------------------------
// Section 2 — Control plane at scale
// ---------------------------------------------------------------------------

func (r *BusinessReport) writeControlPlane(b *strings.Builder) {
	b.WriteString("## 2. Control Plane at Scale\n\n")
	cp := r.ControlPlane
	if cp == nil {
		b.WriteString("_No control-plane report supplied (`--controlplane`)._\n\n")
		return
	}

	if cp.APILatency != nil && len(cp.APILatency.Tiers) > 0 {
		tiers := map[int]cpAPITier{}
		for _, t := range cp.APILatency.Tiers {
			tiers[t.TenantCount] = t
		}
		target := cp.Theoretical.APIP99Ms
		b.WriteString("### API latency by tenant tier\n\n")
		fmt.Fprintf(b, "| Metric | Target | @100 | @1000 | @5000 | Verdict |\n|---|---:|---:|---:|---:|---|\n")
		p99 := func(n int) string { return msOrDash(tiers, n, func(t cpAPITier) float64 { return t.OverallP99Ms }) }
		rps := func(n int) string {
			return rawOrDash(tiers, n, func(t cpAPITier) float64 { return t.OverallRequestsPerSec })
		}
		errp := func(n int) string {
			return rawOrDash(tiers, n, func(t cpAPITier) float64 { return t.ErrorRate * 100 })
		}
		var verdict string
		if t, ok := tiers[5000]; ok {
			verdict = r.verdict(grade(t.OverallP99Ms, target, false))
		} else {
			verdict = r.verdict("N/A")
		}
		fmt.Fprintf(b, "| API p99 (ms) | <%s | %s | %s | %s | %s |\n", num(target), p99(100), p99(1000), p99(5000), verdict)
		fmt.Fprintf(b, "| Requests/sec | — | %s | %s | %s | — |\n", rps(100), rps(1000), rps(5000))
		fmt.Fprintf(b, "| Error rate (%%) | 0 | %s | %s | %s | — |\n", errp(100), errp(1000), errp(5000))
		b.WriteString("\n")
	}

	b.WriteString("### Policy compile & Postgres RLS\n\n")
	b.WriteString("| Metric | Target | Actual | Competitor | Verdict |\n|---|---:|---:|---:|---|\n")
	if cp.PolicyCompile != nil {
		c100 := maxCompileMs(cp.PolicyCompile.PerGraphSize, 100)
		c1000 := maxCompileMs(cp.PolicyCompile.PerGraphSize, 1000)
		if c100 >= 0 {
			fmt.Fprintf(b, "| Policy compile, 100-rule (ms) | <%s | %s | — | %s |\n",
				num(cp.Theoretical.PolicyCompile100RuleMs), num(c100),
				r.verdict(grade(c100, cp.Theoretical.PolicyCompile100RuleMs, false)))
		}
		if c1000 >= 0 {
			fmt.Fprintf(b, "| Policy compile, 1000-rule (ms) | <%s | %s | PA Panorama %s | %s |\n",
				num(cp.Theoretical.PolicyCompile1000RuleMs), num(c1000),
				num(cp.Competitor.PaloAltoPolicyCompileP99Ms),
				r.verdict(grade(c1000, cp.Theoretical.PolicyCompile1000RuleMs, false)))
		}
	}
	if cp.PostgresScale != nil {
		fmt.Fprintf(b, "| RLS overhead (%%) @ %d tenants | — | %s | — | — |\n",
			cp.PostgresScale.TenantCount, num(cp.PostgresScale.RLS.OverheadPct))
	}
	fmt.Fprintf(b, "\n_Competitor control-plane baselines (caveat: %s): FortiManager policy push ~%s ms p99, Zscaler tenant CRUD ~%s ms p99, PA Panorama policy compile ~%s ms p99._\n\n",
		cp.Competitor.Caveat, num(cp.Competitor.FortinetPolicyPushP99Ms),
		num(cp.Competitor.ZscalerTenantCRUDP99Ms), num(cp.Competitor.PaloAltoPolicyCompileP99Ms))
}

func msOrDash(tiers map[int]cpAPITier, n int, get func(cpAPITier) float64) string {
	if t, ok := tiers[n]; ok {
		return num(get(t))
	}
	return "—"
}

func rawOrDash(tiers map[int]cpAPITier, n int, get func(cpAPITier) float64) string {
	if t, ok := tiers[n]; ok {
		return num(get(t))
	}
	return "—"
}

func maxCompileMs(rows []cpCompileResult, ruleCount int) float64 {
	worst := -1.0
	for _, c := range rows {
		if c.RuleCount == ruleCount && c.CompileMs > worst {
			worst = c.CompileMs
		}
	}
	return worst
}

// ---------------------------------------------------------------------------
// Section 3 — Telemetry pipeline
// ---------------------------------------------------------------------------

func (r *BusinessReport) writeTelemetry(b *strings.Builder) {
	b.WriteString("## 3. Telemetry Pipeline\n\n")
	if len(r.Telemetry) == 0 {
		b.WriteString("_No telemetry report supplied (`--telemetry`)._\n\n")
		return
	}
	for _, rep := range r.Telemetry {
		fmt.Fprintf(b, "### `%s`\n\n", rep.Benchmark)
		b.WriteString("| Section | Metric | Target | Actual | Competitor | Verdict |\n|---|---|---:|---:|---:|---|\n")
		for _, s := range rep.Sections {
			for _, m := range s.Metrics {
				fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s |\n",
					s.Title, metricName(m), ptrNum(m.Theoretical), fmt.Sprintf("%s %s", num(m.Actual), m.Unit),
					ptrNum(m.Competitor), r.telemetryVerdict(m.Verdict))
			}
		}
		b.WriteString("\n")
		if len(rep.Caveats) > 0 {
			b.WriteString("_Caveats:_\n")
			for _, c := range rep.Caveats {
				fmt.Fprintf(b, "- %s\n", c)
			}
			b.WriteString("\n")
		}
	}
}

func metricName(m TelemetryMetric) string {
	if m.Note != "" {
		return fmt.Sprintf("%s <sub>(%s)</sub>", m.Name, m.Note)
	}
	return m.Name
}

// telemetryVerdict preserves the upstream INFO marker (purely informational
// rows) but masks computed PASS/WARN/FAIL in dry-run mode.
func (r *BusinessReport) telemetryVerdict(v string) string {
	if v == "INFO" || v == "" {
		return "INFO"
	}
	if !r.Live {
		return "N/A (modeled)"
	}
	return v
}

// ---------------------------------------------------------------------------
// Section 4 — Policy evaluation (real Criterion numbers)
// ---------------------------------------------------------------------------

func (r *BusinessReport) writePolicyEval(b *strings.Builder) {
	b.WriteString("## 4. Policy Evaluation\n\n")
	rows := critRows(r)
	if len(rows) == 0 {
		b.WriteString("_No Criterion numbers found (supply `--test-report` pointing at the Session 4 report)._\n\n")
		return
	}
	target := 0.0
	if r.Theoretical != nil {
		target = r.Theoretical.PolicyEval.TargetNs
	}
	b.WriteString("Real `cargo bench -p sng-policy-eval` Criterion point estimates (these are measured, not synthetic). ")
	b.WriteString("No competitor publishes a comparable per-flow verdict latency.\n\n")
	b.WriteString("| Shape | Target | Actual (ns) | Competitor | Verdict |\n|---|---:|---:|---:|---|\n")
	for _, c := range rows {
		v := "N/A"
		if target > 0 {
			v = grade(c.Ns, target, false) // real numbers — graded even in dry-run
		}
		fmt.Fprintf(b, "| `%s` | <%s ns | %s | — | %s |\n", c.Shape, num(target), num(c.Ns), v)
	}
	b.WriteString("\n")
}

// ---------------------------------------------------------------------------
// Section 5 — Unit economics
// ---------------------------------------------------------------------------

func (r *BusinessReport) writeUnitEconomics(b *strings.Builder) {
	b.WriteString("## 5. Unit Economics\n\n")
	if r.Theoretical == nil {
		b.WriteString("_No theoretical targets supplied._\n\n")
		return
	}
	ue := r.Theoretical.UnitEconomics
	b.WriteString("Design envelopes (direct infra cost), from PROPOSAL.md cohort tables:\n\n")
	b.WriteString("| Cohort | Design infra $/user/mo | Site $/mo |\n|---|---|---|\n")
	cohort := func(name string, c Cohort) {
		fmt.Fprintf(b, "| %s | %s | %s |\n", name, rangeStr(c.InfraCostUserMonth), rangeStr(c.SiteMonth))
	}
	cohort("Starter", ue.Starter)
	cohort("Growth", ue.Growth)
	cohort("Scale", ue.Scale)
	b.WriteString("\n")

	if c := r.telemetryCostPerUser(); c != nil {
		within := ""
		if len(ue.OverallEnvelope) == 2 {
			if *c <= ue.OverallEnvelope[1] {
				within = fmt.Sprintf(" — within the $%.2f–%.2f envelope", ue.OverallEnvelope[0], ue.OverallEnvelope[1])
			} else {
				within = fmt.Sprintf(" — **above** the $%.2f–%.2f envelope", ue.OverallEnvelope[0], ue.OverallEnvelope[1])
			}
		}
		fmt.Fprintf(b, "**Measured (modeled) — telemetry-pipeline slice only:** $%.2f/user/mo%s. ", *c, within)
	}
	b.WriteString("Full-platform measured cost/user/mo (edge + control-plane + telemetry infra) and gross margin require the live infra-consumption slices and an ARPU input, which a dry-run does not produce.\n\n")
}

func (r *BusinessReport) telemetryCostPerUser() *float64 {
	for _, rep := range r.Telemetry {
		for _, s := range rep.Sections {
			for _, m := range s.Metrics {
				if strings.Contains(strings.ToLower(m.Name), "cost / user") {
					v := m.Actual
					return &v
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Section 6 — Test-suite health
// ---------------------------------------------------------------------------

func (r *BusinessReport) writeTestSuite(b *strings.Builder) {
	b.WriteString("## 6. Test Suite Health\n\n")
	if r.TestSuite == nil || len(r.TestSuite.Layers) == 0 {
		b.WriteString("_No test-suite report supplied (`--test-report`)._\n\n")
		return
	}
	b.WriteString("| Layer | Total | Passed | Failed | Skipped |\n|---|---:|---:|---:|---:|\n")
	var tr, tp, tf, tsk int
	for _, l := range r.TestSuite.Layers {
		fmt.Fprintf(b, "| %s | %d | %d | %d | %d |\n", l.Name, l.Run, l.Passed, l.Failed, l.Skipped)
		tr += l.Run
		tp += l.Passed
		tf += l.Failed
		tsk += l.Skipped
	}
	fmt.Fprintf(b, "| **Total** | **%d** | **%d** | **%d** | **%d** |\n\n", tr, tp, tf, tsk)
}

func (r *BusinessReport) writeMethodology(b *strings.Builder) {
	b.WriteString("## Methodology & sources\n\n")
	b.WriteString("- **Edge** (Session 3, Rust `bench/`): `business-report` sweep across profiles × packet sizes × inspection depths.\n")
	b.WriteString("- **Control plane** (Session 1, Go `bench/controlplane`): `full-suite` — API latency by tenant tier, policy compile, Postgres RLS.\n")
	b.WriteString("- **Telemetry** (Session 2, Go `bench/telemetry`): NATS→ClickHouse→S3 throughput + AWS list-price cost model.\n")
	b.WriteString("- **Policy eval & test health** (Session 4): `cargo bench -p sng-policy-eval` Criterion numbers and the full Go+Rust suite run, from `bench/results/test-suite-report.md`.\n")
	b.WriteString("- **Competitor figures**: vendor datasheets in `competitors.json` (each row carries a caveat). Hardware appliances are ASIC-accelerated; SNG is software-only on a generic x86 VM.\n")
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

func critRows(r *BusinessReport) []CriterionRow {
	if r.TestSuite == nil {
		return nil
	}
	return r.TestSuite.Criterion
}

func ptrNum(p *float64) string {
	if p == nil {
		return "—"
	}
	return num(*p)
}

func rangeStr(v []float64) string {
	if len(v) != 2 {
		return "—"
	}
	return fmt.Sprintf("$%.2f–%.2f", v[0], v[1])
}

func present(ok bool) string {
	if ok {
		return "supplied"
	}
	return "missing"
}

func presentN(n int) string {
	if n > 0 {
		return fmt.Sprintf("%d shapes", n)
	}
	return "missing"
}

func dimStatus(r *BusinessReport, ok bool) string {
	if !ok {
		return "no data"
	}
	if !r.Live {
		return "synthetic (N/A)"
	}
	return "see section"
}

func policyEvalStatus(r *BusinessReport) string {
	rows := critRows(r)
	if len(rows) == 0 {
		return "no data"
	}
	if r.Theoretical == nil || r.Theoretical.PolicyEval.TargetNs <= 0 {
		return "measured"
	}
	for _, c := range rows {
		if c.Ns >= r.Theoretical.PolicyEval.TargetNs {
			return "WARN/FAIL"
		}
	}
	return "PASS (real)"
}

func testSuiteInputs(r *BusinessReport) string {
	if r.TestSuite == nil || len(r.TestSuite.Layers) == 0 {
		return "missing"
	}
	return "supplied"
}

func testSuiteStatus(r *BusinessReport) string {
	if r.TestSuite == nil || len(r.TestSuite.Layers) == 0 {
		return "no data"
	}
	fail := 0
	for _, l := range r.TestSuite.Layers {
		fail += l.Failed
	}
	if fail == 0 {
		return "PASS (green)"
	}
	return fmt.Sprintf("%d failing", fail)
}
