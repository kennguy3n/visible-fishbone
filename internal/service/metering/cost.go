package metering

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// UnitCosts holds the configurable per-meter unit prices used to turn
// raw meter readings into estimated dollar figures. All values are USD.
// These are estimates for internal margin analysis, not billed
// amounts, so float64 is acceptable; figures are rounded to whole
// cents at the report boundary.
type UnitCosts struct {
	// LLMPer1KTokensUSD is the blended (input+output) price per 1,000
	// tokens. The metering layer tracks combined tokens, so a single
	// blended rate is applied; operators with a known input/output mix
	// can fold it into this number.
	LLMPer1KTokensUSD float64
	// LLMPerCallUSD is an optional fixed per-call overhead (e.g. a
	// minimum request charge). Usually 0.
	LLMPerCallUSD float64
	// LLMSelfHostedPerMonthUSD is the flat monthly cost of operating a
	// self-hosted inference deployment (e.g. Ternary-Bonsai-8B on a
	// single A10G GPU) as an alternative to per-token managed-API
	// pricing. Unlike LLMPer1KTokensUSD it does NOT scale with token
	// volume — it is a fixed infrastructure charge for the deployment,
	// amortised across every tenant sharing it. Used by the
	// self-hosted pricing model (see LLMPricingModel); 0 means
	// "no self-hosted deployment configured" and disables self-hosted
	// projections. See docs/cost-model.md for the economics.
	LLMSelfHostedPerMonthUSD float64
	// URLCatPer1KLookupsUSD is the price per 1,000 URL-categorisation
	// feed lookups.
	URLCatPer1KLookupsUSD float64
	// MalwarePerScanUSD is the price per malware-feed scan.
	MalwarePerScanUSD float64
	// EgressPerGBUSD is the price per GB of proxied egress bandwidth.
	EgressPerGBUSD float64
	// ClickHousePer1MRowsUSD is the price per 1,000,000 telemetry rows
	// written.
	ClickHousePer1MRowsUSD float64
	// StorageTier is the S3 cold-archive storage class the archive is
	// written to. It is the single source of truth for S3PerGBMonthUSD:
	// the two are kept consistent by WithStorageTier / DefaultUnitCosts,
	// so finance can re-tier the archive (e.g. Standard → Glacier Deep
	// Archive) by changing one field rather than re-deriving a price.
	// A zero/unknown value is treated as DefaultStorageTier.
	StorageTier StorageTier
	// S3PerGBMonthUSD is the price per GB-month of cold archive storage.
	// It is the list price of StorageTier; set them together (via
	// WithStorageTier) so a tier and its price never disagree.
	S3PerGBMonthUSD float64
	// NATSPerGBMonthUSD is the price per GB-month of NATS JetStream
	// file-storage retained on disk. JetStream persistence is backed by
	// block storage (a provisioned volume that is paid for whether or
	// not it is full), so it is priced higher than S3 cold archive and
	// billed against the stream's point-in-time retained size rather
	// than a cumulative write counter.
	NATSPerGBMonthUSD float64
	// PolicyEvalPer1MUSD is the amortised control-plane compute price
	// per 1,000,000 policy-engine evaluations. Each evaluation is a
	// near-free in-memory bundle lookup, so this is a small figure used
	// to attribute control-plane CPU to a tenant's traffic pattern, not
	// a feed/egress charge.
	PolicyEvalPer1MUSD float64
}

// StorageTier identifies the S3 storage class the telemetry cold
// archive is written to. The class chosen dominates the archive's
// per-GB-month cost: the telemetry archive is write-once / read-rarely
// (forensic + compliance retention), so the cheaper, higher-restore-
// latency Glacier classes are a far better fit than S3 Standard. The
// constants mirror the AWS S3 storage classes; see docs/cost-model.md.
type StorageTier string

const (
	// StorageTierStandard is S3 Standard — millisecond access, the
	// most expensive class. Appropriate only for a hot archive.
	StorageTierStandard StorageTier = "standard"
	// StorageTierGlacierInstant is Glacier Instant Retrieval —
	// millisecond access at a fraction of Standard's price, for an
	// archive that is read rarely but must return immediately.
	StorageTierGlacierInstant StorageTier = "glacier_instant_retrieval"
	// StorageTierGlacierFlexible is Glacier Flexible Retrieval —
	// minutes-to-hours restore, cheaper still.
	StorageTierGlacierFlexible StorageTier = "glacier_flexible_retrieval"
	// StorageTierGlacierDeepArchive is Glacier Deep Archive — the
	// cheapest class (multi-hour restore). The correct default for a
	// write-once compliance/forensic telemetry archive.
	StorageTierGlacierDeepArchive StorageTier = "glacier_deep_archive"
)

// DefaultStorageTier is the cold-archive class the cost model assumes.
// The telemetry archive is written once and read only for incident
// forensics or a compliance request, so Glacier Deep Archive — the
// cheapest class, trading a multi-hour restore latency that is
// immaterial for this access pattern — is the cost-optimal default.
const DefaultStorageTier = StorageTierGlacierDeepArchive

// storageTierPriceUSD maps each storage class to its public-cloud list
// price per GB-month (AWS S3, us-east-1, list pricing). These are
// estimates for internal margin analysis; finance can re-tier via
// WithStorageTier without a code change.
var storageTierPriceUSD = map[StorageTier]float64{
	StorageTierStandard:           0.023,
	StorageTierGlacierInstant:     0.004,
	StorageTierGlacierFlexible:    0.0036,
	StorageTierGlacierDeepArchive: 0.00099,
}

// Valid reports whether t is a recognised storage tier.
func (t StorageTier) Valid() bool {
	_, ok := storageTierPriceUSD[t]
	return ok
}

// PerGBMonthUSD returns the list price per GB-month for the tier. An
// unknown/zero tier falls back to the DefaultStorageTier price so a
// mis-set tier never silently prices the archive at $0 (which would
// over-report margin — the wrong direction for a conservative estimate).
func (t StorageTier) PerGBMonthUSD() float64 {
	if p, ok := storageTierPriceUSD[t]; ok {
		return p
	}
	return storageTierPriceUSD[DefaultStorageTier]
}

// DefaultUnitCosts are conservative public-cloud list-price estimates.
// They are intentionally configurable (CostCalculator takes a
// UnitCosts) so finance can tune them without a code change.
var DefaultUnitCosts = UnitCosts{
	LLMPer1KTokensUSD: 0.002,
	LLMPerCallUSD:     0,
	// $300/mo: a single AWS A10G GPU instance (g5.xlarge on-demand
	// rounds to ~$730/mo, but the inference deployment is sized for a
	// reserved / committed-use rate and the 8B model leaves headroom
	// to co-locate, landing the conservative public-cloud figure near
	// $300). Bare-metal A10G is ~$150/mo and CPU-only ~$80/mo — see
	// docs/cost-model.md §"AI cost model". Finance can retune via
	// NewCostCalculator without a code change.
	LLMSelfHostedPerMonthUSD: 300,
	URLCatPer1KLookupsUSD:    0.10,
	MalwarePerScanUSD:        0.001,
	EgressPerGBUSD:           0.09,
	ClickHousePer1MRowsUSD:   0.20,
	// The telemetry cold archive is write-once / read-rarely, so it is
	// stored in Glacier Deep Archive — the cheapest S3 class. The tier
	// and its $/GB-month price are set together so they never disagree.
	StorageTier:        DefaultStorageTier,
	S3PerGBMonthUSD:    DefaultStorageTier.PerGBMonthUSD(),
	NATSPerGBMonthUSD:  0.10,
	PolicyEvalPer1MUSD: 0.01,
}

const (
	// bytesPerGB is the SI gigabyte (10^9 bytes), not the binary GiB
	// (2^30). The per-GB unit prices (EgressPerGBUSD, S3PerGBMonthUSD)
	// mirror cloud-provider list prices, which are quoted per SI GB, so
	// the denominator must match to avoid systematically under-counting
	// GB. Using the binary GiB here would inflate the denominator by
	// ~7.4%, under-reporting bandwidth/archive cost and thus
	// over-reporting margin — the wrong direction for a margin estimate,
	// which should stay conservative.
	bytesPerGB = 1_000_000_000
)

// tierMonthlyPriceUSD is the assumed monthly subscription revenue per
// tier, used for margin analysis in the cost report. The Session K
// spec does not specify prices, so these are documented placeholder
// list prices a finance operator can override via NewCostCalculator.
var tierMonthlyPriceUSD = map[repository.TenantTier]float64{
	repository.TenantTierStarter:      99,
	repository.TenantTierProfessional: 499,
	repository.TenantTierEnterprise:   1999,
}

// CostCalculator maps meter readings to estimated dollar costs.
type CostCalculator struct {
	costs      UnitCosts
	tierPrices map[repository.TenantTier]float64
	now        func() time.Time
}

// CostOption customises a CostCalculator.
type CostOption func(*CostCalculator)

// WithTierPrices overrides the per-tier monthly revenue figures used
// for margin analysis.
func WithTierPrices(prices map[repository.TenantTier]float64) CostOption {
	return func(c *CostCalculator) {
		if len(prices) > 0 {
			c.tierPrices = prices
		}
	}
}

// WithStorageTier re-tiers the S3 cold archive: it records the chosen
// storage class and sets S3PerGBMonthUSD to that class's list price in
// one step, so the tier and its price can never drift apart. An
// unrecognised tier is ignored (the calculator keeps its current S3
// price) rather than silently re-pricing the archive at the fallback.
func WithStorageTier(tier StorageTier) CostOption {
	return func(c *CostCalculator) {
		if !tier.Valid() {
			return
		}
		c.costs.StorageTier = tier
		c.costs.S3PerGBMonthUSD = tier.PerGBMonthUSD()
	}
}

// withCostClock overrides the wall clock; test-only.
func withCostClock(now func() time.Time) CostOption {
	return func(c *CostCalculator) {
		if now != nil {
			c.now = now
		}
	}
}

// NewCostCalculator constructs a CostCalculator. A zero-value UnitCosts
// is replaced with DefaultUnitCosts so callers can pass UnitCosts{} to
// accept the defaults.
//
// The fallback is all-or-nothing: it triggers only on a wholly-zero
// struct, so a partial override (e.g. UnitCosts{LLMPer1KTokensUSD: x})
// keeps every other rate at 0 rather than inheriting the default. Pass
// UnitCosts{} for the full default set, or specify every rate you need.
// This applies uniformly to all priced fields (S3PerGBMonthUSD,
// NATSPerGBMonthUSD, …); when adding a new rate, prefer extending
// DefaultUnitCosts over relying on partial-construct fallthrough.
func NewCostCalculator(costs UnitCosts, opts ...CostOption) *CostCalculator {
	if costs == (UnitCosts{}) {
		costs = DefaultUnitCosts
	}
	c := &CostCalculator{
		costs:      costs,
		tierPrices: tierMonthlyPriceUSD,
		now:        time.Now,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// MeterCostUSD returns the estimated dollar cost of `value` units of
// `meter`. Unknown meters cost 0.
func (c *CostCalculator) MeterCostUSD(meter Meter, value int64) float64 {
	if value <= 0 {
		return 0
	}
	v := float64(value)
	switch meter {
	case MeterLLMTokensUsed:
		return v / 1000 * c.costs.LLMPer1KTokensUSD
	case MeterLLMCalls:
		return v * c.costs.LLMPerCallUSD
	case MeterURLCatLookups:
		return v / 1000 * c.costs.URLCatPer1KLookupsUSD
	case MeterMalwareScans:
		return v * c.costs.MalwarePerScanUSD
	case MeterBandwidthProxiedBytes:
		return v / bytesPerGB * c.costs.EgressPerGBUSD
	case MeterClickHouseRowsWritten:
		return v / 1_000_000 * c.costs.ClickHousePer1MRowsUSD
	case MeterS3BytesArchived:
		return v / bytesPerGB * c.costs.S3PerGBMonthUSD
	case MeterPolicyEvaluations:
		return v / 1_000_000 * c.costs.PolicyEvalPer1MUSD
	default:
		return 0
	}
}

// LLMPricingModel selects how the dollar cost of AI inference is
// attributed. The two models have fundamentally different cost
// curves, which is the whole point of the comparison:
//
//   - Per-token (managed API, e.g. OpenAI GPT-4o-mini): cost scales
//     linearly with token volume. Cheap at low usage, unbounded at
//     high usage.
//   - Self-hosted (e.g. Ternary-Bonsai-8B on a dedicated GPU/CPU):
//     a flat monthly infrastructure charge, independent of token
//     volume. Expensive at low usage, flat (and eventually far
//     cheaper) at high usage.
//
// CostCalculator supports both so finance can decide, at a given
// projected fleet token volume, which model is cheaper.
type LLMPricingModel string

const (
	// LLMPricingPerToken prices inference per 1K tokens via
	// LLMPer1KTokensUSD plus the optional LLMPerCallUSD per-call
	// overhead. This is the default model and matches the existing
	// MeterLLMTokensUsed / MeterLLMCalls meters.
	LLMPricingPerToken LLMPricingModel = "per_token"
	// LLMPricingSelfHosted prices inference as the flat
	// LLMSelfHostedPerMonthUSD monthly charge, independent of token
	// or call volume.
	LLMPricingSelfHosted LLMPricingModel = "self_hosted"
)

// Valid reports whether m is a recognised pricing model.
func (m LLMPricingModel) Valid() bool {
	return m == LLMPricingPerToken || m == LLMPricingSelfHosted
}

// LLMSelfHostedMonthlyUSD returns the flat monthly cost of the
// configured self-hosted inference deployment, independent of token
// volume. Returns 0 when no self-hosted deployment is configured
// (LLMSelfHostedPerMonthUSD == 0).
func (c *CostCalculator) LLMSelfHostedMonthlyUSD() float64 {
	if c.costs.LLMSelfHostedPerMonthUSD <= 0 {
		return 0
	}
	return c.costs.LLMSelfHostedPerMonthUSD
}

// LLMPerTokenMonthlyUSD returns the per-token (managed-API) monthly
// cost of `tokens` tokens spread across `calls` invocations. The
// per-call overhead (LLMPerCallUSD, usually 0) is added on top of
// the per-1K-token charge. Negative inputs are treated as 0.
func (c *CostCalculator) LLMPerTokenMonthlyUSD(tokens, calls int64) float64 {
	cost := c.MeterCostUSD(MeterLLMTokensUsed, tokens)
	cost += c.MeterCostUSD(MeterLLMCalls, calls)
	return cost
}

// LLMMonthlyCostUSD returns the projected monthly AI inference cost
// under the requested pricing model. This is the single entry point
// that "supports both pricing models": per-token cost scales with
// the (tokens, calls) projection, self-hosted cost is the flat
// monthly charge regardless of usage. An unknown model is treated as
// per-token (the conservative default that never silently hides a
// usage-driven charge).
func (c *CostCalculator) LLMMonthlyCostUSD(model LLMPricingModel, tokens, calls int64) float64 {
	if model == LLMPricingSelfHosted {
		return round2(c.LLMSelfHostedMonthlyUSD())
	}
	return round2(c.LLMPerTokenMonthlyUSD(tokens, calls))
}

// LLMCostComparison contrasts the two AI inference pricing models at
// a single projected monthly token/call volume so finance can pick
// the cheaper one and see the crossover point.
type LLMCostComparison struct {
	// ProjectedMonthlyTokens / ProjectedMonthlyCalls are the inputs
	// the comparison was computed against.
	ProjectedMonthlyTokens int64 `json:"projected_monthly_tokens"`
	ProjectedMonthlyCalls  int64 `json:"projected_monthly_calls"`
	// PerTokenMonthlyUSD is the managed-API cost at this volume.
	PerTokenMonthlyUSD float64 `json:"per_token_monthly_usd"`
	// SelfHostedMonthlyUSD is the flat self-hosted cost (volume-
	// independent). 0 when no self-hosted deployment is configured.
	SelfHostedMonthlyUSD float64 `json:"self_hosted_monthly_usd"`
	// Cheaper is the model with the lower projected monthly cost at
	// this volume. Ties resolve to per-token (no infra to operate).
	Cheaper LLMPricingModel `json:"cheaper"`
	// SavingsUSD is the absolute monthly saving of the cheaper model
	// over the dearer one (always >= 0).
	SavingsUSD float64 `json:"savings_usd"`
	// BreakevenTokens is the monthly token volume at which the two
	// models cost the same, holding the call count fixed. Above it,
	// self-hosting is cheaper; below it, per-token wins. 0 when the
	// breakeven is undefined (per-token pricing is free, or no
	// self-hosted deployment is configured).
	BreakevenTokens int64 `json:"breakeven_tokens"`
}

// CompareLLMPricing computes the per-token vs self-hosted comparison
// for a projected monthly volume. `calls` feeds the per-call
// overhead (pass 0 when LLMPerCallUSD is 0, the common case).
//
// The breakeven is the token volume where per-token cost equals the
// flat self-hosted cost, holding `calls` fixed:
//
//	selfHosted = breakevenTokens/1000 * LLMPer1KTokensUSD + calls*LLMPerCallUSD
//	=> breakevenTokens = (selfHosted - calls*LLMPerCallUSD) * 1000 / LLMPer1KTokensUSD
//
// It is reported as 0 (undefined) when per-token pricing is free
// (LLMPer1KTokensUSD == 0) or no self-hosted deployment is configured.
func (c *CostCalculator) CompareLLMPricing(tokens, calls int64) LLMCostComparison {
	if tokens < 0 {
		tokens = 0
	}
	if calls < 0 {
		calls = 0
	}
	// Keep the raw (unrounded) self-hosted cost for the breakeven
	// math below; the displayed figures are cent-rounded. Rounding
	// the cost before dividing by the per-1K-token rate would push
	// the crossover volume off by up to ~half a cent's worth of
	// tokens, so the breakeven is derived from the exact cost.
	rawSelfHosted := c.LLMSelfHostedMonthlyUSD()
	perToken := round2(c.LLMPerTokenMonthlyUSD(tokens, calls))
	selfHosted := round2(rawSelfHosted)
	cmp := LLMCostComparison{
		ProjectedMonthlyTokens: tokens,
		ProjectedMonthlyCalls:  calls,
		PerTokenMonthlyUSD:     perToken,
		SelfHostedMonthlyUSD:   selfHosted,
	}
	// With no self-hosted deployment configured the only model is
	// per-token; report it as cheaper with no savings or breakeven.
	if selfHosted <= 0 {
		cmp.Cheaper = LLMPricingPerToken
		return cmp
	}
	if perToken <= selfHosted {
		cmp.Cheaper = LLMPricingPerToken
		cmp.SavingsUSD = round2(selfHosted - perToken)
	} else {
		cmp.Cheaper = LLMPricingSelfHosted
		cmp.SavingsUSD = round2(perToken - selfHosted)
	}
	// Breakeven token volume (undefined when per-token tokens are free).
	if c.costs.LLMPer1KTokensUSD > 0 {
		callOverhead := float64(calls) * c.costs.LLMPerCallUSD
		tokenBudget := rawSelfHosted - callOverhead
		if tokenBudget > 0 {
			cmp.BreakevenTokens = int64(math.Round(tokenBudget * 1000 / c.costs.LLMPer1KTokensUSD))
		}
	}
	return cmp
}

// CostLine is one meter's slice of a TenantCostReport.
type CostLine struct {
	Meter  Meter  `json:"meter"`
	Period Period `json:"period"`
	// Usage is the consumption recorded so far in the current period.
	Usage int64 `json:"usage"`
	// CostUSD is the cost of `Usage` at the configured unit price.
	CostUSD float64 `json:"cost_usd"`
	// ProjectedUsage extrapolates Usage to the end of the current
	// period assuming a constant rate.
	ProjectedUsage int64 `json:"projected_usage"`
	// ProjectedCostUSD is the cost of ProjectedUsage.
	ProjectedCostUSD float64 `json:"projected_cost_usd"`
	// MonthlyCostUSD normalises ProjectedCostUSD to a full month so
	// daily and monthly meters can be summed into one monthly total.
	MonthlyCostUSD float64 `json:"monthly_cost_usd"`
	// HardLimit is the meter's hard budget (0 = unbounded).
	HardLimit int64 `json:"hard_limit"`
	// BudgetUtilization is ProjectedUsage / HardLimit (0 when
	// unbounded), expressed as a fraction.
	BudgetUtilization float64 `json:"budget_utilization"`
	// OverBudget is true when the projected usage exceeds the hard
	// limit.
	OverBudget bool `json:"over_budget"`
}

// TenantCostReport is a per-tenant monthly cost breakdown with
// projection and margin analysis.
type TenantCostReport struct {
	TenantID    uuid.UUID             `json:"tenant_id"`
	Tier        repository.TenantTier `json:"tier"`
	GeneratedAt time.Time             `json:"generated_at"`
	Lines       []CostLine            `json:"lines"`
	// TotalCostUSD is the sum of per-meter CostUSD (cost incurred so
	// far this period).
	TotalCostUSD float64 `json:"total_cost_usd"`
	// ProjectedMonthlyCostUSD is the sum of per-meter MonthlyCostUSD.
	ProjectedMonthlyCostUSD float64 `json:"projected_monthly_cost_usd"`
	// MonthlyRevenueUSD is the tier subscription price used for margin.
	MonthlyRevenueUSD float64 `json:"monthly_revenue_usd"`
	// MarginUSD is MonthlyRevenueUSD - ProjectedMonthlyCostUSD.
	MarginUSD float64 `json:"margin_usd"`
	// MarginPct is MarginUSD / MonthlyRevenueUSD (0 when revenue is 0).
	MarginPct float64 `json:"margin_pct"`
}

// elapsedFraction returns the fraction (0,1] of the period containing
// `at` that has already elapsed. Guarded against a zero denominator
// and clamped to [minFraction, 1] so a just-started period does not
// project to an absurd figure.
func elapsedFraction(period Period, at time.Time) float64 {
	start, end := period.Bounds(at)
	total := end.Sub(start).Seconds()
	if total <= 0 {
		return 1
	}
	elapsed := at.UTC().Sub(start).Seconds()
	frac := elapsed / total
	const minFraction = 0.01 // never extrapolate by more than 100x
	if frac < minFraction {
		return minFraction
	}
	if frac > 1 {
		return 1
	}
	return frac
}

// ProjectToPeriodEnd extrapolates a partial-period usage value to the
// full period it belongs to, using the same elapsed-fraction model the
// cost report uses for projected spend. It is what the usage view
// surfaces as "on track to use N this period", so a budget gauge reads
// the steady-state run rate rather than the raw mid-period accumulator
// (which understates utilisation early in a period). A non-positive
// value projects to 0.
func ProjectToPeriodEnd(value int64, period Period, at time.Time) int64 {
	if value <= 0 {
		return 0
	}
	return int64(math.Ceil(float64(value) / elapsedFraction(period, at)))
}

// monthlyMultiplier scales a single-period projected cost to a full
// calendar month: daily meters multiply by the number of days in the
// month; monthly meters are already monthly.
func monthlyMultiplier(period Period, at time.Time) float64 {
	if period != PeriodDaily {
		return 1
	}
	at = at.UTC()
	firstNext := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 1, 0)
	last := firstNext.AddDate(0, 0, -1)
	return float64(last.Day())
}

// BuildReport assembles a TenantCostReport from a tenant's
// current-period usage rows and resolved budget limits. `usage` is
// typically MeteringService.CurrentUsage output; `limits` is
// BudgetEnforcer.TenantBudgets output.
func (c *CostCalculator) BuildReport(tenantID uuid.UUID, tier repository.TenantTier, usage []UsageRecord, limits map[Meter]BudgetLimit) TenantCostReport {
	now := c.now()
	rep := TenantCostReport{
		TenantID:    tenantID,
		Tier:        tier,
		GeneratedAt: now,
	}
	for _, u := range usage {
		period := DefaultMeterPeriod(u.Meter)
		if lim, ok := limits[u.Meter]; ok && lim.Period.Valid() {
			period = lim.Period
		}
		frac := elapsedFraction(period, now)
		projected := int64(math.Ceil(float64(u.Value) / frac))
		line := CostLine{
			Meter:            u.Meter,
			Period:           period,
			Usage:            u.Value,
			CostUSD:          round2(c.MeterCostUSD(u.Meter, u.Value)),
			ProjectedUsage:   projected,
			ProjectedCostUSD: round2(c.MeterCostUSD(u.Meter, projected)),
		}
		line.MonthlyCostUSD = round2(c.MeterCostUSD(u.Meter, projected) * monthlyMultiplier(period, now))
		if lim, ok := limits[u.Meter]; ok && !lim.hardUnbounded() {
			line.HardLimit = lim.HardLimit
			line.BudgetUtilization = round4(float64(projected) / float64(lim.HardLimit))
			line.OverBudget = projected > lim.HardLimit
		}
		rep.Lines = append(rep.Lines, line)
		rep.TotalCostUSD += line.CostUSD
		rep.ProjectedMonthlyCostUSD += line.MonthlyCostUSD
	}
	sort.Slice(rep.Lines, func(i, j int) bool { return rep.Lines[i].Meter < rep.Lines[j].Meter })
	rep.TotalCostUSD = round2(rep.TotalCostUSD)
	rep.ProjectedMonthlyCostUSD = round2(rep.ProjectedMonthlyCostUSD)
	rep.MonthlyRevenueUSD = c.tierPrices[tier]
	rep.MarginUSD = round2(rep.MonthlyRevenueUSD - rep.ProjectedMonthlyCostUSD)
	if rep.MonthlyRevenueUSD > 0 {
		rep.MarginPct = round4(rep.MarginUSD / rep.MonthlyRevenueUSD)
	}
	return rep
}

// NATSStorageCostUSD returns the monthly cost of retaining
// `streamBytes` of NATS JetStream file storage for one tenant.
//
// Unlike ClickHouse rows or S3 archived bytes — both cumulative *flow*
// counters that the additive meter pipeline records and BuildReport
// extrapolates — a JetStream stream's size is a point-in-time *gauge*:
// retention (max age / max bytes) bounds it, so a tenant pays for the
// volume the stream currently occupies, not the lifetime sum of bytes
// ever published. Pricing it per GB-month against the sampled size is
// therefore the correct model; running it through the additive
// pipeline would double-count every redelivered or re-published
// message.
func (c *CostCalculator) NATSStorageCostUSD(streamBytes int64) float64 {
	if streamBytes <= 0 {
		return 0
	}
	return float64(streamBytes) / bytesPerGB * c.costs.NATSPerGBMonthUSD
}

// S3StorageCostUSD returns the monthly cost of retaining `archiveBytes`
// of S3 cold archive for one tenant.
//
// Like NATS JetStream — and unlike the per-request meters — a tenant's
// cold-archive footprint is a point-in-time *gauge* sized by the
// retention/compaction policy, so it is priced directly per GB-month
// against the sampled size rather than summed through the additive
// meter pipeline. This is numerically identical to
// MeterCostUSD(MeterS3BytesArchived, archiveBytes); it exists so the
// gauge semantics are explicit at the infra-projection call site and
// symmetric with NATSStorageCostUSD. The MeterS3BytesArchived branch in
// MeterCostUSD is retained for callers that record S3 through the meter
// pipeline.
func (c *CostCalculator) S3StorageCostUSD(archiveBytes int64) float64 {
	if archiveBytes <= 0 {
		return 0
	}
	return float64(archiveBytes) / bytesPerGB * c.costs.S3PerGBMonthUSD
}

// InfraUsageSample captures the three infrastructure cost drivers for a
// single tenant at one point in time. It is the input to
// ProjectInfraMonthlyCost and is populated either from a tenant's
// actual recorded usage (ClickHouse) plus sampled backend gauges (NATS,
// S3), or from a capacity-planning model (see bench/controlplane).
type InfraUsageSample struct {
	TenantID uuid.UUID `json:"tenant_id"`
	// ClickHouseRowsThisPeriod is the telemetry rows written so far in
	// the current ClickHousePeriod. It is a flow counter and is
	// extrapolated to a full month.
	ClickHouseRowsThisPeriod int64 `json:"clickhouse_rows_this_period"`
	// ClickHousePeriod is the accumulation window the row count was
	// measured over. Zero/invalid defaults to monthly.
	ClickHousePeriod Period `json:"clickhouse_period"`
	// NATSStreamBytes is the tenant's current JetStream retained size
	// (a gauge). Priced directly per GB-month.
	NATSStreamBytes int64 `json:"nats_stream_bytes"`
	// S3ArchiveBytes is the tenant's current cold-archive footprint (a
	// gauge). Priced directly per GB-month.
	S3ArchiveBytes int64 `json:"s3_archive_bytes"`
}

// InfraCostProjection is the per-driver and total projected monthly
// infrastructure cost for one tenant. It isolates the three storage /
// write-amplification drivers (ClickHouse, NATS, S3) from the
// per-request meters in TenantCostReport so the cost-model doc and the
// metering dashboard can attribute spend to a specific backend.
type InfraCostProjection struct {
	TenantID uuid.UUID `json:"tenant_id"`
	// ClickHouseProjectedRows is ClickHouseRowsThisPeriod extrapolated
	// to a full calendar month at the current rate.
	ClickHouseProjectedRows int64   `json:"clickhouse_projected_rows"`
	ClickHouseMonthlyUSD    float64 `json:"clickhouse_monthly_usd"`
	NATSStreamBytes         int64   `json:"nats_stream_bytes"`
	NATSMonthlyUSD          float64 `json:"nats_monthly_usd"`
	S3ArchiveBytes          int64   `json:"s3_archive_bytes"`
	S3MonthlyUSD            float64 `json:"s3_monthly_usd"`
	// TotalMonthlyUSD is the sum of the three driver costs.
	TotalMonthlyUSD float64 `json:"total_monthly_usd"`
	// Hibernated reports whether the tenant is currently in dormant-
	// tenant scale-to-zero hibernation (see
	// internal/service/tenancy/hibernation). It is set only when a
	// HibernationStateReader is wired (false otherwise). A hibernated
	// trial's drivers are already near-zero — telemetry ingest is
	// sampled to near-zero so ClickHouse rows stop accruing, NATS
	// subscriptions are condensed, and retention is at the aggressive
	// floor — so this flag lets the fleet view attribute the near-zero
	// projection to the parked state rather than to an absence of data.
	Hibernated bool `json:"hibernated"`
}

// ProjectInfraMonthlyCost turns one tenant's infrastructure usage
// sample into a projected monthly cost broken down per backend.
//
// ClickHouse rows are a flow: the in-period count is divided by the
// elapsed fraction of its period (so an early-month sample is not
// under-projected) and scaled to a whole month. NATS and S3 are gauges
// priced directly per GB-month. The clock is the calculator's own
// (overridable in tests) so the elapsed-fraction maths is deterministic.
func (c *CostCalculator) ProjectInfraMonthlyCost(sample InfraUsageSample) InfraCostProjection {
	now := c.now()
	period := sample.ClickHousePeriod
	if !period.Valid() {
		period = PeriodMonthly
	}
	frac := elapsedFraction(period, now)
	projectedRows := int64(0)
	if sample.ClickHouseRowsThisPeriod > 0 {
		// Extrapolate the in-period count to a full period (÷ elapsed
		// fraction), then to a full calendar month (× the period's
		// monthly multiplier) so ClickHouseProjectedRows is a genuine
		// monthly figure consistent with ClickHouseMonthlyUSD — not just
		// a full-period count that would diverge for sub-monthly periods.
		fullPeriodRows := float64(sample.ClickHouseRowsThisPeriod) / frac
		projectedRows = int64(math.Ceil(fullPeriodRows * monthlyMultiplier(period, now)))
	}
	chMonthly := round2(c.MeterCostUSD(MeterClickHouseRowsWritten, projectedRows))
	natsMonthly := round2(c.NATSStorageCostUSD(sample.NATSStreamBytes))
	s3Monthly := round2(c.S3StorageCostUSD(sample.S3ArchiveBytes))
	return InfraCostProjection{
		TenantID:                sample.TenantID,
		ClickHouseProjectedRows: projectedRows,
		ClickHouseMonthlyUSD:    chMonthly,
		NATSStreamBytes:         sample.NATSStreamBytes,
		NATSMonthlyUSD:          natsMonthly,
		S3ArchiveBytes:          sample.S3ArchiveBytes,
		S3MonthlyUSD:            s3Monthly,
		TotalMonthlyUSD:         round2(chMonthly + natsMonthly + s3Monthly),
	}
}

// PlatformInfraCost aggregates per-tenant infrastructure projections
// into a fleet-wide monthly total, preserving the per-driver split so a
// capacity planner can see which backend dominates spend at scale.
type PlatformInfraCost struct {
	GeneratedAt          time.Time             `json:"generated_at"`
	TenantCount          int                   `json:"tenant_count"`
	Tenants              []InfraCostProjection `json:"tenants"`
	ClickHouseMonthlyUSD float64               `json:"clickhouse_monthly_usd"`
	NATSMonthlyUSD       float64               `json:"nats_monthly_usd"`
	S3MonthlyUSD         float64               `json:"s3_monthly_usd"`
	TotalMonthlyUSD      float64               `json:"total_monthly_usd"`
}

// AggregateInfraCost projects every sample and sums the results into a
// PlatformInfraCost. Tenant order is preserved from the input.
func (c *CostCalculator) AggregateInfraCost(samples []InfraUsageSample) PlatformInfraCost {
	out := PlatformInfraCost{GeneratedAt: c.now(), Tenants: make([]InfraCostProjection, 0, len(samples))}
	for _, s := range samples {
		p := c.ProjectInfraMonthlyCost(s)
		out.Tenants = append(out.Tenants, p)
		out.ClickHouseMonthlyUSD += p.ClickHouseMonthlyUSD
		out.NATSMonthlyUSD += p.NATSMonthlyUSD
		out.S3MonthlyUSD += p.S3MonthlyUSD
	}
	out.TenantCount = len(out.Tenants)
	// Per-tenant driver costs are already cent-rounded by ProjectInfraMonthlyCost,
	// so the per-driver round2 below is effectively exact. TotalMonthlyUSD is
	// deliberately derived from the rounded driver subtotals (not the raw grand
	// total) so the displayed total always equals the sum of the displayed parts.
	// That rounding-of-rounded total can drift from round2(raw grand total) by at
	// most a cent — acceptable for an explicitly-approximate projection, and the
	// same pattern BuildReport uses.
	out.ClickHouseMonthlyUSD = round2(out.ClickHouseMonthlyUSD)
	out.NATSMonthlyUSD = round2(out.NATSMonthlyUSD)
	out.S3MonthlyUSD = round2(out.S3MonthlyUSD)
	out.TotalMonthlyUSD = round2(out.ClickHouseMonthlyUSD + out.NATSMonthlyUSD + out.S3MonthlyUSD)
	return out
}

// PlatformCostReport aggregates per-tenant reports into a platform-wide
// view for the MSP/admin cost-report endpoint.
type PlatformCostReport struct {
	GeneratedAt             time.Time          `json:"generated_at"`
	TenantCount             int                `json:"tenant_count"`
	Tenants                 []TenantCostReport `json:"tenants"`
	TotalCostUSD            float64            `json:"total_cost_usd"`
	ProjectedMonthlyCostUSD float64            `json:"projected_monthly_cost_usd"`
	TotalRevenueUSD         float64            `json:"total_revenue_usd"`
	TotalMarginUSD          float64            `json:"total_margin_usd"`
}

// round2 rounds a dollar figure to whole cents.
func round2(v float64) float64 { return math.Round(v*100) / 100 }

// round4 rounds a ratio to four decimal places.
func round4(v float64) float64 { return math.Round(v*10000) / 10000 }

// currentUsageReader is the per-tenant current-period usage surface
// the Reports orchestrator needs; satisfied by *MeteringService.
type currentUsageReader interface {
	CurrentUsage(ctx context.Context, tenantID uuid.UUID) ([]UsageRecord, error)
}

// resolvedBudgetReader returns a tenant's effective per-meter limits;
// satisfied by *BudgetEnforcer.
type resolvedBudgetReader interface {
	TenantBudgets(ctx context.Context, tenantID uuid.UUID) (map[Meter]BudgetLimit, error)
	// TenantBudgetsBatch resolves the effective per-meter limits for
	// many tenants in a bounded number of queries instead of one round
	// trip per tenant. The result is keyed by tenant id; every id in
	// the input appears in the output (a tenant with no overrides still
	// maps to its tier/global defaults), so callers can index the map
	// directly without a presence check. Each value is a private copy
	// the caller may mutate freely, matching TenantBudgets.
	TenantBudgetsBatch(ctx context.Context, tenantIDs []uuid.UUID) (map[uuid.UUID]map[Meter]BudgetLimit, error)
	// TenantBudgetsBatchWithTiers is TenantBudgetsBatch for a caller
	// that has already resolved each tenant's tier: it reuses the
	// supplied tier map instead of resolving tiers again, so the
	// platform report resolves tiers once rather than twice. The
	// supplied tiers must cover every requested id. Results are
	// identical to TenantBudgetsBatch in every other respect.
	TenantBudgetsBatchWithTiers(ctx context.Context, tenantIDs []uuid.UUID, tiers map[uuid.UUID]repository.TenantTier) (map[uuid.UUID]map[Meter]BudgetLimit, error)
}

// platformUsageReader returns the current-period usage of every
// tenant; satisfied by the system-scoped UsageStore.
type platformUsageReader interface {
	PlatformCurrentUsage(ctx context.Context, at time.Time) ([]UsageRecord, error)
}

// NATSStreamSizer reports a tenant's current JetStream retained byte
// size — a point-in-time storage gauge (see NATSStorageCostUSD for why
// it is a gauge, not a flow). It is intentionally optional: JetStream
// has no per-tenant stream-size primitive (SNG_TELEMETRY is one stream
// shared across tenants), so attributing retained bytes to a tenant
// requires a deployment-specific source (e.g. a subject-prefixed
// per-tenant stream, or a sampler that buckets `streams info` by the
// tenant subject token). When no sizer is wired, the infra projection
// reports the NATS driver as 0 rather than guessing — honest under-
// reporting an operator can see, not a fabricated number. The
// ClickHouse and S3 drivers are always populated from real recorded
// meters and do not depend on this.
type NATSStreamSizer interface {
	TenantStreamBytes(ctx context.Context, tenantID uuid.UUID) (int64, error)
}

// Reports orchestrates the per-tenant and platform-wide cost reports
// for the metering handler: it joins a tenant's current usage, its
// resolved budgets, and its tier, then runs them through the
// CostCalculator. It holds only read surfaces so it is safe to share.
type Reports struct {
	usage         currentUsageReader
	budgets       resolvedBudgetReader
	platformUsage platformUsageReader
	tiers         TierResolver
	calc          *CostCalculator
	natsSizer     NATSStreamSizer
	hibReader     HibernationStateReader
	now           func() time.Time
}

// HibernationStateReader reports whether a tenant is currently in
// dormant-tenant scale-to-zero hibernation. It is an in-memory read
// (the hibernation registry), so it is cheap to consult per projection.
// Wiring it is optional: without it the fleet view simply never marks a
// projection hibernated. A *hibernation.Registry satisfies it.
type HibernationStateReader interface {
	IsHibernated(tenantID uuid.UUID) bool
}

// ReportsOption customises a Reports orchestrator.
type ReportsOption func(*Reports)

// WithNATSStreamSizer wires the optional per-tenant NATS retained-byte
// gauge into the infra projection. Without it, TenantInfraProjection
// reports the NATS driver as 0 (see NATSStreamSizer). A nil sizer is
// ignored so callers can pass an optional dependency unconditionally.
func WithNATSStreamSizer(s NATSStreamSizer) ReportsOption {
	return func(r *Reports) {
		if s != nil {
			r.natsSizer = s
		}
	}
}

// WithHibernationStateReader wires the optional hibernation-state read
// surface so TenantInfraProjection can mark a parked trial's projection
// hibernated. A nil reader is ignored so callers can pass an optional
// dependency (e.g. a feature-gated registry) unconditionally.
func WithHibernationStateReader(h HibernationStateReader) ReportsOption {
	return func(r *Reports) {
		if h != nil {
			r.hibReader = h
		}
	}
}

// withReportsClock overrides the wall clock; test-only.
func withReportsClock(now func() time.Time) ReportsOption {
	return func(r *Reports) {
		if now != nil {
			r.now = now
		}
	}
}

// NewReports wires a Reports orchestrator. All required dependencies
// must be non-nil; calc is typically the same CostCalculator used
// elsewhere. Optional collaborators (e.g. a NATS stream sizer) are
// supplied via ReportsOption.
func NewReports(usage currentUsageReader, budgets resolvedBudgetReader, platformUsage platformUsageReader, tiers TierResolver, calc *CostCalculator, opts ...ReportsOption) (*Reports, error) {
	if usage == nil || budgets == nil || platformUsage == nil || tiers == nil || calc == nil {
		return nil, fmt.Errorf("metering: reports: all dependencies must be non-nil")
	}
	r := &Reports{
		usage:         usage,
		budgets:       budgets,
		platformUsage: platformUsage,
		tiers:         tiers,
		calc:          calc,
		now:           time.Now,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r, nil
}

// TenantReport builds the current-period cost report for one tenant.
func (r *Reports) TenantReport(ctx context.Context, tenantID uuid.UUID) (TenantCostReport, error) {
	if tenantID == uuid.Nil {
		return TenantCostReport{}, fmt.Errorf("metering: reports: tenant id must not be nil")
	}
	usage, err := r.usage.CurrentUsage(ctx, tenantID)
	if err != nil {
		return TenantCostReport{}, fmt.Errorf("metering: reports: current usage: %w", err)
	}
	limits, err := r.budgets.TenantBudgets(ctx, tenantID)
	if err != nil {
		return TenantCostReport{}, fmt.Errorf("metering: reports: budgets: %w", err)
	}
	tier, err := r.tiers.TenantTier(ctx, tenantID)
	if err != nil {
		return TenantCostReport{}, fmt.Errorf("metering: reports: tier: %w", err)
	}
	return r.calc.BuildReport(tenantID, tier, usage, limits), nil
}

// TenantInfraProjection builds the per-tenant infrastructure cost
// breakdown (ClickHouse / NATS / S3 projected monthly USD) that the
// GET /tenants/{id}/cost endpoint surfaces.
//
// It reads only the calling tenant's current-period usage (so the
// projection is tenant-scoped and RLS-safe), derives the two recorded
// drivers from real meters — ClickHouse rows written (a flow,
// extrapolated to a month by ProjectInfraMonthlyCost) and S3 archived
// bytes (a gauge) — and folds in the NATS retained-byte gauge when a
// sizer is wired (0 otherwise; see NATSStreamSizer). The ClickHouse
// accumulation period is the meter's own budget period so the
// extrapolation window matches how the rows were counted.
func (r *Reports) TenantInfraProjection(ctx context.Context, tenantID uuid.UUID) (InfraCostProjection, error) {
	if tenantID == uuid.Nil {
		return InfraCostProjection{}, fmt.Errorf("metering: reports: tenant id must not be nil")
	}
	usage, err := r.usage.CurrentUsage(ctx, tenantID)
	if err != nil {
		return InfraCostProjection{}, fmt.Errorf("metering: reports: current usage: %w", err)
	}
	var clickHouseRows, s3Bytes int64
	for _, rec := range usage {
		switch rec.Meter {
		case MeterClickHouseRowsWritten:
			clickHouseRows += rec.Value
		case MeterS3BytesArchived:
			s3Bytes += rec.Value
		}
	}
	var natsBytes int64
	if r.natsSizer != nil {
		natsBytes, err = r.natsSizer.TenantStreamBytes(ctx, tenantID)
		if err != nil {
			return InfraCostProjection{}, fmt.Errorf("metering: reports: nats stream size: %w", err)
		}
		if natsBytes < 0 {
			natsBytes = 0
		}
	}
	sample := InfraUsageSample{
		TenantID:                 tenantID,
		ClickHouseRowsThisPeriod: clickHouseRows,
		ClickHousePeriod:         DefaultMeterPeriod(MeterClickHouseRowsWritten),
		NATSStreamBytes:          natsBytes,
		S3ArchiveBytes:           s3Bytes,
	}
	proj := r.calc.ProjectInfraMonthlyCost(sample)
	if r.hibReader != nil {
		proj.Hibernated = r.hibReader.IsHibernated(tenantID)
	}
	return proj, nil
}

// PlatformReport builds the platform-wide cost report across every
// tenant with current-period usage. Tenants are processed in first-seen
// order so the output is deterministic for a given usage snapshot. A
// per-tenant tier or budget lookup failure aborts the report rather
// than emitting a silently partial total a finance operator might trust.
func (r *Reports) PlatformReport(ctx context.Context) (PlatformCostReport, error) {
	now := r.now()
	rows, err := r.platformUsage.PlatformCurrentUsage(ctx, now)
	if err != nil {
		return PlatformCostReport{}, fmt.Errorf("metering: reports: platform usage: %w", err)
	}
	byTenant := make(map[uuid.UUID][]UsageRecord)
	order := make([]uuid.UUID, 0)
	for _, row := range rows {
		if _, seen := byTenant[row.TenantID]; !seen {
			order = append(order, row.TenantID)
		}
		byTenant[row.TenantID] = append(byTenant[row.TenantID], row)
	}
	// Resolve every tenant's tier and budgets up front in exactly two
	// batched lookups — one tier lookup and one override lookup —
	// instead of the two round trips per tenant the per-tenant
	// TenantTier/TenantBudgets calls incurred inside the loop (the N+1
	// that dominated control-plane DB load at scale). The tier map is
	// resolved once here and threaded into the budget batch via
	// TenantBudgetsBatchWithTiers, so the budget enforcer does not
	// resolve tiers a second time (tier resolution stays N, not 2N,
	// round trips in production where the tier adapter has no batched
	// primitive). A batch lookup failure aborts the whole report
	// exactly as a per-tenant failure did, so a finance operator never
	// sees a silently partial total.
	tiers, err := r.tiers.TenantTiersBatch(ctx, order)
	if err != nil {
		return PlatformCostReport{}, fmt.Errorf("metering: reports: platform tiers: %w", err)
	}
	limitsByTenant, err := r.budgets.TenantBudgetsBatchWithTiers(ctx, order, tiers)
	if err != nil {
		return PlatformCostReport{}, fmt.Errorf("metering: reports: platform budgets: %w", err)
	}
	rep := PlatformCostReport{GeneratedAt: now}
	for _, tenantID := range order {
		tr := r.calc.BuildReport(tenantID, tiers[tenantID], byTenant[tenantID], limitsByTenant[tenantID])
		rep.Tenants = append(rep.Tenants, tr)
		rep.TotalCostUSD += tr.TotalCostUSD
		rep.ProjectedMonthlyCostUSD += tr.ProjectedMonthlyCostUSD
		rep.TotalRevenueUSD += tr.MonthlyRevenueUSD
	}
	rep.TenantCount = len(rep.Tenants)
	rep.TotalCostUSD = round2(rep.TotalCostUSD)
	rep.ProjectedMonthlyCostUSD = round2(rep.ProjectedMonthlyCostUSD)
	rep.TotalRevenueUSD = round2(rep.TotalRevenueUSD)
	rep.TotalMarginUSD = round2(rep.TotalRevenueUSD - rep.ProjectedMonthlyCostUSD)
	return rep, nil
}
