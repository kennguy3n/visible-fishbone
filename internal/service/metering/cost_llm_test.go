package metering

import "testing"

// TestLLMSelfHostedMonthlyUSD covers the flat self-hosted accessor,
// including the "no deployment configured" (0) disposition.
func TestLLMSelfHostedMonthlyUSD(t *testing.T) {
	if got := NewCostCalculator(DefaultUnitCosts).LLMSelfHostedMonthlyUSD(); !approx(got, 300) {
		t.Errorf("default self-hosted monthly = %v, want 300", got)
	}

	costs := DefaultUnitCosts
	costs.LLMSelfHostedPerMonthUSD = 150 // bare-metal A10G
	if got := NewCostCalculator(costs).LLMSelfHostedMonthlyUSD(); !approx(got, 150) {
		t.Errorf("bare-metal self-hosted monthly = %v, want 150", got)
	}

	// A zero (or negative) configured cost means "no self-hosted
	// deployment" and must report 0, not fall back to a default — the
	// caller distinguishes "self-hosting disabled" from "self-hosting
	// at $0".
	costs.LLMSelfHostedPerMonthUSD = 0
	if got := NewCostCalculator(costs).LLMSelfHostedMonthlyUSD(); got != 0 {
		t.Errorf("unconfigured self-hosted monthly = %v, want 0", got)
	}
}

// TestLLMPerTokenMonthlyUSD verifies the managed-API model scales
// linearly with tokens and folds in the optional per-call overhead.
func TestLLMPerTokenMonthlyUSD(t *testing.T) {
	c := NewCostCalculator(DefaultUnitCosts)
	// 5M tokens * $0.002/1K = $10.00; default per-call overhead is 0.
	if got := c.LLMPerTokenMonthlyUSD(5_000_000, 100_000); !approx(got, 10.0) {
		t.Errorf("per-token monthly = %v, want 10.0", got)
	}

	// With a non-zero per-call overhead the call count contributes.
	costs := DefaultUnitCosts
	costs.LLMPerCallUSD = 0.0001
	c2 := NewCostCalculator(costs)
	// 1M tokens * $0.002/1K = $2.00 + 100K calls * $0.0001 = $10.00 → $12.00
	if got := c2.LLMPerTokenMonthlyUSD(1_000_000, 100_000); !approx(got, 12.0) {
		t.Errorf("per-token monthly with per-call = %v, want 12.0", got)
	}

	// Negative inputs are treated as zero (MeterCostUSD guards them).
	if got := c.LLMPerTokenMonthlyUSD(-5, -5); got != 0 {
		t.Errorf("negative inputs = %v, want 0", got)
	}
}

// TestLLMMonthlyCostUSD checks the single dispatch entry point that
// "supports both pricing models": self-hosted is flat regardless of
// volume, per-token scales, and an unknown model defaults to
// per-token.
func TestLLMMonthlyCostUSD(t *testing.T) {
	c := NewCostCalculator(DefaultUnitCosts)

	// Self-hosted is flat regardless of the token/call projection.
	lo := c.LLMMonthlyCostUSD(LLMPricingSelfHosted, 1_000, 10)
	hi := c.LLMMonthlyCostUSD(LLMPricingSelfHosted, 1_000_000_000, 10_000_000)
	if !approx(lo, 300) || !approx(hi, 300) {
		t.Errorf("self-hosted should be flat $300 regardless of volume, got lo=%v hi=%v", lo, hi)
	}

	// Per-token scales with volume.
	pt := c.LLMMonthlyCostUSD(LLMPricingPerToken, 5_000_000, 0)
	if !approx(pt, 10.0) {
		t.Errorf("per-token monthly = %v, want 10.0", pt)
	}

	// Unknown model falls back to per-token (never silently hides a
	// usage-driven charge as a flat $0).
	def := c.LLMMonthlyCostUSD(LLMPricingModel("bogus"), 5_000_000, 0)
	if !approx(def, pt) {
		t.Errorf("unknown model = %v, want per-token %v", def, pt)
	}
}

// TestCompareLLMPricing exercises the economic crossover: which model
// is cheaper at a given volume, the savings, and the breakeven token
// count. These mirror the worked example in docs/cost-model.md.
func TestCompareLLMPricing(t *testing.T) {
	c := NewCostCalculator(DefaultUnitCosts) // $0.002/1K tokens, $300/mo self-hosted

	// Breakeven: $300 = tokens/1000 * $0.002 → tokens = 150,000,000.
	const wantBreakeven = 150_000_000

	// Low volume (50M tokens → $100): per-token wins by $200.
	low := c.CompareLLMPricing(50_000_000, 0)
	if low.Cheaper != LLMPricingPerToken {
		t.Errorf("at 50M tokens cheaper = %q, want per_token", low.Cheaper)
	}
	if !approx(low.PerTokenMonthlyUSD, 100) || !approx(low.SelfHostedMonthlyUSD, 300) {
		t.Errorf("low volume costs: per-token=%v self-hosted=%v", low.PerTokenMonthlyUSD, low.SelfHostedMonthlyUSD)
	}
	if !approx(low.SavingsUSD, 200) {
		t.Errorf("low volume savings = %v, want 200", low.SavingsUSD)
	}
	if low.BreakevenTokens != wantBreakeven {
		t.Errorf("breakeven = %d, want %d", low.BreakevenTokens, wantBreakeven)
	}

	// High volume (500M tokens → $1000): self-hosted wins by $700.
	high := c.CompareLLMPricing(500_000_000, 0)
	if high.Cheaper != LLMPricingSelfHosted {
		t.Errorf("at 500M tokens cheaper = %q, want self_hosted", high.Cheaper)
	}
	if !approx(high.SavingsUSD, 700) {
		t.Errorf("high volume savings = %v, want 700", high.SavingsUSD)
	}

	// Exactly at breakeven the costs are equal and the tie resolves to
	// per-token (no infra to operate) with zero savings.
	at := c.CompareLLMPricing(wantBreakeven, 0)
	if !approx(at.PerTokenMonthlyUSD, at.SelfHostedMonthlyUSD) {
		t.Errorf("at breakeven costs differ: %v vs %v", at.PerTokenMonthlyUSD, at.SelfHostedMonthlyUSD)
	}
	if at.Cheaper != LLMPricingPerToken || !approx(at.SavingsUSD, 0) {
		t.Errorf("at breakeven cheaper=%q savings=%v, want per_token/0", at.Cheaper, at.SavingsUSD)
	}
}

// TestCompareLLMPricingNoSelfHosted verifies the comparison degrades
// gracefully when no self-hosted deployment is configured: per-token
// is the only model, with no savings or breakeven.
func TestCompareLLMPricingNoSelfHosted(t *testing.T) {
	costs := DefaultUnitCosts
	costs.LLMSelfHostedPerMonthUSD = 0
	c := NewCostCalculator(costs)

	cmp := c.CompareLLMPricing(500_000_000, 0)
	if cmp.Cheaper != LLMPricingPerToken {
		t.Errorf("cheaper = %q, want per_token", cmp.Cheaper)
	}
	if cmp.SelfHostedMonthlyUSD != 0 {
		t.Errorf("self-hosted = %v, want 0", cmp.SelfHostedMonthlyUSD)
	}
	if cmp.SavingsUSD != 0 || cmp.BreakevenTokens != 0 {
		t.Errorf("savings=%v breakeven=%d, want 0/0", cmp.SavingsUSD, cmp.BreakevenTokens)
	}
}

// TestCompareLLMPricingFreeTokens guards the breakeven divide-by-zero
// path: a zero per-token rate makes per-token always cheaper and the
// breakeven undefined.
func TestCompareLLMPricingFreeTokens(t *testing.T) {
	costs := DefaultUnitCosts
	costs.LLMPer1KTokensUSD = 0
	c := NewCostCalculator(costs)

	cmp := c.CompareLLMPricing(1_000_000_000, 0)
	if cmp.Cheaper != LLMPricingPerToken {
		t.Errorf("cheaper = %q, want per_token", cmp.Cheaper)
	}
	if cmp.BreakevenTokens != 0 {
		t.Errorf("breakeven = %d, want 0 (undefined for free tokens)", cmp.BreakevenTokens)
	}
}

// TestCompareLLMPricingBreakevenUsesRawCost pins the breakeven to the
// *unrounded* self-hosted cost. With a sub-cent monthly cost the
// displayed figure is cent-rounded, but the crossover token volume
// must be derived from the exact cost — otherwise it drifts by up to
// ~half a cent's worth of tokens. Here $300.336/mo at $0.002/1K
// tokens breaks even at 150,168,000 tokens; using the rounded $300.34
// would wrongly report 150,170,000.
func TestCompareLLMPricingBreakevenUsesRawCost(t *testing.T) {
	costs := DefaultUnitCosts
	costs.LLMSelfHostedPerMonthUSD = 300.336
	c := NewCostCalculator(costs)

	cmp := c.CompareLLMPricing(150_000_000, 0)

	// Displayed cost is cent-rounded.
	if !approx(cmp.SelfHostedMonthlyUSD, 300.34) {
		t.Errorf("self-hosted displayed = %v, want 300.34", cmp.SelfHostedMonthlyUSD)
	}
	// Breakeven is computed from the raw 300.336, not the rounded 300.34.
	const wantBreakeven = 150_168_000
	if cmp.BreakevenTokens != wantBreakeven {
		t.Errorf("breakeven = %d, want %d (must use raw self-hosted cost, not cent-rounded)",
			cmp.BreakevenTokens, wantBreakeven)
	}
}

// TestLLMPricingModelValid covers the small Valid helper.
func TestLLMPricingModelValid(t *testing.T) {
	for _, m := range []LLMPricingModel{LLMPricingPerToken, LLMPricingSelfHosted} {
		if !m.Valid() {
			t.Errorf("%q should be valid", m)
		}
	}
	if LLMPricingModel("nope").Valid() {
		t.Error("bogus model should be invalid")
	}
}
