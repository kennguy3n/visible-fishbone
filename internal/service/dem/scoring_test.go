package dem

import (
	"math"
	"testing"
)

func ptr(v float64) *float64 { return &v }

func TestLatencyScore_Boundaries(t *testing.T) {
	c := DefaultConfig()
	cases := []struct {
		p50  float64
		want float64
	}{
		{0, 1},
		{100, 1},    // at Good
		{2000, 0},   // at Bad
		{3000, 0},   // beyond Bad
		{1050, 0.5}, // midpoint of [100,2000]
	}
	for _, tc := range cases {
		if got := c.latencyScore(tc.p50); math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("latencyScore(%v) = %v, want %v", tc.p50, got, tc.want)
		}
	}
}

func TestExperienceScore_Composite(t *testing.T) {
	c := DefaultConfig()
	// Perfect availability + perfect latency -> 100.
	if got := c.experienceScore(1, ptr(10)); math.Abs(got-100) > 1e-9 {
		t.Errorf("perfect score = %v, want 100", got)
	}
	// Perfect availability, worst latency -> 100*0.6 = 60.
	if got := c.experienceScore(1, ptr(5000)); math.Abs(got-60) > 1e-9 {
		t.Errorf("avail-only score = %v, want 60", got)
	}
	// Zero availability with no successful latency sample (the real
	// shape of a fully-down target) -> 0.
	if got := c.experienceScore(0, nil); math.Abs(got-0) > 1e-9 {
		t.Errorf("unavailable score = %v, want 0", got)
	}
	// No latency sample -> latency contributes 0.
	if got := c.experienceScore(1, nil); math.Abs(got-60) > 1e-9 {
		t.Errorf("nil-latency score = %v, want 60", got)
	}
}

func TestEWMAUpdate(t *testing.T) {
	c := DefaultConfig() // alpha 0.2
	// First sample seeds the mean, zero variance.
	mean, variance := c.ewmaUpdate(0, 0, 0, 100)
	if mean != 100 || variance != 0 {
		t.Fatalf("first sample = (%v,%v), want (100,0)", mean, variance)
	}
	// Steady state: feeding the mean back keeps it put.
	mean, variance = c.ewmaUpdate(1, 100, 0, 100)
	if mean != 100 || variance != 0 {
		t.Fatalf("steady = (%v,%v), want (100,0)", mean, variance)
	}
	// A drop moves the mean toward the sample and grows variance.
	// delta=-50, mean=100+0.2*(-50)=90, var=0.8*(0+0.2*2500)=400.
	mean, variance = c.ewmaUpdate(2, 100, 0, 50)
	if math.Abs(mean-90) > 1e-9 || math.Abs(variance-400) > 1e-9 {
		t.Fatalf("drop = (%v,%v), want (90,400)", mean, variance)
	}
}

func TestAssessDegradation(t *testing.T) {
	c := DefaultConfig() // floor 70, z 2.0, minSamples 10
	// Mature baseline (mean 95, std 2). A 2.5-sigma drop to 90 trips
	// the relative z-trigger while staying above the absolute floor.
	d := c.assessDegradation(10, 95, 4, 90)
	if !d.degraded || !d.zExceeded || d.belowFloor {
		t.Fatalf("z drop: %+v", d)
	}
	if math.Abs(d.zScore-2.5) > 1e-9 {
		t.Fatalf("zScore = %v, want 2.5", d.zScore)
	}
	// Above floor, sub-threshold z -> healthy.
	if d := c.assessDegradation(10, 90, 400, 80); d.degraded {
		t.Fatalf("healthy misflagged: %+v", d)
	}
	// Below the absolute floor -> degraded regardless of baseline.
	if d := c.assessDegradation(10, 90, 400, 65); !d.degraded || !d.belowFloor {
		t.Fatalf("floor not tripped: %+v", d)
	}
	// Young baseline (n<minSamples): z trigger disarmed even on a big
	// drop; only the floor can fire.
	if d := c.assessDegradation(5, 90, 400, 80); d.degraded {
		t.Fatalf("young baseline z misfired: %+v", d)
	}
}
