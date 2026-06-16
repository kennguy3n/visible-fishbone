package dem

import "math"

// scoring.go holds the pure experience-scoring math: it has no I/O
// and no dependencies on the repository, so the model is exercised
// directly in unit tests over known series.

// latencyScore maps a p50 latency (ms) to [0,1]: 1.0 at or below
// GoodLatencyMs, 0.0 at or above BadLatencyMs, linear in between.
func (c Config) latencyScore(p50 float64) float64 {
	switch {
	case p50 <= c.GoodLatencyMs:
		return 1
	case p50 >= c.BadLatencyMs:
		return 0
	default:
		return 1 - (p50-c.GoodLatencyMs)/(c.BadLatencyMs-c.GoodLatencyMs)
	}
}

// normalizedWeights returns the availability/latency weights scaled to
// sum to 1, falling back to the documented 0.6/0.4 split if the
// configured weights are non-positive.
func (c Config) normalizedWeights() (availability, latency float64) {
	sum := c.AvailabilityWeight + c.LatencyWeight
	if sum <= 0 {
		return 0.6, 0.4
	}
	return c.AvailabilityWeight / sum, c.LatencyWeight / sum
}

// experienceScore composes availability and latency into a 0..100
// score. availability is in [0,1]; p50 is nil when no successful
// probe yielded a latency, in which case the latency term contributes
// 0 (a deliberately conservative floor — we under-state rather than
// over-state experience when latency data is missing). In practice
// every successful DNS/TCP/HTTP probe carries at least dns_ms and the
// window aggregate coalesces to it, so p50 is non-nil whenever
// availability > 0; the nil case coincides with all-failure windows
// (availability 0 → score 0).
func (c Config) experienceScore(availability float64, p50 *float64) float64 {
	lat := 0.0
	if p50 != nil {
		lat = c.latencyScore(*p50)
	}
	wa, wl := c.normalizedWeights()
	return clampFloat(100*(wa*availability+wl*lat), 0, 100)
}

// ewmaUpdate folds a new score sample into the running exponentially
// weighted mean and variance. For the first sample (n == 0) the mean
// is the sample itself and the variance is 0. The variance recurrence
// is the standard EW incremental form
//
//	variance' = (1-α)·(variance + α·δ²),  δ = sample − mean
//
// which keeps the baseline cheap (O(1), no window buffer) — important
// at 5,000 tenants × several targets each.
func (c Config) ewmaUpdate(n int64, prevMean, prevVar, sample float64) (mean, variance float64) {
	if n <= 0 {
		return sample, 0
	}
	delta := sample - prevMean
	mean = prevMean + c.EWMAAlpha*delta
	variance = (1 - c.EWMAAlpha) * (prevVar + c.EWMAAlpha*delta*delta)
	return mean, variance
}

// degradeDecision captures why (or why not) a score is considered
// degraded, so the alert can carry the evidence.
type degradeDecision struct {
	degraded   bool
	belowFloor bool
	zExceeded  bool
	zScore     float64
	stdDev     float64
}

// assessDegradation decides whether the new score is degraded relative
// to the pre-update baseline. Two independent triggers: an absolute
// floor (score below DegradeScoreFloor) and a relative drop (score is
// DegradeZScore standard deviations or more below the EWMA mean). The
// z-trigger only arms once the baseline has seen MinSamplesForZ
// samples and has non-zero variance, so a cold/young baseline never
// produces spurious alerts.
func (c Config) assessDegradation(n int64, prevMean, prevVar, score float64) degradeDecision {
	d := degradeDecision{belowFloor: score < c.DegradeScoreFloor}
	if n >= c.MinSamplesForZ && prevVar > 0 {
		d.stdDev = math.Sqrt(prevVar)
		if d.stdDev > 1e-9 {
			d.zScore = (prevMean - score) / d.stdDev
			d.zExceeded = d.zScore >= c.DegradeZScore
		}
	}
	d.degraded = d.belowFloor || d.zExceeded
	return d
}

func clampFloat(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
