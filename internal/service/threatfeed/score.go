package threatfeed

import (
	"math"
	"time"
)

// DefaultHalfLife is the recency half-life: an indicator last seen one
// half-life ago has its recency factor (and thus its score) halved. A
// month is a reasonable default for open malware/abuse feeds, whose
// indicators stay actionable for weeks.
const DefaultHalfLife = 30 * 24 * time.Hour

// noisyOr fuses independent evidence weights into a single belief in
// [0,1]: 1 - prod(1 - w_i). This is the standard noisy-OR combination
// for independent signals — it rises with BOTH corroboration (more
// contributing feeds) and source authority (higher per-feed weight),
// is monotonic, and is bounded without ad-hoc capping. Two feeds of
// weight 0.7 and 0.8 yield 1-(0.3)(0.2)=0.94: more confident than
// either alone, never exceeding 1.
func noisyOr(weights []float64) float64 {
	prod := 1.0
	for _, w := range weights {
		prod *= 1 - clamp01(w)
	}
	return clamp01(1 - prod)
}

// recencyFactor is an exponential decay in (0,1]: 2^(-age/halfLife). A
// freshly-seen indicator scores 1.0; one seen exactly halfLife ago
// scores 0.5. A non-positive age (lastSeen at/after now) or
// non-positive halfLife yields 1.0 (no decay).
func recencyFactor(age, halfLife time.Duration) float64 {
	if age <= 0 || halfLife <= 0 {
		return 1
	}
	return math.Exp2(-float64(age) / float64(halfLife))
}

// clamp01 maps any float to [0,1], collapsing NaN/-Inf to 0 and +Inf to
// 1 so a garbage weight can never poison the score arithmetic.
func clamp01(v float64) float64 {
	switch {
	case math.IsNaN(v), v < 0:
		return 0
	case v > 1:
		return 1
	}
	return v
}

// earliest returns the earlier of two instants, treating a zero time as
// "unknown" (the other value wins).
func earliest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case a.Before(b):
		return a
	default:
		return b
	}
}

// latest returns the later of two instants, treating a zero time as
// "unknown" (the other value wins).
func latest(a, b time.Time) time.Time {
	switch {
	case a.IsZero():
		return b
	case b.IsZero():
		return a
	case a.After(b):
		return a
	default:
		return b
	}
}
