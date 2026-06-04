package main

import (
	"math"
	"sort"
	"sync"
	"time"
)

// latencyRecorder accumulates per-request latency samples and request
// outcomes for one endpoint, then folds them into an EndpointLatency.
//
// It is safe for concurrent use: the api-latency workload fans out
// across many goroutines that all record into the same recorder. The
// percentile maths is exact (sorts the captured samples) rather than a
// streaming estimate — the control-plane workloads measure thousands,
// not billions, of requests, so the memory is bounded and the exactness
// is worth more than the allocation saved by a histogram.
type latencyRecorder struct {
	method string
	route  string

	mu       sync.Mutex
	samples  []time.Duration
	count    int64
	errors   int64
	totalDur time.Duration
}

func newLatencyRecorder(method, route string) *latencyRecorder {
	return &latencyRecorder{method: method, route: route}
}

// record captures one request's latency and whether it failed.
func (r *latencyRecorder) record(d time.Duration, failed bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.samples = append(r.samples, d)
	r.count++
	r.totalDur += d
	if failed {
		r.errors++
	}
}

// finish folds the recorder into an EndpointLatency over a measurement
// window of `elapsed`. RequestsPerSec is computed against wall-clock
// elapsed so it reflects achieved throughput, not the sum of per-
// request service times.
func (r *latencyRecorder) finish(elapsed time.Duration) EndpointLatency {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := EndpointLatency{
		Method: r.method,
		Route:  r.route,
		Count:  r.count,
		Errors: r.errors,
	}
	if elapsed > 0 {
		out.RequestsPerSec = float64(r.count) / elapsed.Seconds()
	}
	out.P50Ms = percentileMs(r.samples, 50)
	out.P95Ms = percentileMs(r.samples, 95)
	out.P99Ms = percentileMs(r.samples, 99)
	out.MaxMs = percentileMs(r.samples, 100)
	return out
}

// percentileMs returns the p-th percentile (0..100) of the samples in
// milliseconds, using the nearest-rank method. Returns 0 for an empty
// set. The input slice is copied before sorting so callers' ordering is
// preserved.
func percentileMs(samples []time.Duration, p float64) float64 {
	if len(samples) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(samples))
	copy(sorted, samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	// Nearest-rank: rank = ceil(p/100 * N), clamped to [1, N].
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return float64(sorted[rank-1].Nanoseconds()) / 1e6
}

// aggregateTier folds a set of per-endpoint recorders into an
// APILatencyTier. The overall p99 is computed across the union of every
// endpoint's samples (not an average of per-endpoint p99s, which would
// understate the tail). The error rate is total errors / total count.
func aggregateTier(tenantCount, durationSecs, concurrency int, elapsed time.Duration, recorders []*latencyRecorder) APILatencyTier {
	tier := APILatencyTier{
		TenantCount:  tenantCount,
		DurationSecs: durationSecs,
		Concurrency:  concurrency,
		Endpoints:    make([]EndpointLatency, 0, len(recorders)),
	}
	var all []time.Duration
	var totalCount, totalErrors int64
	for _, rec := range recorders {
		tier.Endpoints = append(tier.Endpoints, rec.finish(elapsed))
		rec.mu.Lock()
		all = append(all, rec.samples...)
		totalCount += rec.count
		totalErrors += rec.errors
		rec.mu.Unlock()
	}
	tier.OverallP99Ms = percentileMs(all, 99)
	if elapsed > 0 {
		tier.OverallRequestsPerSec = float64(totalCount) / elapsed.Seconds()
	}
	if totalCount > 0 {
		tier.ErrorRate = float64(totalErrors) / float64(totalCount)
	}
	return tier
}
