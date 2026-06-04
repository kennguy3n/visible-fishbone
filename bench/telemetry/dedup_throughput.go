package main

import (
	"fmt"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry"
)

// dedup_throughput.go benchmarks the in-memory LRU dedup layer
// (telemetry.LRUDedup) directly. It needs no containers — the dedup is
// pure in-process state — so it produces real measurements in every
// mode, --dry-run or not.

// runDedupThroughput drives telemetry.LRUDedup.SeenOrAdd over a stream
// carrying the configured duplicate fraction and reports the achieved
// ops/sec and the observed dedup hit rate (which should track the
// generator's duplicate rate).
func runDedupThroughput(opts Options) (*Report, error) {
	g := NewGenerator(GenConfig{
		Tenants:       opts.Tenants,
		Seed:          opts.Seed,
		DuplicateRate: opts.DupRate,
	})
	dedup := telemetry.NewLRUDedup(telemetry.DefaultLRUDedupCapacity)

	n := opts.Samples
	start := time.Now()
	for i := 0; i < n; i++ {
		env := g.Next()
		dedup.SeenOrAdd(telemetry.DedupKey{
			DeviceID: env.DeviceID,
			EventID:  env.EventID,
		})
	}
	elapsed := time.Since(start)
	st := dedup.Stats()

	var opsPerSec, hitRate float64
	if elapsed > 0 {
		opsPerSec = float64(n) / elapsed.Seconds()
	}
	if n > 0 {
		hitRate = float64(st.Hits) / float64(n)
	}

	r := NewReport("dedup-throughput", nowUnix(), opts.GitSHA, opts.DryRun)
	r.AddSection(Section{
		Title:   "LRU dedup throughput",
		Summary: fmt.Sprintf("SeenOrAdd over %d events at %.0f%% synthetic duplicates, capacity %d.", n, opts.DupRate*100, st.Capacity),
		Metrics: []MetricRow{
			{
				Name: "dedup throughput", Unit: "ops/sec",
				Actual: opsPerSec, Verdict: VerdictInfo,
				Note: "single-goroutine SeenOrAdd; the consumer fans out under RLock on the read path",
			},
			{
				Name: "observed hit rate", Unit: "fraction",
				Actual:      hitRate,
				Theoretical: ptr(opts.DupRate),
				Verdict:     classify(hitRate, ptr(opts.DupRate), true, 0.25),
				Note:        "should track --dup-rate; capacity-bound eviction lowers it when the working set exceeds capacity",
			},
			{Name: "evicted", Unit: "entries", Actual: float64(st.Evicted), Verdict: VerdictInfo},
			{Name: "resident entries", Unit: "entries", Actual: float64(st.Len), Verdict: VerdictInfo},
		},
	})
	r.AddCaveat("Dedup throughput is a single-goroutine in-process measurement; production fans out concurrent SeenOrAdd callers under an RWMutex read lock.")
	if hitRate < opts.DupRate*0.75 {
		r.AddCaveat("Observed hit rate fell below the synthetic duplicate rate: the duplicate working set exceeded the LRU capacity, so some duplicates were evicted before their replay. Raise capacity or lower --tenants to keep the working set resident.")
	}
	return r, nil
}
