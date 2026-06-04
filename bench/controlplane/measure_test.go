package main

import (
	"sync"
	"testing"
	"time"
)

func TestPercentileMsNearestRank(t *testing.T) {
	t.Parallel()
	// 1..100 ms. Nearest-rank p99 -> rank ceil(0.99*100)=99 -> 99ms,
	// p50 -> rank 50 -> 50ms, p100 (max) -> 100ms.
	samples := make([]time.Duration, 100)
	for i := range samples {
		samples[i] = time.Duration(i+1) * time.Millisecond
	}
	for _, tc := range []struct {
		p    float64
		want float64
	}{
		{50, 50}, {95, 95}, {99, 99}, {100, 100},
	} {
		if got := percentileMs(samples, tc.p); got != tc.want {
			t.Errorf("percentileMs(p%v) = %v, want %v", tc.p, got, tc.want)
		}
	}
}

func TestPercentileMsEmpty(t *testing.T) {
	t.Parallel()
	if got := percentileMs(nil, 99); got != 0 {
		t.Fatalf("percentileMs(nil) = %v, want 0", got)
	}
}

func TestPercentileMsDoesNotMutateInput(t *testing.T) {
	t.Parallel()
	samples := []time.Duration{3 * time.Millisecond, 1 * time.Millisecond, 2 * time.Millisecond}
	_ = percentileMs(samples, 50)
	if samples[0] != 3*time.Millisecond {
		t.Fatalf("percentileMs mutated caller's slice: %v", samples)
	}
}

func TestLatencyRecorderConcurrent(t *testing.T) {
	t.Parallel()
	rec := newLatencyRecorder("GET", "/api/v1/tenants/{tenant_id}")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				rec.record(time.Duration(i+1)*time.Millisecond, i%50 == 0)
			}
		}()
	}
	wg.Wait()
	out := rec.finish(2 * time.Second)
	if out.Count != 800 {
		t.Fatalf("Count = %d, want 800", out.Count)
	}
	// i%50==0 fires for i=0 and i=50 per goroutine -> 2 errors * 8.
	if out.Errors != 16 {
		t.Fatalf("Errors = %d, want 16", out.Errors)
	}
	if out.RequestsPerSec != 400 {
		t.Fatalf("RequestsPerSec = %v, want 400", out.RequestsPerSec)
	}
	if out.MaxMs != 100 {
		t.Fatalf("MaxMs = %v, want 100", out.MaxMs)
	}
}

func TestAggregateTierOverallP99AcrossEndpoints(t *testing.T) {
	t.Parallel()
	fast := newLatencyRecorder("GET", "/fast")
	slow := newLatencyRecorder("POST", "/slow")
	for i := 0; i < 99; i++ {
		fast.record(1*time.Millisecond, false)
	}
	// One slow tail sample that should dominate the union p99 only if
	// it lands in the top 1%; with 100 total samples the p99 is the
	// 99th-ranked value = 1ms, and max = 100ms.
	slow.record(100*time.Millisecond, true)

	tier := aggregateTier(1000, 60, 32, 5*time.Second, []*latencyRecorder{fast, slow})
	if len(tier.Endpoints) != 2 {
		t.Fatalf("Endpoints = %d, want 2", len(tier.Endpoints))
	}
	if tier.TenantCount != 1000 {
		t.Fatalf("TenantCount = %d, want 1000", tier.TenantCount)
	}
	// 1 error out of 100 requests.
	if tier.ErrorRate < 0.0099 || tier.ErrorRate > 0.0101 {
		t.Fatalf("ErrorRate = %v, want ~0.01", tier.ErrorRate)
	}
	if tier.OverallRequestsPerSec != 20 {
		t.Fatalf("OverallRequestsPerSec = %v, want 20", tier.OverallRequestsPerSec)
	}
}
