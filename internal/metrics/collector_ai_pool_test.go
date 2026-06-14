package metrics

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAIPoolCollectorRecordsSnapshot(t *testing.T) {
	m := newTestMetrics(t)
	c := NewAIPoolCollector(m, nil, 0)
	c.record(AIPoolSnapshot{
		Inflight:     3,
		PeakInflight: 4,
		Queued:       5,
		PeakQueued:   9,
		Admitted:     100,
		Completed:    97,
		Errors:       2,
		Rejected:     6,
		WaitTimeouts: 1,
		Cancelled:    4,
		AvgWaitMS:    12.5,
	})

	checks := []struct {
		name string
		coll prometheus.Collector
		want float64
	}{
		{"inflight", m.AIPoolInflight, 3},
		{"peak_inflight", m.AIPoolPeakInflight, 4},
		{"queued", m.AIPoolQueued, 5},
		{"peak_queued", m.AIPoolPeakQueued, 9},
		{"admitted", m.AIPoolAdmitted, 100},
		{"completed", m.AIPoolCompleted, 97},
		{"errors", m.AIPoolErrors, 2},
		{"rejected", m.AIPoolRejected, 6},
		{"wait_timeouts", m.AIPoolWaitTimeouts, 1},
		{"cancelled", m.AIPoolCancelled, 4},
		{"avg_wait_ms", m.AIPoolAvgWaitMS, 12.5},
	}
	for _, c := range checks {
		if got := testutil.ToFloat64(c.coll); got != c.want {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAIPoolCollectorCountersTrackCumulativeDeltas verifies the
// cumulative-total counters advance by the per-scrape delta of the
// pool's process-cumulative snapshot (not by the raw value each scrape),
// and that a backwards jump (pool recreated) re-baselines instead of
// emitting a negative delta.
func TestAIPoolCollectorCountersTrackCumulativeDeltas(t *testing.T) {
	m := newTestMetrics(t)
	c := NewAIPoolCollector(m, nil, 0)

	c.record(AIPoolSnapshot{Admitted: 100, Completed: 97})
	c.record(AIPoolSnapshot{Admitted: 150, Completed: 145})
	if got := testutil.ToFloat64(m.AIPoolAdmitted); got != 150 {
		t.Errorf("admitted after delta = %v, want 150", got)
	}
	if got := testutil.ToFloat64(m.AIPoolCompleted); got != 145 {
		t.Errorf("completed after delta = %v, want 145", got)
	}

	// Source reset (e.g. pool recreated): counter must not go backwards;
	// it re-baselines and only advances on subsequent growth.
	c.record(AIPoolSnapshot{Admitted: 5, Completed: 5})
	c.record(AIPoolSnapshot{Admitted: 12, Completed: 11})
	if got := testutil.ToFloat64(m.AIPoolAdmitted); got != 157 {
		t.Errorf("admitted after reset+7 = %v, want 157", got)
	}
	if got := testutil.ToFloat64(m.AIPoolCompleted); got != 151 {
		t.Errorf("completed after reset+6 = %v, want 151", got)
	}
}

// TestAIPoolCollectorNilSourceIsNoop verifies Run returns immediately
// (no panic) when the source is nil, matching the unconditional wiring
// when the pool is disabled.
func TestAIPoolCollectorNilSourceIsNoop(t *testing.T) {
	m := newTestMetrics(t)
	NewAIPoolCollector(m, nil, 0).Run(context.Background())
}
