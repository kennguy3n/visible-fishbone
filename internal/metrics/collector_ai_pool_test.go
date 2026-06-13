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
		name  string
		gauge prometheus.Gauge
		want  float64
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
		if got := testutil.ToFloat64(c.gauge); got != c.want {
			t.Errorf("%s = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestAIPoolCollectorNilSourceIsNoop verifies Run returns immediately
// (no panic) when the source is nil, matching the unconditional wiring
// when the pool is disabled.
func TestAIPoolCollectorNilSourceIsNoop(t *testing.T) {
	m := newTestMetrics(t)
	NewAIPoolCollector(m, nil, 0).Run(context.Background())
}
