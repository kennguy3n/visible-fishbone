package identity

import (
	"testing"
	"time"
)

// TestNextFetchBackoff pins the capped-exponential contract the Run
// loop relies on to avoid busy-spinning on a persistent Fetch error:
// the first failure waits the base delay, each subsequent failure
// doubles, and the delay is clamped at the ceiling.
func TestNextFetchBackoff(t *testing.T) {
	t.Parallel()

	// First failure (no prior backoff) starts at the base.
	if got := nextFetchBackoff(0); got != fetchErrBackoffBase {
		t.Fatalf("first backoff = %v, want %v", got, fetchErrBackoffBase)
	}

	// Subsequent failures double until they reach the ceiling, then
	// stay pinned there no matter how many more failures occur.
	prev := nextFetchBackoff(0)
	var sawMax bool
	for i := 0; i < 12; i++ {
		next := nextFetchBackoff(prev)
		if next < prev {
			t.Fatalf("backoff decreased: %v -> %v", prev, next)
		}
		if next > fetchErrBackoffMax {
			t.Fatalf("backoff %v exceeded ceiling %v", next, fetchErrBackoffMax)
		}
		if !sawMax && next != fetchErrBackoffMax {
			// Before the ceiling each step must be a clean doubling.
			if next != prev*2 {
				t.Fatalf("backoff step %v -> %v is not a doubling", prev, next)
			}
		}
		if next == fetchErrBackoffMax {
			sawMax = true
		}
		prev = next
	}
	if !sawMax {
		t.Fatalf("backoff never reached ceiling %v", fetchErrBackoffMax)
	}

	// Once at the ceiling it is idempotent.
	if got := nextFetchBackoff(fetchErrBackoffMax); got != fetchErrBackoffMax {
		t.Fatalf("backoff at ceiling = %v, want %v", got, fetchErrBackoffMax)
	}
	// A backoff already above the ceiling (defensive) clamps down.
	if got := nextFetchBackoff(fetchErrBackoffMax + time.Second); got != fetchErrBackoffMax {
		t.Fatalf("over-ceiling backoff = %v, want %v", got, fetchErrBackoffMax)
	}
}
