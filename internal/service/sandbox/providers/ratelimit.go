package providers

import (
	"context"
	"sync"
	"time"
)

// rateLimiter enforces a minimum interval between operations so a
// free-tier reputation API (VirusTotal: 4 req/min; Hybrid Analysis:
// a few req/min) is not tripped into HTTP 429. It is a single-token
// pacing gate, not a burst bucket: each acquire is admitted no
// sooner than `interval` after the previous admission.
//
// It is context-aware — a caller whose context is cancelled while
// waiting for its slot returns ctx.Err() instead of blocking — and
// safe for concurrent use. A zero/negative interval disables pacing
// (every acquire is admitted immediately), which is what tests and
// paid tiers want.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	now      func() time.Time
	sleep    func(ctx context.Context, d time.Duration) error
}

func newRateLimiter(interval time.Duration) *rateLimiter {
	return &rateLimiter{
		interval: interval,
		now:      time.Now,
		sleep:    contextSleep,
	}
}

// acquire blocks until the caller may proceed or ctx is done. It
// reserves the slot under the lock (advancing `next`) before
// sleeping, so concurrent callers are serialised onto distinct,
// monotonically increasing slots rather than all waking at once.
func (r *rateLimiter) acquire(ctx context.Context) error {
	if r == nil || r.interval <= 0 {
		// No pacing configured — still honour a cancelled context.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}

	r.mu.Lock()
	now := r.now()
	slot := r.next
	if slot.Before(now) {
		slot = now
	}
	r.next = slot.Add(r.interval)
	r.mu.Unlock()

	wait := slot.Sub(now)
	if wait <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	if err := r.sleep(ctx, wait); err != nil {
		// Caller is abandoning its slot; pull `next` back so the
		// reserved-but-unused slot does not permanently skew pacing.
		r.mu.Lock()
		r.next = r.next.Add(-r.interval)
		r.mu.Unlock()
		return err
	}
	return nil
}

// contextSleep sleeps for d unless ctx is cancelled first.
func contextSleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
