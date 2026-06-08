package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestAttemptLimiter(t *testing.T, cfg AttemptLimiterConfig) (*AttemptLimiter, func(time.Duration)) {
	t.Helper()
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = time.Hour // disable background churn in tests
	}
	if cfg.IdleTTL == 0 {
		cfg.IdleTTL = 10 * time.Minute
	}
	l, err := NewAttemptLimiter(cfg)
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	clock, advance := newTestClock(time.Unix(1_700_000_000, 0))
	l.now = clock
	return l, advance
}

// TestNewAttemptLimiter_RejectsNonPositiveConfig asserts the guard is
// self-validating: a non-positive MaxFailures (would trip on the first
// attempt) or Cooldown (would never lock out) is rejected at
// construction rather than silently defeating the control.
func TestNewAttemptLimiter_RejectsNonPositiveConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  AttemptLimiterConfig
	}{
		{"zero max failures", AttemptLimiterConfig{MaxFailures: 0, Cooldown: time.Second}},
		{"negative max failures", AttemptLimiterConfig{MaxFailures: -1, Cooldown: time.Second}},
		{"zero cooldown", AttemptLimiterConfig{MaxFailures: 5, Cooldown: 0}},
		{"negative cooldown", AttemptLimiterConfig{MaxFailures: 5, Cooldown: -time.Second}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			l, err := NewAttemptLimiter(tc.cfg)
			if err == nil {
				l.Close()
				t.Fatalf("NewAttemptLimiter(%+v) = nil error, want validation error", tc.cfg)
			}
		})
	}
}

func TestAttemptLimiter_LocksOutAfterThreshold(t *testing.T) {
	t.Parallel()
	l, _ := newTestAttemptLimiter(t, AttemptLimiterConfig{MaxFailures: 5, Cooldown: 30 * time.Second})
	defer l.Close()

	const ip = "203.0.113.7"
	// Four failures stay under the threshold: not blocked yet.
	for i := 0; i < 4; i++ {
		if tripped := l.RecordFailure(ip); tripped {
			t.Fatalf("failure %d tripped early", i+1)
		}
		if _, blocked := l.Blocked(ip); blocked {
			t.Fatalf("blocked after only %d failures", i+1)
		}
	}
	// Fifth failure trips the cooldown.
	if tripped := l.RecordFailure(ip); !tripped {
		t.Fatal("5th failure did not trip cooldown")
	}
	retryAfter, blocked := l.Blocked(ip)
	if !blocked {
		t.Fatal("IP not blocked after reaching threshold")
	}
	if retryAfter < 1 || retryAfter > 30 {
		t.Errorf("retryAfter = %d, want within (0,30]", retryAfter)
	}
}

func TestAttemptLimiter_CooldownExpires(t *testing.T) {
	t.Parallel()
	l, advance := newTestAttemptLimiter(t, AttemptLimiterConfig{MaxFailures: 2, Cooldown: 30 * time.Second})
	defer l.Close()

	const ip = "203.0.113.8"
	l.RecordFailure(ip)
	l.RecordFailure(ip)
	if _, blocked := l.Blocked(ip); !blocked {
		t.Fatal("not blocked after threshold")
	}
	// Still locked just before expiry.
	advance(29 * time.Second)
	if _, blocked := l.Blocked(ip); !blocked {
		t.Fatal("unblocked too early")
	}
	// Past the cooldown the IP is free again.
	advance(2 * time.Second)
	if _, blocked := l.Blocked(ip); blocked {
		t.Fatal("still blocked after cooldown expired")
	}
}

func TestAttemptLimiter_SuccessResetsCounter(t *testing.T) {
	t.Parallel()
	l, _ := newTestAttemptLimiter(t, AttemptLimiterConfig{MaxFailures: 3, Cooldown: 30 * time.Second})
	defer l.Close()

	const ip = "203.0.113.9"
	l.RecordFailure(ip)
	l.RecordFailure(ip)
	// A success wipes the accumulated failures.
	l.RecordSuccess(ip)
	// Two more failures should NOT trip (counter restarted from 0).
	if tripped := l.RecordFailure(ip); tripped {
		t.Fatal("tripped after success reset (1st)")
	}
	if tripped := l.RecordFailure(ip); tripped {
		t.Fatal("tripped after success reset (2nd)")
	}
	if _, blocked := l.Blocked(ip); blocked {
		t.Fatal("blocked despite success reset")
	}
}

func TestAttemptLimiter_PerIPIsolation(t *testing.T) {
	t.Parallel()
	l, _ := newTestAttemptLimiter(t, AttemptLimiterConfig{MaxFailures: 2, Cooldown: 30 * time.Second})
	defer l.Close()

	const victim = "198.51.100.1"
	const other = "198.51.100.2"
	l.RecordFailure(victim)
	l.RecordFailure(victim)
	if _, blocked := l.Blocked(victim); !blocked {
		t.Fatal("victim IP not blocked")
	}
	// A different IP is unaffected.
	if _, blocked := l.Blocked(other); blocked {
		t.Fatal("unrelated IP wrongly blocked")
	}
}

func TestAttemptLimiter_FloodDuringCooldownIsFixedWindow(t *testing.T) {
	t.Parallel()
	l, advance := newTestAttemptLimiter(t, AttemptLimiterConfig{MaxFailures: 2, Cooldown: 30 * time.Second})
	defer l.Close()

	const ip = "203.0.113.10"
	l.RecordFailure(ip)
	l.RecordFailure(ip) // trips: cooldownUntil = t0+30s
	// A failure mid-cooldown still reports locked but must NOT push the
	// unlock time out — the window is fixed from when it tripped.
	advance(10 * time.Second)
	if tripped := l.RecordFailure(ip); !tripped {
		t.Fatal("failure during cooldown should report tripped/locked")
	}
	if _, blocked := l.Blocked(ip); !blocked {
		t.Fatal("IP should still be locked 10s into a 30s cooldown")
	}
	// Past the original 30s window (t=10+25=35s > 30s) the IP is released
	// despite the flood — a persistent retrier is not locked out forever.
	advance(25 * time.Second)
	if _, blocked := l.Blocked(ip); blocked {
		t.Fatal("cooldown should expire on its fixed schedule, not be extended by a flood")
	}
}

func TestAttemptLimiter_EvictIdle(t *testing.T) {
	t.Parallel()
	l, advance := newTestAttemptLimiter(t, AttemptLimiterConfig{
		MaxFailures: 5, Cooldown: 30 * time.Second, IdleTTL: time.Minute,
	})
	defer l.Close()

	const ip = "203.0.113.11"
	l.RecordFailure(ip)
	l.mu.Lock()
	n := len(l.entries)
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("entry count = %d, want 1", n)
	}
	advance(2 * time.Minute)
	l.evictIdle()
	l.mu.Lock()
	n = len(l.entries)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("entry count after evict = %d, want 0", n)
	}
}

func TestAttemptLimiter_ClientIPTrustedProxy(t *testing.T) {
	t.Parallel()
	l, _ := newTestAttemptLimiter(t, AttemptLimiterConfig{
		MaxFailures: 5, Cooldown: 30 * time.Second, TrustedProxies: "10.0.0.0/8",
	})
	defer l.Close()

	// From a trusted proxy, the real client is taken from XFF.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", nil)
	req.RemoteAddr = "10.1.2.3:443"
	req.Header.Set("X-Forwarded-For", "203.0.113.20")
	if got := l.ClientIP(req); got != "203.0.113.20" {
		t.Errorf("ClientIP via trusted proxy = %q, want 203.0.113.20", got)
	}

	// From an untrusted source, XFF is ignored and RemoteAddr wins.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", nil)
	req2.RemoteAddr = "203.0.113.30:443"
	req2.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := l.ClientIP(req2); got != "203.0.113.30" {
		t.Errorf("ClientIP from untrusted source = %q, want 203.0.113.30", got)
	}
}
