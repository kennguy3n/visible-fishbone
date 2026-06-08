package middleware

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// AttemptLimiterConfig configures an AttemptLimiter. It is a plain
// value (not the config.* struct) so the middleware package stays
// decoupled from config and the limiter can be constructed directly in
// tests.
type AttemptLimiterConfig struct {
	// MaxFailures is the number of failures from one IP that trips the
	// cooldown.
	MaxFailures int
	// Cooldown is how long an IP stays locked out after tripping.
	Cooldown time.Duration
	// CleanupInterval is the idle-entry eviction period (default 1m).
	CleanupInterval time.Duration
	// IdleTTL is how long an idle entry is retained (default 10m).
	IdleTTL time.Duration
	// TrustedProxies is the comma-separated reverse-proxy CIDR list used
	// to derive the real client IP from X-Forwarded-For.
	TrustedProxies string
}

// AttemptLimiter is an IP-keyed brute-force guard. It counts failed
// attempts per source IP and, once MaxFailures is reached, locks that
// IP out for Cooldown; a successful attempt clears the IP's counter. A
// background goroutine prunes idle entries so a churn of one-shot IPs
// doesn't grow the map unbounded.
//
// It is deliberately backend-agnostic of WHAT failed: the auth
// middleware feeds it credential-validation failures, and the public
// enrolment endpoint feeds it failed claim-token redemptions, each
// with its own thresholds.
type AttemptLimiter struct {
	maxFailures     int
	cooldown        time.Duration
	cleanupInterval time.Duration
	idleTTL         time.Duration
	trustedProxies  []*net.IPNet
	now             func() time.Time

	mu      sync.Mutex
	entries map[string]*attemptEntry
	stop    chan struct{}
	stopped chan struct{}
}

type attemptEntry struct {
	failures      int
	cooldownUntil time.Time
	lastSeen      time.Time
}

// NewAttemptLimiter constructs a guard and starts its cleanup
// goroutine. Caller is responsible for invoking Close on shutdown.
func NewAttemptLimiter(cfg AttemptLimiterConfig) (*AttemptLimiter, error) {
	proxies, err := parseProxyCIDRs(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	cleanup := cfg.CleanupInterval
	if cleanup <= 0 {
		cleanup = time.Minute
	}
	idle := cfg.IdleTTL
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	l := &AttemptLimiter{
		maxFailures:     cfg.MaxFailures,
		cooldown:        cfg.Cooldown,
		cleanupInterval: cleanup,
		idleTTL:         idle,
		trustedProxies:  proxies,
		now:             time.Now,
		entries:         make(map[string]*attemptEntry),
		stop:            make(chan struct{}),
		stopped:         make(chan struct{}),
	}
	go l.cleanupLoop()
	return l, nil
}

// Close stops the cleanup goroutine. Idempotent.
func (l *AttemptLimiter) Close() {
	select {
	case <-l.stop:
	default:
		close(l.stop)
		<-l.stopped
	}
}

// ClientIP derives the keying IP for r using the configured
// trusted-proxy set (identical logic to the per-IP rate limiter).
func (l *AttemptLimiter) ClientIP(r *http.Request) string {
	return clientIP(r, l.trustedProxies)
}

// Blocked reports whether ip is currently in cooldown and, if so, the
// number of whole seconds (>=1) until it expires — suitable for a
// Retry-After header.
func (l *AttemptLimiter) Blocked(ip string) (retryAfter int, blocked bool) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		return 0, false
	}
	e.lastSeen = now
	if now.Before(e.cooldownUntil) {
		secs := int(e.cooldownUntil.Sub(now).Seconds())
		if secs < 1 {
			secs = 1
		}
		return secs, true
	}
	return 0, false
}

// RecordFailure increments ip's failure counter. When the counter
// reaches MaxFailures the IP enters Cooldown and the counter resets, so
// the next burst must again accumulate MaxFailures to re-trip. Returns
// true when this failure tripped (or extended) the cooldown.
func (l *AttemptLimiter) RecordFailure(ip string) (tripped bool) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[ip]
	if !ok {
		e = &attemptEntry{}
		l.entries[ip] = e
	}
	e.lastSeen = now
	// Already cooling down: keep it locked (extend from now) without
	// further accounting, so a flood during cooldown can't race the
	// counter.
	if now.Before(e.cooldownUntil) {
		e.cooldownUntil = now.Add(l.cooldown)
		return true
	}
	e.failures++
	if e.failures >= l.maxFailures {
		e.cooldownUntil = now.Add(l.cooldown)
		e.failures = 0
		return true
	}
	return false
}

// RecordSuccess clears ip's failure counter and any cooldown. A
// successful authentication / enrolment is proof the source is not
// (currently) brute-forcing, so it starts fresh.
func (l *AttemptLimiter) RecordSuccess(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}

func (l *AttemptLimiter) cleanupLoop() {
	defer close(l.stopped)
	t := time.NewTicker(l.cleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-l.stop:
			return
		case <-t.C:
			l.evictIdle()
		}
	}
}

func (l *AttemptLimiter) evictIdle() {
	now := l.now()
	cutoff := now.Add(-l.idleTTL)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.entries {
		// Keep entries that are still cooling down regardless of
		// lastSeen, so eviction can't prematurely lift a lockout.
		if now.Before(e.cooldownUntil) {
			continue
		}
		if e.lastSeen.Before(cutoff) {
			delete(l.entries, k)
		}
	}
}
