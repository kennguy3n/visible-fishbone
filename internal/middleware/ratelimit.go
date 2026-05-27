package middleware

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// RateLimiter is the per-IP token-bucket limiter. Buckets are
// created on demand and pruned by a background goroutine after
// `IdleTTL` of inactivity so a flood of one-shot IPs doesn't grow
// the map unbounded.
type RateLimiter struct {
	cfg            *config.RateLimit
	trustedProxies []*net.IPNet

	mu      sync.Mutex
	buckets map[string]*bucketEntry
	stop    chan struct{}
	stopped chan struct{}
}

type bucketEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter constructs a limiter and starts the cleanup
// goroutine. Caller is responsible for invoking Close on shutdown.
func NewRateLimiter(cfg *config.RateLimit) (*RateLimiter, error) {
	proxies, err := parseProxyCIDRs(cfg.TrustedProxies)
	if err != nil {
		return nil, err
	}
	rl := &RateLimiter{
		cfg:            cfg,
		trustedProxies: proxies,
		buckets:        make(map[string]*bucketEntry),
		stop:           make(chan struct{}),
		stopped:        make(chan struct{}),
	}
	go rl.cleanupLoop()
	return rl, nil
}

// Close stops the cleanup goroutine. Idempotent.
func (rl *RateLimiter) Close() {
	select {
	case <-rl.stop:
	default:
		close(rl.stop)
		<-rl.stopped
	}
}

// Middleware returns the HTTP middleware. When the limiter is
// disabled (RATE_LIMIT_ENABLED=false) it is a pass-through.
func (rl *RateLimiter) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !rl.cfg.Enabled {
				next.ServeHTTP(w, r)
				return
			}
			ip := rl.clientIP(r)
			if !rl.allow(ip) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":{"code":"rate_limited","message":"rate limit exceeded"}}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// allow consumes a token and reports whether the request may proceed.
func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.buckets[key]
	if !ok {
		b = &bucketEntry{
			limiter: rate.NewLimiter(rate.Limit(rl.cfg.Rate), rl.cfg.Burst),
		}
		rl.buckets[key] = b
	}
	b.lastSeen = time.Now()
	return b.limiter.Allow()
}

// clientIP returns the source IP, honouring X-Forwarded-For only if
// r.RemoteAddr falls inside a configured trusted-proxy CIDR.
func (rl *RateLimiter) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if len(rl.trustedProxies) == 0 {
		return host
	}
	remote := net.ParseIP(host)
	if remote == nil {
		return host
	}
	if !ipInAny(remote, rl.trustedProxies) {
		return host
	}
	// Pick the right-most non-trusted entry from XFF — that's the
	// last hop before the trusted chain.
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	parts := strings.Split(xff, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if p == "" {
			continue
		}
		ip := net.ParseIP(p)
		if ip == nil {
			continue
		}
		if !ipInAny(ip, rl.trustedProxies) {
			return p
		}
	}
	return host
}

// cleanupLoop prunes idle buckets.
func (rl *RateLimiter) cleanupLoop() {
	defer close(rl.stopped)
	interval := rl.cfg.CleanupInterval
	if interval <= 0 {
		interval = time.Minute
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-rl.stop:
			return
		case <-t.C:
			rl.evictIdle()
		}
	}
}

func (rl *RateLimiter) evictIdle() {
	cutoff := time.Now().Add(-rl.cfg.IdleTTL)
	rl.mu.Lock()
	defer rl.mu.Unlock()
	for k, b := range rl.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(rl.buckets, k)
		}
	}
}

// parseProxyCIDRs parses a comma-separated list of CIDR ranges.
func parseProxyCIDRs(raw string) ([]*net.IPNet, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var out []*net.IPNet
	for _, part := range strings.Split(raw, ",") {
		s := strings.TrimSpace(part)
		if s == "" {
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
