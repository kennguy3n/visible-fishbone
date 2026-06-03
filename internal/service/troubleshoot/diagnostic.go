package troubleshoot

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot/checks"
)

// DefaultDiagnosticCacheTTL is how long RunAll reuses a tenant's last
// diagnostic sweep before re-running. It bounds the cost of chatty
// sessions on large fleets while staying fresh enough to reflect fixes
// made mid-session. RunCheck (the explicit /diagnostics/{check} endpoint)
// is never cached, so on-demand refresh is always live.
const DefaultDiagnosticCacheTTL = 30 * time.Second

// DiagnosticEngine runs diagnostic checks against tenant state.
type DiagnosticEngine struct {
	registry map[string]checks.DiagnosticCheck

	cacheTTL time.Duration
	clock    func() time.Time

	mu    sync.Mutex
	cache map[uuid.UUID]diagCacheEntry
}

type diagCacheEntry struct {
	results []DiagnosticResult
	at      time.Time
}

// NewDiagnosticEngine creates a diagnostic engine with the provided checks
// and the default RunAll cache TTL.
func NewDiagnosticEngine(diagnosticChecks []checks.DiagnosticCheck) *DiagnosticEngine {
	reg := make(map[string]checks.DiagnosticCheck, len(diagnosticChecks))
	for _, c := range diagnosticChecks {
		reg[c.Name()] = c
	}
	return &DiagnosticEngine{
		registry: reg,
		cacheTTL: DefaultDiagnosticCacheTTL,
		clock:    nowFunc,
		cache:    make(map[uuid.UUID]diagCacheEntry),
	}
}

// SetCacheTTL overrides the RunAll cache TTL. A value <= 0 disables
// caching (every RunAll re-runs the checks).
func (e *DiagnosticEngine) SetCacheTTL(ttl time.Duration) { e.cacheTTL = ttl }

// SetClock overrides the time source used for cache expiry (for tests).
func (e *DiagnosticEngine) SetClock(fn func() time.Time) { e.clock = fn }

// RunAll executes every registered diagnostic check and returns
// all results sorted by check name for deterministic ordering. Results
// are cached per tenant for cacheTTL; within that window a cached copy
// is returned without re-running the checks.
func (e *DiagnosticEngine) RunAll(ctx context.Context, tenantID uuid.UUID) []DiagnosticResult {
	now := e.clock()
	if e.cacheTTL > 0 {
		e.mu.Lock()
		ent, ok := e.cache[tenantID]
		e.mu.Unlock()
		if ok && now.Sub(ent.at) < e.cacheTTL {
			return cloneResults(ent.results)
		}
	}

	names := make([]string, 0, len(e.registry))
	for name := range e.registry {
		names = append(names, name)
	}
	sort.Strings(names)
	results := make([]DiagnosticResult, 0, len(names))
	for _, name := range names {
		r := e.registry[name].Run(ctx, tenantID)
		results = append(results, toServiceResult(r))
	}

	if e.cacheTTL > 0 {
		e.mu.Lock()
		e.cache[tenantID] = diagCacheEntry{results: cloneResults(results), at: now}
		e.mu.Unlock()
	}
	return results
}

// cloneResults returns a shallow copy of the slice so a cached entry is
// never aliased with a returned slice (Details RawMessage is read-only).
func cloneResults(in []DiagnosticResult) []DiagnosticResult {
	if in == nil {
		return nil
	}
	out := make([]DiagnosticResult, len(in))
	copy(out, in)
	return out
}

// RunCheck executes a single diagnostic check by name.
func (e *DiagnosticEngine) RunCheck(ctx context.Context, tenantID uuid.UUID, checkName string) (DiagnosticResult, error) {
	c, ok := e.registry[checkName]
	if !ok {
		return DiagnosticResult{}, fmt.Errorf("unknown diagnostic check %q", checkName)
	}
	r := c.Run(ctx, tenantID)
	return toServiceResult(r), nil
}

// ListChecks returns the names of all registered checks.
func (e *DiagnosticEngine) ListChecks() []string {
	names := make([]string, 0, len(e.registry))
	for name := range e.registry {
		names = append(names, name)
	}
	return names
}

func toServiceResult(r checks.DiagnosticResult) DiagnosticResult {
	return DiagnosticResult{
		CheckName:  r.CheckName,
		Status:     DiagnosticStatus(r.Status),
		Message:    r.Message,
		Details:    r.Details,
		ExecutedAt: r.ExecutedAt,
	}
}
