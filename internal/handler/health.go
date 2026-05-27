// Package handler holds the HTTP handlers for the SNG control plane.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

// Pinger is anything that can be checked for liveness with a context
// deadline. Postgres pools and NATS connections both satisfy this
// shape via small adapters in the wiring layer.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Health is the HTTP health/readiness handler. It exposes two
// endpoints:
//
//   - /healthz returns 200 as soon as the process is running. It is
//     used by Kubernetes liveness probes — failing this kills the
//     pod. The control plane considers itself "live" as long as the
//     run loop hasn't crashed; dependency outages do not turn it off.
//
//   - /readyz returns 200 only when every registered dependency
//     pings successfully. It is used by readiness probes and by load
//     balancers — failing this drains traffic until dependencies
//     recover, without restarting the pod.
//
// Dependencies are pinged in parallel with a per-check timeout so
// one slow check cannot delay the readiness response. Results are
// reported as a JSON map of name -> {status, error}.
type Health struct {
	timeout time.Duration

	mu    sync.RWMutex
	deps  map[string]Pinger
	start time.Time
}

// NewHealth constructs a Health handler. The per-check timeout
// defaults to 1 second when timeout is <= 0.
func NewHealth(timeout time.Duration) *Health {
	if timeout <= 0 {
		timeout = time.Second
	}
	return &Health{
		timeout: timeout,
		deps:    make(map[string]Pinger),
		start:   time.Now().UTC(),
	}
}

// Register adds (or replaces) a named dependency to be checked by
// /readyz. Name must be non-empty.
func (h *Health) Register(name string, p Pinger) {
	if name == "" || p == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.deps[name] = p
}

// Liveness handles GET /healthz. Always 200 unless the request
// method is unsupported.
func (h *Health) Liveness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	resp := livenessResponse{
		Status: "ok",
		Uptime: time.Since(h.start).Truncate(time.Second).String(),
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
	}
	writeJSON(w, http.StatusOK, resp)
}

// Readiness handles GET /readyz. Returns 200 only when every
// dependency reports OK.
func (h *Health) Readiness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.mu.RLock()
	checks := make(map[string]Pinger, len(h.deps))
	for k, v := range h.deps {
		checks[k] = v
	}
	h.mu.RUnlock()

	results := make(map[string]checkResult, len(checks))
	var wg sync.WaitGroup
	var mu sync.Mutex
	for name, p := range checks {
		wg.Add(1)
		go func(name string, p Pinger) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
			defer cancel()
			err := p.Ping(ctx)
			res := checkResult{Status: "ok"}
			if err != nil {
				res.Status = "error"
				res.Error = err.Error()
			}
			mu.Lock()
			results[name] = res
			mu.Unlock()
		}(name, p)
	}
	wg.Wait()

	overall := http.StatusOK
	status := "ready"
	for _, r := range results {
		if r.Status != "ok" {
			overall = http.StatusServiceUnavailable
			status = "not_ready"
			break
		}
	}
	resp := readinessResponse{
		Status: status,
		Checks: results,
	}
	writeJSON(w, overall, resp)
}

type livenessResponse struct {
	Status string `json:"status"`
	Uptime string `json:"uptime"`
	Time   string `json:"time"`
}

type checkResult struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type readinessResponse struct {
	Status string                 `json:"status"`
	Checks map[string]checkResult `json:"checks"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(body); err != nil {
		// Body has already been partially written; just log via the
		// connection close path. The caller's request log will see
		// a truncated response.
		_ = err
	}
}

// PingerFunc adapts a plain function into the Pinger interface.
type PingerFunc func(ctx context.Context) error

// Ping implements Pinger.
func (f PingerFunc) Ping(ctx context.Context) error { return f(ctx) }

// ErrUnregistered is returned by lookups when a dependency name has
// never been registered. It exists primarily for tests.
var ErrUnregistered = errors.New("dependency not registered")

// Dependency returns the Pinger registered under name, or
// ErrUnregistered.
func (h *Health) Dependency(name string) (Pinger, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	p, ok := h.deps[name]
	if !ok {
		return nil, ErrUnregistered
	}
	return p, nil
}
