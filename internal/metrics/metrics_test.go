package metrics

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

func newTestMetrics(t *testing.T) *Metrics {
	t.Helper()
	return New(config.Metrics{Enabled: true, Port: 9090, Namespace: "sng"})
}

func TestNewRegistersNamespacedMetrics(t *testing.T) {
	m := newTestMetrics(t)
	if got := m.Namespace(); got != "sng" {
		t.Fatalf("Namespace() = %q, want sng", got)
	}
	// Touch a metric so it appears in the exposition, then confirm
	// the namespaced name is present.
	m.HTTPRequestsInFlight.Set(0)
	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	want := "sng_http_requests_in_flight"
	found := false
	for _, mf := range mfs {
		if mf.GetName() == want {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("metric %q not found in exposition", want)
	}
}

func TestNewEmptyNamespaceDefaults(t *testing.T) {
	m := New(config.Metrics{Enabled: true})
	if got := m.Namespace(); got != "sng" {
		t.Errorf("Namespace() = %q, want sng (default)", got)
	}
}

func TestMiddlewareRecordsRequest(t *testing.T) {
	m := newTestMetrics(t)
	h := m.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/123/devices", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	// Path 123 collapses to :id; status recorded exactly on the
	// counter and by class on the histogram.
	if got := testutil.ToFloat64(m.HTTPRequestsTotal.WithLabelValues("GET", "/api/v1/tenants/:id/devices", "418")); got != 1 {
		t.Errorf("requests_total = %v, want 1", got)
	}
	if got := testutil.CollectAndCount(m.HTTPRequestDuration); got == 0 {
		t.Error("request_duration histogram recorded no observations")
	}
}

func TestNilMiddlewareIsPassThrough(t *testing.T) {
	var m *Metrics
	called := false
	h := m.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Error("nil-metrics middleware did not call next handler")
	}
}

func TestStatusClass(t *testing.T) {
	cases := map[int]string{
		100: "1xx", 200: "2xx", 204: "2xx", 301: "3xx",
		404: "4xx", 418: "4xx", 500: "5xx", 503: "5xx",
		0: "unknown", 600: "unknown",
	}
	for code, want := range cases {
		if got := statusClass(code); got != want {
			t.Errorf("statusClass(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestNormalizePath(t *testing.T) {
	cases := map[string]string{
		"":                   "",
		"/":                  "/",
		"/api/v1/health":     "/api/v1/health",
		"/api/v1/tenants/42": "/api/v1/tenants/:id",
		"/api/v1/devices/0":  "/api/v1/devices/:id",
		"/api/v1/tenants/9f8b2c1d-1234-4567-89ab-0123456789ab/sites": "/api/v1/tenants/:id/sites",
		"/api/v1/tenants/not-a-uuid":                                 "/api/v1/tenants/not-a-uuid",
	}
	for in, want := range cases {
		if got := normalizePath(in); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPGCollectorRecord(t *testing.T) {
	m := newTestMetrics(t)
	c := NewPGCollector(m, nil, 0)

	// First snapshot establishes the acquire baseline; the counter
	// should jump by the full cumulative value on first record.
	c.record(10, 3, 20)
	if got := testutil.ToFloat64(m.PGPoolAcquired); got != 10 {
		t.Errorf("pool_acquired_total = %v, want 10", got)
	}
	if got := testutil.ToFloat64(m.PGPoolIdle); got != 3 {
		t.Errorf("pool_idle = %v, want 3", got)
	}
	if got := testutil.ToFloat64(m.PGPoolMax); got != 20 {
		t.Errorf("pool_max = %v, want 20", got)
	}

	// A higher cumulative value adds only the delta.
	c.record(14, 1, 20)
	if got := testutil.ToFloat64(m.PGPoolAcquired); got != 14 {
		t.Errorf("pool_acquired_total = %v, want 14", got)
	}

	// A backwards value (pool recreated) rebaselines without
	// emitting a negative delta — the counter holds steady.
	c.record(2, 5, 20)
	if got := testutil.ToFloat64(m.PGPoolAcquired); got != 14 {
		t.Errorf("pool_acquired_total = %v, want 14 after rebaseline", got)
	}
	if got := testutil.ToFloat64(m.PGPoolIdle); got != 5 {
		t.Errorf("pool_idle = %v, want 5", got)
	}

	// Subsequent growth resumes from the new baseline (2 -> 6 = +4).
	c.record(6, 0, 20)
	if got := testutil.ToFloat64(m.PGPoolAcquired); got != 18 {
		t.Errorf("pool_acquired_total = %v, want 18", got)
	}
}

func TestConsumerLag(t *testing.T) {
	if got := consumerLag(nil); got != 0 {
		t.Errorf("consumerLag(nil) = %d, want 0", got)
	}
	info := &jetstream.ConsumerInfo{NumPending: 100, NumAckPending: 25}
	if got := consumerLag(info); got != 125 {
		t.Errorf("consumerLag = %d, want 125 (100 pending + 25 ack-pending)", got)
	}
}
