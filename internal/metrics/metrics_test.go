package metrics

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/service/activity"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

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

// TestNATSCollectorPrunesStaleSeries verifies the churn-cleanup
// logic: a consumer that disappears from a scraped stream has its
// gauge series deleted, while a consumer on a stream that failed to
// scrape this round is left untouched (no flapping).
func TestNATSCollectorPrunesStaleSeries(t *testing.T) {
	m := newTestMetrics(t)
	c := NewNATSCollector(m, nil, []string{"ORDERS", "EVENTS"}, 0, discardLogger())

	// Seed a prior sweep that recorded three consumers.
	prior := [][2]string{{"ORDERS", "c1"}, {"ORDERS", "c2"}, {"EVENTS", "c3"}}
	for _, k := range prior {
		m.NATSConsumerLag.WithLabelValues(k[0], k[1]).Set(1)
		c.tracked[k] = struct{}{}
	}
	if got := testutil.CollectAndCount(m.NATSConsumerLag); got != 3 {
		t.Fatalf("precondition: series count = %d, want 3", got)
	}

	// This round: ORDERS scraped but only c1 seen (c2 gone); EVENTS
	// failed to scrape (transient), so c3 must be preserved.
	seen := map[[2]string]struct{}{{"ORDERS", "c1"}: {}}
	scraped := map[string]struct{}{"ORDERS": {}}
	c.prune(seen, scraped)

	if got := testutil.CollectAndCount(m.NATSConsumerLag); got != 2 {
		t.Fatalf("series count = %d, want 2 (c2 pruned, c1+c3 kept)", got)
	}
	if _, ok := c.tracked[[2]string{"ORDERS", "c2"}]; ok {
		t.Error("ORDERS/c2 should be pruned from tracked set")
	}
	if _, ok := c.tracked[[2]string{"ORDERS", "c1"}]; !ok {
		t.Error("ORDERS/c1 should remain tracked")
	}
	if _, ok := c.tracked[[2]string{"EVENTS", "c3"}]; !ok {
		t.Error("EVENTS/c3 should remain tracked (stream not scraped this round)")
	}
}

func TestIdentityDirectoryMetricsRegistered(t *testing.T) {
	m := newTestMetrics(t)
	// Touch each metric so it appears in the exposition.
	m.IdentityDirectorySyncTotal.WithLabelValues("zoho", "success").Inc()
	m.IdentityDirectoryUsersListed.WithLabelValues("zoho").Add(3)

	mfs, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	present := map[string]bool{}
	for _, mf := range mfs {
		present[mf.GetName()] = true
	}
	for _, want := range []string{
		"sng_identity_directory_sync_total",
		"sng_identity_directory_users_listed_total",
	} {
		if !present[want] {
			t.Errorf("metric %q not found in exposition", want)
		}
	}
	if got := testutil.ToFloat64(m.IdentityDirectoryUsersListed.WithLabelValues("zoho")); got != 3 {
		t.Errorf("users listed = %v, want 3", got)
	}
}

func TestActivityCollectorRecord(t *testing.T) {
	m := newTestMetrics(t)
	c := NewActivityCollector(m, nil, 0)

	enq := func(src activity.Source) float64 {
		return testutil.ToFloat64(m.ActivityTouches.WithLabelValues(string(src), outcomeEnqueued))
	}

	// First snapshot establishes the baseline; the counter jumps by the
	// full cumulative value on first record. Two sources prove the
	// per-source label dimension is wired.
	c.record(activity.Stats{BySource: map[activity.Source]activity.SourceStat{
		activity.SourceTelemetry: {Enqueued: 10, Written: 9},
		activity.SourceEnroll:    {Enqueued: 2, Written: 2},
	}}, 5)
	if got := enq(activity.SourceTelemetry); got != 10 {
		t.Errorf("telemetry enqueued = %v, want 10", got)
	}
	if got := enq(activity.SourceEnroll); got != 2 {
		t.Errorf("enroll enqueued = %v, want 2", got)
	}
	if got := testutil.ToFloat64(m.ActivityTouches.WithLabelValues(string(activity.SourceTelemetry), outcomeWritten)); got != 9 {
		t.Errorf("telemetry written = %v, want 9", got)
	}
	if got := testutil.ToFloat64(m.ActivityQueueDepth); got != 5 {
		t.Errorf("queue_depth = %v, want 5", got)
	}

	// A higher cumulative value adds only the delta (10 -> 13 = +3).
	c.record(activity.Stats{BySource: map[activity.Source]activity.SourceStat{
		activity.SourceTelemetry: {Enqueued: 13, Written: 12},
	}}, 1)
	if got := enq(activity.SourceTelemetry); got != 13 {
		t.Errorf("telemetry enqueued = %v, want 13", got)
	}
	if got := testutil.ToFloat64(m.ActivityQueueDepth); got != 1 {
		t.Errorf("queue_depth = %v, want 1", got)
	}

	// A backwards value (recorder replaced) rebaselines without emitting
	// a negative delta — the counter holds steady.
	c.record(activity.Stats{BySource: map[activity.Source]activity.SourceStat{
		activity.SourceTelemetry: {Enqueued: 1},
	}}, 0)
	if got := enq(activity.SourceTelemetry); got != 13 {
		t.Errorf("telemetry enqueued = %v, want 13 after rebaseline", got)
	}

	// Growth resumes from the new baseline (1 -> 4 = +3 ⇒ 13+3 = 16).
	c.record(activity.Stats{BySource: map[activity.Source]activity.SourceStat{
		activity.SourceTelemetry: {Enqueued: 4},
	}}, 0)
	if got := enq(activity.SourceTelemetry); got != 16 {
		t.Errorf("telemetry enqueued = %v, want 16", got)
	}
}
