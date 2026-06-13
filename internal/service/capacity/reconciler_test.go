package capacity

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/capacityplan"
)

// docKnobs is the documented default knob set docs/scaling.md grades
// its tier tables against (3 replicas, PG_MAX_OPEN_CONNS=20, PgBouncer
// on, max_connections=200, 2 ClickHouse shards, batch 1024, 16 NATS
// partitions). The reconciler grades the live fleet against exactly
// these, so its recommendation reproduces the documented numbers.
func docKnobs() RuntimeKnobs {
	return RuntimeKnobs{
		ControlPlaneReplicas: 3,
		PGMaxOpenConns:       20,
		PGMaxConnections:     200,
		PGBouncerMode:        true,
		ClickHouseShards:     2,
		ClickHouseBatchSize:  1024,
		NATSPartitions:       16,
	}
}

type fakeObserver struct {
	obs FleetObservation
	err error
}

func (f fakeObserver) Observe(context.Context) (FleetObservation, error) {
	return f.obs, f.err
}

type settingKey struct{ axis, knob string }

type fakeSink struct {
	mu       sync.Mutex
	settings map[settingKey][2]float64 // [current, recommended]
	pending  map[string]bool
	fleet    int
	okCount  int
	errCount int
}

func newFakeSink() *fakeSink {
	return &fakeSink{
		settings: map[settingKey][2]float64{},
		pending:  map[string]bool{},
	}
}

func (s *fakeSink) SetCapacitySetting(axis, knob string, current, recommended float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settings[settingKey{axis, knob}] = [2]float64{current, recommended}
}

func (s *fakeSink) SetCapacityRecommendationPending(axis string, pending bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[axis] = pending
}

func (s *fakeSink) SetCapacityFleetTenants(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fleet = n
}

func (s *fakeSink) IncCapacityReconcile(outcome string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch outcome {
	case "ok":
		s.okCount++
	case "error":
		s.errCount++
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestReconciler(obs FleetObservation, knobs RuntimeKnobs, sink MetricSink) *Reconciler {
	return New(Config{
		Observer: fakeObserver{obs: obs},
		Knobs:    func() RuntimeKnobs { return knobs },
		Metrics:  sink,
		Logger:   testLogger(),
		NowFunc:  func() time.Time { return time.Unix(0, 0) },
	})
}

// TestReconcileMatchesModelTiers proves the live reconciler's
// recommendation is identical to the offline capacity-plan model for
// the documented 1K / 2.5K / 5K tiers — the WS6 success criterion.
func TestReconcileMatchesModelTiers(t *testing.T) {
	for _, tenants := range []int{1000, 2500, 5000} {
		knobs := docKnobs()
		sink := newFakeSink()
		r := newTestReconciler(FleetObservation{TenantCount: tenants}, knobs, sink)

		rec, err := r.Reconcile(context.Background())
		if err != nil {
			t.Fatalf("%d tenants: reconcile: %v", tenants, err)
		}

		want := capacityplan.Run(capacityplan.Config{
			TenantCount:          tenants,
			ControlPlaneReplicas: knobs.ControlPlaneReplicas,
			PGMaxOpenConns:       knobs.PGMaxOpenConns,
			PGBouncerMode:        capacityplan.BoolPtr(knobs.PGBouncerMode),
			PGMaxConnections:     knobs.PGMaxConnections,
			ClickHouseShards:     knobs.ClickHouseShards,
			ClickHouseBatchSize:  knobs.ClickHouseBatchSize,
			NATSPartitions:       knobs.NATSPartitions,
		})
		if !reflect.DeepEqual(rec.Plan, want) {
			t.Fatalf("%d tenants: plan mismatch\n got %+v\nwant %+v", tenants, *rec.Plan, *want)
		}
		if sink.fleet != tenants {
			t.Errorf("%d tenants: fleet gauge = %d", tenants, sink.fleet)
		}
		if sink.okCount != 1 || sink.errCount != 0 {
			t.Errorf("%d tenants: outcomes ok=%d err=%d", tenants, sink.okCount, sink.errCount)
		}
	}
}

// TestReconcileGradesAxes checks the per-axis pending logic at the 5K
// tier with default knobs: the static 1024 batch is well below the
// model's recommended 13250 (ClickHouse under-provisioned), while the
// generous pool and 16 partitions carry the load (not pending).
func TestReconcileGradesAxes(t *testing.T) {
	sink := newFakeSink()
	r := newTestReconciler(FleetObservation{TenantCount: 5000}, docKnobs(), sink)
	rec, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rec.Pending {
		t.Fatal("expected an under-provisioned axis at 5K with the default 1024 batch")
	}

	byAxis := map[string]AxisStatus{}
	for _, a := range rec.Axes {
		byAxis[a.Axis] = a
	}
	if !byAxis[AxisClickHouse].Pending {
		t.Error("clickhouse axis should be pending (batch 1024 << recommended 13250)")
	}
	if byAxis[AxisPostgres].Pending {
		t.Error("postgres axis should not be pending (pool 20 >> recommended 5, backend within max)")
	}
	if byAxis[AxisNATS].Pending {
		t.Error("nats axis should not be pending (16 partitions carry 5K)")
	}

	// The pending flag and the current/recommended split must reach the
	// metrics sink so an operator dashboard can alert on the divergence.
	if !sink.pending[AxisClickHouse] {
		t.Error("clickhouse pending flag did not reach metrics")
	}
	if got := sink.settings[settingKey{AxisClickHouse, "batch_size"}]; got[0] != 1024 || got[1] != 13250 {
		t.Errorf("clickhouse batch_size gauge = %v, want [1024 13250]", got)
	}
}

// TestNoPendingWhenAdequatelyProvisioned: a fleet whose knobs already
// meet the recommendation reports no pending action and over-
// provisioning is never flagged (fail-safe toward more capacity).
func TestNoPendingWhenAdequatelyProvisioned(t *testing.T) {
	knobs := docKnobs()
	knobs.ClickHouseBatchSize = 20000 // above the 13250 recommendation
	knobs.PGMaxOpenConns = 50         // above the recommended 5
	sink := newFakeSink()
	r := newTestReconciler(FleetObservation{TenantCount: 5000}, knobs, sink)

	rec, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Pending {
		t.Fatalf("over-provisioned fleet should report no pending action, got %+v", rec.Axes)
	}
}

// TestZeroTenantsSkipsModel: a brand-new install with no tenants records
// a clean pass without fabricating a recommendation from the model's
// default tier.
func TestZeroTenantsSkipsModel(t *testing.T) {
	sink := newFakeSink()
	r := newTestReconciler(FleetObservation{TenantCount: 0}, docKnobs(), sink)

	rec, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Plan != nil {
		t.Fatal("model should not run with zero tenants")
	}
	if sink.fleet != 0 {
		t.Errorf("fleet gauge = %d, want 0", sink.fleet)
	}
	if sink.okCount != 1 {
		t.Errorf("zero-tenant pass should count as ok, got %d", sink.okCount)
	}
	if _, ok := r.Latest(); ok {
		t.Error("zero-tenant pass should not publish a recommendation")
	}
}

// TestObserveErrorIsFailSafe: an observation error records the error
// outcome and never overwrites the last good recommendation.
func TestObserveErrorIsFailSafe(t *testing.T) {
	sink := newFakeSink()
	r := New(Config{
		Observer: fakeObserver{err: errors.New("db down")},
		Knobs:    docKnobs,
		Metrics:  sink,
		Logger:   testLogger(),
	})

	if _, err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if sink.errCount != 1 {
		t.Errorf("error outcome count = %d, want 1", sink.errCount)
	}
	if _, ok := r.Latest(); ok {
		t.Error("a failed reconcile should not publish a recommendation")
	}
}

// TestLatestSnapshot: the latest recommendation is retrievable for an
// operator endpoint and reflects the most recent successful pass.
func TestLatestSnapshot(t *testing.T) {
	sink := newFakeSink()
	r := newTestReconciler(FleetObservation{TenantCount: 5000}, docKnobs(), sink)

	if _, ok := r.Latest(); ok {
		t.Fatal("no recommendation should exist before the first reconcile")
	}
	rec, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := r.Latest()
	if !ok {
		t.Fatal("expected a cached recommendation after reconcile")
	}
	if got.Observation.TenantCount != rec.Observation.TenantCount {
		t.Errorf("Latest tenant count = %d, want %d", got.Observation.TenantCount, rec.Observation.TenantCount)
	}
}

// TestMeasuredRateLowersBatchRecommendation: when the observer supplies
// a live event rate well below the synthetic model, the recommended
// batch tracks real traffic rather than the worst-case projection.
func TestMeasuredRateLowersBatchRecommendation(t *testing.T) {
	sink := newFakeSink()
	r := newTestReconciler(
		FleetObservation{TenantCount: 5000, EventsPerSec: 2650},
		docKnobs(), sink,
	)
	rec, err := r.Reconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.Plan.ClickHouse.RecommendedBatchSize >= 13250 {
		t.Fatalf("measured-rate batch %d should be below the modelled 13250",
			rec.Plan.ClickHouse.RecommendedBatchSize)
	}
}

func TestNewPanicsOnMissingDeps(t *testing.T) {
	assertPanic(t, "nil observer", func() {
		New(Config{Knobs: docKnobs})
	})
	assertPanic(t, "nil knobs", func() {
		New(Config{Observer: fakeObserver{}})
	})
}

func assertPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected panic", name)
		}
	}()
	fn()
}
