package activity

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fakeToucher records every TouchLastActive call and can be made to
// fail or block, for exercising the drain worker.
type fakeToucher struct {
	mu      sync.Mutex
	calls   []call
	err     error
	block   chan struct{}  // when non-nil, each touch waits on it
	started chan uuid.UUID // when non-nil, signals the id of each touch as it begins
}

type call struct {
	id   uuid.UUID
	seen time.Time
}

func (f *fakeToucher) TouchLastActive(ctx context.Context, id uuid.UUID, seen time.Time) error {
	if f.started != nil {
		select {
		case f.started <- id:
		default:
		}
	}
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call{id: id, seen: seen})
	return f.err
}

func (f *fakeToucher) snapshot() []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]call, len(f.calls))
	copy(out, f.calls)
	return out
}

// drainUntil polls cond up to timeout, returning whether it held.
func drainUntil(timeout time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

func TestRecorder_PersistsObservedActivity(t *testing.T) {
	f := &fakeToucher{}
	r := NewRecorder(f, WithMinInterval(time.Hour))
	go r.Run()
	defer r.Stop()

	id := uuid.New()
	seen := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	r.Observe(id, seen)

	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == 1 }) {
		t.Fatalf("touch never persisted: %+v", f.snapshot())
	}
	got := f.snapshot()[0]
	if got.id != id || !got.seen.Equal(seen) {
		t.Fatalf("persisted %v@%v, want %v@%v", got.id, got.seen, id, seen)
	}
}

func TestRecorder_DebouncesWithinInterval(t *testing.T) {
	f := &fakeToucher{}
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	r := NewRecorder(f, WithMinInterval(5*time.Minute), WithClock(clock))
	go r.Run()
	defer r.Stop()

	id := uuid.New()
	r.Observe(id, now)
	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == 1 }) {
		t.Fatalf("first touch not persisted")
	}

	// Second observe within the debounce window must be suppressed.
	r.Observe(id, now.Add(time.Minute))
	// Give the worker a chance to (incorrectly) write.
	time.Sleep(20 * time.Millisecond)
	if n := len(f.snapshot()); n != 1 {
		t.Fatalf("debounce failed: got %d touches, want 1", n)
	}
	if s := r.Stats(); s.Debounced != 1 {
		t.Fatalf("Debounced = %d, want 1", s.Debounced)
	}

	// Advancing past the window admits the next touch.
	now = now.Add(6 * time.Minute)
	r.Observe(id, now)
	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == 2 }) {
		t.Fatalf("touch after window not persisted: %d", len(f.snapshot()))
	}
}

func TestRecorder_DistinctTenantsNotDebouncedTogether(t *testing.T) {
	f := &fakeToucher{}
	now := time.Now()
	r := NewRecorder(f, WithMinInterval(time.Hour), WithClock(func() time.Time { return now }))
	go r.Run()
	defer r.Stop()

	a, b := uuid.New(), uuid.New()
	r.Observe(a, now)
	r.Observe(b, now)
	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == 2 }) {
		t.Fatalf("both tenants should be persisted, got %d", len(f.snapshot()))
	}
}

func TestRecorder_NilAndZeroAreSafe(t *testing.T) {
	var r *Recorder
	r.Observe(uuid.New(), time.Now()) // nil receiver: must not panic
	// Stats now carries a BySource map so it is no longer comparable
	// with ==; assert the scalar counters are zero and no per-source
	// breakdown was allocated.
	if got := r.Stats(); got.Enqueued != 0 || got.Debounced != 0 || got.Dropped != 0 ||
		got.Written != 0 || got.Failed != 0 || got.BySource != nil {
		t.Fatalf("nil Stats = %+v, want zero", got)
	}

	f := &fakeToucher{}
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	r2 := NewRecorder(f, WithClock(func() time.Time { return now }))
	go r2.Run()
	defer r2.Stop()

	r2.Observe(uuid.Nil, now) // nil tenant: no-op
	time.Sleep(20 * time.Millisecond)
	if n := len(f.snapshot()); n != 0 {
		t.Fatalf("nil tenant produced %d touches, want 0", n)
	}

	// Zero seen is replaced with now.
	id := uuid.New()
	r2.Observe(id, time.Time{})
	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == 1 }) {
		t.Fatalf("zero-seen touch not persisted")
	}
	if got := f.snapshot()[0].seen; !got.Equal(now) {
		t.Fatalf("zero seen persisted as %v, want now %v", got, now)
	}
}

func TestRecorder_DropsWhenQueueFull(t *testing.T) {
	block := make(chan struct{})
	f := &fakeToucher{block: block}
	// Queue size 1 + a worker blocked on the first write means the
	// second distinct enqueue fills the buffer and the third drops.
	r := NewRecorder(f, WithMinInterval(time.Hour), WithQueueSize(1))
	go r.Run()
	defer r.Stop()

	// First touch is pulled by the worker and blocks there.
	r.Observe(uuid.New(), time.Now())
	if !drainUntil(time.Second, func() bool { return r.Stats().Enqueued >= 1 }) {
		t.Fatalf("first touch not enqueued")
	}
	// Fill the 1-slot buffer, then overflow it. Distinct tenants so
	// debounce never suppresses.
	for i := 0; i < 50; i++ {
		r.Observe(uuid.New(), time.Now())
	}
	if s := r.Stats(); s.Dropped == 0 {
		t.Fatalf("expected drops with a saturated queue, stats=%+v", s)
	}
	close(block) // let the worker finish so the deferred cancel is clean
}

func TestRecorder_DropDoesNotSilenceTenant(t *testing.T) {
	block := make(chan struct{})
	f := &fakeToucher{block: block, started: make(chan uuid.UUID, 8)}
	now := time.Now()
	clk := func() time.Time { return now }
	r := NewRecorder(f, WithMinInterval(5*time.Minute), WithQueueSize(1), WithClock(clk))
	go r.Run()
	defer r.Stop()

	// A: worker pulls this and blocks inside the write, leaving the
	// 1-slot buffer empty.
	a := uuid.New()
	r.Observe(a, now)
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("worker never started the first write")
	}
	// B fills the 1-slot buffer; X then drops. X has never been seen,
	// so the only thing that can keep it out of the next window is a
	// (wrongly) set debounce marker.
	x := uuid.New()
	r.Observe(uuid.New(), now)
	r.Observe(x, now) // queue full -> drop, must NOT mark x
	if s := r.Stats(); s.Dropped == 0 {
		t.Fatalf("expected a drop, stats=%+v", s)
	}
	// Unblock and let the backlog drain.
	close(block)
	if !drainUntil(time.Second, func() bool { return r.Stats().Written >= 2 }) {
		t.Fatalf("queue did not drain, stats=%+v", r.Stats())
	}
	// A fresh Observe for the dropped tenant within the same window
	// must still be accepted: the drop left no debounce marker.
	before := r.Stats().Enqueued
	r.Observe(x, now)
	if !drainUntil(time.Second, func() bool { return r.Stats().Enqueued == before+1 }) {
		t.Fatalf("dropped tenant was silenced for the whole window, stats=%+v", r.Stats())
	}
}

func TestRecorder_WriteFailureCounted(t *testing.T) {
	f := &fakeToucher{err: errors.New("boom")}
	r := NewRecorder(f, WithMinInterval(time.Hour))
	go r.Run()
	defer r.Stop()

	r.Observe(uuid.New(), time.Now())
	if !drainUntil(time.Second, func() bool { return r.Stats().Failed == 1 }) {
		t.Fatalf("write failure not counted, stats=%+v", r.Stats())
	}
	if got := r.Stats().Written; got != 0 {
		t.Fatalf("Written = %d on failure, want 0", got)
	}
}

func TestRecorder_StopDrainsRemaining(t *testing.T) {
	// A worker blocked on the first write leaves later touches buffered.
	// Stop must drain those before returning — not discard them — so the
	// trailing activity window survives graceful shutdown.
	block := make(chan struct{})
	f := &fakeToucher{block: block, started: make(chan uuid.UUID, 8)}
	r := NewRecorder(f, WithMinInterval(time.Hour), WithQueueSize(8))
	go r.Run()

	a, b, c := uuid.New(), uuid.New(), uuid.New()
	r.Observe(a, time.Now()) // pulled by worker, blocks inside write
	select {
	case <-f.started:
	case <-time.After(time.Second):
		t.Fatal("worker never started the first write")
	}
	r.Observe(b, time.Now()) // buffers behind the blocked worker
	r.Observe(c, time.Now())
	if !drainUntil(time.Second, func() bool { return r.Stats().Enqueued == 3 }) {
		t.Fatalf("expected 3 enqueued, stats=%+v", r.Stats())
	}

	// Unblock writes, then Stop: its final drain must persist all three
	// and block until they land.
	close(block)
	r.Stop()
	if got := len(f.snapshot()); got != 3 {
		t.Fatalf("Stop persisted %d touches, want 3", got)
	}
	if w := r.Stats().Written; w != 3 {
		t.Fatalf("Written = %d after Stop, want 3", w)
	}
}

func TestRecorder_StopBeforeRunIsSafe(t *testing.T) {
	// Stop on a recorder whose Run never started must not block.
	r := NewRecorder(&fakeToucher{})
	done := make(chan struct{})
	go func() { r.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop blocked when Run was never started")
	}
	// Idempotent: a second Stop is a no-op.
	r.Stop()
}

func TestRecorder_SecondRunIsNoOp(t *testing.T) {
	// A repeat Run must not start a second loop (which would panic on
	// the double close(doneCh)). The guard admits exactly one.
	f := &fakeToucher{}
	r := NewRecorder(f, WithMinInterval(time.Hour))
	go r.Run()
	// Drive one touch through so the first loop has definitely won the
	// started CAS before we re-enter Run.
	r.Observe(uuid.New(), time.Now())
	if !drainUntil(time.Second, func() bool { return r.Stats().Written == 1 }) {
		t.Fatalf("first loop never ran, stats=%+v", r.Stats())
	}
	// started is now true, so this second Run is guaranteed the loser:
	// it must return immediately (not block, not panic on double close).
	r.Run()
	r.Stop()
}

func TestRecorder_PruneEvictsStaleTenants(t *testing.T) {
	t.Parallel()
	// minInterval 5m => eviction horizon pruneFactor*5m = 10m.
	f := &fakeToucher{}
	r := NewRecorder(f, WithMinInterval(5*time.Minute))
	base := time.Now()
	fresh := uuid.New() // 0m old  -> retained
	mid := uuid.New()   // 5m old  -> within 10m horizon, retained
	stale := uuid.New() // 30m old -> past horizon, evicted

	r.mu.Lock()
	r.last[fresh] = base
	r.last[mid] = base.Add(-5 * time.Minute)
	r.last[stale] = base.Add(-30 * time.Minute)
	r.mu.Unlock()

	r.prune(base)

	r.mu.Lock()
	_, freshOK := r.last[fresh]
	_, midOK := r.last[mid]
	_, staleOK := r.last[stale]
	n := len(r.last)
	r.mu.Unlock()

	if !freshOK || !midOK {
		t.Fatalf("entry within horizon evicted: fresh=%v mid=%v", freshOK, midOK)
	}
	if staleOK {
		t.Fatal("stale entry past horizon not evicted")
	}
	if n != 2 {
		t.Fatalf("last map size = %d, want 2", n)
	}
}

// TestRecorder_PerSourceAttribution proves the coverage metric's data
// source: a touch made through From(src).Observe is counted under that
// src in Stats.BySource (enqueued + eventually written), and a debounced
// repeat lands in that src's Debounced bucket — never another source's.
func TestRecorder_PerSourceAttribution(t *testing.T) {
	f := &fakeToucher{}
	now := time.Date(2026, 6, 11, 12, 0, 0, 0, time.UTC)
	r := NewRecorder(f, WithMinInterval(time.Hour), WithClock(func() time.Time { return now }))
	go r.Run()
	defer r.Stop()

	// One touch per non-unknown source, each for a distinct tenant so
	// no cross-source debounce interferes.
	srcs := []Source{SourceTelemetry, SourceAPI, SourceEnroll, SourceMobileToken, SourceMobileRefresh}
	ids := make(map[Source]uuid.UUID, len(srcs))
	for _, s := range srcs {
		id := uuid.New()
		ids[s] = id
		r.From(s).Observe(id, now)
	}
	// A second touch for one source's tenant within MinInterval must be
	// debounced and attributed to that same source.
	r.From(SourceAPI).Observe(ids[SourceAPI], now)

	if !drainUntil(time.Second, func() bool { return len(f.snapshot()) == len(srcs) }) {
		t.Fatalf("not all sources persisted: got %d, want %d", len(f.snapshot()), len(srcs))
	}

	stats := r.Stats()
	if stats.BySource == nil {
		t.Fatal("Stats.BySource is nil")
	}
	// Every Sources() value must have an entry so the metric exporter
	// can iterate without nil checks.
	for _, s := range Sources() {
		if _, ok := stats.BySource[s]; !ok {
			t.Errorf("BySource missing entry for source %q", s)
		}
	}
	for _, s := range srcs {
		st := stats.BySource[s]
		if st.Enqueued != 1 {
			t.Errorf("source %q enqueued = %d, want 1", s, st.Enqueued)
		}
		if st.Written != 1 {
			t.Errorf("source %q written = %d, want 1", s, st.Written)
		}
	}
	if got := stats.BySource[SourceAPI].Debounced; got != 1 {
		t.Errorf("api debounced = %d, want 1 (the repeat touch)", got)
	}
	if got := stats.BySource[SourceUnknown].Enqueued; got != 0 {
		t.Errorf("unknown enqueued = %d, want 0 (no un-attributed touches)", got)
	}
	// Per-source totals must reconcile with the aggregate counters.
	var sumEnq, sumWritten uint64
	for _, st := range stats.BySource {
		sumEnq += st.Enqueued
		sumWritten += st.Written
	}
	if sumEnq != stats.Enqueued {
		t.Errorf("sum of per-source enqueued = %d, aggregate = %d", sumEnq, stats.Enqueued)
	}
	if sumWritten != stats.Written {
		t.Errorf("sum of per-source written = %d, aggregate = %d", sumWritten, stats.Written)
	}
}

func TestNewRecorder_NilRepoPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on nil repo")
		}
	}()
	NewRecorder(nil)
}
