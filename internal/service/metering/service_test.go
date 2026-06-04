package metering

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mustService(t *testing.T, store UsageStore, opts ...Option) *MeteringService {
	t.Helper()
	svc, err := NewMeteringService(store, nil, opts...)
	if err != nil {
		t.Fatalf("NewMeteringService: %v", err)
	}
	return svc
}

func TestNewMeteringServiceRejectsNilStore(t *testing.T) {
	if _, err := NewMeteringService(nil, nil); err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestRecordRejectsBadInput(t *testing.T) {
	svc := mustService(t, newFakeStore())
	ctx := context.Background()

	if err := svc.Record(ctx, uuid.Nil, MeterLLMCalls, 1); err == nil {
		t.Fatal("expected error for nil tenant")
	}
	if err := svc.Record(ctx, uuid.New(), Meter("nope"), 1); err == nil {
		t.Fatal("expected error for unknown meter")
	}
	// Non-positive amounts are silent no-ops (never decrement a meter).
	tid := uuid.New()
	if err := svc.Record(ctx, tid, MeterLLMCalls, 0); err != nil {
		t.Fatalf("zero amount should be a no-op, got %v", err)
	}
	if err := svc.Record(ctx, tid, MeterLLMCalls, -5); err != nil {
		t.Fatalf("negative amount should be a no-op, got %v", err)
	}
	if got := svc.Current(ctx, tid, MeterLLMCalls); got != 0 {
		t.Fatalf("Current = %d, want 0", got)
	}
}

func TestRecordAndCurrentAccumulate(t *testing.T) {
	svc := mustService(t, newFakeStore())
	ctx := context.Background()
	tid := uuid.New()

	for i := 0; i < 5; i++ {
		if err := svc.Record(ctx, tid, MeterLLMTokensUsed, 100); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if got := svc.Current(ctx, tid, MeterLLMTokensUsed); got != 500 {
		t.Fatalf("Current = %d, want 500", got)
	}
	// A different meter / tenant is isolated.
	if got := svc.Current(ctx, tid, MeterLLMCalls); got != 0 {
		t.Fatalf("unrelated meter = %d, want 0", got)
	}
	if got := svc.Current(ctx, uuid.New(), MeterLLMTokensUsed); got != 0 {
		t.Fatalf("unrelated tenant = %d, want 0", got)
	}
}

func TestFlushPersistsDeltaOnceThenIsIdempotent(t *testing.T) {
	store := newFakeStore()
	svc := mustService(t, store)
	ctx := context.Background()
	tid := uuid.New()

	if err := svc.Record(ctx, tid, MeterURLCatLookups, 250); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	start, _ := DefaultMeterPeriod(MeterURLCatLookups).Bounds(time.Now())
	got, _ := store.TenantPeriodUsage(ctx, tid, MeterURLCatLookups, start)
	if got != 250 {
		t.Fatalf("persisted = %d, want 250", got)
	}
	// A second flush with no new records must not double-write.
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
	got, _ = store.TenantPeriodUsage(ctx, tid, MeterURLCatLookups, start)
	if got != 250 {
		t.Fatalf("after no-op flush = %d, want 250", got)
	}

	// New records flush additively (value += delta, not last-write-wins).
	if err := svc.Record(ctx, tid, MeterURLCatLookups, 50); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("third Flush: %v", err)
	}
	got, _ = store.TenantPeriodUsage(ctx, tid, MeterURLCatLookups, start)
	if got != 300 {
		t.Fatalf("after additive flush = %d, want 300", got)
	}
}

func TestFlushReturnsErrorAndKeepsDeltaPending(t *testing.T) {
	store := newFakeStore()
	store.failBatch = errors.New("db down")
	svc := mustService(t, store)
	ctx := context.Background()
	tid := uuid.New()

	if err := svc.Record(ctx, tid, MeterLLMCalls, 10); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := svc.Flush(ctx); err == nil {
		t.Fatal("expected flush error")
	}
	// The high-water mark must not have advanced, so a later successful
	// flush still writes the full delta.
	store.failBatch = nil
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("recovery Flush: %v", err)
	}
	start, _ := DefaultMeterPeriod(MeterLLMCalls).Bounds(time.Now())
	got, _ := store.TenantPeriodUsage(ctx, tid, MeterLLMCalls, start)
	if got != 10 {
		t.Fatalf("persisted = %d, want 10 (no count lost on transient error)", got)
	}
}

func TestSeedFromPersistedBaseline(t *testing.T) {
	store := newFakeStore()
	ctx := context.Background()
	tid := uuid.New()
	// Pretend a previous process already wrote 1000 tokens this period.
	start, end := DefaultMeterPeriod(MeterLLMTokensUsed).Bounds(time.Now())
	if err := store.BatchUpsertUsage(ctx, []UsageDelta{{
		TenantID: tid, Meter: MeterLLMTokensUsed, PeriodStart: start, PeriodEnd: end, Delta: 1000,
	}}); err != nil {
		t.Fatalf("seed write: %v", err)
	}

	svc := mustService(t, store)
	// First touch should seed the cell from the persisted value.
	if got := svc.Current(ctx, tid, MeterLLMTokensUsed); got != 1000 {
		t.Fatalf("seeded Current = %d, want 1000", got)
	}
	// Recording more adds on top of the baseline.
	if err := svc.Record(ctx, tid, MeterLLMTokensUsed, 500); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := svc.Current(ctx, tid, MeterLLMTokensUsed); got != 1500 {
		t.Fatalf("Current = %d, want 1500", got)
	}
	// Flushing must only persist the NEW 500 (the baseline was already
	// written), giving 1500 total — not 2500.
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	got, _ := store.TenantPeriodUsage(ctx, tid, MeterLLMTokensUsed, start)
	if got != 1500 {
		t.Fatalf("persisted = %d, want 1500", got)
	}
}

func TestPeriodRolloverResetsAndFlushesTrailingDelta(t *testing.T) {
	store := newFakeStore()
	// Daily meter so a one-day clock advance crosses the period.
	day1 := time.Date(2026, 1, 10, 12, 0, 0, 0, time.UTC)
	clock := day1
	svc := mustService(t, store, withClock(func() time.Time { return clock }))
	ctx := context.Background()
	tid := uuid.New()

	if err := svc.Record(ctx, tid, MeterURLCatLookups, 400); err != nil {
		t.Fatalf("Record day1: %v", err)
	}
	// Advance into the next day and record again — this triggers a
	// rollover inside getCell, which must flush the trailing delta of
	// the previous period before resetting.
	clock = day1.AddDate(0, 0, 1)
	if err := svc.Record(ctx, tid, MeterURLCatLookups, 30); err != nil {
		t.Fatalf("Record day2: %v", err)
	}

	day1Start, _ := PeriodDaily.Bounds(day1)
	day2Start, _ := PeriodDaily.Bounds(clock)
	if got, _ := store.TenantPeriodUsage(ctx, tid, MeterURLCatLookups, day1Start); got != 400 {
		t.Fatalf("day1 persisted = %d, want 400 (trailing delta flushed on rollover)", got)
	}
	// The live counter now reflects only the new period.
	if got := svc.Current(ctx, tid, MeterURLCatLookups); got != 30 {
		t.Fatalf("day2 Current = %d, want 30", got)
	}
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if got, _ := store.TenantPeriodUsage(ctx, tid, MeterURLCatLookups, day2Start); got != 30 {
		t.Fatalf("day2 persisted = %d, want 30", got)
	}
}

func TestCurrentUsageMergesUnflushedDeltas(t *testing.T) {
	store := newFakeStore()
	now := time.Date(2026, 3, 15, 9, 0, 0, 0, time.UTC)
	svc := mustService(t, store, withClock(fixedClock(now)))
	ctx := context.Background()
	tid := uuid.New()

	if err := svc.Record(ctx, tid, MeterLLMTokensUsed, 700); err != nil {
		t.Fatalf("Record: %v", err)
	}
	// No flush yet: CurrentUsage must still report the live in-memory
	// value rather than the as-of-last-flush (0) persisted value.
	recs, err := svc.CurrentUsage(ctx, tid)
	if err != nil {
		t.Fatalf("CurrentUsage: %v", err)
	}
	var found bool
	for _, r := range recs {
		if r.Meter == MeterLLMTokensUsed {
			found = true
			if r.Value != 700 {
				t.Fatalf("live value = %d, want 700", r.Value)
			}
		}
	}
	if !found {
		t.Fatal("expected a llm_tokens_used record")
	}
}

func TestStatsTracksFlushBookkeeping(t *testing.T) {
	store := newFakeStore()
	svc := mustService(t, store)
	ctx := context.Background()
	tid := uuid.New()

	_ = svc.Record(ctx, tid, MeterMalwareScans, 3)
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	st := svc.Stats()
	if st.Flushes != 1 {
		t.Fatalf("Flushes = %d, want 1", st.Flushes)
	}
	if st.RecordsSeen != 1 {
		t.Fatalf("RecordsSeen = %d, want 1", st.RecordsSeen)
	}
	if st.Cells != 1 {
		t.Fatalf("Cells = %d, want 1", st.Cells)
	}
	if st.LastFlush.IsZero() {
		t.Fatal("LastFlush should be set after a successful flush")
	}
}

func TestRunFinalFlushOnContextCancel(t *testing.T) {
	store := newFakeStore()
	// Long interval so the only flush is the cancellation flush.
	svc := mustService(t, store, WithFlushInterval(time.Hour))
	tid := uuid.New()
	_ = svc.Record(context.Background(), tid, MeterLLMCalls, 7)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.Run(ctx)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	start, _ := DefaultMeterPeriod(MeterLLMCalls).Bounds(time.Now())
	if got, _ := store.TenantPeriodUsage(context.Background(), tid, MeterLLMCalls, start); got != 7 {
		t.Fatalf("final flush persisted = %d, want 7", got)
	}
}

// TestConcurrentFlushRolloverNoLossOrDoubleCount stresses the three-way
// interleaving of Record (hot path), periodic Flush, and period
// rollover. Each recorded unit must be persisted exactly once across
// all periods: a regression in the claim/flush handshake shows up as
// either a lost count (sum < total) or a double count (sum > total).
// Run with -race to also catch unsynchronised access.
func TestConcurrentFlushRolloverNoLossOrDoubleCount(t *testing.T) {
	const (
		recorders   = 8
		perRecorder = 2000
		meter       = MeterURLCatLookups // daily period
	)
	store := newFakeStore()

	// Monotonic clock advanced in 6h steps so the daily meter rolls
	// over repeatedly while records and flushes are in flight.
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var steps int64
	clock := func() time.Time {
		return base.Add(time.Duration(atomic.LoadInt64(&steps)) * 6 * time.Hour)
	}
	svc := mustService(t, store, withClock(clock))
	ctx := context.Background()
	tid := uuid.New()

	stop := make(chan struct{})
	var bg sync.WaitGroup // background helpers (advancer + flusher)

	// Clock advancer: forces period rollovers while records are in flight.
	bg.Add(1)
	go func() {
		defer bg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				atomic.AddInt64(&steps, 1)
				time.Sleep(50 * time.Microsecond)
			}
		}
	}()

	// Periodic flusher racing the recorders and rollovers.
	bg.Add(1)
	go func() {
		defer bg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				if err := svc.Flush(ctx); err != nil {
					t.Errorf("Flush: %v", err)
				}
				time.Sleep(30 * time.Microsecond)
			}
		}
	}()

	var recWG sync.WaitGroup
	for i := 0; i < recorders; i++ {
		recWG.Add(1)
		go func() {
			defer recWG.Done()
			for j := 0; j < perRecorder; j++ {
				if err := svc.Record(ctx, tid, meter, 1); err != nil {
					t.Errorf("Record: %v", err)
					return
				}
			}
		}()
	}
	recWG.Wait() // all records issued
	close(stop)  // halt advancer + flusher
	bg.Wait()    // they observed stop and returned

	// Drain anything still buffered (in-flight cell deltas + retries).
	if err := svc.Flush(ctx); err != nil {
		t.Fatalf("final Flush: %v", err)
	}

	// Every unit must be persisted exactly once across all periods.
	hist, err := store.TenantUsageHistory(ctx, tid, 0)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	var sum int64
	for _, r := range hist {
		if r.Value < 0 {
			t.Fatalf("negative persisted value %d (flushed high-water corruption)", r.Value)
		}
		sum += r.Value
	}
	want := int64(recorders * perRecorder)
	if sum != want {
		t.Fatalf("persisted total = %d across %d periods, want %d (loss or double-count)", sum, len(hist), want)
	}
}
