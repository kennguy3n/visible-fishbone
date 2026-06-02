// Package alert — feedback_run_test pins the Run/tickOnce
// concurrency contract: the per-tick goroutine fanout is
// bounded by opts.RunConcurrency regardless of tenant count.
//
// Without the bound, an operator with 1000 tenants would see a
// 1000-way goroutine + connection burst every interval; with
// the bound the worst-case in-flight goroutine count stays at
// RunConcurrency.
package alert

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// trackingBaseline wraps a no-op baseline list with a counter
// that records the peak number of concurrent List calls. It
// blocks each List on a shared channel so the bounded limiter
// is observably saturated.
type trackingBaseline struct {
	inFlight atomic.Int32
	peak     atomic.Int32
	release  chan struct{}
}

func (t *trackingBaseline) GetForDimension(
	context.Context, uuid.UUID, string, int,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, repository.ErrNotFound
}

func (t *trackingBaseline) Upsert(
	context.Context, uuid.UUID, repository.BaselineModel,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, nil
}

func (t *trackingBaseline) UpdateThreshold(
	context.Context, uuid.UUID, string, int, float64,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, nil
}

func (t *trackingBaseline) List(
	ctx context.Context, _ uuid.UUID, _ repository.Page,
) (repository.PageResult[repository.BaselineModel], error) {
	cur := t.inFlight.Add(1)
	for {
		peak := t.peak.Load()
		if cur <= peak {
			break
		}
		if t.peak.CompareAndSwap(peak, cur) {
			break
		}
	}
	defer t.inFlight.Add(-1)
	select {
	case <-t.release:
	case <-ctx.Done():
	}
	return repository.PageResult[repository.BaselineModel]{}, nil
}

// stubFeedback satisfies the AlertFeedbackRepository minimally —
// Run only calls baseline.List then TuneDimension; with no
// baseline models the per-tenant iteration is empty so the
// feedback methods are never invoked. We still need the
// interface to compile.
type stubFeedback struct{}

func (stubFeedback) Create(context.Context, uuid.UUID, repository.AlertFeedback) (repository.AlertFeedback, error) {
	return repository.AlertFeedback{}, nil
}
func (stubFeedback) GetForAlert(context.Context, uuid.UUID, uuid.UUID) (repository.AlertFeedback, error) {
	return repository.AlertFeedback{}, repository.ErrNotFound
}
func (stubFeedback) Delete(context.Context, uuid.UUID, uuid.UUID) error { return nil }
func (stubFeedback) ListByDimension(context.Context, uuid.UUID, string, int, time.Time) ([]repository.AlertFeedback, error) {
	return nil, nil
}

func TestFeedback_TickOnce_BoundsConcurrentTenantFanout(t *testing.T) {
	t.Parallel()
	const tenantCount = 200
	const concurrency = 8

	tb := &trackingBaseline{release: make(chan struct{})}
	fb := NewFeedback(
		stubFeedback{},
		nil, // alerts repo: unused by Run
		tb,
		FeedbackTuningOptions{
			MinSampleCount: 1,
			RunConcurrency: concurrency,
		},
	)

	tenants := make([]uuid.UUID, tenantCount)
	for i := range tenants {
		tenants[i] = uuid.New()
	}

	// Drive a single tickOnce in a goroutine; release the
	// blocked List calls after we've observed the peak.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		fb.tickOnce(ctx, func(context.Context) ([]uuid.UUID, error) {
			return tenants, nil
		})
	}()

	// Wait until the limiter saturates — peak should hit
	// `concurrency`. Poll with a tight deadline.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if tb.peak.Load() >= int32(concurrency) {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	close(tb.release)
	wg.Wait()

	peak := tb.peak.Load()
	if peak > int32(concurrency) {
		t.Fatalf("peak concurrent List = %d, want <= %d", peak, concurrency)
	}
	if peak == 0 {
		t.Fatalf("List was never invoked")
	}
}

// pagingBaseline returns multiple cursor pages on List so the
// round-4 fix to tickOnce (cursor-loop instead of hardcoded page
// limit) can be pinned: every page MUST be visited and every
// dimension MUST reach TuneDimension. Before the fix, the loop
// stopped after a single 200-row page (MaxPageLimit clamp) and
// silently dropped the tail.
type pagingBaseline struct {
	mu        sync.Mutex
	pages     [][]repository.BaselineModel // pages[0] returned for After="", pages[1] for cursor of page-0, ...
	cursors   []string                     // cursors[i] is the NextCursor returned alongside pages[i]; "" on the last page
	listCalls atomic.Int32
	getCalls  atomic.Int32
}

func (p *pagingBaseline) GetForDimension(
	_ context.Context, _ uuid.UUID, _ string, _ int,
) (repository.BaselineModel, error) {
	p.getCalls.Add(1)
	return repository.BaselineModel{}, repository.ErrNotFound
}

func (p *pagingBaseline) Upsert(
	context.Context, uuid.UUID, repository.BaselineModel,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, nil
}

func (p *pagingBaseline) UpdateThreshold(
	context.Context, uuid.UUID, string, int, float64,
) (repository.BaselineModel, error) {
	return repository.BaselineModel{}, nil
}

func (p *pagingBaseline) List(
	_ context.Context, _ uuid.UUID, page repository.Page,
) (repository.PageResult[repository.BaselineModel], error) {
	p.listCalls.Add(1)
	p.mu.Lock()
	defer p.mu.Unlock()
	// First page lookup: page.After == "".
	idx := 0
	if page.After != "" {
		for i, c := range p.cursors {
			if c == page.After {
				idx = i + 1
				break
			}
		}
	}
	if idx >= len(p.pages) {
		return repository.PageResult[repository.BaselineModel]{}, nil
	}
	return repository.PageResult[repository.BaselineModel]{
		Items:      p.pages[idx],
		NextCursor: p.cursors[idx],
	}, nil
}

// recordingFeedback wraps stubFeedback to record which dimension
// names reached ListByDimension — proves tickOnce iterated the
// page Items and called TuneDimension on each of them.
type recordingFeedback struct {
	stubFeedback
	mu   sync.Mutex
	dims []string
}

func (r *recordingFeedback) ListByDimension(
	_ context.Context, _ uuid.UUID, dim string, _ int, _ time.Time,
) ([]repository.AlertFeedback, error) {
	r.mu.Lock()
	r.dims = append(r.dims, dim)
	r.mu.Unlock()
	return nil, nil
}

func TestFeedback_TickOnce_PaginatesThroughAllBaselines(t *testing.T) {
	t.Parallel()
	pb := &pagingBaseline{
		pages: [][]repository.BaselineModel{
			{{Dimension: "page0_dim", WindowSeconds: 60}},
			{{Dimension: "page1_dim", WindowSeconds: 60}},
			{{Dimension: "page2_dim", WindowSeconds: 60}},
		},
		cursors: []string{"c1", "c2", ""},
	}
	rf := &recordingFeedback{}
	fb := NewFeedback(
		rf,
		nil,
		pb,
		FeedbackTuningOptions{MinSampleCount: 1, RunConcurrency: 1},
	)
	tenantID := uuid.New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fb.tickOnce(ctx, func(context.Context) ([]uuid.UUID, error) {
		return []uuid.UUID{tenantID}, nil
	})

	if pb.listCalls.Load() != 3 {
		t.Fatalf("List was called %d times, want 3 (one per cursor page)",
			pb.listCalls.Load())
	}
	rf.mu.Lock()
	defer rf.mu.Unlock()
	want := map[string]bool{"page0_dim": true, "page1_dim": true, "page2_dim": true}
	for _, d := range rf.dims {
		delete(want, d)
	}
	if len(want) > 0 {
		t.Fatalf("tickOnce dropped dimensions: %v (tuned only %v)", want, rf.dims)
	}
}
