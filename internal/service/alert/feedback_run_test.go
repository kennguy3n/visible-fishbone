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
