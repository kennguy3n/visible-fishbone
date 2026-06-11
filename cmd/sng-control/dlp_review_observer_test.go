package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

// fakeEnqueuer records every enqueue and optionally blocks/fails.
type fakeEnqueuer struct {
	mu      sync.Mutex
	calls   []dlpreview.EnqueueInput
	tenants []uuid.UUID
	err     error
	release chan struct{} // when non-nil, Enqueue blocks until it receives
}

func (f *fakeEnqueuer) Enqueue(ctx context.Context, tenantID uuid.UUID, in dlpreview.EnqueueInput) (dlpreview.ReviewEvent, error) {
	if f.release != nil {
		select {
		case <-f.release:
		case <-ctx.Done():
			return dlpreview.ReviewEvent{}, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return dlpreview.ReviewEvent{}, f.err
	}
	f.calls = append(f.calls, in)
	f.tenants = append(f.tenants, tenantID)
	return dlpreview.ReviewEvent{ID: uuid.New()}, nil
}

func (f *fakeEnqueuer) recorded() []dlpreview.EnqueueInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]dlpreview.EnqueueInput, len(f.calls))
	copy(out, f.calls)
	return out
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func sampleWireEvent() schema.DLPEvent {
	return schema.DLPEvent{
		DestinationApp: "chatgpt",
		Action:         schema.DLPActionCoach,
		Severity:       "high",
		Confidence:     0.91,
		Findings: []schema.DLPFinding{
			{Kind: schema.DLPFindingSecret, Label: "github_token", Count: 2, MaxConfidence: 0.99, Severity: "high"},
			{Kind: schema.DLPFindingPII, Label: "email", Count: 1, MaxConfidence: 0.7, Severity: "low"},
		},
	}
}

func TestDLPReviewIngest_EnqueuesAndMaps(t *testing.T) {
	fake := &fakeEnqueuer{}
	ing := newDLPReviewIngest(fake, discardLogger(), dlpReviewIngestConfig{})
	tenant := uuid.New()
	ing.ObserveDLP(context.Background(), tenant, uuid.New(), sampleWireEvent(), time.Now())
	ing.Stop() // drains

	got := fake.recorded()
	if len(got) != 1 {
		t.Fatalf("want 1 enqueue, got %d", len(got))
	}
	in := got[0]
	if in.DestinationApp != "chatgpt" || in.Severity != dlpreview.SeverityHigh || in.Confidence != 0.91 {
		t.Fatalf("bad mapping: %+v", in)
	}
	if in.Signal != "" {
		t.Fatalf("signal should be left empty for service default, got %q", in.Signal)
	}
	if len(in.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(in.Findings))
	}
	if in.Findings[0].Kind != dlpreview.FindingSecret || in.Findings[0].Label != "github_token" ||
		in.Findings[0].Count != 2 || in.Findings[0].Severity != dlpreview.SeverityHigh {
		t.Fatalf("finding[0] mismatch: %+v", in.Findings[0])
	}
	if ing.enqueued.Load() != 1 || ing.dropped.Load() != 0 || ing.failed.Load() != 0 {
		t.Fatalf("counters: enqueued=%d dropped=%d failed=%d", ing.enqueued.Load(), ing.dropped.Load(), ing.failed.Load())
	}
}

func TestDLPReviewIngest_DropsWhenBufferFull(t *testing.T) {
	// Block the worker on the first enqueue so the buffer fills, then
	// confirm subsequent observations are dropped (counted) rather than
	// blocking the caller.
	release := make(chan struct{})
	fake := &fakeEnqueuer{release: release}
	ing := newDLPReviewIngest(fake, discardLogger(), dlpReviewIngestConfig{BufferSize: 1})

	// First event is picked up by the worker (which then blocks on
	// release); second fills the size-1 buffer; the rest are dropped.
	for i := 0; i < 5; i++ {
		ing.ObserveDLP(context.Background(), uuid.New(), uuid.New(), sampleWireEvent(), time.Now())
	}
	// Give the worker a moment to pull the first item.
	deadline := time.After(time.Second)
	for ing.dropped.Load() == 0 {
		select {
		case <-deadline:
			t.Fatalf("expected at least one drop, got none")
		case <-time.After(time.Millisecond):
		}
	}
	if ing.dropped.Load() == 0 {
		t.Fatal("expected drops when buffer full")
	}
	close(release)
	ing.Stop()
}

func TestDLPReviewIngest_CountsFailures(t *testing.T) {
	fake := &fakeEnqueuer{err: errors.New("db down")}
	ing := newDLPReviewIngest(fake, discardLogger(), dlpReviewIngestConfig{})
	ing.ObserveDLP(context.Background(), uuid.New(), uuid.New(), sampleWireEvent(), time.Now())
	ing.Stop()
	if ing.failed.Load() != 1 || ing.enqueued.Load() != 0 {
		t.Fatalf("counters: enqueued=%d failed=%d", ing.enqueued.Load(), ing.failed.Load())
	}
}

func TestDLPReviewIngest_StopIsIdempotent(t *testing.T) {
	ing := newDLPReviewIngest(&fakeEnqueuer{}, discardLogger(), dlpReviewIngestConfig{})
	ing.Stop()
	ing.Stop() // must not panic or block
}

func TestDLPReviewIngest_ObserveAfterStopDrops(t *testing.T) {
	fake := &fakeEnqueuer{}
	ing := newDLPReviewIngest(fake, discardLogger(), dlpReviewIngestConfig{})
	ing.Stop()
	ing.ObserveDLP(context.Background(), uuid.New(), uuid.New(), sampleWireEvent(), time.Now())
	if len(fake.recorded()) != 0 {
		t.Fatalf("no enqueue should happen after Stop")
	}
	if ing.dropped.Load() != 1 {
		t.Fatalf("expected 1 drop after stop, got %d", ing.dropped.Load())
	}
}
