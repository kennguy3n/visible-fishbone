package telemetry_test

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry"
)

// e2eClock is a manually-advanced clock for the end-to-end sampling
// test, so the sampler's keep probability is pinned before the
// asynchronous consumer touches it.
type e2eClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *e2eClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *e2eClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestService_AdaptiveSamplingEndToEnd drives the full consumer path
// (NATS → decode → sampler → hot writer) and asserts the wiring:
// over-budget events are dropped (Ack'd, counted as Sampled) and kept
// events are stamped with their sampling rate for de-bias. The keep
// probability is pinned to 0.5 deterministically via a fixed clock so
// the test is not timing-dependent.
func TestService_AdaptiveSamplingEndToEnd(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	clk := &e2eClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	const (
		budget = rate.Limit(1000)
		window = time.Second
		total  = 2000
	)
	sampler := telemetry.NewAdaptiveSampler(telemetry.SamplerConfig{
		Resolver: telemetry.StaticLimitResolver{Limit: telemetry.TenantLimit{Rate: budget, Burst: int(budget)}},
		Window:   window,
		NowFunc:  clk.now,
	})

	tenant := uuid.New()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Pin keepProb to budget/arrivals = 1000/2000 = 0.5: feed window-1
	// arrivals, then advance exactly one window. The consumer's first
	// Decide rolls the window and computes the 0.5 probability, which
	// then stays stable because the clock no longer moves.
	for i := 0; i < 2000; i++ {
		sampler.Decide(ctx, tenant, uuid.New())
	}
	clk.advance(window)

	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-sample"}, hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	svc.WithSampler(sampler)
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	for i := 0; i < total; i++ {
		env := schema.Envelope{
			SchemaVersion: schema.SchemaVersion, EventID: uuid.New(),
			TenantID: tenant, DeviceID: uuid.New(),
			Timestamp:  time.Now().UTC(),
			EventClass: schema.EventClassFlow, Platform: schema.PlatformLinux,
			Payload: newPayload(t),
		}
		if err := pub.PublishEnvelope(ctx, env, sngnats.PublishOptions{}); err != nil {
			t.Fatalf("publish %d: %v", i, err)
		}
	}

	// Wait until every published event has been Ack'd (written or
	// sampled-dropped; both Ack).
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if svc.MetricsSnapshot().Acked >= total {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)

	m := svc.MetricsSnapshot()
	written := hot.Snapshot()

	if m.Sampled == 0 {
		t.Fatal("expected some events to be sampled (dropped), got 0")
	}
	if len(written) == 0 {
		t.Fatal("expected some events to be written, got 0")
	}
	// Conservation: every decoded event was either written or sampled.
	if uint64(len(written))+m.Sampled != uint64(total) {
		t.Errorf("written(%d) + sampled(%d) = %d, want %d",
			len(written), m.Sampled, uint64(len(written))+m.Sampled, total)
	}
	// At keepProb 0.5 roughly half survive — assert a generous band so
	// the test asserts the wiring, not the RNG.
	if len(written) < total/4 || len(written) > 3*total/4 {
		t.Errorf("written = %d, want roughly half of %d", len(written), total)
	}
	// Every kept event must carry the 0.5 de-bias rate.
	for _, env := range written {
		if env.SampleRate != 0.5 {
			t.Fatalf("kept event %s has SampleRate %v, want 0.5", env.EventID, env.SampleRate)
		}
	}
}
