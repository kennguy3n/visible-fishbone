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

// TestService_SamplingDoesNotDropRedeliveredEvent is a regression test
// for the sampler/redelivery interaction: an event admitted by the
// sampler on its first delivery whose hot write transiently fails is
// redelivered, and by then the tenant's keep probability may have
// fallen (rate rose). Re-sampling that redelivery against the lower
// probability could drop an already-admitted event for good — the
// dedup ring cannot save it because it only records events that
// reached a *successful* hot write. The fix samples only first
// deliveries; this test forces exactly that race and asserts the
// redelivered event is still written.
func TestService_SamplingDoesNotDropRedeliveredEvent(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	// failNTH=1: the first hot write fails → Nak (2s) → redeliver.
	hot := &captureWriter{failNTH: 1}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	const (
		budget   = rate.Limit(1000)
		window   = time.Second
		overload = 50000 // arrivals/window → far over budget → floor keepProb
	)
	clk := &e2eClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	sampler := telemetry.NewAdaptiveSampler(telemetry.SamplerConfig{
		Resolver: telemetry.StaticLimitResolver{Limit: telemetry.TenantLimit{Rate: budget, Burst: int(budget)}},
		Window:   window,
		NowFunc:  clk.now,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// Pick an event ID that a *fresh* sampling decision at the min-rate
	// floor (0.05) would DROP. hashFraction is a pure function of the
	// UUID, so an independent probe sampler pinned to the floor
	// classifies exactly as the real sampler will on redelivery.
	probeClk := &e2eClock{t: clk.now()}
	probe := telemetry.NewAdaptiveSampler(telemetry.SamplerConfig{
		Resolver: telemetry.StaticLimitResolver{Limit: telemetry.TenantLimit{Rate: budget, Burst: int(budget)}},
		Window:   window,
		NowFunc:  probeClk.now,
	})
	probeTenant := uuid.New()
	for i := 0; i < overload; i++ {
		probe.Decide(ctx, probeTenant, uuid.New())
	}
	probeClk.advance(window) // next Decide rolls into the floor-keepProb window
	tenant := uuid.New()
	var event schema.Envelope
	for {
		id := uuid.New()
		if keep, _ := probe.Decide(ctx, probeTenant, id); !keep {
			event = schema.Envelope{
				SchemaVersion: schema.SchemaVersion, EventID: id,
				TenantID: tenant, DeviceID: uuid.New(),
				Timestamp:  time.Now().UTC(),
				EventClass: schema.EventClassFlow, Platform: schema.PlatformLinux,
				Payload: newPayload(t),
			}
			break
		}
	}

	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-sample-redeliver", DedupRingSize: 16},
		hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	svc.WithSampler(sampler)
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	if err := pub.PublishEnvelope(ctx, event, sngnats.PublishOptions{}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// First delivery: the tenant has no history, so keepProb is 1.0 and
	// the event is admitted; the hot write then fails and the message is
	// Nak'd. Wait for that failure before driving the rate up.
	failDeadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(failDeadline) {
		if svc.MetricsSnapshot().HotWriteFails >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if svc.MetricsSnapshot().HotWriteFails < 1 {
		t.Fatal("first delivery never reached the (failing) hot writer")
	}

	// Drive the tenant far over budget so a fresh sampling decision would
	// clamp to the 0.05 floor and drop our chosen event. Inject arrivals
	// into the just-closed window, then advance one window so the pending
	// redelivery rolls into the floor-keepProb window. This all happens
	// inside the 2s Nak backoff, before the redelivery lands.
	for i := 0; i < overload; i++ {
		sampler.Decide(ctx, tenant, uuid.New())
	}
	clk.advance(window)

	// The redelivery (NumDelivered=2) must bypass the sampler and be
	// written. Without the first-delivery-only guard it would be
	// sampled-dropped here and never written.
	writeDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(writeDeadline) {
		if len(hot.Snapshot()) == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)

	written := hot.Snapshot()
	if len(written) != 1 {
		t.Fatalf("redelivered event was dropped by the sampler (got %d writes, want 1): "+
			"the sampler must not re-evaluate an already-admitted redelivery", len(written))
	}
	if m := svc.MetricsSnapshot(); m.Sampled != 0 {
		t.Errorf("redelivered event must not be counted as a sampling drop, Sampled=%d", m.Sampled)
	}
	// It was admitted at full rate on its first delivery, so it carries
	// no de-bias rate (SampleRate 0 is interpreted downstream as 1.0).
	if written[0].SampleRate != 0 {
		t.Errorf("redelivered event SampleRate = %v, want 0 (admitted at full rate)", written[0].SampleRate)
	}
}

// TestService_RedeliveryPreservesSubUnitySampleRate is the companion
// regression test to the one above: when an event is admitted at a
// keep probability < 1.0 on its first delivery, the SampleRate stamped
// then lives only on the in-memory envelope. If the hot write fails
// and the event is redelivered, the redelivered copy is re-decoded
// from the producer's wire bytes (which never carry SampleRate), so a
// redelivery path that merely skips the sampler would write the event
// with SampleRate 0 — interpreted downstream as 1.0 — silently
// dropping the 1/rate de-bias weight and under-counting the tenant's
// true volume. The fix re-stamps the tenant's current keep probability
// on redelivery (read-only, recording no arrival). This test pins the
// tenant to keepProb 0.5, admits a kept event, fails its first write,
// and asserts the redelivered event is written carrying SampleRate
// 0.5 rather than 0.
func TestService_RedeliveryPreservesSubUnitySampleRate(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{failNTH: 1} // first write fails → Nak → redeliver
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	const (
		budget = rate.Limit(1000)
		window = time.Second
		prime  = 2000 // arrivals/window → keepProb = 1000/2000 = 0.5
	)
	clk := &e2eClock{t: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)}
	sampler := telemetry.NewAdaptiveSampler(telemetry.SamplerConfig{
		Resolver: telemetry.StaticLimitResolver{Limit: telemetry.TenantLimit{Rate: budget, Burst: int(budget)}},
		Window:   window,
		NowFunc:  clk.now,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	// Pick an event ID that a decision at keepProb 0.5 KEEPS (admitted
	// on first delivery). hashFraction is pure, so an independent probe
	// sampler pinned to 0.5 classifies exactly as the real sampler will.
	probeClk := &e2eClock{t: clk.now()}
	probe := telemetry.NewAdaptiveSampler(telemetry.SamplerConfig{
		Resolver: telemetry.StaticLimitResolver{Limit: telemetry.TenantLimit{Rate: budget, Burst: int(budget)}},
		Window:   window,
		NowFunc:  probeClk.now,
	})
	probeTenant := uuid.New()
	for i := 0; i < prime; i++ {
		probe.Decide(ctx, probeTenant, uuid.New())
	}
	probeClk.advance(window) // next Decide rolls into the 0.5-keepProb window
	tenant := uuid.New()
	var event schema.Envelope
	for {
		id := uuid.New()
		if keep, sr := probe.Decide(ctx, probeTenant, id); keep && sr == 0.5 {
			event = schema.Envelope{
				SchemaVersion: schema.SchemaVersion, EventID: id,
				TenantID: tenant, DeviceID: uuid.New(),
				Timestamp:  time.Now().UTC(),
				EventClass: schema.EventClassFlow, Platform: schema.PlatformLinux,
				Payload: newPayload(t),
			}
			break
		}
	}

	// Pin the real tenant to keepProb 0.5 the same way: feed window-1
	// arrivals then advance one window, so the consumer's first Decide
	// rolls and computes 0.5. The clock then stays put, so the rate
	// recovered on redelivery is exactly 0.5.
	for i := 0; i < prime; i++ {
		sampler.Decide(ctx, tenant, uuid.New())
	}
	clk.advance(window)

	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-sample-sr-redeliver", DedupRingSize: 16},
		hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	svc.WithSampler(sampler)
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	if err := pub.PublishEnvelope(ctx, event, sngnats.PublishOptions{}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// First delivery: keepProb 0.5, the event is kept and stamped 0.5,
	// then the hot write fails and the message is Nak'd. Redelivery
	// (NumDelivered=2) bypasses the keep/drop decision but must re-stamp
	// the 0.5 rate before the (now succeeding) write.
	writeDeadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(writeDeadline) {
		if len(hot.Snapshot()) == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)

	written := hot.Snapshot()
	if len(written) != 1 {
		t.Fatalf("expected the redelivered event to be written exactly once, got %d", len(written))
	}
	if m := svc.MetricsSnapshot(); m.Sampled != 0 {
		t.Errorf("redelivered event must not be counted as a sampling drop, Sampled=%d", m.Sampled)
	}
	if written[0].SampleRate != 0.5 {
		t.Errorf("redelivered event SampleRate = %v, want 0.5 (de-bias weight must survive redelivery)",
			written[0].SampleRate)
	}
}
