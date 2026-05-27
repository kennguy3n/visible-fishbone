package telemetry_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry"
)

func startNATS(t *testing.T) (jetstream.JetStream, *config.NATS) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "js")
	opts := &natsserver.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: dir, NoSigs: true,
	}
	srv, err := natsserver.NewServer(opts)
	if err != nil {
		t.Fatalf("nats server: %v", err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatalf("not ready")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })

	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { nc.Close() })

	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatalf("js: %v", err)
	}
	cfg := &config.NATS{
		StreamPrefix:   "TEST",
		Replicas:       1,
		Storage:        "memory",
		DedupWindow:    2 * time.Minute,
		FetchBatchSize: 10,
		FetchMaxWait:   100 * time.Millisecond,
		RequestTimeout: 2 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sngnats.EnsureStreams(ctx, js, sngnats.DefaultStreams(cfg)); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	return js, cfg
}

type captureWriter struct {
	mu      sync.Mutex
	events  []schema.Envelope
	failNTH int
	count   atomic.Int32
}

func (c *captureWriter) Write(_ context.Context, env schema.Envelope) error {
	n := c.count.Add(1)
	if c.failNTH > 0 && int(n) <= c.failNTH {
		return errors.New("simulated hot-path failure")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, env)
	return nil
}

func (c *captureWriter) Snapshot() []schema.Envelope {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]schema.Envelope, len(c.events))
	copy(out, c.events)
	return out
}

func newPayload(t *testing.T) []byte {
	t.Helper()
	b, err := schema.PackPayload(schema.FlowEvent{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 80, DstPort: 8080,
		Protocol: "tcp", Verdict: schema.VerdictAllow,
	})
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return b
}

func TestService_PublishConsume(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := telemetry.New(js, cfg, telemetry.Config{Durable: "tlm-test"}, hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	tenant := uuid.New()
	for i := 0; i < 5; i++ {
		env := schema.Envelope{
			SchemaVersion: schema.SchemaVersion, EventID: uuid.New(),
			TenantID: tenant, DeviceID: uuid.New(),
			Timestamp:  time.Now().UTC(),
			EventClass: schema.EventClassFlow, Platform: schema.PlatformLinux,
			Payload: newPayload(t),
		}
		if err := pub.PublishEnvelope(ctx, env, sngnats.PublishOptions{}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}

	// Wait for the consumer to drain.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(hot.Snapshot()) == 5 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	if err := svc.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	if got := len(hot.Snapshot()); got != 5 {
		t.Errorf("hot writer received %d, want 5", got)
	}
	m := svc.MetricsSnapshot()
	if m.Received < 5 || m.Decoded < 5 || m.Acked < 5 {
		t.Errorf("metrics: %+v", m)
	}
}

func TestService_DedupRingDropsDuplicates(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-dedup", DedupRingSize: 16},
		hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	tenant := uuid.New()
	device := uuid.New()
	id := uuid.New()
	for i := 0; i < 3; i++ {
		env := schema.Envelope{
			SchemaVersion: schema.SchemaVersion, EventID: id,
			TenantID: tenant, DeviceID: device,
			Timestamp:  time.Now().UTC(),
			EventClass: schema.EventClassFlow, Platform: schema.PlatformLinux,
			Payload: newPayload(t),
		}
		// Force the dedup at publish time too via the message ID.
		if err := pub.PublishEnvelope(ctx, env,
			sngnats.PublishOptions{MessageID: id.String() + "-" + uuidNew()}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		m := svc.MetricsSnapshot()
		if m.Received >= 3 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)

	if got := len(hot.Snapshot()); got != 1 {
		t.Errorf("expected 1 unique event after dedup, got %d", got)
	}
}

func uuidNew() string { return uuid.NewString() }
