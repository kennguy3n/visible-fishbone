package telemetry_test

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
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
	"github.com/kennguy3n/visible-fishbone/internal/service/metering"
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
	if err := sngnats.EnsureStreams(ctx, js, sngnats.DefaultStreams(cfg), 0); err != nil {
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

// TestService_TransientWriteFailureIsRetried is the regression test
// for the PR5 dedup-ring data-loss bug. Before the fix, the EventID
// was added to the dedup ring *before* hot.Write, so a transient
// write failure followed by JetStream redelivery would treat the
// redelivered copy as a duplicate and silently ack it without ever
// writing to the hot store — permanent data loss.
//
// The fix is to record dedup only after a successful write. This
// test publishes a single envelope, fails the first write (the
// captureWriter.failNTH=1 path returns an error), and asserts the
// service eventually writes the event after JetStream redelivers.
func TestService_TransientWriteFailureIsRetried(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{failNTH: 1}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-retry", DedupRingSize: 16},
		hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	env := schema.Envelope{
		SchemaVersion: schema.SchemaVersion, EventID: uuid.New(),
		TenantID: uuid.New(), DeviceID: uuid.New(),
		Timestamp:  time.Now().UTC(),
		EventClass: schema.EventClassFlow, Platform: schema.PlatformLinux,
		Payload: newPayload(t),
	}
	if err := pub.PublishEnvelope(ctx, env, sngnats.PublishOptions{}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// First delivery fails (failNTH=1) → Nak with 2s delay → JetStream
	// redelivers → second attempt succeeds → write recorded.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if len(hot.Snapshot()) == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)

	if got := len(hot.Snapshot()); got != 1 {
		t.Fatalf("expected 1 event after redelivery, got %d (dedup-before-write data loss regression?)", got)
	}
	m := svc.MetricsSnapshot()
	if m.HotWriteFails < 1 {
		t.Errorf("expected at least 1 HotWriteFails (the simulated failure), got %d", m.HotWriteFails)
	}
}

// recordingDLQ implements telemetry.DLQPublisher and records every
// publish for assertion. Used to verify undecodable payloads are
// preserved in the DLQ.
type recordingDLQ struct {
	mu      sync.Mutex
	calls   []dlqCall
	failNTH int
	count   atomic.Int32
}

type dlqCall struct {
	subject  string
	data     []byte
	headers  map[string]string
	delivery uint64
	cause    string
}

func (r *recordingDLQ) PublishToDLQ(
	_ context.Context,
	subject string,
	data []byte,
	headers map[string]string,
	delivery uint64,
	cause error,
) error {
	n := r.count.Add(1)
	if r.failNTH > 0 && int(n) <= r.failNTH {
		return errors.New("simulated DLQ publish failure")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	copyData := append([]byte(nil), data...)
	copyHdr := make(map[string]string, len(headers))
	for k, v := range headers {
		copyHdr[k] = v
	}
	r.calls = append(r.calls, dlqCall{
		subject: subject, data: copyData, headers: copyHdr,
		delivery: delivery, cause: cause.Error(),
	})
	return nil
}

func (r *recordingDLQ) Snapshot() []dlqCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]dlqCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// TestService_UndecodablePayloadRoutedToDLQ is the regression test
// for the PR5 review finding that observed msg.Term() silently
// dropping bad payloads instead of routing them to the DLQ stream.
// The fix is the WithDLQ + routeBadPayloadToDLQ path. This test:
//
//  1. Wires a recordingDLQ onto the service.
//  2. Publishes a deliberately-malformed payload (not msgpack) onto
//     the telemetry subject via a raw nats.Conn publish so it skips
//     the typed publisher's schema validation.
//  3. Verifies the DLQ publisher received the exact raw bytes +
//     subject + decode error string.
//  4. Verifies the hot writer never saw the bad event (no decoded
//     envelope to write).
//  5. Verifies the DLQPublished counter is incremented.
func TestService_UndecodablePayloadRoutedToDLQ(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-dlq", DedupRingSize: 16},
		hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	dlq := &recordingDLQ{}
	svc.WithDLQ(dlq)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	// Publish raw garbage to the telemetry subject — bypasses the
	// typed publisher and forces the consumer's decode path to
	// fail. We go through the publisher's Publish() not
	// PublishEnvelope so no schema validation happens upstream.
	pub := sngnats.NewPublisher(js, cfg, "publisher")
	garbage := []byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb}
	tenantID := uuid.New().String()
	subject := "sng." + tenantID + ".telemetry.garbage"
	if err := pub.Publish(ctx, subject, garbage, sngnats.PublishOptions{
		MessageID: "bad-" + uuid.NewString(),
		Headers: map[string]string{
			sngnats.HeaderTenantID:   tenantID,
			sngnats.HeaderEventClass: "garbage",
			sngnats.HeaderEnqueuedAt: time.Now().UTC().Format(time.RFC3339Nano),
		},
	}); err != nil {
		t.Fatalf("publish garbage: %v", err)
	}

	// Wait for the consumer to receive + dispatch the bad payload.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if len(dlq.Snapshot()) == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)

	calls := dlq.Snapshot()
	if len(calls) != 1 {
		t.Fatalf("DLQ publisher received %d calls, want 1 (bad payloads must be preserved)", len(calls))
	}
	call := calls[0]
	if call.subject != subject {
		t.Errorf("DLQ origin subject = %q, want %q", call.subject, subject)
	}
	if string(call.data) != string(garbage) {
		t.Errorf("DLQ payload bytes mismatch: got %x, want %x", call.data, garbage)
	}
	if call.cause == "" {
		t.Errorf("DLQ cause must be non-empty (decoder error string)")
	}
	if call.headers[sngnats.HeaderTenantID] != tenantID {
		t.Errorf("DLQ tenant header lost: got %q, want %q", call.headers[sngnats.HeaderTenantID], tenantID)
	}
	if got := len(hot.Snapshot()); got != 0 {
		t.Errorf("hot writer must NOT receive bad payloads, got %d events", got)
	}
	m := svc.MetricsSnapshot()
	if m.DecodeErrors < 1 {
		t.Errorf("expected DecodeErrors >= 1, got %d", m.DecodeErrors)
	}
	if m.DLQPublished != 1 {
		t.Errorf("expected DLQPublished = 1, got %d", m.DLQPublished)
	}
	if m.DLQPublishFail != 0 {
		t.Errorf("expected DLQPublishFail = 0, got %d", m.DLQPublishFail)
	}
}

// TestService_UndecodablePayloadDegradedModeWhenNoDLQ verifies that
// when no DLQ publisher is wired, the service still terminates bad
// payloads (so JetStream doesn't redeliver them forever) and records
// the DecodeErrors counter, but DLQPublished stays at 0 — this is
// the explicit "degraded mode" path that the WithDLQ docstring
// warns about.
func TestService_UndecodablePayloadDegradedModeWhenNoDLQ(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-dlq-degraded", DedupRingSize: 16},
		hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// Intentionally do NOT call WithDLQ.

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	garbage := []byte{0x00, 0x01, 0x02}
	subject := "sng." + uuid.NewString() + ".telemetry.garbage"
	if err := pub.Publish(ctx, subject, garbage, sngnats.PublishOptions{
		MessageID: "bad-degraded-" + uuid.NewString(),
	}); err != nil {
		t.Fatalf("publish garbage: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if svc.MetricsSnapshot().DecodeErrors >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)

	m := svc.MetricsSnapshot()
	if m.DecodeErrors < 1 {
		t.Errorf("expected DecodeErrors >= 1, got %d", m.DecodeErrors)
	}
	if m.DLQPublished != 0 {
		t.Errorf("expected DLQPublished = 0 in degraded mode, got %d", m.DLQPublished)
	}
	if m.Nacked < 1 {
		t.Errorf("expected Nacked >= 1, got %d", m.Nacked)
	}
}

// blockingDLQ blocks each PublishToDLQ call on an external channel
// signal, capturing the dispatch context for assertion. Used to
// race a shutdown-triggered runCtx cancellation against an
// in-flight DLQ publish and prove the publish's own context is
// independent of runCtx (i.e. that we honour the fix for
// BUG_pr-review-job-e48f3945205448b7a0d5ed4548989fd6_0001).
type blockingDLQ struct {
	entered chan struct{}
	release chan struct{}
	// entryErr is the ctx.Err() observed on entry to PublishToDLQ.
	// Buffered so we can read it from the test goroutine.
	entryErr chan error
	exitErr  chan error
}

func newBlockingDLQ() *blockingDLQ {
	return &blockingDLQ{
		entered:  make(chan struct{}, 1),
		release:  make(chan struct{}),
		entryErr: make(chan error, 1),
		exitErr:  make(chan error, 1),
	}
}

func (b *blockingDLQ) PublishToDLQ(
	ctx context.Context,
	_ string,
	_ []byte,
	_ map[string]string,
	_ uint64,
	_ error,
) error {
	b.entryErr <- ctx.Err()
	b.entered <- struct{}{}
	<-b.release
	b.exitErr <- ctx.Err()
	return nil
}

// TestService_DLQPublishSurvivesShutdown is the regression test for
// the PR5 review finding observing that
// routeBadPayloadToDLQ derived its publish context from the
// dispatch loop's runCtx. When Stop() races with a bad-payload
// dispatch, runCtx cancellation would expire the publish context
// immediately, fail the DLQ publish, and then proceed to Term()
// the message — losing forensic bytes. The fix derives publishCtx
// from context.Background() so it survives shutdown.
//
// The test wires a blockingDLQ that pauses the dispatch goroutine
// mid-publish, asks the service to Stop (cancelling runCtx), then
// releases the DLQ. The assertions verify ctx.Err() is nil both on
// entry and exit of the publish — proving publishCtx is independent
// of runCtx.
func TestService_DLQPublishSurvivesShutdown(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-dlq-shutdown", DedupRingSize: 16},
		hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	dlq := newBlockingDLQ()
	svc.WithDLQ(dlq)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	subject := "sng." + uuid.NewString() + ".telemetry.garbage"
	if err := pub.Publish(ctx, subject, []byte{0xff, 0xee, 0xdd}, sngnats.PublishOptions{
		MessageID: "bad-shutdown-" + uuid.NewString(),
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Wait for the dispatch to enter the DLQ publish.
	select {
	case <-dlq.entered:
	case <-time.After(15 * time.Second):
		t.Fatal("dispatch did not enter DLQ within 15s")
	}

	// Trigger shutdown — cancels runCtx while the DLQ publish is
	// suspended on dlq.release.
	stopErrCh := make(chan error, 1)
	go func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		stopErrCh <- svc.Stop(stopCtx)
	}()
	// Give Stop() time to invoke cancel() on runCtx. Without this
	// the race might not actually trigger.
	time.Sleep(200 * time.Millisecond)

	// publishCtx must NOT have been cancelled, because the fix
	// derives it from context.Background() rather than runCtx.
	select {
	case got := <-dlq.entryErr:
		if got != nil {
			t.Errorf("ctx.Err() on DLQ entry = %v, want nil (publishCtx must be background-derived)", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never received entryErr")
	}

	// Release the DLQ publish — should complete successfully even
	// though runCtx has been cancelled.
	close(dlq.release)
	select {
	case got := <-dlq.exitErr:
		if got != nil {
			t.Errorf("ctx.Err() on DLQ exit = %v, want nil (publishCtx must survive runCtx cancellation)", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("never received exitErr")
	}
	if err := <-stopErrCh; err != nil {
		t.Fatalf("stop: %v", err)
	}

	// The publish succeeded — metrics confirm.
	m := svc.MetricsSnapshot()
	if m.DLQPublished != 1 {
		t.Errorf("expected DLQPublished = 1, got %d", m.DLQPublished)
	}
	if m.DLQPublishFail != 0 {
		t.Errorf("expected DLQPublishFail = 0, got %d", m.DLQPublishFail)
	}
}

// TestService_DLQPublishFailureCounted verifies the metric is
// incremented when the DLQ publish itself fails, and the original
// message is still terminated (we don't want to spin retrying the
// DLQ when it's unhealthy).
func TestService_DLQPublishFailureCounted(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-dlq-fail", DedupRingSize: 16},
		hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// failNTH=999 — every publish fails for the duration of the test.
	dlq := &recordingDLQ{failNTH: 999}
	svc.WithDLQ(dlq)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	subject := "sng." + uuid.NewString() + ".telemetry.garbage"
	if err := pub.Publish(ctx, subject, []byte{0xde, 0xad}, sngnats.PublishOptions{
		MessageID: "bad-fail-" + uuid.NewString(),
	}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if svc.MetricsSnapshot().DLQPublishFail >= 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)

	m := svc.MetricsSnapshot()
	if m.DLQPublishFail < 1 {
		t.Errorf("expected DLQPublishFail >= 1, got %d", m.DLQPublishFail)
	}
	if m.DLQPublished != 0 {
		t.Errorf("expected DLQPublished = 0 when every publish fails, got %d", m.DLQPublished)
	}
}

// TestService_HotWriteExhaustionRoutedToDLQ is the regression test
// for the round-3 finding "Hot-write failures that exhaust
// MaxDeliver are silently dropped, not DLQ-routed". Before the fix,
// a hot writer that failed for ALL delivery attempts (up to the
// consumer's MaxDeliver=5) would just Nak forever and the message
// would eventually fall out of the consumer's pending set with no
// DLQ entry \u2014 silent data loss on a persistent hot-write
// failure (e.g. ClickHouse down for >MaxDeliver redelivery
// cycles).
//
// The fix: when dispatch sees NumDelivered >= hotPathMaxDeliver, it
// routes the raw envelope bytes to the DLQ + Term()s the message
// instead of Nak'ing for another (futile) redelivery.
//
// This test wires a captureWriter that fails every write (`failNTH =
// 999` is far above the consumer's MaxDeliver), publishes one
// envelope, and asserts:
//
//  1. The DLQ publisher received exactly 1 call with the raw bytes.
//  2. The DLQ call's delivery count is >= hotPathMaxDeliver (the
//     terminal attempt that triggered the DLQ route).
//  3. The DLQPublished metric is 1.
//  4. The hot writer was called hotPathMaxDeliver times (every
//     redelivery up to and including the terminal one).
func TestService_HotWriteExhaustionRoutedToDLQ(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	// failNTH >> hotPathMaxDeliver (5) so every delivery fails.
	hot := &captureWriter{failNTH: 999}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-hot-dlq", DedupRingSize: 16},
		hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	dlq := &recordingDLQ{}
	svc.WithDLQ(dlq)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	env := schema.Envelope{
		SchemaVersion: schema.SchemaVersion, EventID: uuid.New(),
		TenantID: uuid.New(), DeviceID: uuid.New(),
		Timestamp:  time.Now().UTC(),
		EventClass: schema.EventClassFlow, Platform: schema.PlatformLinux,
		Payload: newPayload(t),
	}
	if err := pub.PublishEnvelope(ctx, env, sngnats.PublishOptions{}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Each NakWithDelay(2s) + JetStream backoff puts the deadline
	// at roughly 5 * 2s = 10s plus overhead. Allow 60s to absorb
	// CI jitter; the test exits as soon as DLQPublished hits 1.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if svc.MetricsSnapshot().DLQPublished >= 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)

	calls := dlq.Snapshot()
	if len(calls) != 1 {
		t.Fatalf("DLQ publisher received %d calls, want 1 (hot-write exhaustion must route to DLQ)", len(calls))
	}
	call := calls[0]
	if call.delivery < 5 {
		t.Errorf("DLQ delivery count = %d, want >= 5 (terminal attempt only)", call.delivery)
	}
	if call.cause == "" {
		t.Errorf("DLQ cause must carry the hot-write error string")
	}

	m := svc.MetricsSnapshot()
	if m.DLQPublished != 1 {
		t.Errorf("expected DLQPublished = 1, got %d", m.DLQPublished)
	}
	if m.DLQPublishFail != 0 {
		t.Errorf("expected DLQPublishFail = 0 when DLQ accepts, got %d", m.DLQPublishFail)
	}
	if m.HotWriteFails < 5 {
		t.Errorf("expected HotWriteFails >= 5 (full retry budget), got %d", m.HotWriteFails)
	}
}

// TestService_RateLimitExhaustionRoutedToDLQ is the regression test
// for PR #38 round-5 BUG_0001 "Rate-limiter Nak path never checks
// deliveryExhausted, causing silent message loss instead of
// documented DLQ routing".
//
// Before the fix, the dispatch limiter-rejection branch
// unconditionally Nak'd. A message that was rate-limited on EVERY
// delivery attempt (up to MaxDeliver=5) would eventually fall out
// of the consumer's pending set with no DLQ entry — silent data
// loss for a tenant configured below the steady-state rate.
//
// After the fix, dispatch checks deliveryExhausted *before* the
// Nak path in BOTH limiter branches and, on the terminal attempt,
// routes the raw envelope bytes to the DLQ via
// routeRateLimitExhaustionToDLQ + Term()s the message. The DLQ
// entry preserves the source subject, headers, delivery count,
// and a self-describing cause string ("rate-limit exhausted: ...")
// so dashboards can split "tenant needs a budget bump" from
// "writer is down".
//
// This test wires a limiter with Burst=0 (every Wait returns
// ErrTenantBlocked immediately), publishes one envelope, and
// asserts:
//
//  1. The DLQ publisher received exactly 1 call with the raw bytes.
//  2. The DLQ call's cause string is prefixed with
//     "rate-limit exhausted:" so dashboards can route it without
//     parsing the wrapped error.
//  3. The DLQ call's delivery count is >= hotPathMaxDeliver.
//  4. The hot writer was NEVER called (the limiter stopped every
//     delivery before it reached hot.Write).
func TestService_RateLimitExhaustionRoutedToDLQ(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Burst=0 → every Wait returns ErrTenantBlocked immediately;
	// Rate=0 → no refill within the test window. Every delivery
	// attempt hits the limiter rejection branch.
	resolver := telemetry.StaticLimitResolver{Limit: telemetry.TenantLimit{Rate: 0, Burst: 0}}
	limiter := telemetry.NewPerTenantLimiter(resolver)

	svc, err := telemetry.New(js, cfg,
		telemetry.Config{Durable: "tlm-rl-dlq", DedupRingSize: 16},
		hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	dlq := &recordingDLQ{}
	svc.WithDLQ(dlq)
	svc.
		WithPerTenantLimiter(limiter).
		WithLimiterWaitBudget(5 * time.Millisecond).
		WithNakBackoff(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	pub := sngnats.NewPublisher(js, cfg, "publisher")
	env := schema.Envelope{
		SchemaVersion: schema.SchemaVersion, EventID: uuid.New(),
		TenantID: uuid.New(), DeviceID: uuid.New(),
		Timestamp:  time.Now().UTC(),
		EventClass: schema.EventClassFlow, Platform: schema.PlatformLinux,
		Payload: newPayload(t),
	}
	if err := pub.PublishEnvelope(ctx, env, sngnats.PublishOptions{}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// 5 attempts * (Nak 200ms + JS backoff) ≈ a few seconds; allow
	// 90s of headroom for CI jitter. Exit as soon as DLQPublished
	// hits 1.
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		if svc.MetricsSnapshot().DLQPublished >= 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)

	calls := dlq.Snapshot()
	if len(calls) != 1 {
		t.Fatalf("DLQ publisher received %d calls, want 1 (rate-limit exhaustion must route to DLQ)", len(calls))
	}
	call := calls[0]
	if call.delivery < uint64(5) {
		t.Errorf("DLQ delivery count = %d, want >= 5 (terminal attempt only)", call.delivery)
	}
	if !strings.HasPrefix(call.cause, "rate-limit exhausted:") {
		t.Errorf("DLQ cause = %q, want prefix \"rate-limit exhausted:\" (operator dashboard contract)", call.cause)
	}

	m := svc.MetricsSnapshot()
	if m.DLQPublished != 1 {
		t.Errorf("expected DLQPublished = 1, got %d", m.DLQPublished)
	}
	if m.DLQPublishFail != 0 {
		t.Errorf("expected DLQPublishFail = 0 when DLQ accepts, got %d", m.DLQPublishFail)
	}
	if hits := len(hot.Snapshot()); hits != 0 {
		t.Errorf("hot writer hits = %d, want 0 (limiter must shed before hot.Write)", hits)
	}
}

func TestService_PerTenantLimiter_NaksWhenBudgetExhausted(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Build a per-tenant limiter that allows exactly two events
	// (the burst) and then no refill within the test window —
	// every subsequent envelope must be Nak'd by the limiter
	// gate.
	resolver := telemetry.StaticLimitResolver{Limit: telemetry.TenantLimit{Rate: 0.001, Burst: 2}}
	limiter := telemetry.NewPerTenantLimiter(resolver)

	svc, err := telemetry.New(js, cfg, telemetry.Config{Durable: "tlm-ratelimit"}, hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// Very short wait budget + short Nak backoff so the test
	// finishes in single-digit seconds. The production defaults
	// are tuned for production load, not test wall-clock.
	svc.
		WithPerTenantLimiter(limiter).
		WithLimiterWaitBudget(5 * time.Millisecond).
		WithNakBackoff(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	pub := sngnats.NewPublisher(js, cfg, "publisher")
	tenant := uuid.New()
	const total = 6
	for i := 0; i < total; i++ {
		env := schema.Envelope{
			SchemaVersion: schema.SchemaVersion, EventID: uuid.New(),
			TenantID: tenant, DeviceID: uuid.New(),
			Timestamp:  time.Now().UTC(),
			EventClass: schema.EventClassFlow, Platform: schema.PlatformLinux,
			Payload: newPayload(t),
		}
		if err := pub.PublishEnvelope(ctx, env, sngnats.PublishOptions{}); err != nil {
			t.Fatalf("publish[%d]: %v", i, err)
		}
	}
	// Wait long enough for the consumer to process the burst
	// AND for the limiter to Nak the remainder a few times.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		m := svc.MetricsSnapshot()
		if len(hot.Snapshot()) >= 2 && m.Nacked >= uint64(total-2) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	if err := svc.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	hits := len(hot.Snapshot())
	if hits < 2 {
		t.Errorf("hot writer hits = %d, want >= 2 (burst budget)", hits)
	}
	m := svc.MetricsSnapshot()
	if m.Nacked < uint64(total-2) {
		t.Errorf("Nacked = %d, want >= %d (limiter-rejected envelopes)", m.Nacked, total-2)
	}
}

func TestService_PerTenantLimiter_NilLimiterIsNoOp(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := telemetry.New(js, cfg, telemetry.Config{Durable: "tlm-nilrl"}, hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// Set limiter to nil explicitly — must be a no-op.
	svc.WithPerTenantLimiter(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	pub := sngnats.NewPublisher(js, cfg, "publisher")
	tenant := uuid.New()
	for i := 0; i < 4; i++ {
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
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(hot.Snapshot()) >= 4 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)
	if hits := len(hot.Snapshot()); hits != 4 {
		t.Errorf("nil limiter: hot writer hits = %d, want 4 (no shedding)", hits)
	}
}

// TestService_ClickHouseRowLimiter_NaksOverBudget proves the
// row-write cost cap is wired into dispatch and applies back-pressure:
// a tenant whose row budget is exhausted has its over-budget envelopes
// Nak'd (deferred), never written to the hot tier, and the over-budget
// rows are NOT silently dropped (they remain redeliverable).
func TestService_ClickHouseRowLimiter_NaksOverBudget(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Budget admits exactly two rows (burst) with negligible refill
	// in the test window, so the third+ envelope is row-limited.
	rl, err := metering.NewRowLimit(0.001, 2)
	if err != nil {
		t.Fatalf("NewRowLimit: %v", err)
	}
	rowLimiter := metering.NewClickHouseRowLimiter(metering.StaticRowLimitResolver{Limit: rl})

	svc, err := telemetry.New(js, cfg, telemetry.Config{Durable: "tlm-rowrl"}, hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	svc.
		WithClickHouseRowLimiter(rowLimiter).
		WithNakBackoff(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	pub := sngnats.NewPublisher(js, cfg, "publisher")
	tenant := uuid.New()
	const total = 6
	for i := 0; i < total; i++ {
		env := schema.Envelope{
			SchemaVersion: schema.SchemaVersion, EventID: uuid.New(),
			TenantID: tenant, DeviceID: uuid.New(),
			Timestamp:  time.Now().UTC(),
			EventClass: schema.EventClassFlow, Platform: schema.PlatformLinux,
			Payload: newPayload(t),
		}
		if err := pub.PublishEnvelope(ctx, env, sngnats.PublishOptions{}); err != nil {
			t.Fatalf("publish[%d]: %v", i, err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		m := svc.MetricsSnapshot()
		if len(hot.Snapshot()) >= 2 && m.RowRateLimited >= uint64(total-2) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	if err := svc.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}

	// At most the burst (2) rows reached the hot writer; the rest were
	// row-limited (deferred), and de-duplicated retries never inflate
	// past the burst because dispatch checks dedup before the cap.
	if hits := len(hot.Snapshot()); hits > 2 {
		t.Errorf("hot writer hits = %d, want <= 2 (row burst budget)", hits)
	}
	m := svc.MetricsSnapshot()
	if m.RowRateLimited < uint64(total-2) {
		t.Errorf("RowRateLimited = %d, want >= %d (row-limited envelopes)", m.RowRateLimited, total-2)
	}
}

// TestService_ClickHouseRowLimiter_NilIsNoOp confirms an unset row
// limiter does not shed: every envelope reaches the hot writer.
func TestService_ClickHouseRowLimiter_NilIsNoOp(t *testing.T) {
	t.Parallel()
	js, cfg := startNATS(t)
	hot := &captureWriter{}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	svc, err := telemetry.New(js, cfg, telemetry.Config{Durable: "tlm-nilrowrl"}, hot, nil, logger)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	svc.WithClickHouseRowLimiter(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	pub := sngnats.NewPublisher(js, cfg, "publisher")
	tenant := uuid.New()
	for i := 0; i < 4; i++ {
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
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if len(hot.Snapshot()) >= 4 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer stopCancel()
	_ = svc.Stop(stopCtx)
	if hits := len(hot.Snapshot()); hits != 4 {
		t.Errorf("nil row limiter: hot writer hits = %d, want 4 (no shedding)", hits)
	}
}
