package nats_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"

	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

func TestPublisher_PublishAndConsume(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	cfg := defaultNATSConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sngnats.EnsureStreams(ctx, js, sngnats.DefaultStreams(cfg), 0); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}
	pub := sngnats.NewPublisher(js, cfg, "sng-control")

	tenant := uuid.New()
	device := uuid.New()
	payload, err := schema.PackPayload(schema.FlowEvent{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 80, DstPort: 8080,
		Protocol: "tcp", Verdict: schema.VerdictAllow,
	})
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	env := schema.Envelope{
		SchemaVersion: schema.SchemaVersion,
		EventID:       uuid.New(),
		TenantID:      tenant,
		DeviceID:      device,
		Timestamp:     time.Now().UTC(),
		EventClass:    schema.EventClassFlow,
		Platform:      schema.PlatformLinux,
		Payload:       payload,
	}
	if err := pub.PublishEnvelope(ctx, env, sngnats.PublishOptions{}); err != nil {
		t.Fatalf("publish: %v", err)
	}

	// Read it back via a one-off consumer.
	cons, err := js.CreateOrUpdateConsumer(ctx, "TEST_TELEMETRY", jetstream.ConsumerConfig{
		Name:          "test-pub-consumer",
		Durable:       "test-pub-consumer",
		FilterSubject: sngnats.SubjectForTelemetry(tenant.String(), "flow"),
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}
	msg, err := cons.Next(jetstream.FetchMaxWait(3 * time.Second))
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if msg.Subject() != sngnats.SubjectForTelemetry(tenant.String(), "flow") {
		t.Errorf("subject = %q", msg.Subject())
	}
	if msg.Headers().Get(sngnats.HeaderTenantID) != tenant.String() {
		t.Errorf("tenant header = %q", msg.Headers().Get(sngnats.HeaderTenantID))
	}
	if msg.Headers().Get(sngnats.HeaderEventClass) != "flow" {
		t.Errorf("class header = %q", msg.Headers().Get(sngnats.HeaderEventClass))
	}
	if msg.Headers().Get(sngnats.HeaderSource) != "sng-control" {
		t.Errorf("source = %q", msg.Headers().Get(sngnats.HeaderSource))
	}
	decoded, err := schema.Unmarshal(msg.Data())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.EventID != env.EventID {
		t.Errorf("event_id mismatch")
	}
	_ = msg.Ack()
}

func TestPublisher_DedupSameMsgID(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	cfg := defaultNATSConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sngnats.EnsureStreams(ctx, js, sngnats.DefaultStreams(cfg), 0); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	pub := sngnats.NewPublisher(js, cfg, "test")

	id := uuid.NewString()
	for i := 0; i < 3; i++ {
		if err := pub.Publish(ctx, "sng.t1.events.foo", []byte("payload"),
			sngnats.PublishOptions{MessageID: id}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	stream, err := js.Stream(ctx, "TEST_EVENTS")
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if info.State.Msgs != 1 {
		t.Errorf("expected 1 msg, got %d (dedup not honoured)", info.State.Msgs)
	}
}

func TestPublisher_DLQ(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	cfg := defaultNATSConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sngnats.EnsureStreams(ctx, js, sngnats.DefaultStreams(cfg), 0); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	pub := sngnats.NewPublisher(js, cfg, "test")

	headers := map[string]string{
		sngnats.HeaderMessageID:  "abc",
		sngnats.HeaderTenantID:   "t1",
		sngnats.HeaderEventClass: "flow",
	}
	if err := pub.PublishToDLQ(ctx, "sng.t1.telemetry.flow", []byte("payload"),
		headers, 5, context.DeadlineExceeded); err != nil {
		t.Fatalf("dlq: %v", err)
	}
	cons, err := js.CreateOrUpdateConsumer(ctx, "TEST_DLQ", jetstream.ConsumerConfig{
		Name:          "dlq-test",
		Durable:       "dlq-test",
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
	})
	if err != nil {
		t.Fatalf("create consumer: %v", err)
	}
	msg, err := cons.Next(jetstream.FetchMaxWait(3 * time.Second))
	if err != nil {
		t.Fatalf("next: %v", err)
	}
	if msg.Headers().Get(sngnats.HeaderOriginSubject) != "sng.t1.telemetry.flow" {
		t.Errorf("origin = %q", msg.Headers().Get(sngnats.HeaderOriginSubject))
	}
	if msg.Headers().Get(sngnats.HeaderDeliveryCount) != "5" {
		t.Errorf("delivery = %q", msg.Headers().Get(sngnats.HeaderDeliveryCount))
	}
	if msg.Headers().Get(sngnats.HeaderError) == "" {
		t.Errorf("error header missing")
	}
	_ = msg.Ack()
}

// TestPublisher_DLQ_StableDedupOnMissingMessageID verifies that
// PublishToDLQ deduplicates DLQ writes by message content when the
// source message lacks HeaderMessageID (an externally-produced
// message that didn't flow through this publisher). Without the
// content-derived fallback key, the downstream Publish() would
// generate a fresh UUID on every call and a flapping consumer
// would write N duplicate DLQ rows for the same source event.
//
// Round-trips two PublishToDLQ calls with the same (originSubject,
// data) but no MessageID; expects exactly one message in the DLQ
// stream after both calls thanks to JetStream's MsgID-based dedup
// (the dedup window in DefaultStreams is 2m, well above the test's
// wall-clock).
func TestPublisher_DLQ_StableDedupOnMissingMessageID(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	cfg := defaultNATSConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sngnats.EnsureStreams(ctx, js, sngnats.DefaultStreams(cfg), 0); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	pub := sngnats.NewPublisher(js, cfg, "test")

	// Headers without HeaderMessageID — simulates an external
	// publisher that doesn't follow the SNG header convention.
	headers := map[string]string{
		sngnats.HeaderTenantID:   "t1",
		sngnats.HeaderEventClass: "flow",
	}
	payload := []byte("identical-payload-bytes")
	if err := pub.PublishToDLQ(ctx, "external.tenant.events", payload, headers, 1, context.DeadlineExceeded); err != nil {
		t.Fatalf("dlq #1: %v", err)
	}
	if err := pub.PublishToDLQ(ctx, "external.tenant.events", payload, headers, 1, context.DeadlineExceeded); err != nil {
		t.Fatalf("dlq #2: %v", err)
	}

	stream, err := js.Stream(ctx, "TEST_DLQ")
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	// Exactly one message: the second PublishToDLQ should hit the
	// server-side dedup window via the content-derived MsgID. If
	// the test sees 2, the dedup fallback is missing.
	if info.State.Msgs != 1 {
		t.Errorf("expected 1 DLQ msg (content-derived dedup), got %d", info.State.Msgs)
	}
}

// TestPublisher_DLQ_DifferentContentNotDeduplicated guards against
// over-aggressive dedup — the content-derived fallback key must
// produce DIFFERENT MsgIDs for different (subject, data) inputs so
// distinct source messages don't collide in the DLQ.
func TestPublisher_DLQ_DifferentContentNotDeduplicated(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	cfg := defaultNATSConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := sngnats.EnsureStreams(ctx, js, sngnats.DefaultStreams(cfg), 0); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	pub := sngnats.NewPublisher(js, cfg, "test")
	headers := map[string]string{sngnats.HeaderTenantID: "t1"}

	if err := pub.PublishToDLQ(ctx, "external.events.flow", []byte("payload-A"), headers, 1, context.DeadlineExceeded); err != nil {
		t.Fatalf("dlq A: %v", err)
	}
	if err := pub.PublishToDLQ(ctx, "external.events.flow", []byte("payload-B"), headers, 1, context.DeadlineExceeded); err != nil {
		t.Fatalf("dlq B: %v", err)
	}
	// Same subject + different data should NOT dedup.
	if err := pub.PublishToDLQ(ctx, "external.events.dns", []byte("payload-A"), headers, 1, context.DeadlineExceeded); err != nil {
		t.Fatalf("dlq C: %v", err)
	}

	stream, err := js.Stream(ctx, "TEST_DLQ")
	if err != nil {
		t.Fatalf("stream: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if info.State.Msgs != 3 {
		t.Errorf("expected 3 distinct DLQ msgs, got %d (false-positive dedup)", info.State.Msgs)
	}
}
