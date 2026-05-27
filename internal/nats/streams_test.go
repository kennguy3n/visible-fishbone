package nats_test

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
)

func defaultNATSConfig() *config.NATS {
	return &config.NATS{
		StreamPrefix:   "TEST",
		Replicas:       1,
		Storage:        "memory",
		DedupWindow:    2 * time.Minute,
		FetchBatchSize: 10,
		FetchMaxWait:   100 * time.Millisecond,
		RequestTimeout: 2 * time.Second,
	}
}

func TestDefaultStreams_PrefixesAndSubjects(t *testing.T) {
	t.Parallel()
	cfg := defaultNATSConfig()
	specs := sngnats.DefaultStreams(cfg)
	if len(specs) != 4 {
		t.Fatalf("expected 4 streams, got %d", len(specs))
	}
	want := map[string][]string{
		"TEST_TELEMETRY": {"sng.*.telemetry.>"},
		"TEST_POLICY":    {"sng.*.policy.>"},
		"TEST_EVENTS":    {"sng.*.events.>"},
		"TEST_DLQ":       {"sngdlq.>"},
	}
	for _, s := range specs {
		exp, ok := want[s.Name]
		if !ok {
			t.Errorf("unexpected stream %s", s.Name)
			continue
		}
		if len(s.Subjects) != 1 || s.Subjects[0] != exp[0] {
			t.Errorf("%s subjects = %v, want %v", s.Name, s.Subjects, exp)
		}
	}
}

func TestDefaultStreams_MemoryStorage(t *testing.T) {
	t.Parallel()
	cfg := defaultNATSConfig()
	cfg.Storage = "memory"
	specs := sngnats.DefaultStreams(cfg)
	for _, s := range specs {
		if s.Storage != jetstream.MemoryStorage {
			t.Errorf("%s storage = %v, want memory", s.Name, s.Storage)
		}
	}
}

func TestDefaultStreams_DefaultPrefix(t *testing.T) {
	t.Parallel()
	cfg := &config.NATS{Replicas: 1, Storage: "memory"}
	specs := sngnats.DefaultStreams(cfg)
	for _, s := range specs {
		if s.Name[:3] != "SNG" {
			t.Errorf("default prefix not applied: %s", s.Name)
		}
	}
}

// TestStreamName_WhitespaceTrim guards the regression where a
// NATS_STREAM_PREFIX with leading/trailing whitespace (e.g. from a
// YAML ConfigMap) would split the stream identity between
// EnsureStreams (which trimmed) and downstream consumers (which
// didn't). Now that telemetry.Service.Start() routes through this
// helper, both sides agree on the trimmed name.
func TestStreamName_WhitespaceTrim(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{" SNG ", "SNG_TELEMETRY"},
		{"\tACME\n", "ACME_TELEMETRY"},
		{"", "SNG_TELEMETRY"},
		{"   ", "SNG_TELEMETRY"},
		{"SNG", "SNG_TELEMETRY"},
	}
	for _, c := range cases {
		got := sngnats.StreamName(c.in, sngnats.StreamSuffixTelemetry)
		if got != c.want {
			t.Errorf("StreamName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEnsureStreams_Idempotent(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	cfg := defaultNATSConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	specs := sngnats.DefaultStreams(cfg)
	if err := sngnats.EnsureStreams(ctx, js, specs, 0); err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	// Re-apply: must be idempotent (Update path).
	if err := sngnats.EnsureStreams(ctx, js, specs, 0); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	// Verify every stream exists.
	for _, s := range specs {
		if _, err := js.Stream(ctx, s.Name); err != nil {
			t.Errorf("stream %s missing: %v", s.Name, err)
		}
	}
}

func TestEnsureConsumer(t *testing.T) {
	t.Parallel()
	_, js := startEmbeddedNATS(t)
	cfg := defaultNATSConfig()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sngnats.EnsureStreams(ctx, js, sngnats.DefaultStreams(cfg), 0); err != nil {
		t.Fatalf("ensure streams: %v", err)
	}
	cons, err := sngnats.EnsureConsumer(ctx, js, sngnats.ConsumerSpec{
		Stream:        "TEST_TELEMETRY",
		Durable:       "test-consumer",
		FilterSubject: "sng.*.telemetry.>",
		AckWait:       30 * time.Second,
		MaxDeliver:    3,
		MaxAckPending: 100,
		Description:   "test",
	})
	if err != nil {
		t.Fatalf("ensure consumer: %v", err)
	}
	info, err := cons.Info(ctx)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	if info.Name != "test-consumer" {
		t.Errorf("name = %q", info.Name)
	}
	// Re-apply: must be idempotent.
	if _, err := sngnats.EnsureConsumer(ctx, js, sngnats.ConsumerSpec{
		Stream:        "TEST_TELEMETRY",
		Durable:       "test-consumer",
		FilterSubject: "sng.*.telemetry.>",
		AckWait:       30 * time.Second,
		MaxDeliver:    3,
		MaxAckPending: 100,
	}); err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
}

func TestSubjectBuilders(t *testing.T) {
	t.Parallel()
	if got := sngnats.SubjectForTelemetry("abc", "flow"); got != "sng.abc.telemetry.flow" {
		t.Errorf("telemetry subject = %q", got)
	}
	if got := sngnats.SubjectForEvent("abc", "tenant.created"); got != "sng.abc.events.tenant.created" {
		t.Errorf("event subject = %q", got)
	}
	if got := sngnats.SubjectForPolicy("abc", "compiled"); got != "sng.abc.policy.compiled" {
		t.Errorf("policy subject = %q", got)
	}
	if got := sngnats.DLQSubjectFor("sng.abc.telemetry.flow"); got != "sngdlq.sng.abc.telemetry.flow" {
		t.Errorf("dlq subject = %q", got)
	}
}
