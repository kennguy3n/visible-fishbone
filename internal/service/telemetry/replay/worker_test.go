package replay_test

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/telemetry/replay"
)

func startNATS(t *testing.T) (jetstream.JetStream, *config.NATS, *sngnats.Publisher) {
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
		StreamPrefix:         "TEST",
		Replicas:             1,
		Storage:              "memory",
		DedupWindow:          2 * time.Minute,
		FetchBatchSize:       10,
		FetchMaxWait:         100 * time.Millisecond,
		RequestTimeout:       2 * time.Second,
		PublishRetryAttempts: 3,
		PublishRetryDelay:    50 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := sngnats.EnsureStreams(ctx, js, sngnats.DefaultStreams(cfg), 0); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	pub := sngnats.NewPublisher(js, cfg, "test-replay")
	return js, cfg, pub
}

// capturePub records all Publish calls so the test can assert
// that replayed envelopes land on the correct subject.
type capturePub struct {
	mu       sync.Mutex
	subjects []string
	data     [][]byte
}

func (c *capturePub) Publish(_ context.Context, subject string, data []byte, _ sngnats.PublishOptions) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.subjects = append(c.subjects, subject)
	cp := make([]byte, len(data))
	copy(cp, data)
	c.data = append(c.data, cp)
	return nil
}

// TestReplay_RoundTrip publishes a telemetry envelope, routes it
// to the DLQ, runs the replay worker, and verifies the envelope
// is re-published to the original subject.
func TestReplay_RoundTrip(t *testing.T) {
	t.Parallel()
	js, cfg, pub := startNATS(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))

	env := schema.Envelope{
		SchemaVersion: 1,
		EventID:       uuid.New(),
		TenantID:      uuid.New(),
		DeviceID:      uuid.New(),
		Timestamp:     time.Now().UTC(),
		EventClass:    schema.EventClassFlow,
		Platform:      schema.PlatformWindows,
		Payload:       []byte(`{"test":"replay"}`),
	}
	data, err := schema.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	originSubject := sngnats.SubjectForTelemetry(env.TenantID.String(), string(env.EventClass))
	dlqSubject := sngnats.DLQSubjectFor(originSubject)

	// Publish directly to the DLQ subject with origin headers.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := pub.Publish(ctx, dlqSubject, data, sngnats.PublishOptions{
		Headers: map[string]string{
			sngnats.HeaderOriginSubject:    originSubject,
			sngnats.HeaderOriginEnqueuedAt: time.Now().UTC().Format(time.RFC3339Nano),
			sngnats.HeaderError:            "simulated hot-path failure",
		},
	}); err != nil {
		t.Fatalf("publish to DLQ: %v", err)
	}

	// Give JetStream a moment to persist.
	time.Sleep(200 * time.Millisecond)

	capPub := &capturePub{}
	w := replay.New(js, capPub, cfg.StreamPrefix, "", logger)
	result, err := w.Run(ctx, replay.Options{
		FetchBatchSize: 10,
		FetchMaxWait:   500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Drained != 1 {
		t.Errorf("drained: want 1, got %d", result.Drained)
	}
	if result.Republished != 1 {
		t.Errorf("republished: want 1, got %d", result.Republished)
	}
	if result.Skipped != 0 {
		t.Errorf("skipped: want 0, got %d", result.Skipped)
	}

	capPub.mu.Lock()
	defer capPub.mu.Unlock()
	if len(capPub.subjects) != 1 {
		t.Fatalf("expected 1 re-publish, got %d", len(capPub.subjects))
	}
	if capPub.subjects[0] != originSubject {
		t.Errorf("re-publish subject: want %q, got %q", originSubject, capPub.subjects[0])
	}
	roundTripped, err := schema.Unmarshal(capPub.data[0])
	if err != nil {
		t.Fatalf("unmarshal re-published: %v", err)
	}
	if roundTripped.EventID != env.EventID {
		t.Errorf("event ID mismatch: want %s, got %s", env.EventID, roundTripped.EventID)
	}
}

// TestReplay_SubjectPrefixFilter confirms that the SubjectPrefix
// option skips messages whose origin subject doesn't match.
func TestReplay_SubjectPrefixFilter(t *testing.T) {
	t.Parallel()
	js, cfg, pub := startNATS(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tntA := uuid.New()
	tntB := uuid.New()
	subA := sngnats.SubjectForTelemetry(tntA.String(), string(schema.EventClassFlow))
	subB := sngnats.SubjectForTelemetry(tntB.String(), string(schema.EventClassDNS))
	for _, pair := range []struct {
		origin string
		tid    uuid.UUID
	}{
		{subA, tntA},
		{subB, tntB},
	} {
		env := schema.Envelope{
			SchemaVersion: 1,
			EventID:       uuid.New(),
			TenantID:      pair.tid,
			DeviceID:      uuid.New(),
			Timestamp:     time.Now().UTC(),
			EventClass:    schema.EventClassFlow,
			Platform:      schema.PlatformLinux,
			Payload:       []byte(`{}`),
		}
		data, _ := schema.Marshal(env)
		dlq := sngnats.DLQSubjectFor(pair.origin)
		if err := pub.Publish(ctx, dlq, data, sngnats.PublishOptions{
			Headers: map[string]string{
				sngnats.HeaderOriginSubject: pair.origin,
				sngnats.HeaderError:         "test",
			},
		}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	capPub := &capturePub{}
	w := replay.New(js, capPub, cfg.StreamPrefix, "test-filter", logger)
	result, err := w.Run(ctx, replay.Options{
		SubjectPrefix:  subA[:len(subA)-5], // match tenant A
		FetchBatchSize: 10,
		FetchMaxWait:   500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Republished != 1 {
		t.Errorf("republished: want 1, got %d", result.Republished)
	}
	if result.Skipped != 1 {
		t.Errorf("skipped: want 1, got %d", result.Skipped)
	}
}

// TestReplay_ConcurrentRunReturnsInProgress asserts the second
// concurrent call to Run returns ErrInProgress.
func TestReplay_ConcurrentRunReturnsInProgress(t *testing.T) {
	t.Parallel()
	js, cfg, pub := startNATS(t)
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	// Fill DLQ with enough messages to keep the first run busy.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for i := 0; i < 100; i++ {
		env := schema.Envelope{
			SchemaVersion: 1,
			EventID:       uuid.New(),
			TenantID:      uuid.New(),
			DeviceID:      uuid.New(),
			Timestamp:     time.Now().UTC(),
			EventClass:    schema.EventClassFlow,
			Platform:      schema.PlatformWindows,
			Payload:       []byte(`{}`),
		}
		data, _ := schema.Marshal(env)
		originSub := sngnats.SubjectForTelemetry(env.TenantID.String(), string(env.EventClass))
		dlqSub := sngnats.DLQSubjectFor(originSub)
		if err := pub.Publish(ctx, dlqSub, data, sngnats.PublishOptions{
			Headers: map[string]string{
				sngnats.HeaderOriginSubject: originSub,
				sngnats.HeaderError:         "test",
			},
		}); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	capPub := &capturePub{}
	w := replay.New(js, capPub, cfg.StreamPrefix, "test-concurrent", logger)

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		_, _ = w.Run(ctx, replay.Options{
			FetchBatchSize: 5,
			FetchMaxWait:   1 * time.Second,
		})
		close(done)
	}()
	<-started
	// Give the first Run a moment to claim the running flag.
	time.Sleep(100 * time.Millisecond)

	_, err := w.Run(ctx, replay.Options{})
	if err != replay.ErrInProgress {
		t.Errorf("expected ErrInProgress, got %v", err)
	}
	<-done
}
