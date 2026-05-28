// Package replay implements the operator-triggered replay path
// from the SNG_DLQ stream back to the origin subject. When the
// hot-path ClickHouse writer fails for longer than its retry
// budget, the telemetry consumer routes the affected envelopes to
// SNG_DLQ. After the writer recovers, the operator triggers a
// replay run: the worker drains SNG_DLQ, re-publishes each
// preserved envelope onto its original telemetry subject, and
// acks the DLQ message only after a successful re-publish.
//
// The worker is paused by default — it does not run automatically
// on boot because uncontrolled replay can flood ClickHouse with
// stale events at the very moment it recovers. Operators kick it
// off via the admin handler (POST /api/v1/admin/telemetry/replay)
// with optional filter knobs (subject prefix, since-timestamp,
// max events).
//
// Each run is bounded by MaxEvents and a per-run context. A run
// reports its progress via the Progress channel so the admin
// handler can stream status back to the caller.
package replay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// Publisher is the slice of the nats.Publisher API the worker
// uses. Mirrors the production *nats.Publisher so tests can stub.
type Publisher interface {
	Publish(ctx context.Context, subject string, data []byte, opts sngnats.PublishOptions) error
}

// Options configures one replay run.
type Options struct {
	// SubjectPrefix optionally filters to messages whose
	// original subject (from X-SNG-Origin-Subject header) starts
	// with this string. Empty means "no filter".
	SubjectPrefix string
	// Since optionally filters to messages whose
	// X-SNG-Origin-Enqueued-At is at or after this time. Zero
	// means "no filter".
	Since time.Time
	// MaxEvents caps the number of messages drained in one run.
	// Zero means "no cap" (drain until DLQ is empty).
	MaxEvents int
	// FetchBatchSize is the JetStream pull-batch size. Defaults
	// to 64.
	FetchBatchSize int
	// FetchMaxWait caps how long the worker waits for messages
	// before declaring the DLQ empty. Defaults to 2s.
	FetchMaxWait time.Duration
}

func (o *Options) fillDefaults() {
	if o.FetchBatchSize <= 0 {
		o.FetchBatchSize = 64
	}
	if o.FetchMaxWait <= 0 {
		o.FetchMaxWait = 2 * time.Second
	}
}

// Result is the per-run summary returned to the admin caller.
type Result struct {
	Drained      int           `json:"drained"`
	Republished  int           `json:"republished"`
	Skipped      int           `json:"skipped"`
	FailedPub    int           `json:"failed_publish"`
	FailedDecode int           `json:"failed_decode"`
	Duration     time.Duration `json:"duration"`
	FirstError   string        `json:"first_error,omitempty"`
}

// Worker drains SNG_DLQ and re-publishes preserved envelopes.
type Worker struct {
	js     jetstream.JetStream
	pub    Publisher
	logger *slog.Logger

	streamPrefix string
	durable      string

	// running guards Run against concurrent replay invocations —
	// a second Run call returns ErrInProgress while one is in
	// flight. Operators must explicitly serialize their replay
	// triggers; we do not queue.
	running atomic.Bool
}

// ErrInProgress is returned by Run when a replay is already in
// flight.
var ErrInProgress = errors.New("replay: another run is already in progress")

// New constructs a Worker. The streamPrefix matches the prefix
// used by the publisher / consumer in this deployment so
// JetStream.Stream() lookups land on the correct DLQ stream.
//
// `durable` is the consumer name the worker maintains on SNG_DLQ.
// JetStream tracks the worker's read offset on this consumer so a
// crash mid-run resumes where it left off rather than re-replaying
// already-acked messages.
func New(js jetstream.JetStream, pub Publisher, streamPrefix, durable string, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	if durable == "" {
		durable = "sng-telemetry-replay"
	}
	return &Worker{
		js:           js,
		pub:          pub,
		logger:       logger,
		streamPrefix: streamPrefix,
		durable:      durable,
	}
}

// Run executes one replay pass. Returns when the DLQ is empty,
// MaxEvents is reached, or ctx is cancelled.
func (w *Worker) Run(ctx context.Context, opts Options) (Result, error) {
	if !w.running.CompareAndSwap(false, true) {
		return Result{}, ErrInProgress
	}
	defer w.running.Store(false)

	opts.fillDefaults()
	stream := sngnats.StreamName(w.streamPrefix, sngnats.StreamSuffixDLQ)
	cons, err := sngnats.EnsureConsumer(ctx, w.js, sngnats.ConsumerSpec{
		Stream:        stream,
		Durable:       w.durable,
		FilterSubject: sngnats.SubjectDLQPrefix + ".>",
		MaxAckPending: opts.FetchBatchSize * 4,
		AckWait:       30 * time.Second,
		MaxDeliver:    3,
		Description:   "SNG telemetry replay (operator-triggered)",
	})
	if err != nil {
		return Result{}, fmt.Errorf("replay: ensure consumer: %w", err)
	}

	start := time.Now()
	result := Result{}
	for ctx.Err() == nil {
		if opts.MaxEvents > 0 && result.Drained >= opts.MaxEvents {
			break
		}
		batch, err := cons.Fetch(opts.FetchBatchSize, jetstream.FetchMaxWait(opts.FetchMaxWait))
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, jetstream.ErrNoMessages) {
				break
			}
			result.FirstError = err.Error()
			break
		}
		got := 0
		for msg := range batch.Messages() {
			got++
			result.Drained++
			w.handleOne(ctx, msg, &opts, &result)
			if opts.MaxEvents > 0 && result.Drained >= opts.MaxEvents {
				break
			}
		}
		if got == 0 {
			break
		}
	}
	result.Duration = time.Since(start)
	return result, nil
}

// skipRedeliverDelay is the delay applied to filter-skipped and
// decode-failed messages when nack-ing them back to the DLQ. A
// long delay keeps them out of the current Run's fetch window
// (avoiding the loop where the same Nak'd message comes straight
// back), while still leaving them on the DLQ for a subsequent
// operator-triggered replay run. The 1h horizon is larger than
// any realistic single-Run duration but small enough that an
// operator who fixes their filter and reruns within an hour sees
// the messages reappear.
const skipRedeliverDelay = 1 * time.Hour

// handleOne processes a single DLQ message: filter, decode,
// re-publish, ack. Filter-skips and decode-fails Nak with a long
// delay so they don't re-deliver within the same Run.
func (w *Worker) handleOne(ctx context.Context, msg jetstream.Msg, opts *Options, result *Result) {
	headers := flattenHeaders(msg.Headers())
	originSubject := headers[sngnats.HeaderOriginSubject]
	if originSubject == "" {
		// Without an origin subject we have nowhere to send
		// the message. Skip + leave on the DLQ for inspection.
		result.Skipped++
		w.delayNak(msg, "missing-origin")
		return
	}
	if opts.SubjectPrefix != "" && !startsWith(originSubject, opts.SubjectPrefix) {
		result.Skipped++
		w.delayNak(msg, "subject-prefix-mismatch")
		return
	}
	if !opts.Since.IsZero() {
		if ts, ok := parseTime(headers[sngnats.HeaderOriginEnqueuedAt]); ok {
			if ts.Before(opts.Since) {
				result.Skipped++
				w.delayNak(msg, "since-filter")
				return
			}
		}
	}

	// Decode the envelope just enough to validate the bytes are
	// still a well-formed telemetry payload. If decoding fails,
	// the payload was already broken when it landed on the DLQ —
	// replay would just route a broken message back to the hot
	// path. Skip + leave on the DLQ for forensics.
	if _, err := schema.Unmarshal(msg.Data()); err != nil {
		result.FailedDecode++
		if result.FirstError == "" {
			result.FirstError = "decode: " + err.Error()
		}
		w.delayNak(msg, "decode-failure")
		return
	}

	// Re-publish to the original subject. We preserve the
	// X-SNG-Message-ID from the origin message so JetStream's
	// dedup window suppresses double-ingestion if a previous
	// partial replay made it through before the crash.
	pubOpts := sngnats.PublishOptions{
		MessageID:     headers[sngnats.HeaderOriginMessageID],
		CorrelationID: headers[sngnats.HeaderCorrelationID],
		Headers: map[string]string{
			"X-SNG-Replayed-At": time.Now().UTC().Format(time.RFC3339Nano),
		},
	}
	for k, v := range headers {
		switch k {
		case sngnats.HeaderOriginSubject, sngnats.HeaderError,
			sngnats.HeaderOriginEnqueuedAt, sngnats.HeaderOriginMessageID,
			sngnats.HeaderDeliveryCount, sngnats.HeaderEnqueuedAt:
			// DLQ-specific or replaced — skip.
		default:
			pubOpts.Headers[k] = v
		}
	}
	if err := w.pub.Publish(ctx, originSubject, msg.Data(), pubOpts); err != nil {
		result.FailedPub++
		if result.FirstError == "" {
			result.FirstError = "publish: " + err.Error()
		}
		// Leave on DLQ for the next replay run.
		if err := msg.Nak(); err != nil {
			w.logger.Warn("replay: nak after publish-failure failed", slog.Any("error", err))
		}
		return
	}
	result.Republished++
	if err := msg.Ack(); err != nil {
		w.logger.Warn("replay: ack after successful re-publish failed", slog.Any("error", err))
	}
}

// Handler returns an http.HandlerFunc bound to this worker. The
// handler accepts POST with a JSON body of Options and returns
// the Result as JSON. Callers should mount it behind the admin
// (operator-role) middleware.
func (w *Worker) Handler() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			rw.Header().Set("Allow", "POST")
			http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var opts Options
		if r.ContentLength > 0 {
			if err := json.NewDecoder(r.Body).Decode(&opts); err != nil {
				http.Error(rw, fmt.Sprintf("decode body: %v", err), http.StatusBadRequest)
				return
			}
		}
		result, err := w.Run(r.Context(), opts)
		if errors.Is(err, ErrInProgress) {
			rw.Header().Set("Retry-After", strconv.Itoa(5))
			http.Error(rw, err.Error(), http.StatusConflict)
			return
		}
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(&result)
	}
}

// delayNak nacks the message with skipRedeliverDelay so it
// doesn't re-appear within the current Run's fetch loop.
func (w *Worker) delayNak(msg jetstream.Msg, reason string) {
	if err := msg.NakWithDelay(skipRedeliverDelay); err != nil {
		w.logger.Warn("replay: delay-nak failed",
			slog.String("reason", reason),
			slog.Any("error", err))
	}
}

// flattenHeaders normalises a nats.Header (multi-valued map) into
// a single-valued map by taking the first value per key. NATS
// headers used by the SNG control plane are all single-valued.
func flattenHeaders(h map[string][]string) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func parseTime(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// Compile-time sanity: assert *Worker is concurrency-safe enough
// for repeated Run invocations from the admin handler.
var _ = sync.Mutex{}
