package main

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

// reviewEnqueuer is the narrow slice of dlpreview.Service the ingest
// adapter needs: enqueue one redacted, flagged upload for review. Kept
// as an interface so the adapter is unit-testable without a Postgres
// repository.
type reviewEnqueuer interface {
	Enqueue(ctx context.Context, tenantID uuid.UUID, in dlpreview.EnqueueInput) (dlpreview.ReviewEvent, error)
}

// dlpReviewIngestConfig tunes the async enqueuer. Zero values fall back
// to the defaults below.
type dlpReviewIngestConfig struct {
	// BufferSize bounds the hand-off channel between the telemetry hot
	// path and the enqueue worker. A full buffer drops (and counts) new
	// events rather than blocking ingestion.
	BufferSize int
	// EnqueueTimeout bounds each Enqueue call so a slow/stuck review
	// store can never wedge the worker.
	EnqueueTimeout time.Duration
}

const (
	defaultDLPIngestBuffer  = 1024
	defaultDLPEnqueueTimout = 5 * time.Second
)

// dlpReviewIngest is the producer half of the human-in-the-loop DLP
// review queue: it implements telemetry.DLPReviewObserver, accepting
// coach-action DLP events off the telemetry dispatch hot path and
// enqueuing them into dlpreview.Service from a background worker.
//
// The hot-path hook (ObserveDLP) never blocks: it maps the wire event
// to a dlpreview.EnqueueInput and does a non-blocking send onto a
// bounded channel, counting a drop when the buffer is full or the
// adapter is shutting down. A single worker goroutine drains the
// channel and performs the (DB-backed) enqueue under a bounded context.
// This keeps the security signal off the latency-critical ingestion
// path while still landing it durably in the queue.
type dlpReviewIngest struct {
	svc     reviewEnqueuer
	logger  *slog.Logger
	timeout time.Duration

	ch       chan reviewJob
	done     chan struct{}
	wg       sync.WaitGroup
	stopOnce sync.Once

	enqueued atomic.Uint64
	dropped  atomic.Uint64
	failed   atomic.Uint64
}

type reviewJob struct {
	tenantID uuid.UUID
	in       dlpreview.EnqueueInput
}

// newDLPReviewIngest builds and starts the adapter. svc and logger must
// be non-nil.
func newDLPReviewIngest(svc reviewEnqueuer, logger *slog.Logger, cfg dlpReviewIngestConfig) *dlpReviewIngest {
	bufSize := cfg.BufferSize
	if bufSize <= 0 {
		bufSize = defaultDLPIngestBuffer
	}
	timeout := cfg.EnqueueTimeout
	if timeout <= 0 {
		timeout = defaultDLPEnqueueTimout
	}
	d := &dlpReviewIngest{
		svc:     svc,
		logger:  logger,
		timeout: timeout,
		ch:      make(chan reviewJob, bufSize),
		done:    make(chan struct{}),
	}
	d.wg.Add(1)
	go d.run()
	return d
}

// ObserveDLP satisfies telemetry.DLPReviewObserver. It is called inline
// on the dispatch hot path and must not block, so the enqueue is handed
// to the worker via a non-blocking send. The dispatch ctx is
// intentionally NOT retained — the worker enqueues under its own bounded
// context so a shut-down dispatch context can't cancel an in-flight
// write.
func (d *dlpReviewIngest) ObserveDLP(_ context.Context, tenantID, _ uuid.UUID, ev schema.DLPEvent, _ time.Time) {
	job := reviewJob{tenantID: tenantID, in: dlpEnqueueInput(ev)}
	// Fast-path drop if we're already shutting down.
	select {
	case <-d.done:
		d.dropped.Add(1)
		return
	default:
	}
	select {
	case d.ch <- job:
	case <-d.done:
		d.dropped.Add(1)
	default:
		// Buffer full: shed the event rather than stall ingestion.
		d.dropped.Add(1)
	}
}

// run drains the hand-off channel until Stop signals done, then drains
// whatever remains buffered before exiting so a graceful shutdown does
// not lose already-accepted events.
func (d *dlpReviewIngest) run() {
	defer d.wg.Done()
	for {
		select {
		case job := <-d.ch:
			d.process(job)
		case <-d.done:
			for {
				select {
				case job := <-d.ch:
					d.process(job)
				default:
					return
				}
			}
		}
	}
}

func (d *dlpReviewIngest) process(job reviewJob) {
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	if _, err := d.svc.Enqueue(ctx, job.tenantID, job.in); err != nil {
		d.failed.Add(1)
		d.logger.Warn("dlp-review: enqueue failed",
			slog.String("tenant_id", job.tenantID.String()),
			slog.String("destination_app", job.in.DestinationApp),
			slog.Any("error", err))
		return
	}
	d.enqueued.Add(1)
}

// Stop signals the worker to drain and waits for it to finish. Called
// during graceful shutdown after the telemetry consumer has drained, so
// events observed during the shutdown window are still enqueued. Safe to
// call multiple times.
func (d *dlpReviewIngest) Stop() {
	d.stopOnce.Do(func() { close(d.done) })
	d.wg.Wait()
}

// dlpEnqueueInput maps the redacted wire event onto the review-queue
// input. Both sides mirror the Rust DLP ladder (snake_case strings), so
// the severity/kind strings round-trip without a lookup table. Signal is
// left empty so the service stamps its default ("ai_app_upload").
func dlpEnqueueInput(ev schema.DLPEvent) dlpreview.EnqueueInput {
	findings := make([]dlpreview.FindingAggregate, 0, len(ev.Findings))
	for _, f := range ev.Findings {
		findings = append(findings, dlpreview.FindingAggregate{
			Kind:          dlpreview.FindingKind(f.Kind),
			Label:         f.Label,
			Count:         int(f.Count),
			MaxConfidence: f.MaxConfidence,
			Severity:      dlpreview.Severity(f.Severity),
		})
	}
	return dlpreview.EnqueueInput{
		DestinationApp: ev.DestinationApp,
		Severity:       dlpreview.Severity(ev.Severity),
		Confidence:     ev.Confidence,
		Findings:       findings,
	}
}
