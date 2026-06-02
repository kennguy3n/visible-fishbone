package integration

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// WorkerConfig tunes the integration delivery worker. Shape and
// defaults are deliberately kept identical to webhook.WorkerConfig
// so the operator-facing knobs are uniform across both fan-out
// systems.
type WorkerConfig struct {
	// BatchSize caps the number of pending deliveries fetched
	// per tick. Default 32.
	BatchSize int
	// PollInterval is the wait between scans of the pending
	// queue when the previous tick produced no work. Default 1s.
	PollInterval time.Duration
	// MaxAttempts caps the retry budget; deliveries are marked
	// `exhausted` after this many total attempts. Default 8.
	MaxAttempts int
	// BackoffBase is the base factor for exponential backoff:
	// next_retry = now + BackoffBase * 2^(attempt-1), capped at
	// BackoffMax. Default 30s.
	BackoffBase time.Duration
	// BackoffMax is the per-attempt backoff ceiling. Default 1h.
	BackoffMax time.Duration
	// ProcessingTimeout is the stuck-row recovery window. Rows
	// that a previous worker claimed (status='processing') but
	// never transitioned out of — typically because the worker
	// crashed mid-Send — are re-claimable once their
	// last_attempt_at is older than `now - ProcessingTimeout`.
	// Choose this to safely exceed the worst-case in-flight
	// Send (the connector plugin's network timeout + scheduler
	// overhead). Default 5m.
	ProcessingTimeout time.Duration
}

func (c *WorkerConfig) defaults() {
	if c.BatchSize <= 0 {
		c.BatchSize = 32
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 8
	}
	if c.BackoffBase <= 0 {
		c.BackoffBase = 30 * time.Second
	}
	if c.BackoffMax <= 0 {
		c.BackoffMax = time.Hour
	}
	if c.ProcessingTimeout <= 0 {
		c.ProcessingTimeout = 5 * time.Minute
	}
}

// DeliveryWorker drains pending IntegrationDelivery rows and
// invokes the per-Kind Connector plugin to dispatch them.
//
// Concurrency contract: the worker is safe to run as a singleton
// OR with multiple instances against the same database. The
// IntegrationDeliveryRepository.ListPending call atomically
// transitions claimed rows to 'processing' so concurrent workers
// never receive overlapping rows. A worker that crashes
// mid-Send leaves its row in 'processing'; the next worker's
// ListPending re-claims it once `cfg.ProcessingTimeout` has
// elapsed since the stuck row's last_attempt_at.
type DeliveryWorker struct {
	connectors repository.IntegrationConnectorRepository
	deliveries repository.IntegrationDeliveryRepository
	registry   Registry
	cfg        WorkerConfig
	logger     *slog.Logger
	nowFunc    func() time.Time

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewDeliveryWorker constructs a worker. The registry MUST be
// the same one wired into the Service; the worker rejects
// deliveries whose connector Kind is not in the registry as
// permanently failed (no retry) — the only way that can happen
// is a deployment that downgraded its plugin set with pending
// rows still queued, and the operator needs to see the
// `unsupported connector kind` error to know to either redeploy
// the dropped plugin or DELETE the orphan connector.
func NewDeliveryWorker(
	connectors repository.IntegrationConnectorRepository,
	deliveries repository.IntegrationDeliveryRepository,
	registry Registry,
	cfg WorkerConfig,
	logger *slog.Logger,
) *DeliveryWorker {
	cfg.defaults()
	if logger == nil {
		logger = slog.Default()
	}
	if registry == nil {
		registry = Registry{}
	}
	return &DeliveryWorker{
		connectors: connectors,
		deliveries: deliveries,
		registry:   registry,
		cfg:        cfg,
		logger:     logger,
		nowFunc:    func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the wall clock. Tests use this to assert
// next_retry_at scheduling deterministically.
func (w *DeliveryWorker) SetClock(f func() time.Time) {
	w.nowFunc = f
}

// Start launches the worker loop. Returns immediately; the loop
// runs until Stop is called or the underlying context is canceled.
// Calling Start twice returns an error.
func (w *DeliveryWorker) Start(parent context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		return errors.New("integration: delivery worker already started")
	}
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	w.done = make(chan struct{})
	go w.loop(ctx)
	return nil
}

// Stop signals the worker to exit and waits for the loop to
// drain. Safe to call multiple times; subsequent calls are
// no-ops. The provided ctx bounds how long Stop waits.
func (w *DeliveryWorker) Stop(ctx context.Context) error {
	w.mu.Lock()
	cancel := w.cancel
	done := w.done
	w.cancel = nil
	w.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ProcessPending drains one batch synchronously and returns the
// number of rows touched. Exposed so callers can run the worker
// as a cron job and so tests can drive a deterministic tick
// without spinning up the background loop. Safe to call from
// multiple goroutines — the repo's atomic-claim guarantees
// competing callers never receive overlapping rows.
func (w *DeliveryWorker) ProcessPending(ctx context.Context) (int, error) {
	return w.tick(ctx)
}

func (w *DeliveryWorker) loop(ctx context.Context) {
	defer close(w.done)
	for {
		if ctx.Err() != nil {
			return
		}
		processed, err := w.tick(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("integration: delivery tick failed", slog.Any("error", err))
		}
		if processed > 0 {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(w.cfg.PollInterval):
		}
	}
}

func (w *DeliveryWorker) tick(ctx context.Context) (int, error) {
	pending, err := w.deliveries.ListPending(ctx, w.cfg.BatchSize, w.cfg.ProcessingTimeout)
	if err != nil {
		return 0, fmt.Errorf("list pending: %w", err)
	}
	for _, d := range pending {
		if ctx.Err() != nil {
			return len(pending), ctx.Err()
		}
		w.deliver(ctx, d)
	}
	return len(pending), nil
}

// deliver executes one attempt for a single pending delivery and
// records the outcome.
func (w *DeliveryWorker) deliver(ctx context.Context, d repository.IntegrationDelivery) {
	attempt := d.Attempts + 1
	now := w.nowFunc()

	conn, err := w.connectors.Get(ctx, d.TenantID, d.ConnectorID)
	if err != nil {
		// Parent row vanished (deleted by operator) or transient
		// DB error. Treat as terminal — no point retrying a
		// dispatch against a connector that no longer exists.
		w.terminate(ctx, d, attempt,
			repository.IntegrationDeliveryStatusFailed,
			fmt.Sprintf("resolve connector: %v", err), 0, now)
		return
	}
	if conn.Status != repository.IntegrationConnectorStatusActive {
		w.terminate(ctx, d, attempt,
			repository.IntegrationDeliveryStatusExhausted,
			"connector disabled", 0, now)
		return
	}
	plugin, ok := w.registry[conn.Type]
	if !ok {
		// See NewDeliveryWorker doc — permanently failed.
		w.terminate(ctx, d, attempt,
			repository.IntegrationDeliveryStatusFailed,
			fmt.Sprintf("unsupported connector kind %q", conn.Type),
			0, now)
		return
	}

	res, sendErr := plugin.Send(ctx, Sendable{
		EventType:         d.EventType,
		Payload:           d.Payload,
		Config:            conn.Config,
		Secret:            conn.Secret,
		ExternalReference: d.ExternalReference,
		Now:               now,
	})
	if sendErr == nil {
		if err := w.deliveries.UpdateStatus(ctx, d.TenantID, d.ID,
			repository.IntegrationDeliveryStatusDelivered, attempt, "",
			res.ResponseStatus, now, res.ExternalReference); err != nil {
			w.logger.Error("integration: failed to mark delivered",
				slog.String("delivery_id", d.ID.String()),
				slog.Any("error", err))
		}
		return
	}

	// Non-nil error. Decide retry vs. terminate.
	transient := errors.Is(sendErr, ErrTransient)
	if !transient || attempt >= w.cfg.MaxAttempts {
		status := repository.IntegrationDeliveryStatusFailed
		if transient && attempt >= w.cfg.MaxAttempts {
			// Hit the retry ceiling on a retryable error — flag
			// distinctly so the operator can tell "we gave up"
			// from "we refused to try".
			status = repository.IntegrationDeliveryStatusExhausted
		}
		w.terminate(ctx, d, attempt, status, sendErr.Error(),
			res.ResponseStatus, now)
		return
	}
	// Transient + still under the cap → reschedule.
	next := now.Add(w.backoff(attempt))
	if err := w.deliveries.UpdateStatus(ctx, d.TenantID, d.ID,
		repository.IntegrationDeliveryStatusPending, attempt,
		sendErr.Error(), res.ResponseStatus, next, ""); err != nil {
		w.logger.Error("integration: failed to reschedule",
			slog.String("delivery_id", d.ID.String()),
			slog.Any("error", err))
	}
}

func (w *DeliveryWorker) terminate(
	ctx context.Context,
	d repository.IntegrationDelivery,
	attempt int,
	status repository.IntegrationDeliveryStatus,
	lastErr string,
	respStatus int,
	now time.Time,
) {
	if err := w.deliveries.UpdateStatus(ctx, d.TenantID, d.ID,
		status, attempt, lastErr, respStatus, now, ""); err != nil {
		w.logger.Error("integration: failed to mark terminal",
			slog.String("delivery_id", d.ID.String()),
			slog.String("status", string(status)),
			slog.Any("error", err))
	}
}

// backoff returns the delay before the next attempt:
//
//	cfg.BackoffBase * 2^(attempt-1), capped at cfg.BackoffMax.
//
// Same formula as the webhook worker so the operator-facing
// "deliveries.last_error" timing tells a uniform story.
func (w *DeliveryWorker) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	// math.Pow returns float64; cast back to int after capping
	// to avoid the int overflow that would happen at attempt ~60.
	scale := math.Pow(2, float64(attempt-1))
	d := time.Duration(float64(w.cfg.BackoffBase) * scale)
	if d <= 0 || d > w.cfg.BackoffMax {
		d = w.cfg.BackoffMax
	}
	return d
}
