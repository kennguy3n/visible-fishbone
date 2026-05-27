package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ErrSecretUnavailable is returned when the signing secret cannot
// be retrieved for an endpoint (deleted between enqueue and
// delivery, or repository-level error).
var ErrSecretUnavailable = errors.New("webhook: signing secret unavailable")

// WorkerConfig tunes the delivery worker.
type WorkerConfig struct {
	// BatchSize caps the number of pending deliveries fetched
	// per tick. Default 32.
	BatchSize int
	// PollInterval is the wait between scans of the pending
	// queue when the previous tick produced no work. Default 1s.
	PollInterval time.Duration
	// RequestTimeout is the per-delivery HTTP timeout. Default 10s.
	RequestTimeout time.Duration
	// MaxAttempts caps the retry budget; deliveries are marked
	// `exhausted` after this many total attempts. Default 8.
	MaxAttempts int
	// BackoffBase is the base factor for exponential backoff:
	// next_retry = now + BackoffBase * 2^(attempt-1), capped at
	// BackoffMax. Default 30s.
	BackoffBase time.Duration
	// BackoffMax is the per-attempt backoff ceiling. Default 1h.
	BackoffMax time.Duration
	// ProcessingTimeout is the stuck-row recovery window passed to
	// WebhookDeliveryRepository.ListPending. Rows that a previous
	// worker claimed (status='processing') but never transitioned
	// out of — typically because the worker crashed mid-delivery
	// — are re-claimable once their last_attempt_at is older than
	// `now - ProcessingTimeout`.
	//
	// Choose this to be safely longer than the worst-case
	// in-flight delivery (RequestTimeout + scheduler overhead): too
	// short and the same delivery is dispatched twice if a single
	// slow upstream pushes past the window; too long and a true
	// worker crash leaves the queue stalled for that duration.
	// Default 5m, which comfortably exceeds the default
	// RequestTimeout of 10s.
	ProcessingTimeout time.Duration
}

// defaults applies sensible defaults to zero-valued fields.
func (c *WorkerConfig) defaults() {
	if c.BatchSize <= 0 {
		c.BatchSize = 32
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = 10 * time.Second
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

// DeliveryWorker drains pending webhook deliveries and POSTs them
// to subscriber URLs with HMAC-signed bodies + exponential-backoff
// retry. The worker is safe to run as a singleton or with multiple
// instances against the same database; the repository layer's
// ListPending performs an atomic claim (UPDATE...RETURNING with
// status transitioned to 'processing') so concurrent workers never
// double-deliver. A worker that crashes mid-delivery leaves its
// rows in 'processing'; they are re-claimed automatically by the
// next ListPending call once `cfg.ProcessingTimeout` has elapsed
// since the stuck row's last_attempt_at.
type DeliveryWorker struct {
	deliveries repository.WebhookDeliveryRepository
	endpoints  repository.WebhookEndpointRepository
	client     *http.Client
	cfg        WorkerConfig
	logger     *slog.Logger
	nowFunc    func() time.Time

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// NewDeliveryWorker constructs a worker. Pass nil for client to
// use a default http.Client tuned for low-latency outbound webhooks
// (10s timeout, no redirects beyond 1 hop). The worker resolves
// each endpoint's plaintext signing secret via the endpoint
// repository at delivery time; the repository is the source of
// truth (encrypted at-rest by the DB layer per the migration's
// signing_secret docstring).
func NewDeliveryWorker(
	deliveries repository.WebhookDeliveryRepository,
	endpoints repository.WebhookEndpointRepository,
	client *http.Client,
	cfg WorkerConfig,
	logger *slog.Logger,
) *DeliveryWorker {
	cfg.defaults()
	if client == nil {
		client = &http.Client{Timeout: cfg.RequestTimeout}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &DeliveryWorker{
		deliveries: deliveries,
		endpoints:  endpoints,
		client:     client,
		cfg:        cfg,
		logger:     logger,
		nowFunc:    func() time.Time { return time.Now().UTC() },
	}
}

// Start launches the worker loop. Returns immediately; the loop
// runs until Stop is called or the underlying context is canceled.
// Calling Start twice returns an error.
func (w *DeliveryWorker) Start(parent context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cancel != nil {
		return errors.New("webhook: delivery worker already started")
	}
	ctx, cancel := context.WithCancel(parent)
	w.cancel = cancel
	w.done = make(chan struct{})
	go w.loop(ctx)
	return nil
}

// Stop signals the worker to exit and waits for the loop to drain.
// It is safe to call Stop multiple times; subsequent calls are
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

func (w *DeliveryWorker) loop(ctx context.Context) {
	defer close(w.done)
	for {
		if ctx.Err() != nil {
			return
		}
		processed, err := w.tick(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			w.logger.Error("webhook: delivery tick failed", slog.Any("error", err))
		}
		// If the tick had work, immediately try another batch so
		// large backlogs drain quickly. Otherwise sleep for the
		// poll interval.
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

// ProcessPending drains one batch of pending deliveries
// synchronously and returns the number of rows touched. This is
// the same logic the Start/loop background runs, but exposed so
// callers can run the worker as a cron job (e.g., a Kubernetes
// CronJob driving the same deliveries from a quiet control plane)
// and so tests can drive a deterministic tick without spinning up
// the background loop. Safe to call from multiple goroutines —
// the repository's atomic-claim ListPending guarantees competing
// callers never receive overlapping rows.
func (w *DeliveryWorker) ProcessPending(ctx context.Context) (int, error) {
	return w.tick(ctx)
}

// tick processes a single batch of pending deliveries. Returns the
// number of deliveries processed and the first non-context error
// encountered.
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
// records the result. All errors are translated into a
// status-update on the row; the caller does not see them.
func (w *DeliveryWorker) deliver(ctx context.Context, d repository.WebhookDelivery) {
	attempt := d.Attempts + 1
	now := w.nowFunc()

	// Resolve the endpoint to get its URL + status.
	ep, err := w.endpoints.Get(ctx, d.TenantID, d.EndpointID)
	if err != nil {
		w.markFailed(ctx, d, attempt, fmt.Sprintf("resolve endpoint: %v", err), 0, now)
		return
	}
	if ep.Status != repository.WebhookEndpointStatusActive {
		// Endpoint disabled — fail-once and exhaust immediately
		// rather than retrying against a disabled subscription.
		_ = w.deliveries.UpdateStatus(ctx, d.TenantID, d.ID,
			repository.WebhookDeliveryStatusExhausted, attempt,
			"endpoint disabled", 0, now)
		return
	}

	if len(ep.SigningSecret) == 0 {
		w.markFailed(ctx, d, attempt, ErrSecretUnavailable.Error(), 0, now)
		return
	}

	status, body, reqErr := w.post(ctx, ep.URL, d, ep.SigningSecret, now)
	if reqErr != nil {
		w.markFailed(ctx, d, attempt, reqErr.Error(), status, now)
		return
	}
	if status < 200 || status >= 300 {
		w.markFailed(ctx, d, attempt,
			fmt.Sprintf("http %d: %s", status, truncate(body, 256)),
			status, now)
		return
	}
	if err := w.deliveries.UpdateStatus(ctx, d.TenantID, d.ID,
		repository.WebhookDeliveryStatusDelivered, attempt, "", status, now); err != nil {
		w.logger.Error("webhook: failed to mark delivered",
			slog.String("delivery_id", d.ID.String()),
			slog.Any("error", err))
	}
}

// post issues the actual HTTP request with signature headers.
func (w *DeliveryWorker) post(
	ctx context.Context,
	rawURL string,
	d repository.WebhookDelivery,
	secret []byte,
	now time.Time,
) (int, []byte, error) {
	body := []byte(d.Payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	timestamp := strconv.FormatInt(now.Unix(), 10)
	signedPayload := append([]byte(timestamp+"."), body...)
	mac := hmac.New(sha256.New, secret)
	mac.Write(signedPayload)
	sig := hex.EncodeToString(mac.Sum(nil))

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "sng-control/0.1 (+webhooks)")
	req.Header.Set("X-Sng-Event", d.EventType)
	req.Header.Set("X-Sng-Delivery-Id", d.ID.String())
	req.Header.Set("X-Sng-Timestamp", timestamp)
	req.Header.Set("X-Sng-Signature", "v1="+sig)

	resp, err := w.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, respBody, nil
}

// markFailed records a failed attempt and computes the next retry
// (or exhausts the delivery if attempts == MaxAttempts).
func (w *DeliveryWorker) markFailed(
	ctx context.Context,
	d repository.WebhookDelivery,
	attempt int,
	reason string,
	httpStatus int,
	now time.Time,
) {
	status := repository.WebhookDeliveryStatusPending
	next := w.nextRetryAt(attempt, now)
	if attempt >= w.cfg.MaxAttempts {
		status = repository.WebhookDeliveryStatusExhausted
		next = now
	}
	if err := w.deliveries.UpdateStatus(ctx, d.TenantID, d.ID,
		status, attempt, reason, httpStatus, next); err != nil {
		w.logger.Error("webhook: failed to record attempt",
			slog.String("delivery_id", d.ID.String()),
			slog.Any("error", err))
	}
}

// nextRetryAt computes the exponential backoff next-retry time
// with the worker's BackoffBase and BackoffMax bounds.
func (w *DeliveryWorker) nextRetryAt(attempt int, now time.Time) time.Time {
	// 2^(attempt-1) — clamp the exponent at 30 so a malicious or
	// misconfigured MaxAttempts can't overflow.
	exp := attempt - 1
	if exp < 0 {
		exp = 0
	}
	if exp > 30 {
		exp = 30
	}
	delay := time.Duration(math.Pow(2, float64(exp))) * w.cfg.BackoffBase
	if delay <= 0 || delay > w.cfg.BackoffMax {
		delay = w.cfg.BackoffMax
	}
	return now.Add(delay)
}

func truncate(b []byte, limit int) string {
	if len(b) <= limit {
		return string(b)
	}
	return string(b[:limit]) + "...(truncated)"
}
