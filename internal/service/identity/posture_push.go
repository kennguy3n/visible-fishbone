package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"

	sngnats "github.com/kennguy3n/visible-fishbone/internal/nats"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Continuous adaptive ZTNA, posture-push half (WS3).
//
// The ZTNA brain (crate sng-ztna) evaluates access once, at session
// open, and then re-evaluates every live session on a periodic
// sweep (default 60s). A device whose posture *regresses* — disk
// encryption switched off, OS rolled back, jailbreak detected —
// should not have to wait up to a full sweep interval before its
// open sessions are torn down.
//
// PosturePushConsumer closes that gap. Agents (and the edge nodes
// that proxy them) publish posture snapshots onto the control-plane
// events stream as they collect them. This consumer:
//
//  1. Applies the snapshot to the authoritative device record
//     (repository.DeviceRepository.UpdatePosture, RLS-scoped to the
//     owning tenant) so the next evaluation — periodic or
//     out-of-cycle — reads the fresh posture.
//  2. Publishes an out-of-cycle re-evaluation trigger for that one
//     device, so the brain re-runs its evaluator for the affected
//     sessions immediately instead of waiting for the next sweep.
//
// The trigger is a latency optimisation layered on top of the
// brain's guaranteed periodic sweep: if the trigger publish fails,
// the posture is still persisted and the next periodic sweep will
// pick up the regression, so a dropped trigger degrades revocation
// latency, never correctness.

const (
	// PostureUpdatedEventKind is the events-stream subject suffix
	// agents publish posture snapshots on:
	// `sng.<tenant>.events.device.posture_updated`.
	PostureUpdatedEventKind = "device.posture_updated"

	// ReevalDeviceEventKind is the events-stream subject suffix the
	// out-of-cycle re-evaluation trigger is published on:
	// `sng.<tenant>.events.ztna.reeval_device`. The ZTNA brain
	// subscribes to this to re-evaluate the named device's live
	// sessions ahead of the periodic sweep.
	ReevalDeviceEventKind = "ztna.reeval_device"

	// DefaultPosturePushDurable is the JetStream durable consumer
	// name maintained on the events stream. JetStream tracks the
	// read offset here so a restart resumes where it left off.
	DefaultPosturePushDurable = "sng-identity-posture-push"

	// posturePushSource labels trigger messages this consumer
	// publishes (X-SNG-Source / audit attribution).
	posturePushSource = "sng-identity-posture-push"

	// fetchErrBackoffBase / fetchErrBackoffMax bound the retry delay
	// after a non-transient Fetch error. The NATS client normally
	// absorbs a reconnect inside Fetch (it blocks up to FetchMaxWait),
	// so a fast-returning error means a pathological state — e.g. the
	// stream/consumer was deleted out from under us, or the connection
	// is drained and not recovering. Without a delay the loop would
	// busy-spin and flood the log; capped exponential backoff keeps a
	// single retry path that neither spins nor stalls recovery.
	fetchErrBackoffBase = 100 * time.Millisecond
	fetchErrBackoffMax  = 5 * time.Second
)

// nextFetchBackoff returns the next capped-exponential backoff after a
// Fetch error: base on the first failure, doubling each subsequent
// failure up to the ceiling. Reset to zero on any successful (or
// empty) fetch by the caller.
func nextFetchBackoff(prev time.Duration) time.Duration {
	if prev <= 0 {
		return fetchErrBackoffBase
	}
	if next := prev * 2; next < fetchErrBackoffMax {
		return next
	}
	return fetchErrBackoffMax
}

// PostureUpdate is the wire payload an agent / edge node publishes
// to announce a fresh device-posture snapshot. JSON-encoded to
// match repository.Posture's existing JSON contract, so an agent
// reports posture in exactly the shape the repository stores.
type PostureUpdate struct {
	// TenantID owns the device. Authoritative for the RLS-scoped
	// UpdatePosture call; validated against the X-SNG-Tenant-ID
	// header when present.
	TenantID uuid.UUID `json:"tenant_id"`
	// DeviceID is the device whose posture changed.
	DeviceID uuid.UUID `json:"device_id"`
	// Posture is the new snapshot.
	Posture repository.Posture `json:"posture"`
}

// reevalDeviceTrigger is the out-of-cycle re-evaluation trigger the
// consumer emits after a posture snapshot lands. The brain re-runs
// its evaluator for every live session on this device.
type reevalDeviceTrigger struct {
	TenantID uuid.UUID `json:"tenant_id"`
	DeviceID uuid.UUID `json:"device_id"`
}

// PostureUpdater is the slice of the identity Service that the
// consumer needs: persisting a posture snapshot for a device,
// RLS-scoped to its tenant. *Service satisfies it.
type PostureUpdater interface {
	UpdatePosture(ctx context.Context, tenantID, deviceID uuid.UUID, p repository.Posture) error
}

// EventPublisher is the slice of *nats.Publisher the consumer needs
// to emit the re-evaluation trigger. Mirrors the production
// publisher so tests can stub it.
type EventPublisher interface {
	Publish(ctx context.Context, subject string, data []byte, opts sngnats.PublishOptions) error
}

// PosturePushConsumer drains device-posture-update messages from the
// control-plane events stream, applies them to the device
// repository, and triggers out-of-cycle ZTNA re-evaluation.
//
// Safe for use as a single long-running goroutine; not intended to
// be Run concurrently with itself on the same durable.
type PosturePushConsumer struct {
	js      jetstream.JetStream
	updater PostureUpdater
	pub     EventPublisher
	logger  *slog.Logger

	streamPrefix string
	durable      string

	fetchBatchSize int
	fetchMaxWait   time.Duration
}

// PosturePushOption configures a PosturePushConsumer without
// breaking the base constructor signature.
type PosturePushOption func(*PosturePushConsumer)

// WithPosturePushDurable overrides the durable consumer name.
func WithPosturePushDurable(durable string) PosturePushOption {
	return func(c *PosturePushConsumer) {
		if durable != "" {
			c.durable = durable
		}
	}
}

// WithPosturePushFetch tunes the pull-batch size and max wait. Zero
// / negative values keep the defaults (64 / 2s).
func WithPosturePushFetch(batchSize int, maxWait time.Duration) PosturePushOption {
	return func(c *PosturePushConsumer) {
		if batchSize > 0 {
			c.fetchBatchSize = batchSize
		}
		if maxWait > 0 {
			c.fetchMaxWait = maxWait
		}
	}
}

// NewPosturePushConsumer constructs a consumer. `streamPrefix` must
// match the prefix the events stream was created under so the
// JetStream stream lookup resolves. The publisher emits the
// re-evaluation triggers.
func NewPosturePushConsumer(
	js jetstream.JetStream,
	updater PostureUpdater,
	pub EventPublisher,
	streamPrefix string,
	logger *slog.Logger,
	opts ...PosturePushOption,
) *PosturePushConsumer {
	if logger == nil {
		logger = slog.Default()
	}
	c := &PosturePushConsumer{
		js:             js,
		updater:        updater,
		pub:            pub,
		logger:         logger,
		streamPrefix:   streamPrefix,
		durable:        DefaultPosturePushDurable,
		fetchBatchSize: 64,
		fetchMaxWait:   2 * time.Second,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// postureUpdatedFilterSubject is the wildcard-tenant filter the
// durable consumer binds to: every tenant's posture-update events.
func postureUpdatedFilterSubject() string {
	return fmt.Sprintf("%s.*.events.%s", sngnats.SubjectPrefix, PostureUpdatedEventKind)
}

// Run drains and processes posture-update messages until ctx is
// cancelled. It creates (or resumes) the durable consumer, then
// loops fetching batches; an empty fetch is normal (no posture
// changed in the window) and simply re-fetches. Returns ctx's error
// on cancellation, or a wrapped error if the durable consumer could
// not be created.
func (c *PosturePushConsumer) Run(ctx context.Context) error {
	stream := sngnats.StreamName(c.streamPrefix, sngnats.StreamSuffixEvents)
	cons, err := sngnats.EnsureConsumer(ctx, c.js, sngnats.ConsumerSpec{
		Stream:        stream,
		Durable:       c.durable,
		FilterSubject: postureUpdatedFilterSubject(),
		MaxAckPending: c.fetchBatchSize * 4,
		AckWait:       30 * time.Second,
		MaxDeliver:    5,
		Description:   "SNG identity device-posture push -> ZTNA re-evaluation",
	})
	if err != nil {
		return fmt.Errorf("posture-push: ensure consumer: %w", err)
	}

	var backoff time.Duration
	for ctx.Err() == nil {
		batch, err := cons.Fetch(c.fetchBatchSize, jetstream.FetchMaxWait(c.fetchMaxWait))
		if err != nil {
			// An empty window (no posture changed) and cancellation
			// are normal: Fetch already blocked for FetchMaxWait, so
			// re-fetch immediately and clear any prior backoff.
			if errors.Is(err, context.Canceled) || errors.Is(err, jetstream.ErrNoMessages) {
				backoff = 0
				continue
			}
			// Any other fetch error is treated as transient (server
			// hiccup, mid-reconnect) and retried rather than exiting
			// the long-running loop. Back off with a capped
			// exponential delay so a fast-returning error (e.g. the
			// connection is drained and not recovering) cannot busy-
			// spin the loop or flood the log.
			backoff = nextFetchBackoff(backoff)
			c.logger.Warn("posture-push: fetch failed, backing off",
				slog.Any("error", err),
				slog.Duration("backoff", backoff))
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
			continue
		}
		// A good fetch clears the backoff so the next transient error
		// starts from the base delay again.
		backoff = 0
		for msg := range batch.Messages() {
			c.handleMessage(ctx, msg)
		}
		// Messages() closes either when the batch is fully drained or
		// when the fetch was cut short by a mid-batch error (heartbeat
		// timeout, connection drop). batch.Error() surfaces the latter;
		// without this check such failures would be silently swallowed
		// until the next Fetch, hiding JetStream connectivity problems.
		// Treat it like a transient fetch error: log and back off so a
		// persistently failing connection cannot busy-spin the loop.
		if err := batch.Error(); err != nil && !errors.Is(err, context.Canceled) {
			backoff = nextFetchBackoff(backoff)
			c.logger.Warn("posture-push: batch ended with error, backing off",
				slog.Any("error", err),
				slog.Duration("backoff", backoff))
			select {
			case <-ctx.Done():
			case <-time.After(backoff):
			}
		}
	}
	return ctx.Err()
}

// handleMessage applies one posture-update message and fires the
// re-evaluation trigger. Ack/Nak/Term discipline:
//
//   - malformed payload or missing ids -> Term: the message is
//     poison; redelivery cannot fix it, so drop it (with a log)
//     rather than loop to MaxDeliver and DLQ.
//   - device not found / invalid argument -> Term: a terminal
//     application error; the device record is gone or the snapshot
//     is structurally invalid, so redelivery is futile.
//   - any other UpdatePosture error -> Nak: treated as transient
//     (DB blip); JetStream redelivers up to MaxDeliver.
//   - trigger publish failure -> Ack anyway: the posture is already
//     persisted and the brain's periodic sweep is the safety net,
//     so we must not re-apply (and re-trigger) the snapshot just
//     because an optimisation hop failed.
func (c *PosturePushConsumer) handleMessage(ctx context.Context, msg jetstream.Msg) {
	var upd PostureUpdate
	if err := json.Unmarshal(msg.Data(), &upd); err != nil {
		c.logger.Warn("posture-push: undecodable payload, dropping",
			slog.Any("error", err))
		c.term(msg, "decode-failure")
		return
	}
	if upd.TenantID == uuid.Nil || upd.DeviceID == uuid.Nil {
		c.logger.Warn("posture-push: payload missing tenant or device id, dropping",
			slog.String("tenant", upd.TenantID.String()),
			slog.String("device", upd.DeviceID.String()))
		c.term(msg, "missing-ids")
		return
	}
	// Defense in depth: if the publisher stamped a tenant header,
	// it must agree with the payload. A mismatch means the message
	// was mis-routed or tampered with; refuse to apply it under
	// either tenant rather than risk a cross-tenant posture write.
	if hdr := msg.Headers().Get(sngnats.HeaderTenantID); hdr != "" && hdr != upd.TenantID.String() {
		c.logger.Warn("posture-push: tenant header/payload mismatch, dropping",
			slog.String("header_tenant", hdr),
			slog.String("payload_tenant", upd.TenantID.String()))
		c.term(msg, "tenant-mismatch")
		return
	}

	if err := c.updater.UpdatePosture(ctx, upd.TenantID, upd.DeviceID, upd.Posture); err != nil {
		if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
			c.logger.Warn("posture-push: terminal update error, dropping",
				slog.String("device", upd.DeviceID.String()),
				slog.Any("error", err))
			c.term(msg, "terminal-update-error")
			return
		}
		c.logger.Warn("posture-push: transient update error, will redeliver",
			slog.String("device", upd.DeviceID.String()),
			slog.Any("error", err))
		c.nak(msg)
		return
	}

	c.triggerReeval(ctx, upd.TenantID, upd.DeviceID, upd.Posture.CollectedAt)

	if err := msg.Ack(); err != nil {
		c.logger.Warn("posture-push: ack failed after applying posture",
			slog.String("device", upd.DeviceID.String()),
			slog.Any("error", err))
	}
}

// triggerReeval publishes the out-of-cycle re-evaluation trigger for
// one device. Best-effort: a failure is logged but never fails the
// message (the periodic sweep is the safety net). The dedup key is
// derived from the (tenant, device, posture-collection-instant) tuple
// by [reevalMessageID] so a redelivery of the *same* posture snapshot
// collapses to one trigger while a genuinely *newer* snapshot still
// fires its own — see that helper for the rationale.
func (c *PosturePushConsumer) triggerReeval(ctx context.Context, tenantID, deviceID uuid.UUID, collectedAt *time.Time) {
	payload, err := json.Marshal(reevalDeviceTrigger{TenantID: tenantID, DeviceID: deviceID})
	if err != nil {
		// Marshalling two UUIDs cannot realistically fail; guard
		// anyway so a future field change surfaces loudly.
		c.logger.Error("posture-push: marshal reeval trigger failed",
			slog.String("device", deviceID.String()),
			slog.Any("error", err))
		return
	}
	subject := sngnats.SubjectForEvent(tenantID.String(), ReevalDeviceEventKind)
	err = c.pub.Publish(ctx, subject, payload, sngnats.PublishOptions{
		MessageID: reevalMessageID(tenantID, deviceID, collectedAt),
		Source:    posturePushSource,
		Headers: map[string]string{
			sngnats.HeaderTenantID: tenantID.String(),
			sngnats.HeaderDeviceID: deviceID.String(),
		},
	})
	if err != nil {
		c.logger.Warn("posture-push: reeval trigger publish failed (periodic sweep will cover)",
			slog.String("device", deviceID.String()),
			slog.Any("error", err))
	}
}

// reevalMessageID builds the JetStream dedup key for an out-of-cycle
// re-evaluation trigger.
//
// The key is scoped to the (tenant, device) pair and, when the agent
// stamped one, the posture's collection instant. This balances the two
// competing failure modes:
//
//   - Without any stable key the publisher mints a fresh UUID per call
//     (internal/nats/publisher.go), so a redelivery of the *same*
//     posture snapshot — JetStream at-least-once redelivery, an agent
//     re-reporting unchanged posture — would emit a duplicate trigger
//     and the brain would redundantly re-evaluate the device's
//     sessions.
//   - Pinning the key to *only* (tenant, device) over-collapses: a
//     genuinely newer snapshot arriving inside the events stream's
//     dedup window (default 2m, streams.go) would be suppressed, so a
//     posture that degrades and then degrades *further* seconds later
//     would not re-evaluate out of cycle until the next periodic sweep
//     — defeating the whole point of the posture-push fast path for
//     the second regression.
//
// Including the collection instant distinguishes distinct snapshots
// (each fires its own trigger, bounding revocation latency to the push
// latency) while still collapsing exact redeliveries of one snapshot
// (same instant -> same key -> deduped). CollectedAt is optional on the
// wire (older / mobile agents may omit it); when absent we fall back to
// the (tenant, device) key, preserving the burst-collapse behaviour for
// those agents. A nanosecond instant is stable across redeliveries and
// monotone across genuine re-collections, so it is the smallest key
// that gets both cases right. Over-firing is always safe regardless:
// the posture is already persisted and re-evaluation is idempotent.
func reevalMessageID(tenantID, deviceID uuid.UUID, collectedAt *time.Time) string {
	if collectedAt == nil {
		return fmt.Sprintf("reeval-%s-%s", tenantID, deviceID)
	}
	return fmt.Sprintf("reeval-%s-%s-%d", tenantID, deviceID, collectedAt.UTC().UnixNano())
}

func (c *PosturePushConsumer) term(msg jetstream.Msg, reason string) {
	if err := msg.TermWithReason(reason); err != nil {
		c.logger.Warn("posture-push: term failed",
			slog.String("reason", reason), slog.Any("error", err))
	}
}

func (c *PosturePushConsumer) nak(msg jetstream.Msg) {
	if err := msg.Nak(); err != nil {
		c.logger.Warn("posture-push: nak failed", slog.Any("error", err))
	}
}
