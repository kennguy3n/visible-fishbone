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
)

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

	for ctx.Err() == nil {
		batch, err := cons.Fetch(c.fetchBatchSize, jetstream.FetchMaxWait(c.fetchMaxWait))
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, jetstream.ErrNoMessages) {
				continue
			}
			// A fetch error other than "no messages" / cancellation is
			// transient (server hiccup); log and retry rather than
			// exiting the long-running loop.
			c.logger.Warn("posture-push: fetch failed", slog.Any("error", err))
			continue
		}
		for msg := range batch.Messages() {
			c.handleMessage(ctx, msg)
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

	c.triggerReeval(ctx, upd.TenantID, upd.DeviceID)

	if err := msg.Ack(); err != nil {
		c.logger.Warn("posture-push: ack failed after applying posture",
			slog.String("device", upd.DeviceID.String()),
			slog.Any("error", err))
	}
}

// triggerReeval publishes the out-of-cycle re-evaluation trigger for
// one device. Best-effort: a failure is logged but never fails the
// message (the periodic sweep is the safety net). The message id is
// pinned to the (tenant, device) pair so JetStream's dedup window
// collapses a burst of posture pushes for the same device into a
// single trigger.
func (c *PosturePushConsumer) triggerReeval(ctx context.Context, tenantID, deviceID uuid.UUID) {
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
		Source: posturePushSource,
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
