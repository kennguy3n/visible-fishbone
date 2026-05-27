// Package nats wraps the JetStream stream/consumer/publisher
// surface for ShieldNet Gateway. Streams are declared declaratively
// in `DefaultStreams` and applied at boot via `EnsureStreams` so
// the control plane is self-bootstrapping — no separate provisioning
// tool required.
//
// The patterns here mirror sn360-es/pkg/events/nats: idempotent
// CreateOrUpdate, configurable storage / replicas / dedup window
// from `config.NATS`, subject namespaces scoped by tenant.
package nats

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
)

// Stream suffixes. The final stream name is
// `<StreamPrefix>_<suffix>` (e.g. "SNG_TELEMETRY") so multiple SNG
// control planes can share a NATS cluster without colliding.
const (
	StreamSuffixTelemetry = "TELEMETRY"
	StreamSuffixPolicy    = "POLICY"
	StreamSuffixEvents    = "EVENTS"
	StreamSuffixDLQ       = "DLQ"
)

// Subject base. Subjects live under `sng.<tenant_id>.<class>...`
// (e.g. `sng.abc-uuid.telemetry.flow`). The DLQ uses a separate
// top-level namespace (`sngdlq`) so its wildcard doesn't overlap
// with primary stream subjects — NATS rejects overlapping stream
// subjects, and `sng.*.{telemetry,events,policy}.>` would otherwise
// accept any value (including literal `dlq`) for the tenant slot.
const (
	SubjectPrefix    = "sng"
	SubjectDLQPrefix = "sngdlq"
)

// StreamSpec describes one JetStream stream the control plane
// expects to exist. Tests assert on the exact configuration
// produced by `DefaultStreams`.
type StreamSpec struct {
	Name        string
	Subjects    []string
	Retention   jetstream.RetentionPolicy
	Storage     jetstream.StorageType
	MaxAge      time.Duration
	MaxMsgSize  int32
	DedupWindow time.Duration
	Replicas    int
	Discard     jetstream.DiscardPolicy
	Description string
}

// streamName returns the prefixed stream name, e.g. "SNG_TELEMETRY".
func streamName(prefix, suffix string) string {
	p := strings.TrimSpace(prefix)
	if p == "" {
		p = "SNG"
	}
	return p + "_" + suffix
}

// DefaultStreams returns the canonical set of streams for the
// control plane. Subject patterns:
//
//   - SNG_TELEMETRY: `sng.*.telemetry.>` — high-volume per-class
//     telemetry events (flow, dns, http, ips, ztna, sdwan, agent),
//     7-day age cap, 2-min dedup, drop oldest on overflow.
//   - SNG_POLICY:    `sng.*.policy.>` — versioned policy graph
//     change notifications + compiled bundle availability. Limits
//     retention so subscribers can replay history.
//   - SNG_EVENTS:    `sng.*.events.>` — control-plane events
//     (tenant/site/device lifecycle, RBAC). WorkQueue retention,
//     24-hour cap.
//   - SNG_DLQ:       `sngdlq.>` — dead-letter queue for messages
//     that hit MaxDeliver on a consumer. 30-day cap. Lives outside
//     the `sng.<tenant>.` namespace so its wildcard does not
//     overlap with primary streams (NATS rejects overlap).
func DefaultStreams(cfg *config.NATS) []StreamSpec {
	storage := jetstream.FileStorage
	if strings.EqualFold(cfg.Storage, "memory") {
		storage = jetstream.MemoryStorage
	}
	replicas := cfg.Replicas
	if replicas <= 0 {
		replicas = 1
	}
	dedup := cfg.DedupWindow
	if dedup <= 0 {
		dedup = 2 * time.Minute
	}
	return []StreamSpec{
		{
			Name:        streamName(cfg.StreamPrefix, StreamSuffixTelemetry),
			Subjects:    []string{"sng.*.telemetry.>"},
			Retention:   jetstream.LimitsPolicy,
			Storage:     storage,
			MaxAge:      7 * 24 * time.Hour,
			MaxMsgSize:  10 * 1024 * 1024,
			DedupWindow: dedup,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SNG control plane: per-tenant telemetry events",
		},
		{
			Name:        streamName(cfg.StreamPrefix, StreamSuffixPolicy),
			Subjects:    []string{"sng.*.policy.>"},
			Retention:   jetstream.LimitsPolicy,
			Storage:     storage,
			MaxAge:      30 * 24 * time.Hour,
			DedupWindow: dedup,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SNG control plane: policy graph + bundle change notifications",
		},
		{
			Name:        streamName(cfg.StreamPrefix, StreamSuffixEvents),
			Subjects:    []string{"sng.*.events.>"},
			Retention:   jetstream.WorkQueuePolicy,
			Storage:     storage,
			MaxAge:      24 * time.Hour,
			DedupWindow: dedup,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SNG control plane: tenant/site/device lifecycle events",
		},
		{
			Name:        streamName(cfg.StreamPrefix, StreamSuffixDLQ),
			Subjects:    []string{"sngdlq.>"},
			Retention:   jetstream.LimitsPolicy,
			Storage:     storage,
			MaxAge:      30 * 24 * time.Hour,
			DedupWindow: dedup,
			Replicas:    replicas,
			Discard:     jetstream.DiscardOld,
			Description: "SNG control plane: dead-letter queue for failed messages",
		},
	}
}

// EnsureStream creates or updates the stream described by spec.
// Idempotent. Safe to call at every process start.
func EnsureStream(ctx context.Context, js jetstream.JetStream, spec StreamSpec) (jetstream.Stream, error) {
	cfg := jetstream.StreamConfig{
		Name:        spec.Name,
		Subjects:    spec.Subjects,
		Retention:   spec.Retention,
		Storage:     spec.Storage,
		MaxAge:      spec.MaxAge,
		MaxMsgSize:  spec.MaxMsgSize,
		Duplicates:  spec.DedupWindow,
		Replicas:    spec.Replicas,
		Discard:     spec.Discard,
		Description: spec.Description,
	}
	_, err := js.Stream(ctx, spec.Name)
	if err == nil {
		updated, uErr := js.UpdateStream(ctx, cfg)
		if uErr != nil {
			return nil, fmt.Errorf("nats: update stream %s: %w", spec.Name, uErr)
		}
		return updated, nil
	}
	if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return nil, fmt.Errorf("nats: lookup stream %s: %w", spec.Name, err)
	}
	created, cErr := js.CreateStream(ctx, cfg)
	if cErr != nil {
		return nil, fmt.Errorf("nats: create stream %s: %w", spec.Name, cErr)
	}
	return created, nil
}

// EnsureStreams ensures every spec exists. Errors aggregate so one
// bad stream doesn't prevent inspecting failures in the others.
//
// If perStreamTimeout > 0, each stream's create/update call is
// bounded by its own fresh WithTimeout derived from ctx. This
// guarantees that a slow JetStream cluster (e.g. the first stream
// taking 4s to update) cannot exhaust a single shared deadline and
// leave later streams with no budget. If perStreamTimeout <= 0,
// every call inherits ctx unchanged (use this for tests where ctx
// is already a per-call WithTimeout).
//
// The caller is responsible for using a sufficiently long overall
// ctx to accommodate (numStreams * perStreamTimeout) in the
// worst case. We don't enforce this because the alternative
// (multiplying internally) makes the per-stream knob misleading.
func EnsureStreams(ctx context.Context, js jetstream.JetStream, specs []StreamSpec, perStreamTimeout time.Duration) error {
	var errs []error
	for _, spec := range specs {
		streamCtx := ctx
		var cancel context.CancelFunc
		if perStreamTimeout > 0 {
			streamCtx, cancel = context.WithTimeout(ctx, perStreamTimeout)
		}
		_, err := EnsureStream(streamCtx, js, spec)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ConsumerSpec describes a durable JetStream consumer.
type ConsumerSpec struct {
	Stream        string
	Durable       string
	FilterSubject string
	AckWait       time.Duration
	MaxDeliver    int
	MaxAckPending int
	Description   string
}

// EnsureConsumer creates or updates the durable consumer described
// by spec. Idempotent.
func EnsureConsumer(ctx context.Context, js jetstream.JetStream, spec ConsumerSpec) (jetstream.Consumer, error) {
	maxDeliver := spec.MaxDeliver
	if maxDeliver == 0 {
		// 0 in JetStream means "unlimited"; we treat the
		// zero-value as "5 attempts then DLQ" so the caller
		// gets a defined behaviour by default.
		maxDeliver = 5
	}
	ackWait := spec.AckWait
	if ackWait <= 0 {
		ackWait = 30 * time.Second
	}
	maxAck := spec.MaxAckPending
	if maxAck <= 0 {
		maxAck = 256
	}
	cfg := jetstream.ConsumerConfig{
		Name:          spec.Durable,
		Durable:       spec.Durable,
		FilterSubject: spec.FilterSubject,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       ackWait,
		MaxDeliver:    maxDeliver,
		MaxAckPending: maxAck,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		Description:   spec.Description,
	}
	cons, err := js.CreateOrUpdateConsumer(ctx, spec.Stream, cfg)
	if err != nil {
		return nil, fmt.Errorf("nats: create consumer %s on %s: %w", spec.Durable, spec.Stream, err)
	}
	return cons, nil
}

// SubjectForTelemetry builds the canonical subject for a telemetry
// event, e.g. SubjectForTelemetry("abc", "flow") → "sng.abc.telemetry.flow".
func SubjectForTelemetry(tenantID, class string) string {
	return fmt.Sprintf("%s.%s.telemetry.%s", SubjectPrefix, tenantID, class)
}

// SubjectForEvent builds the canonical subject for a control-plane
// event, e.g. SubjectForEvent("abc", "tenant.created") →
// "sng.abc.events.tenant.created".
func SubjectForEvent(tenantID, kind string) string {
	return fmt.Sprintf("%s.%s.events.%s", SubjectPrefix, tenantID, kind)
}

// SubjectForPolicy builds the canonical subject for a policy
// notification, e.g. SubjectForPolicy("abc", "compiled") →
// "sng.abc.policy.compiled".
func SubjectForPolicy(tenantID, kind string) string {
	return fmt.Sprintf("%s.%s.policy.%s", SubjectPrefix, tenantID, kind)
}

// DLQSubjectFor wraps the original subject in the DLQ namespace,
// e.g. DLQSubjectFor("sng.abc.telemetry.flow") →
// "sngdlq.sng.abc.telemetry.flow". The full original subject is
// preserved so the DLQ consumer can route to the original handler.
func DLQSubjectFor(originSubject string) string {
	return SubjectDLQPrefix + "." + originSubject
}
