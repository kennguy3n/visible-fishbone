package nats

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// PublishOptions narrows publish behaviour.
type PublishOptions struct {
	// MessageID overrides the dedup key. If empty, a UUID v4 is
	// generated. The same value is written to
	// jetstream.MsgIDHeader so server-side dedup applies.
	MessageID string
	// CorrelationID groups related messages. Optional.
	CorrelationID string
	// Source labels the publishing service. Falls back to
	// Publisher.source.
	Source string
	// Extra headers merged after the canonical ones (cannot
	// override canonical names).
	Headers map[string]string
	// Timeout applied to each publish attempt. <=0 means use the
	// publisher's configured default.
	Timeout time.Duration
	// MaxAttempts is the total number of publish attempts
	// (including the first — NOT additional retries after the
	// first). 0/negative falls back to the publisher's configured
	// PublishRetryAttempts, then to a hard-coded default of 3.
	// Named to match its semantic (total tries) rather than the
	// older `MaxRetries` which was misleading.
	MaxAttempts int
	// MaxRetries is a deprecated alias for MaxAttempts. If both
	// are set, MaxAttempts wins. Retained for back-compat with
	// any external callers staged on the older API; will be
	// removed in a future PR.
	//
	// Deprecated: use MaxAttempts.
	MaxRetries int
	// Subject overrides the destination subject. When zero, the
	// envelope's canonical telemetry subject is used (see
	// SubjectForTelemetry). Callers wanting to route an envelope
	// onto the events or policy stream pass an explicit subject
	// here instead of calling Publish() directly so the canonical
	// header set is still applied.
	Subject string
	// RetryDelay overrides the publisher's default. <=0 falls
	// back to the publisher default.
	RetryDelay time.Duration
}

// Publisher publishes JetStream messages with retries, dedup, and
// canonical SNG headers. Safe for concurrent use.
type Publisher struct {
	js      jetstream.JetStream
	cfg     *config.NATS
	source  string
	timeout time.Duration
}

// NewPublisher returns a Publisher bound to js and the global NATS
// config. The source label is stamped onto every published message.
func NewPublisher(js jetstream.JetStream, cfg *config.NATS, source string) *Publisher {
	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &Publisher{js: js, cfg: cfg, source: source, timeout: timeout}
}

// Publish sends data on subject with retries and dedup.
func (p *Publisher) Publish(ctx context.Context, subject string, data []byte, opts PublishOptions) error {
	if subject == "" {
		return errors.New("nats: subject required")
	}
	if p.js == nil {
		return errors.New("nats: jetstream not connected")
	}

	maxAttempts := opts.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = opts.MaxRetries
	}
	if maxAttempts <= 0 {
		maxAttempts = p.cfg.PublishRetryAttempts
	}
	if maxAttempts <= 0 {
		maxAttempts = 3
	}
	retryDelay := opts.RetryDelay
	if retryDelay <= 0 {
		retryDelay = p.cfg.PublishRetryDelay
	}
	if retryDelay <= 0 {
		retryDelay = 100 * time.Millisecond
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = p.timeout
	}

	msgID := opts.MessageID
	if msgID == "" {
		msgID = uuid.NewString()
	}
	src := opts.Source
	if src == "" {
		src = p.source
	}

	msg := &nats.Msg{Subject: subject, Data: data, Header: nats.Header{}}
	msg.Header.Set(jetstream.MsgIDHeader, msgID)
	msg.Header.Set(HeaderMessageID, msgID)
	if opts.CorrelationID != "" {
		msg.Header.Set(HeaderCorrelationID, opts.CorrelationID)
	}
	if src != "" {
		msg.Header.Set(HeaderSource, src)
	}
	msg.Header.Set(HeaderEnqueuedAt, time.Now().UTC().Format(time.RFC3339Nano))
	for k, v := range opts.Headers {
		if msg.Header.Get(k) == "" {
			msg.Header.Set(k, v)
		}
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		_, err := p.js.PublishMsg(callCtx, msg, jetstream.WithMsgID(msgID))
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err

		// Bail on context errors and unrecoverable subject mismatches.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
		}
		if errors.Is(err, jetstream.ErrNoStreamResponse) {
			return fmt.Errorf("nats: publish %s: %w", subject, err)
		}

		if attempt < maxAttempts {
			sleep := retryDelay * time.Duration(1<<(attempt-1))
			timer := time.NewTimer(sleep)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("nats: publish %s after %d attempts: %w", subject, maxAttempts, lastErr)
}

// PublishEnvelope marshals + publishes a typed envelope on its
// canonical subject. Headers carry the parsed tenant/device/event
// metadata so downstream consumers don't have to decode the
// envelope to route.
func (p *Publisher) PublishEnvelope(ctx context.Context, env schema.Envelope, opts PublishOptions) error {
	data, err := schema.Marshal(env)
	if err != nil {
		return err
	}
	subject := opts.Subject
	if subject == "" {
		subject = SubjectForTelemetry(env.TenantID.String(), string(env.EventClass))
	}
	hdrs := make(map[string]string, len(opts.Headers)+5)
	for k, v := range opts.Headers {
		hdrs[k] = v
	}
	hdrs[HeaderTenantID] = env.TenantID.String()
	hdrs[HeaderDeviceID] = env.DeviceID.String()
	if env.SiteID != nil {
		hdrs[HeaderSiteID] = env.SiteID.String()
	}
	hdrs[HeaderEventClass] = string(env.EventClass)
	hdrs[HeaderPlatform] = string(env.Platform)
	opts.Headers = hdrs
	if opts.MessageID == "" {
		opts.MessageID = env.EventID.String()
	}
	return p.Publish(ctx, subject, data, opts)
}

// PublishToDLQ republishes a failed message onto the DLQ namespace
// with error + delivery-count metadata.
func (p *Publisher) PublishToDLQ(
	ctx context.Context,
	originSubject string,
	data []byte,
	headers map[string]string,
	delivery uint64,
	cause error,
) error {
	dlqSubject := DLQSubjectFor(originSubject)
	hdrs := map[string]string{}
	for k, v := range headers {
		hdrs[k] = v
	}
	hdrs[HeaderOriginSubject] = originSubject
	hdrs[HeaderDeliveryCount] = strconv.FormatUint(delivery, 10)
	if cause != nil {
		hdrs[HeaderError] = cause.Error()
	}

	// Re-use the original dedup ID prefixed with "dlq-" so a flapping
	// consumer doesn't write duplicate DLQ rows for the same source
	// message.
	originID := headers[HeaderMessageID]
	msgID := ""
	if originID != "" {
		msgID = "dlq-" + originID
	}
	return p.Publish(ctx, dlqSubject, data, PublishOptions{
		MessageID:     msgID,
		CorrelationID: headers[HeaderCorrelationID],
		Headers:       hdrs,
	})
}
