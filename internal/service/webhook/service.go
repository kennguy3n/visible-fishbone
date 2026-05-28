// Package webhook implements webhook subscription management +
// delivery for tenant-scoped event notifications.
//
// The service exposes two surfaces:
//
//  1. CRUD over webhook endpoints (URL + event filter + signing
//     secret). The secret is returned exactly once on Create and
//     subsequently only its SHA-256 hash is persisted.
//  2. Enqueue: given an event type + JSON payload, the service
//     fans out a webhook_deliveries row for every active endpoint
//     subscribed to the event. The background DeliveryWorker
//     picks these up and POSTs them with retry/backoff.
//
// Deliveries are signed with HMAC-SHA256 over the request body
// using the endpoint's secret. The signature is sent in the
// `X-SNG-Signature` header. Receivers verify with the secret
// returned on Create.
package webhook

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Service implements webhook operations.
type Service struct {
	endpoints  repository.WebhookEndpointRepository
	deliveries repository.WebhookDeliveryRepository
	audit      repository.AuditLogRepository
	logger     *slog.Logger
	nowFunc    func() time.Time
}

// New returns a ready-to-use webhook service.
func New(
	endpoints repository.WebhookEndpointRepository,
	deliveries repository.WebhookDeliveryRepository,
	audit repository.AuditLogRepository,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		endpoints:  endpoints,
		deliveries: deliveries,
		audit:      audit,
		logger:     logger,
		nowFunc:    func() time.Time { return time.Now().UTC() },
	}
}

// CreateEndpointResult is returned by Create: it carries the
// persisted record plus the freshly minted signing secret. The
// secret is returned exactly once.
type CreateEndpointResult struct {
	Endpoint repository.WebhookEndpoint
	Secret   string
}

// CreateEndpoint provisions a new webhook subscription. The
// returned `Secret` is a base64url-encoded 32-byte random value
// the receiver uses to verify HMAC signatures on incoming requests.
func (svc *Service) CreateEndpoint(
	ctx context.Context,
	tenantID uuid.UUID,
	rawURL string,
	events []string,
	actorID *uuid.UUID,
) (CreateEndpointResult, error) {
	if err := validateURL(rawURL); err != nil {
		return CreateEndpointResult{}, err
	}
	cleanEvents, err := normaliseEvents(events)
	if err != nil {
		return CreateEndpointResult{}, err
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return CreateEndpointResult{}, fmt.Errorf("generate webhook secret: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(secret)

	ep := repository.WebhookEndpoint{
		URL:           rawURL,
		Events:        cleanEvents,
		SigningSecret: secret,
		Status:        repository.WebhookEndpointStatusActive,
	}
	created, err := svc.endpoints.Create(ctx, tenantID, ep)
	if err != nil {
		return CreateEndpointResult{}, err
	}

	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID,
		"webhook.endpoint_created", "webhook_endpoint", &created.ID,
		mustMarshal(map[string]any{"url": rawURL, "events": cleanEvents})))

	return CreateEndpointResult{Endpoint: created, Secret: plaintext}, nil
}

// GetEndpoint retrieves a single endpoint by id.
func (svc *Service) GetEndpoint(ctx context.Context, tenantID, id uuid.UUID) (repository.WebhookEndpoint, error) {
	return svc.endpoints.Get(ctx, tenantID, id)
}

// ListEndpoints returns paginated endpoints for the tenant.
func (svc *Service) ListEndpoints(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.WebhookEndpoint], error) {
	return svc.endpoints.List(ctx, tenantID, page)
}

// UpdateEndpoint applies a partial update. Empty URL or nil events
// are treated as "no change". Status is updated when non-empty.
func (svc *Service) UpdateEndpoint(
	ctx context.Context,
	tenantID uuid.UUID,
	id uuid.UUID,
	rawURL string,
	events []string,
	status repository.WebhookEndpointStatus,
	actorID *uuid.UUID,
) (repository.WebhookEndpoint, error) {
	existing, err := svc.endpoints.Get(ctx, tenantID, id)
	if err != nil {
		return repository.WebhookEndpoint{}, err
	}
	if rawURL != "" {
		if err := validateURL(rawURL); err != nil {
			return repository.WebhookEndpoint{}, err
		}
		existing.URL = rawURL
	}
	if events != nil {
		cleanEvents, err := normaliseEvents(events)
		if err != nil {
			return repository.WebhookEndpoint{}, err
		}
		existing.Events = cleanEvents
	}
	if status != "" {
		switch status {
		case repository.WebhookEndpointStatusActive,
			repository.WebhookEndpointStatusDisabled:
			existing.Status = status
		default:
			return repository.WebhookEndpoint{}, fmt.Errorf(
				"invalid status %q: %w", status, repository.ErrInvalidArgument)
		}
	}
	updated, err := svc.endpoints.Update(ctx, tenantID, existing)
	if err != nil {
		return repository.WebhookEndpoint{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID,
		"webhook.endpoint_updated", "webhook_endpoint", &id, nil))
	return updated, nil
}

// DeleteEndpoint removes an endpoint.
func (svc *Service) DeleteEndpoint(ctx context.Context, tenantID, id uuid.UUID, actorID *uuid.UUID) error {
	if err := svc.endpoints.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID,
		"webhook.endpoint_deleted", "webhook_endpoint", &id, nil))
	return nil
}

// Enqueue fans out a deliver-once event to every active endpoint
// subscribed to `eventType`. Returns the slice of created
// delivery rows (empty if no endpoint matched). The delivery
// worker picks pending rows up out of band.
func (svc *Service) Enqueue(
	ctx context.Context,
	tenantID uuid.UUID,
	eventType string,
	payload json.RawMessage,
) ([]repository.WebhookDelivery, error) {
	if eventType == "" {
		return nil, fmt.Errorf("event type is required: %w", repository.ErrInvalidArgument)
	}
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if !json.Valid(payload) {
		return nil, fmt.Errorf("payload is not valid JSON: %w", repository.ErrInvalidArgument)
	}

	matches, err := svc.endpoints.ListActive(ctx, tenantID, []string{eventType})
	if err != nil {
		return nil, fmt.Errorf("list active endpoints: %w", err)
	}
	if len(matches) == 0 {
		return nil, nil
	}

	now := svc.nowFunc()
	out := make([]repository.WebhookDelivery, 0, len(matches))
	for _, ep := range matches {
		d := repository.WebhookDelivery{
			EndpointID:  ep.ID,
			EventType:   eventType,
			Payload:     append(json.RawMessage{}, payload...),
			Status:      repository.WebhookDeliveryStatusPending,
			NextRetryAt: now,
		}
		created, err := svc.deliveries.Create(ctx, tenantID, d)
		if err != nil {
			return out, fmt.Errorf("enqueue delivery for endpoint %s: %w", ep.ID, err)
		}
		out = append(out, created)
	}
	return out, nil
}

// ListDeliveries returns paginated deliveries for a tenant,
// optionally scoped to a single endpoint.
func (svc *Service) ListDeliveries(
	ctx context.Context,
	tenantID uuid.UUID,
	endpointID *uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.WebhookDelivery], error) {
	return svc.deliveries.List(ctx, tenantID, endpointID, page)
}

// validateURL rejects obviously malformed URLs at the service
// layer. The repository can still reject duplicates / overly-long
// values; this is just a fast-path.
func validateURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("url is required: %w", repository.ErrInvalidArgument)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", repository.ErrInvalidArgument)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("url scheme must be http or https, got %q: %w",
			u.Scheme, repository.ErrInvalidArgument)
	}
	if u.Host == "" {
		return fmt.Errorf("url must have a host: %w", repository.ErrInvalidArgument)
	}
	return nil
}

// normaliseEvents trims, lowercases, dedupes, and sorts the event
// filter so the persisted ordering is stable.
func normaliseEvents(events []string) ([]string, error) {
	if len(events) == 0 {
		return nil, fmt.Errorf("at least one event subscription is required: %w",
			repository.ErrInvalidArgument)
	}
	seen := make(map[string]struct{}, len(events))
	out := make([]string, 0, len(events))
	for _, e := range events {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "" {
			continue
		}
		if _, dup := seen[e]; dup {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one non-empty event is required: %w",
			repository.ErrInvalidArgument)
	}
	sort.Strings(out)
	return out, nil
}

func (svc *Service) appendAudit(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	action, resourceType string,
	resourceID *uuid.UUID,
	details json.RawMessage,
) error {
	if details == nil {
		details = json.RawMessage(`{}`)
	}
	// Stamp acting API-key ID into details for machine-to-machine
	// authenticated requests; see middleware.EnrichAuditDetails for
	// the rationale (actor_id is a *user* UUID and NULL on API-key
	// paths, so machine-actor attribution lives in details).
	details = middleware.EnrichAuditDetails(ctx, details)
	_, err := svc.audit.Append(ctx, tenantID, repository.AuditEntry{
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	})
	return err
}

func (svc *Service) logAuditErr(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return
	}
	svc.logger.Warn("webhook: audit append failed", slog.Any("error", err))
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		// Marshalling map[string]any with strings is unreachable
		// in practice; fall back to an empty object rather than
		// blowing up the call site.
		return json.RawMessage(`{}`)
	}
	return b
}
