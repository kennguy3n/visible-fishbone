package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Service orchestrates the integration-connector lifecycle and
// hands off delivery work to the DeliveryWorker (see worker.go).
// The split mirrors internal/service/webhook: this file owns the
// synchronous request path; worker.go owns the asynchronous drain.
type Service struct {
	connectors repository.IntegrationConnectorRepository
	deliveries repository.IntegrationDeliveryRepository
	audit      repository.AuditLogRepository
	registry   Registry
	logger     *slog.Logger
	nowFunc    func() time.Time
}

// New constructs a ready-to-use integration service. The registry
// maps every IntegrationConnectorType the deployment supports to
// its plugin implementation; a missing entry causes Enqueue to
// reject deliveries for that kind at the service boundary rather
// than producing dead pending rows.
func New(
	connectors repository.IntegrationConnectorRepository,
	deliveries repository.IntegrationDeliveryRepository,
	audit repository.AuditLogRepository,
	registry Registry,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if registry == nil {
		registry = Registry{}
	}
	return &Service{
		connectors: connectors,
		deliveries: deliveries,
		audit:      audit,
		registry:   registry,
		logger:     logger,
		nowFunc:    func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the wall clock — used by tests to pin
// timestamps. Not safe for concurrent use with live traffic.
func (svc *Service) SetClock(f func() time.Time) {
	svc.nowFunc = f
}

// SupportsKind reports whether the registry has a plugin
// registered for the given connector kind. Useful for the REST
// layer's POST /integrations validation: rejecting at the service
// boundary surfaces the misconfiguration to the operator instead
// of producing a row that will silently fail every delivery.
func (svc *Service) SupportsKind(kind repository.IntegrationConnectorType) bool {
	_, ok := svc.registry[kind]
	return ok
}

// CreateConnectorInput is the validated input to CreateConnector.
// Surfaced as a struct (rather than positional params) because
// the REST handler decodes JSON straight into this shape.
type CreateConnectorInput struct {
	Type        repository.IntegrationConnectorType
	Name        string
	Description string
	EventTypes  []string
	Config      json.RawMessage
	Secret      json.RawMessage
}

// CreateConnector persists a new integration connector. The
// service refuses kinds the registry doesn't recognise so the
// operator gets an ErrInvalidArgument up front rather than a
// stream of failed deliveries later.
func (svc *Service) CreateConnector(
	ctx context.Context,
	tenantID uuid.UUID,
	in CreateConnectorInput,
	actorID *uuid.UUID,
) (repository.IntegrationConnector, error) {
	if err := svc.validateCreate(in); err != nil {
		return repository.IntegrationConnector{}, err
	}
	events, err := normaliseEvents(in.EventTypes)
	if err != nil {
		return repository.IntegrationConnector{}, err
	}
	row := repository.IntegrationConnector{
		TenantID:    tenantID,
		Type:        in.Type,
		Name:        strings.TrimSpace(in.Name),
		Description: strings.TrimSpace(in.Description),
		EventTypes:  events,
		Config:      cloneRawJSON(in.Config),
		Secret:      cloneRawJSON(in.Secret),
		Status:      repository.IntegrationConnectorStatusActive,
	}
	created, err := svc.connectors.Create(ctx, tenantID, row)
	if err != nil {
		return repository.IntegrationConnector{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID,
		"integration.connector_created",
		"integration_connector",
		&created.ID,
		mustMarshal(map[string]any{
			"type":   string(in.Type),
			"name":   created.Name,
			"events": events,
		})))
	return created, nil
}

// UpdateConnectorInput is the partial-update payload. Empty Name
// / Description / EventTypes / Config / Secret are treated as
// "no change" so the REST handler can support PATCH-style writes
// without re-sending every field.
type UpdateConnectorInput struct {
	Name        string
	Description string
	EventTypes  []string
	Config      json.RawMessage
	Secret      json.RawMessage
}

// UpdateConnector applies a partial update. Type is immutable —
// a row created as `jira` cannot be morphed into `servicenow`;
// operators must Delete + Create. This keeps the Config / Secret
// schemas tied to a single connector plugin for their lifetime,
// which simplifies the worker's "what does this byte blob mean?"
// model.
func (svc *Service) UpdateConnector(
	ctx context.Context,
	tenantID, id uuid.UUID,
	in UpdateConnectorInput,
	actorID *uuid.UUID,
) (repository.IntegrationConnector, error) {
	existing, err := svc.connectors.Get(ctx, tenantID, id)
	if err != nil {
		return repository.IntegrationConnector{}, err
	}
	if v := strings.TrimSpace(in.Name); v != "" {
		existing.Name = v
	}
	// Description is intentionally allowed to be cleared by
	// sending an explicit empty string; the handler signals
	// "no change" by omitting the field, which leaves
	// in.Description as its zero value. To keep things simple
	// the partial-update model treats blank as no-op.
	if v := strings.TrimSpace(in.Description); v != "" {
		existing.Description = v
	}
	if in.EventTypes != nil {
		// nil and []string{} carry different semantics on PATCH:
		// nil  = client omitted the field => no change.
		// []   = client explicitly cleared it => subscribe to all.
		// normaliseEvents collapses both to nil, so we shortcut
		// the empty case to write an explicit []string{} that the
		// repo Update will not COALESCE-away.
		if len(in.EventTypes) == 0 {
			existing.EventTypes = []string{}
		} else {
			events, err := normaliseEvents(in.EventTypes)
			if err != nil {
				return repository.IntegrationConnector{}, err
			}
			existing.EventTypes = events
		}
	}
	if len(in.Config) > 0 {
		if !json.Valid(in.Config) {
			return repository.IntegrationConnector{}, fmt.Errorf(
				"config must be valid JSON: %w", repository.ErrInvalidArgument)
		}
		existing.Config = cloneRawJSON(in.Config)
	}
	if len(in.Secret) > 0 {
		if !json.Valid(in.Secret) {
			return repository.IntegrationConnector{}, fmt.Errorf(
				"secret must be valid JSON: %w", repository.ErrInvalidArgument)
		}
		existing.Secret = cloneRawJSON(in.Secret)
	}
	updated, err := svc.connectors.Update(ctx, tenantID, existing)
	if err != nil {
		return repository.IntegrationConnector{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID,
		"integration.connector_updated", "integration_connector", &id, nil))
	return updated, nil
}

// GetConnector returns a single connector by id.
func (svc *Service) GetConnector(ctx context.Context, tenantID, id uuid.UUID) (repository.IntegrationConnector, error) {
	return svc.connectors.Get(ctx, tenantID, id)
}

// ListConnectors returns paginated connectors for the tenant.
func (svc *Service) ListConnectors(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.IntegrationConnector], error) {
	return svc.connectors.List(ctx, tenantID, page)
}

// DeleteConnector removes a connector. The postgres migration
// declares integration_deliveries.connector_id with ON DELETE
// CASCADE (migrations/014_integrations.up.sql:64) and the
// memory repo mirrors that cascade explicitly (see
// internal/repository/memory/integration.go:184-187), so every
// pending and historical delivery row for this connector is
// removed atomically with the parent. The audit row is written
// regardless so the operator-visible delete event is preserved
// even though the delivery history disappears.
func (svc *Service) DeleteConnector(
	ctx context.Context,
	tenantID, id uuid.UUID,
	actorID *uuid.UUID,
) error {
	if err := svc.connectors.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID,
		"integration.connector_deleted", "integration_connector", &id, nil))
	return nil
}

// SetConnectorStatus toggles enable / disable. Used by the
// operator portal to take a misbehaving connector out of rotation
// without dropping its config — re-enabling preserves the
// (tenant, name) uniqueness window and the pending deliveries.
func (svc *Service) SetConnectorStatus(
	ctx context.Context,
	tenantID, id uuid.UUID,
	status repository.IntegrationConnectorStatus,
	actorID *uuid.UUID,
) (repository.IntegrationConnector, error) {
	switch status {
	case repository.IntegrationConnectorStatusActive,
		repository.IntegrationConnectorStatusDisabled:
	default:
		return repository.IntegrationConnector{}, fmt.Errorf(
			"invalid status %q: %w", status, repository.ErrInvalidArgument)
	}
	updated, err := svc.connectors.SetStatus(ctx, tenantID, id, status)
	if err != nil {
		return repository.IntegrationConnector{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID,
		"integration.connector_status_set",
		"integration_connector",
		&id,
		mustMarshal(map[string]any{"status": string(status)})))
	return updated, nil
}

// TestConnector runs the plugin's Test() probe synchronously
// and records the outcome on the connector row. The probe MUST
// be side-effect free on the upstream — see Connector.Test docs.
// Returns the updated connector row so the operator portal can
// surface LastTestAt / LastTestResult / LastTestError in one
// round-trip.
func (svc *Service) TestConnector(
	ctx context.Context,
	tenantID, id uuid.UUID,
	actorID *uuid.UUID,
) (repository.IntegrationConnector, error) {
	row, err := svc.connectors.Get(ctx, tenantID, id)
	if err != nil {
		return repository.IntegrationConnector{}, err
	}
	plugin, ok := svc.registry[row.Type]
	if !ok {
		return repository.IntegrationConnector{}, fmt.Errorf(
			"no plugin registered for connector kind %q: %w",
			row.Type, repository.ErrInvalidArgument)
	}
	now := svc.nowFunc()
	probeErr := plugin.Test(ctx, row.Config, row.Secret)
	result := repository.IntegrationTestResultSuccess
	lastErr := ""
	if probeErr != nil {
		result = repository.IntegrationTestResultFailure
		lastErr = probeErr.Error()
	}
	updated, recErr := svc.connectors.RecordTestResult(ctx, tenantID, id, result, now, lastErr)
	if recErr != nil {
		return repository.IntegrationConnector{}, fmt.Errorf(
			"record test result: %w", recErr)
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID,
		"integration.connector_tested",
		"integration_connector",
		&id,
		mustMarshal(map[string]any{
			"result": string(result),
			"error":  lastErr,
		})))
	// Surface the probe outcome to the caller too — REST handler
	// translates this into 200 (success) vs. 502 (probe failed
	// but row updated). We deliberately don't swallow probeErr.
	if probeErr != nil {
		return updated, fmt.Errorf("test connector: %w", probeErr)
	}
	return updated, nil
}

// Enqueue fans out an event to every active connector subscribed
// to eventType. Returns the slice of created delivery rows
// (empty when no connector matches). The worker is what actually
// dispatches; Enqueue's job is purely "persist the fan-out rows
// atomically". The split lets callers (alert.Router,
// telemetry.Service) emit fire-and-forget without blocking on
// connector latency.
//
// Behaviour for partial fan-out failures: Enqueue returns the
// first non-nil Create error along with the already-persisted
// rows. The operator's view via ListDeliveries shows the
// successful rows; the caller's audit log shows the partial
// failure. We chose this over an all-or-nothing transaction
// because the alert hot path must not block on a single
// connector row's index contention — and the worker is happy to
// drain whatever the repo accepted.
func (svc *Service) Enqueue(
	ctx context.Context,
	tenantID uuid.UUID,
	eventType string,
	payload json.RawMessage,
) ([]repository.IntegrationDelivery, error) {
	if strings.TrimSpace(eventType) == "" {
		return nil, fmt.Errorf("event type is required: %w", repository.ErrInvalidArgument)
	}
	if len(payload) == 0 {
		payload = json.RawMessage(`{}`)
	}
	if !json.Valid(payload) {
		return nil, fmt.Errorf("payload is not valid JSON: %w", repository.ErrInvalidArgument)
	}
	matches, err := svc.connectors.ListActive(ctx, tenantID, []string{eventType})
	if err != nil {
		return nil, fmt.Errorf("list active connectors: %w", err)
	}
	if len(matches) == 0 {
		return nil, nil
	}
	now := svc.nowFunc()
	out := make([]repository.IntegrationDelivery, 0, len(matches))
	for _, c := range matches {
		if _, ok := svc.registry[c.Type]; !ok {
			// Defensive: a row with an unknown Kind. The Create
			// path rejects these, but a deployment that
			// downgraded its registry (dropped a plugin) could
			// still hold them. Log + skip rather than creating
			// a dead pending row.
			svc.logger.Warn("integration: skipping enqueue for unsupported connector kind",
				slog.String("tenant_id", tenantID.String()),
				slog.String("connector_id", c.ID.String()),
				slog.String("kind", string(c.Type)))
			continue
		}
		d := repository.IntegrationDelivery{
			ConnectorID: c.ID,
			EventType:   eventType,
			Payload:     append(json.RawMessage{}, payload...),
			Status:      repository.IntegrationDeliveryStatusPending,
			NextRetryAt: now,
		}
		created, cerr := svc.deliveries.Create(ctx, tenantID, d)
		if cerr != nil {
			return out, fmt.Errorf(
				"enqueue delivery for connector %s: %w", c.ID, cerr)
		}
		out = append(out, created)
	}
	return out, nil
}

// ListDeliveries returns paginated delivery rows for a tenant,
// optionally scoped to a single connector.
func (svc *Service) ListDeliveries(
	ctx context.Context,
	tenantID uuid.UUID,
	connectorID *uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.IntegrationDelivery], error) {
	return svc.deliveries.List(ctx, tenantID, connectorID, page)
}

// GetDelivery returns one delivery by id.
func (svc *Service) GetDelivery(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.IntegrationDelivery, error) {
	return svc.deliveries.Get(ctx, tenantID, id)
}

// --- internals ------------------------------------------------------------

func (svc *Service) validateCreate(in CreateConnectorInput) error {
	if !in.Type.IsValid() {
		return fmt.Errorf("invalid connector type %q: %w", in.Type, repository.ErrInvalidArgument)
	}
	if _, ok := svc.registry[in.Type]; !ok {
		return fmt.Errorf(
			"no plugin registered for connector kind %q: %w",
			in.Type, repository.ErrInvalidArgument)
	}
	if strings.TrimSpace(in.Name) == "" {
		return fmt.Errorf("name is required: %w", repository.ErrInvalidArgument)
	}
	if len(in.Config) == 0 {
		return fmt.Errorf("config is required: %w", repository.ErrInvalidArgument)
	}
	if !json.Valid(in.Config) {
		return fmt.Errorf("config must be valid JSON: %w", repository.ErrInvalidArgument)
	}
	if len(in.Secret) > 0 && !json.Valid(in.Secret) {
		return fmt.Errorf("secret must be valid JSON: %w", repository.ErrInvalidArgument)
	}
	return nil
}

// normaliseEvents trims, lowercases, dedupes, and sorts so the
// persisted ordering is stable and ListActive's IN-clause is
// deterministic. It treats len(events)==0 as "subscribe to all"
// and returns (nil, nil). On CREATE the caller passes the input
// through unconditionally; on UPDATE the caller must distinguish
// nil (no change) from []string{} (subscribe to all) BEFORE
// calling this helper, since both collapse to nil here.
func normaliseEvents(events []string) ([]string, error) {
	if len(events) == 0 {
		return nil, nil
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

// cloneRawJSON returns a copy of the input bytes so the caller's
// buffer reuse cannot mutate persisted rows.
func cloneRawJSON(in json.RawMessage) json.RawMessage {
	if len(in) == 0 {
		return nil
	}
	out := make(json.RawMessage, len(in))
	copy(out, in)
	return out
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
	svc.logger.Warn("integration: audit append failed", slog.Any("error", err))
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
