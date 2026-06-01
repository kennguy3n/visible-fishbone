// Package integration implements the integration-connector service:
// per-tenant outbound destinations (syslog, SIEM webhook, Jira,
// ServiceNow) that consume the same alert.* + telemetry.* events
// the webhook subscription system fans out to URL endpoints.
//
// # Architectural contract
//
// The service is intentionally shaped to mirror
// internal/service/webhook so the operator mental model is
// "webhook destinations are URL connectors; integration
// destinations are typed connectors". The two pipes share:
//
//   - The same Enqueue / DeliveryWorker lifecycle.
//   - The same UPDATE … RETURNING SKIP-LOCKED atomic-claim
//     pattern in ListPending.
//   - The same exponential-backoff retry budget shape.
//
// They diverge on the dispatch step: webhooks always POST a JSON
// body to a URL; integrations dispatch to a typed Connector
// plugin (syslog, siem, jira, servicenow) that owns its own wire
// protocol, body encoding, and "what counts as success" rule. The
// plugin contract is the Connector interface below.
package integration

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ErrTransient signals the dispatcher that the delivery failed
// in a way that warrants retry. Connectors return ErrTransient
// (wrapped via fmt.Errorf("...: %w", ErrTransient)) for network
// timeouts, 5xx upstream responses, rate-limits, etc. The
// dispatcher schedules the next attempt with exponential backoff
// up to MaxAttempts before terminating the delivery as
// 'exhausted'.
//
// Any non-transient error (4xx upstream excluding 429, malformed
// payload that won't be fixed by retry, etc.) terminates the
// delivery as 'failed' immediately so a misconfigured connector
// does not hog the worker's retry budget.
var ErrTransient = errors.New("integration: transient delivery error")

// Sendable carries everything a Connector.Send call needs to
// dispatch one delivery. The dispatcher fills this in before
// invoking the connector — connectors must not retain any
// references to the fields past Send's return: Payload and Secret
// may be reused by the worker on subsequent calls.
type Sendable struct {
	// EventType is the routing key — e.g. "alert.created",
	// "alert.acknowledged". Connectors use this to pick the
	// right downstream operation (e.g. Jira creates an issue on
	// alert.created, transitions it on alert.resolved).
	EventType string
	// Payload is the connector-agnostic event body (JSON). The
	// connector translates this into its native wire format
	// (CEF / RFC5424 for syslog, REST JSON for SIEM, Jira's
	// nested ADF for Jira, etc.).
	Payload json.RawMessage
	// Config + Secret are the connector-specific configuration
	// (URL, project key, instance name, auth token …) read out
	// of the IntegrationConnector row. The plugin is responsible
	// for unmarshalling them.
	Config json.RawMessage
	Secret json.RawMessage
	// ExternalReference, when non-empty, identifies a previously
	// created remote object that the current Send should update
	// rather than create a new one (Jira issue key, ServiceNow
	// sys_id). Read-only inside Send.
	ExternalReference string
	// Now is the dispatcher's monotonic time-of-dispatch.
	// Connectors should prefer this over time.Now() so
	// timestamps stay deterministic in tests.
	Now time.Time
}

// SendResult is what Send returns on success. ExternalReference
// is the remote object's stable identifier (Jira issue key,
// ServiceNow sys_id) — empty for connectors that don't surface
// one (syslog). Persisted on the IntegrationDelivery row so the
// follow-up alert.acknowledged / alert.resolved events know which
// remote object to update.
type SendResult struct {
	ExternalReference string
	// ResponseStatus is the HTTP status (or syslog-equivalent
	// integer) the connector observed. Persisted for audit so
	// operators can debug "why did this delivery fail?".
	ResponseStatus int
}

// Connector is the plugin contract every integration kind
// implements. Implementations are stateless and reusable across
// tenants — per-tenant state lives in (Config, Secret), the
// connector unmarshals on each call. This keeps the dispatcher's
// concurrency model trivial: many goroutines can call Send /
// Test on the same Connector pointer with different inputs.
type Connector interface {
	// Kind returns the IntegrationConnectorType this plugin
	// implements. The Service's registry indexes plugins by
	// Kind() so a row with Type=jira routes to the jira plugin.
	Kind() repository.IntegrationConnectorType

	// Send delivers one event. Returns SendResult on success or
	// an error. Wrap retryable errors with ErrTransient so the
	// dispatcher knows to schedule a retry rather than terminate
	// the delivery.
	Send(ctx context.Context, s Sendable) (SendResult, error)

	// Test runs a connectivity probe: validates Config / Secret,
	// reaches the upstream, and returns nil on success. Surface
	// at the REST layer as POST /integrations/{id}/test. Must not
	// have side effects on the upstream (e.g. should NOT create
	// a Jira issue; should at most probe `GET /myself`).
	Test(ctx context.Context, config, secret json.RawMessage) error
}

// Registry maps an IntegrationConnectorType to its implementing
// Connector. Registries are populated at boot in cmd/sng-control
// and passed to the Service. A registry without an entry for a
// stored connector row is treated as a configuration error: the
// Service refuses to enqueue deliveries for unknown kinds rather
// than silently dropping the event.
type Registry map[repository.IntegrationConnectorType]Connector
