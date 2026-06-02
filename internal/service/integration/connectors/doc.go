// Package connectors implements the four integration plugin
// kinds the IntegrationConnector service routes events to:
// syslog, SIEM webhook, Jira, and ServiceNow.
//
// Each connector is a thin adapter over a transport: it
// unmarshals the per-row Config + Secret, formats the event
// payload into the destination's native wire shape, dispatches
// it, and returns either nil (success), an error wrapping
// integration.ErrTransient (retry me), or a non-wrapping error
// (give up — do not waste the worker's retry budget).
//
// All four plugins are stateless and safe to share across
// tenants and goroutines. Per-tenant state lives in the
// Connector + Delivery rows; the plugin re-unmarshals on every
// call. This keeps the dispatcher concurrency model trivial
// (many goroutines, one plugin pointer) and lets the registry
// be a plain map without locking.
//
// # Error policy
//
// Connectors follow a single rule for retryable-vs-terminal
// failures:
//
//   - network / DNS / TLS handshake errors,
//   - 408, 429, 502, 503, 504 from HTTP destinations,
//   - syslog transport-level write failures,
//
// are wrapped with integration.ErrTransient. The dispatcher will
// retry these up to WorkerConfig.MaxAttempts with exponential
// backoff, then mark the delivery exhausted.
//
// Every other failure (4xx other than 429, malformed config, the
// upstream rejected the payload as invalid) is returned as a
// plain error. The dispatcher marks the delivery 'failed' and
// stops. Connector configuration bugs should never burn the
// retry budget; transient infrastructure issues should not
// terminate deliveries prematurely.
package connectors
