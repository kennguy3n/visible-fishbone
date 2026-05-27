package nats

// Common NATS message headers used by the control plane. Mirrors
// the header conventions in sn360-es/pkg/events so cross-platform
// tooling can read them uniformly.
const (
	// HeaderMessageID is the canonical dedup key. Also written to
	// jetstream.MsgIDHeader so server-side deduplication kicks in
	// within the stream's DedupWindow.
	HeaderMessageID = "X-SNG-Message-ID"

	// HeaderCorrelationID groups a chain of related messages.
	HeaderCorrelationID = "X-SNG-Correlation-ID"

	// HeaderTenantID carries the tenant UUID for downstream
	// authorization (set RLS GUC).
	HeaderTenantID = "X-SNG-Tenant-ID"

	// HeaderDeviceID identifies the source device (telemetry path).
	HeaderDeviceID = "X-SNG-Device-ID"

	// HeaderSiteID identifies the source site, when known.
	HeaderSiteID = "X-SNG-Site-ID"

	// HeaderEventClass identifies the schema variant (flow, dns,
	// http, ips, ztna, sdwan, agent, ...).
	HeaderEventClass = "X-SNG-Event-Class"

	// HeaderPlatform identifies the source platform (windows,
	// macos, linux, ios, android).
	HeaderPlatform = "X-SNG-Platform"

	// HeaderSource is the publishing service name (sng-control,
	// sng-agent, etc.).
	HeaderSource = "X-SNG-Source"

	// HeaderEnqueuedAt is RFC3339Nano timestamp set by the
	// publisher just before the JetStream PublishMsg call. Used
	// to compute end-to-end consumer lag.
	HeaderEnqueuedAt = "X-SNG-Enqueued-At"

	// HeaderDeliveryCount is the redelivery counter copied from
	// jetstream metadata into the DLQ envelope.
	HeaderDeliveryCount = "X-SNG-Delivery-Count"

	// HeaderError is the error string that caused a message to
	// land in the DLQ.
	HeaderError = "X-SNG-Error"

	// HeaderOriginSubject is the subject of the message before it
	// was routed to the DLQ.
	HeaderOriginSubject = "X-SNG-Origin-Subject"

	// HeaderOriginEnqueuedAt preserves the original publisher's
	// HeaderEnqueuedAt value when a message is republished to the
	// DLQ. The DLQ publish itself stamps a fresh HeaderEnqueuedAt
	// (so DLQ consumer-lag stays meaningful for the DLQ stream
	// itself), but operators investigating an exhausted-delivery
	// incident need the original publish timestamp to compute
	// end-to-end latency / time-to-fail across the boundary —
	// without this, the original timestamp would be silently lost
	// the moment a message hit the DLQ.
	HeaderOriginEnqueuedAt = "X-SNG-Origin-Enqueued-At"

	// HeaderOriginMessageID preserves the source message's
	// X-SNG-Message-ID when republished to the DLQ. The DLQ
	// envelope itself uses a "dlq-"-prefixed MessageID for its
	// own dedup identity, so a consumer reading from the DLQ
	// can no longer recover the upstream identifier directly
	// from X-SNG-Message-ID. This header makes the original ID
	// explicit so DLQ tooling can join back to the source
	// stream without string-prefix stripping.
	HeaderOriginMessageID = "X-SNG-Origin-Message-ID"
)
