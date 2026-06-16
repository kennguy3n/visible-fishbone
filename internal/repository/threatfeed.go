package repository

import (
	"context"
	"time"
)

// This file defines the data layer for the MANAGED threat-content
// engine (internal/service/threatfeed) — the curated, no-ops producer
// that turns several built-in reputable open feeds into one signed,
// versioned content bundle distributed to every tenant by default.
//
// It is deliberately separate from the ThreatIOC store (threat_ioc.go),
// which is owned by the internal/service/ai feed manager: that store is
// a whole-table ReplaceAll snapshot the ai persister clobbers on every
// flush, so the managed engine keeps its own tables (migrations
// 076-078) and never writes there. Like ThreatIOC, every row here is a
// neutral, primitive-typed projection (the data layer does not import
// the service packages) and the backing tables are platform-GLOBAL, not
// tenant-scoped — managed threat content is a fleet-wide signal pushed
// to all tenants identically, so writes run in a system-role
// transaction mirroring the global app_registry rather than a
// per-tenant table.

// ThreatFeedSource is one row of the managed-feed source registry
// (migration 076). The registry is the operator-visible record of which
// curated feeds the platform ingests; it is seeded from the engine's
// built-in defaults at boot and is the join target for the per-source
// health surface. Tenants never configure these — the set is centrally
// managed.
type ThreatFeedSource struct {
	// Name is the stable internal identifier (e.g. "abuse.ch:feodo").
	// Primary key.
	Name string
	// DisplayName is the human-facing label for the posture surface.
	DisplayName string
	// Kind is the dominant indicator category the feed contributes
	// ("domain", "ip", "url", "hash", or "mixed"). Advisory metadata —
	// the parser, not this field, decides each indicator's real type.
	Kind string
	// URL is the upstream feed location. Empty for an in-process bridge
	// source (e.g. one that reads the live aggregator).
	URL string
	// Weight is the source's trust weight in (0,1], folded into the
	// corroboration score. Higher means a more authoritative feed.
	Weight float64
	// Enabled gates ingestion. A disabled source is retained in the
	// registry (for history/telemetry) but skipped by the refresh loop
	// (the engine drops its cached payload and contributes none of its
	// indicators). It is operator-owned: the curated boot seed only sets
	// it on first insert and UpsertSources preserves it thereafter, so an
	// operator disable survives leader restarts and re-seeds.
	Enabled bool
	// DefaultTTLSeconds is how long an indicator from this feed stays
	// live after it was last seen, when the feed itself supplies no
	// expiry. Zero means "never expires on its own".
	DefaultTTLSeconds int64
	// CreatedAt / UpdatedAt are set by the repository.
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ThreatFeedIngestState is the per-source ingestion cursor + last
// outcome (migration 077). It makes the refresh incremental — the HTTP
// validators (ETag / Last-Modified) let an unchanged feed be skipped
// with a conditional GET — and powers the per-source health view so an
// operator can see, with zero per-tenant work, whether each curated
// feed is fresh or failing.
type ThreatFeedIngestState struct {
	// SourceName references ThreatFeedSource.Name. Primary key.
	SourceName string
	// LastAttemptAt is when the loop last tried to fetch this source.
	LastAttemptAt time.Time
	// LastSuccessAt is when the source last parsed to a usable result.
	// Zero until the first success; staleness is measured from it.
	LastSuccessAt time.Time
	// LastError is the most recent failure message (empty on success).
	LastError string
	// IndicatorCount is how many indicators the last successful parse
	// contributed (post-normalization, pre-dedup).
	IndicatorCount int64
	// ConsecutiveFailures counts back-to-back failures since the last
	// success; it resets to zero on any success and bounds alerting.
	ConsecutiveFailures int64
	// ETag / LastModified are the HTTP cache validators echoed back on
	// the next fetch for a conditional GET (incremental refresh).
	ETag         string
	LastModified string
	// UpdatedAt is set by the repository.
	UpdatedAt time.Time
}

// ThreatFeedBundle is one signed, versioned managed-content bundle
// (migration 078). It is the distributable artifact: Envelope is the
// self-describing signed envelope (the same Ed25519 trust model as the
// policy / IPS / threat-intel DNS bundles) that a consumer verifies
// against the pinned platform key before applying. Persisting it makes
// distribution durable and replica-independent — any control-plane
// replica can serve the current managed posture from the latest row
// without re-running ingestion, and a consumer that reconnects after a
// restart still sees the last good bundle.
type ThreatFeedBundle struct {
	// Serial is the monotonically non-decreasing version (producer unix
	// seconds, advanced past the last serial). Primary key. A consumer
	// pins the highest serial it has applied and ignores any lower one,
	// so an out-of-order delivery can never roll the feed back.
	Serial int64
	// SchemaVersion is the payload layout version stamped in the bundle.
	SchemaVersion int
	// GeneratedAt is the producer timestamp (UTC).
	GeneratedAt time.Time
	// KeyID labels which signing key produced the envelope so the
	// consumer selects the matching pinned verifying key.
	KeyID string
	// Algorithm is the signature algorithm identifier ("ed25519").
	Algorithm string
	// IndicatorCount is the total indicator count in the bundle.
	IndicatorCount int64
	// SizeBytes is the marshalled envelope size, for telemetry.
	SizeBytes int64
	// Digest is the lowercase-hex SHA-256 of the bundle's CONTENT
	// IDENTITY: each indicator's type/value/hash plus its sorted
	// contributing sources. It deliberately excludes Serial, GeneratedAt,
	// the recency-decayed score, and the observation timestamps — all of
	// which drift every run — so the producer can detect that a refresh
	// reproduced the same indicator set and skip minting/re-publishing a
	// new version. This churn-avoidance fast path is what keeps the
	// bounded refresh cheap at fleet scale (see ContentDigest in the
	// threatfeed service for the full rationale).
	Digest string
	// CountsByType is the per-type indicator cardinality
	// (domain/ip/cidr/url/hash) surfaced on the posture endpoint without
	// unpacking the envelope. Stored as JSONB.
	CountsByType map[string]int
	// Envelope is the signed bundle JSON distributed to consumers.
	Envelope []byte
	// CreatedAt is set by the repository.
	CreatedAt time.Time
}

// ThreatFeedRepository persists the managed threat-content engine's
// state: the source registry, per-source ingestion cursors, and the
// signed versioned bundle history. All operations are platform-global
// (system-role); none are tenant-scoped.
//
// It is implemented by both the postgres and memory backends in NEW
// files (postgres/threatfeed.go, memory/threatfeed.go) so this addition
// touches no shared repository file.
type ThreatFeedRepository interface {
	// UpsertSources idempotently writes the managed source registry.
	// Called at boot to seed/refresh the built-in feed set. On an
	// existing row it updates the curated metadata (display name, kind,
	// URL, weight, default TTL), preserves CreatedAt, and bumps
	// UpdatedAt. It deliberately PRESERVES the existing Enabled flag
	// rather than overwriting it from the seed, so an operator's per-feed
	// disable is durable across leader restarts and re-seeds; Enabled is
	// only set from the input on the initial insert.
	UpsertSources(ctx context.Context, sources []ThreatFeedSource) error
	// ListSources returns the registry ordered by Name.
	ListSources(ctx context.Context) ([]ThreatFeedSource, error)

	// SaveIngestState upserts one source's ingestion cursor/outcome.
	SaveIngestState(ctx context.Context, state ThreatFeedIngestState) error
	// ListIngestState returns every source's cursor ordered by
	// SourceName.
	ListIngestState(ctx context.Context) ([]ThreatFeedIngestState, error)

	// SaveBundle persists a signed bundle version. A serial collision
	// (two replicas producing within the same second) overwrites the
	// row with the newer envelope — both are valid managed content and
	// last-writer-wins keeps monotonicity without a re-sign loop.
	SaveBundle(ctx context.Context, bundle ThreatFeedBundle) error
	// LatestBundle returns the highest-serial bundle, or ErrNotFound
	// when none has been produced yet.
	LatestBundle(ctx context.Context) (*ThreatFeedBundle, error)
	// LatestSerial returns the highest persisted serial, or 0 when no
	// bundle exists. Used to seed the engine's monotonic serial across
	// restarts and replicas without decoding an envelope.
	LatestSerial(ctx context.Context) (int64, error)
	// PruneBundles deletes all but the newest keep versions, bounding
	// history growth. keep <= 0 is a no-op (retain everything).
	PruneBundles(ctx context.Context, keep int) error
}
