package repository

import (
	"context"
	"time"
)

// ThreatIOC is one persisted indicator-of-compromise row. It is a
// neutral, primitive-typed projection of the in-memory
// ai.IOC: the data layer deliberately does not import the ai
// package (which owns the rich IOCType / HashAlgo enums and the
// normalization helpers), so the ai-side persister maps between
// this row and its domain type at the composition root.
//
// The table backing it is a single global snapshot of the
// aggregated IOC store — NOT tenant-scoped. Threat-intel feeds are
// fleet-wide signals (the same C2 IP is malicious for every
// tenant), mirroring the global app_registry rather than the
// per-tenant app_registry_overrides.
type ThreatIOC struct {
	// Type is the indicator category ("domain", "ip", "url",
	// "hash") — the string form of ai.IOCType.
	Type string
	// Value is the already-normalized indicator.
	Value string
	// HashAlgo is the digest algorithm for hash indicators
	// ("md5", "sha1", "sha256"); empty for other types.
	HashAlgo string
	// Source is the feed that produced the indicator.
	Source string
	// ThreatActor / Campaign are optional attribution.
	ThreatActor string
	Campaign    string
	// Confidence is the feed-supplied confidence in [0,1].
	Confidence float64
	// FirstSeen / LastSeen bound the observation window. A zero
	// time means "unknown" and persists as NULL.
	FirstSeen time.Time
	LastSeen  time.Time
	// ExpiresAt is the TTL boundary. A zero time means the
	// indicator never expires on its own and persists as NULL.
	ExpiresAt time.Time
}

// ThreatIOCRepository is the durability boundary for the
// aggregated IOC store. It is a whole-set snapshot store, not a
// row-level CRUD surface: the in-memory store is the source of
// truth at runtime, and this table only exists so a control-plane
// restart can re-warm the store immediately instead of waiting for
// every feed to re-fetch (which, with hourly feeds, can leave a
// long enforcement gap).
//
// NOT tenant-scoped — see ThreatIOC. Writes run in a system-role
// transaction.
type ThreatIOCRepository interface {
	// ReplaceAll atomically replaces the persisted indicator set
	// with the provided snapshot inside a single transaction. An
	// empty slice clears the table. Snapshot semantics (rather
	// than per-row upsert) keep the persisted set in lock-step
	// with the live store, including expiry-driven removals.
	ReplaceAll(ctx context.Context, iocs []ThreatIOC) error
	// LoadAll returns every persisted indicator. Callers filter
	// already-expired rows on restore.
	LoadAll(ctx context.Context) ([]ThreatIOC, error)
}
