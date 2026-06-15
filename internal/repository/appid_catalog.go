package repository

import (
	"context"
	"time"
)

// AppIDCatalogVersion is the metadata for one immutable, published
// revision of the fleet-wide Application-ID signature catalog. It is
// a neutral, primitive-typed projection: the data layer deliberately
// does not import the appid service (which owns the rich signed-bundle
// envelope and the canonical-JSON encoding), so the service maps
// between this row and its domain types at the composition root.
//
// The catalog is NOT tenant-scoped. Application signatures are
// fleet-wide knowledge (teams.microsoft.com is Microsoft Teams for
// every tenant), so it mirrors the global app_registry / threat-intel
// IOC store rather than the per-tenant app_registry_overrides. Writes
// run in a system-role transaction; the publish action is gated by a
// platform permission at the service/handler layer.
//
// Versions are identified by a monotonic Serial (not a UUID): the edge
// uses Serial for replay protection exactly like the threat-intel and
// policy bundles do — a consumer ignores any bundle whose serial is
// less than or equal to the highest it has already applied.
type AppIDCatalogVersion struct {
	// Serial is the monotonic version number. Higher is newer. It is
	// the bundle serial the edge pins for replay protection.
	Serial int64
	// SchemaVersion is the catalog schema the entries conform to.
	SchemaVersion int
	// AppCount is the number of signature entries in this version,
	// denormalised for cheap listing without counting entries.
	AppCount int
	// Checksum is the lowercase-hex SHA-256 of the canonical bundle
	// payload, so an operator can confirm two environments serve the
	// byte-identical catalog without diffing every entry.
	Checksum string
	// Note is an optional operator-supplied changelog line.
	Note string
	// CreatedAt is when the version was published.
	CreatedAt time.Time
}

// AppIDCatalogEntry is one persisted application signature within a
// catalog version. The list-valued match keys are stored as text
// arrays; byte-probe prefixes are lowercase-hex strings (the same
// on-the-wire form the Rust crate's catalog.json uses) so the row is
// a faithful, queryable projection of one signature.
//
// Entries are persisted in addition to the signed bundle so operators
// can browse and audit the live catalog through SQL / the read API
// without parsing the bundle, and so a future server-side rebuild of
// the matcher has a structured source. The signed bundle remains the
// authoritative distribution artifact.
type AppIDCatalogEntry struct {
	// Serial ties the entry to its AppIDCatalogVersion.
	Serial int64
	// AppID is the stable catalog identity (e.g. "microsoft.teams").
	AppID string
	// Category groups the app (e.g. "collaboration", "storage").
	Category string
	// SNISuffixes / HostSuffixes are normalised dotted suffixes
	// matched longest-first against the TLS SNI and HTTP Host.
	SNISuffixes  []string
	HostSuffixes []string
	// JA3 holds optional TLS client fingerprints (lowercase hex).
	JA3 []string
	// BytePrefixes are small bounded payload prefixes (lowercase hex)
	// used to identify non-TLS protocols.
	BytePrefixes []string
	// Ports / Transport are weak modifiers, never an identity on
	// their own. Transport is "tcp" or "udp".
	Ports     []int
	Transport string
	// Confidence is the base match confidence in [0,100].
	Confidence int
}

// AppIDCatalogBundle is the signed, canonical distribution artifact
// for one catalog version. It is the verbatim Ed25519-signed envelope
// the appid service produces; the edge verifies Signature against a
// pinned public key before parsing Payload (fail-closed). All binary
// fields are stored raw (BYTEA) rather than base64 so the row is the
// canonical bytes, not a re-encoding.
type AppIDCatalogBundle struct {
	// Serial ties the bundle to its AppIDCatalogVersion.
	Serial int64
	// Algorithm is the signature algorithm, currently "ed25519".
	Algorithm string
	// KeyID optionally identifies the signing key for rotation.
	KeyID string
	// PublicKey is the Ed25519 public key the bundle was signed with
	// (advisory; the edge trusts only its pinned key).
	PublicKey []byte
	// Payload is the canonical catalog JSON that was signed.
	Payload []byte
	// Signature is the Ed25519 signature over Payload.
	Signature []byte
	// CreatedAt is when the bundle was signed and stored.
	CreatedAt time.Time
}

// AppIDCatalogRepository is the durability boundary for the versioned,
// fleet-wide Application-ID catalog. Each published version is an
// immutable triple — metadata, the structured entries, and the signed
// bundle — written atomically so a reader never observes a version
// whose bundle or entries are missing.
//
// NOT tenant-scoped — see AppIDCatalogVersion. Writes run in a
// system-role transaction; the tenant-scoped read path serves the
// same global content to every authenticated tenant.
type AppIDCatalogRepository interface {
	// PublishVersion atomically persists a new catalog version: its
	// metadata, every entry, and the signed bundle, in a single
	// transaction. The version's Serial must be strictly greater than
	// the current one; a duplicate or regressing serial returns
	// ErrConflict so concurrent publishers cannot fork history.
	PublishVersion(ctx context.Context, version AppIDCatalogVersion, entries []AppIDCatalogEntry, bundle AppIDCatalogBundle) error
	// CurrentVersion returns the highest-serial version's metadata, or
	// ErrNotFound when the catalog has never been published.
	CurrentVersion(ctx context.Context) (AppIDCatalogVersion, error)
	// CurrentEntries returns every entry of the highest-serial
	// version, ordered by app_id for deterministic output. It returns
	// ErrNotFound when the catalog has never been published.
	CurrentEntries(ctx context.Context) ([]AppIDCatalogEntry, error)
	// CurrentBundleWithVersion returns the highest-serial version's
	// signed bundle together with its own version metadata, read in a
	// single transaction so the two can never disagree. It returns
	// ErrNotFound when the catalog has never been published. This is
	// the artifact the tenant read endpoint serves and the edge
	// verifies: the bundle and the metadata (serial, app_count,
	// checksum) are guaranteed to describe the same published version
	// even under a concurrent publish, so an edge never sees a checksum
	// that does not match the payload it received.
	CurrentBundleWithVersion(ctx context.Context) (AppIDCatalogBundle, AppIDCatalogVersion, error)
	// ListVersions returns published version metadata newest-first,
	// capped at limit (a non-positive or oversized limit is clamped to
	// a sane default). It is the catalog's change history.
	ListVersions(ctx context.Context, limit int) ([]AppIDCatalogVersion, error)
}
