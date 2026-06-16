// Package threatfeed is SNG's MANAGED, no-ops threat-content engine.
//
// The existing internal/service/threatintel package is a DELIVERY
// pipeline: it pulls operator-configured feed URLs, is default-OFF
// (THREAT_INTEL_ENABLED), and ships nothing unless an operator finds,
// vets and wires upstreams. SME tenants have neither the expertise nor
// the time, so in practice they run with no threat content — while
// leaders (Unit 42 / FortiGuard) ship curated managed content out of
// the box.
//
// threatfeed closes that gap. It ingests a curated set of built-in
// reputable open feeds (domain / IP / URL / hash indicators), reuses
// the codebase's normalization conventions (internal/service/ai.NewIOC:
// lowercase domains, trailing-dot strip, canonical IP/CIDR, hash-algo
// detection), deduplicates across feeds, scores each indicator from
// corroboration + source weight + recency, expires stale indicators,
// and assembles a single SIGNED, VERSIONED content bundle that is
// distributed to every tenant BY DEFAULT with ZERO per-tenant
// configuration. It is default-ON with a kill switch, refreshes
// incrementally on a bounded schedule, and degrades gracefully (last
// good per-source set) when an upstream is unreachable.
//
// Cost model (no-ops at SME scale): ingestion + scoring + bundle build
// run ONCE centrally on the elected leader and the single signed bundle
// is pushed to all tenants. The work is O(feeds + indicators), not
// O(tenants), so adding tenants adds no ingestion cost — the amortized
// per-tenant cost of managed content is effectively zero.
//
// The engine is a NEW PRODUCER that runs alongside threatintel; it does
// not modify that package and keeps its own tables (migrations
// 081-083) rather than clobbering the ai-owned threat_intel_iocs store.
package threatfeed

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// SchemaVersion is the managed-content bundle payload layout version.
// A consumer that understands version N accepts <= N and rejects a
// newer payload it cannot interpret.
const SchemaVersion = 1

// Algorithm is the signature algorithm identifier stamped in the
// signed envelope.
const Algorithm = "ed25519"

// ErrSignatureMismatch is returned when a signed bundle fails
// verification against the pinned public key.
var ErrSignatureMismatch = errors.New("threatfeed: bundle signature mismatch")

// Indicator is one scored, normalized indicator in a managed-content
// bundle. Values are already canonical (see ai.NewIOC) so a consumer
// compares them byte-for-byte without re-normalizing.
type Indicator struct {
	// Type is the indicator category: domain / ip / cidr / url / hash.
	Type string `json:"type"`
	// Value is the normalized indicator.
	Value string `json:"value"`
	// HashAlgo is set only for hash indicators (md5 / sha1 / sha256).
	HashAlgo string `json:"hash_algo,omitempty"`
	// Score is the aggregated confidence in [0,1] from corroboration +
	// source weight + recency (see score.go).
	Score float64 `json:"score"`
	// Sources is the sorted set of contributing feed names. Its length
	// is the corroboration count.
	Sources []string `json:"sources"`
	// FirstSeen / LastSeen bound the observation window across all
	// contributors (UTC).
	FirstSeen time.Time `json:"first_seen,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
	// ExpiresAt is the aggregated TTL boundary (UTC). Zero means the
	// indicator does not expire on its own.
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// ContentBundle is the unsigned managed-content payload: the full
// scored indicator set at a given version.
type ContentBundle struct {
	SchemaVersion int         `json:"schema_version"`
	Serial        int64       `json:"serial"`
	GeneratedAt   time.Time   `json:"generated_at"`
	Indicators    []Indicator `json:"indicators"`
}

// newBundle builds an empty bundle stamped with the current schema
// version.
func newBundle(serial int64, generatedAt time.Time) *ContentBundle {
	return &ContentBundle{
		SchemaVersion: SchemaVersion,
		Serial:        serial,
		GeneratedAt:   generatedAt.UTC(),
	}
}

// normalize makes the bundle deterministic: every indicator's source
// list is sorted+deduped, its timestamps are coerced to UTC, and the
// indicators are sorted by (type, value). Two bundles with the same
// logical content therefore marshal to identical bytes, which is what
// makes the signature reproducible (and keeps ContentDigest's iteration
// order stable).
func (b *ContentBundle) normalize() {
	for i := range b.Indicators {
		b.Indicators[i].Sources = sortedUnique(b.Indicators[i].Sources)
		b.Indicators[i].FirstSeen = b.Indicators[i].FirstSeen.UTC()
		b.Indicators[i].LastSeen = b.Indicators[i].LastSeen.UTC()
		b.Indicators[i].ExpiresAt = b.Indicators[i].ExpiresAt.UTC()
	}
	sort.Slice(b.Indicators, func(i, j int) bool {
		if b.Indicators[i].Type != b.Indicators[j].Type {
			return b.Indicators[i].Type < b.Indicators[j].Type
		}
		return b.Indicators[i].Value < b.Indicators[j].Value
	})
}

// Counts returns the total indicator count and the per-type breakdown
// (domain/ip/cidr/url/hash).
func (b *ContentBundle) Counts() (total int, byType map[string]int) {
	byType = make(map[string]int, 5)
	for _, ind := range b.Indicators {
		byType[ind.Type]++
	}
	return len(b.Indicators), byType
}

// CanonicalBytes returns the deterministic JSON encoding of the whole
// bundle (normalized first), used as the signing payload.
func (b *ContentBundle) CanonicalBytes() ([]byte, error) {
	b.normalize()
	return json.Marshal(b)
}

// ContentDigest is a SHA-256 over the indicator SET's stable identity:
// for each indicator its type, value, hash-algo, and sorted contributing
// sources. It powers the engine's churn-avoidance fast path — when a
// refresh reproduces the same digest the engine keeps the current serial
// and skips re-signing / re-persisting / re-publishing.
//
// Score, FirstSeen, LastSeen and ExpiresAt are DELIBERATELY EXCLUDED.
// The score carries a recency-decay factor (see score.go) that drifts
// continuously with wall-clock time, and the observation timestamps are
// re-stamped to "now" on every full re-parse; including any of them
// would change the digest on essentially every refresh and defeat the
// fast path this digest exists to enable (turning the hourly tick into a
// fleet-wide re-sign + re-publish for 5,000 tenants even when the threat
// set is unchanged). A new version is therefore minted exactly when the
// membership or corroboration of the set changes — a new sighting, an
// expiry-driven drop, or a feed gaining/losing a source — which are the
// events a consumer's blocklist actually cares about. Serial and
// GeneratedAt are excluded for the same reason (they change every run).
//
// Source weights are code-defined constants (builtinFeedSpecs); a weight
// retune ships via a deploy and takes effect on the next genuine content
// change (sub-day for these churny abuse feeds), so it does not need a
// score term in the digest to be picked up.
func (b *ContentBundle) ContentDigest() string {
	b.normalize()
	h := sha256.New()
	for _, ind := range b.Indicators {
		// NUL-separated identity fields with a 0x1f sub-separator for
		// the source list and a trailing newline terminating each
		// record. None of the field values (normalized type/value/hash
		// and source strings) can contain those control bytes, so the
		// encoding is injective and no value can be confused with a
		// separator. hash.Hash.Write never errors, so the Fprintf
		// returns are intentionally ignored.
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00", ind.Type, ind.Value, ind.HashAlgo)
		for _, s := range ind.Sources {
			_, _ = fmt.Fprintf(h, "%s\x1f", s)
		}
		_, _ = h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Signer holds the Ed25519 private key used to sign managed-content
// bundles. The key is unexported so a *Signer can be passed around
// without exposing the secret.
type Signer struct {
	priv ed25519.PrivateKey
}

// NewSigner builds a signer from raw key bytes: a 32-byte seed or a
// 64-byte expanded private key.
func NewSigner(key []byte) (*Signer, error) {
	switch len(key) {
	case ed25519.SeedSize:
		return &Signer{priv: ed25519.NewKeyFromSeed(key)}, nil
	case ed25519.PrivateKeySize:
		priv := make(ed25519.PrivateKey, ed25519.PrivateKeySize)
		copy(priv, key)
		return &Signer{priv: priv}, nil
	default:
		return nil, fmt.Errorf("threatfeed: signing key must be %d (seed) or %d (expanded) bytes, got %d",
			ed25519.SeedSize, ed25519.PrivateKeySize, len(key))
	}
}

// GenerateSigner mints a fresh ephemeral key. Bundles signed with it
// verify only within this process lifetime — used as a dev/test
// fallback when no key is configured.
func GenerateSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("threatfeed: generate signer: %w", err)
	}
	return &Signer{priv: priv}, nil
}

// Public returns the verifying key for the signer.
func (s *Signer) Public() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// SignedBundle is the self-describing signed envelope distributed to
// consumers. All binary fields are standard base64. PublicKey is
// embedded for transparency but a verifier MUST trust its own pinned
// key, not this field (see VerifyWith).
type SignedBundle struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"key_id,omitempty"`
	PublicKey string `json:"public_key"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Sign serializes the bundle canonically and signs it, returning the
// envelope.
func (b *ContentBundle) Sign(signer *Signer, keyID string) (SignedBundle, error) {
	if signer == nil {
		return SignedBundle{}, errors.New("threatfeed: nil signer")
	}
	payload, err := b.CanonicalBytes()
	if err != nil {
		return SignedBundle{}, fmt.Errorf("threatfeed: canonical bytes: %w", err)
	}
	sig := ed25519.Sign(signer.priv, payload)
	return SignedBundle{
		Algorithm: Algorithm,
		KeyID:     keyID,
		PublicKey: base64.StdEncoding.EncodeToString(signer.Public()),
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Marshal encodes the envelope as JSON for transport / storage.
func (e SignedBundle) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// UnmarshalSignedBundle decodes a transport/storage envelope.
func UnmarshalSignedBundle(data []byte) (SignedBundle, error) {
	var e SignedBundle
	if err := json.Unmarshal(data, &e); err != nil {
		return SignedBundle{}, fmt.Errorf("threatfeed: unmarshal signed bundle: %w", err)
	}
	return e, nil
}

// VerifyWith checks the envelope's signature against the PINNED public
// key, ignoring the embedded PublicKey field (which an attacker could
// swap along with a forged signature). It validates the algorithm and
// key length before the constant-time Ed25519 verify.
func (e SignedBundle) VerifyWith(pub ed25519.PublicKey) error {
	if e.Algorithm != Algorithm {
		return fmt.Errorf("threatfeed: unsupported signature algorithm %q", e.Algorithm)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("threatfeed: pinned key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return fmt.Errorf("threatfeed: decode payload: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return fmt.Errorf("threatfeed: decode signature: %w", err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrSignatureMismatch
	}
	return nil
}

// DecodeVerified verifies the envelope against the pinned key and only
// THEN parses the payload — fail-closed, so a consumer never decodes an
// unauthenticated bundle.
func (e SignedBundle) DecodeVerified(pub ed25519.PublicKey) (*ContentBundle, error) {
	if err := e.VerifyWith(pub); err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("threatfeed: decode payload: %w", err)
	}
	var b ContentBundle
	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, fmt.Errorf("threatfeed: unmarshal payload: %w", err)
	}
	if b.SchemaVersion > SchemaVersion {
		return nil, fmt.Errorf("threatfeed: bundle schema version %d newer than supported %d", b.SchemaVersion, SchemaVersion)
	}
	return &b, nil
}

// sortedUnique returns the sorted, de-duplicated, empty-stripped copy
// of in.
func sortedUnique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
