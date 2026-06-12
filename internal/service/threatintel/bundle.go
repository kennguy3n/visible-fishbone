package threatintel

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// SchemaVersion is the version of the FeedBundle payload schema. It is
// stamped into every bundle and re-checked by the `sng-dns` consumer so
// a future incompatible layout change can be rejected rather than
// silently mis-parsed. Bump it only on a breaking payload change.
const SchemaVersion = 1

// Algorithm is the signature algorithm identifier carried in the
// envelope. Only Ed25519 is supported, matching the policy / IPS /
// compliance-evidence bundles so the edge verifier speaks one curve.
const Algorithm = "ed25519"

// ErrSignatureMismatch is returned when an envelope's payload does not
// verify against the recorded signature — i.e. the bundle was tampered
// with, corrupted, or signed by a different key.
var ErrSignatureMismatch = errors.New("threatintel: bundle signature mismatch")

// FeedBundle is the deterministic, signable payload the managed
// pipeline produces and the `sng-dns` crate consumes. It carries the
// reputation FQDN set and the per-category domain membership; the
// per-category disposition (Allow/Log/Block) is the OPERATOR's policy
// and stays on the consumer side, so it is intentionally absent here.
//
// The bundle is platform-global: it is shared threat intelligence, not
// tenant data, so there is no tenant binding.
type FeedBundle struct {
	// SchemaVersion is the payload layout version (see SchemaVersion).
	SchemaVersion int `json:"schema_version"`
	// Serial is a monotonically non-decreasing generation counter
	// (producer wall-clock unix seconds). The consumer pins the highest
	// serial it has applied and ignores any bundle with a lower one, so
	// an out-of-order or replayed delivery can never roll the feed back
	// to stale data.
	Serial int64 `json:"serial"`
	// GeneratedAt is the producer timestamp (UTC, RFC3339). Advisory:
	// for telemetry / staleness display only — Serial is the
	// authoritative ordering key.
	GeneratedAt time.Time `json:"generated_at"`
	// Categories maps a category name to its canonical domain
	// membership (suffix-match semantics on the consumer).
	Categories map[string][]string `json:"categories,omitempty"`
	// Reputation is the exact-match known-bad FQDN set.
	Reputation []string `json:"reputation,omitempty"`
}

// newBundle returns an empty bundle stamped with the schema version and
// the given generation time.
func newBundle(serial int64, generatedAt time.Time) *FeedBundle {
	return &FeedBundle{
		SchemaVersion: SchemaVersion,
		Serial:        serial,
		GeneratedAt:   generatedAt.UTC(),
		Categories:    map[string][]string{},
	}
}

// normalize sorts and de-duplicates every domain list and drops empty
// categories so the canonical bytes are stable regardless of source
// fetch order or upstream duplication. It is idempotent.
func (b *FeedBundle) normalize() {
	b.Reputation = sortedUnique(b.Reputation)
	if len(b.Reputation) == 0 {
		b.Reputation = nil
	}
	for cat, domains := range b.Categories {
		uniq := sortedUnique(domains)
		if len(uniq) == 0 {
			delete(b.Categories, cat)
			continue
		}
		b.Categories[cat] = uniq
	}
	if len(b.Categories) == 0 {
		b.Categories = nil
	}
}

// Counts returns the reputation entry count and the per-category domain
// counts, used for telemetry and the refresh result.
func (b *FeedBundle) Counts() (reputation int, categories map[string]int) {
	categories = make(map[string]int, len(b.Categories))
	for cat, domains := range b.Categories {
		categories[cat] = len(domains)
	}
	return len(b.Reputation), categories
}

// CanonicalBytes returns the deterministic byte encoding of the bundle
// used both as the signed message and as the envelope payload.
//
// Determinism matters: the signature is computed over these exact bytes
// and re-verified on the edge, so the encoding must be stable across
// processes and machines. normalize() sorts every slice; encoding/json
// emits struct fields in declaration order and map keys in sorted
// order, so the result is canonical. CanonicalBytes does not mutate the
// receiver's observable contents (normalize is idempotent on an
// already-normalized bundle), so it is safe to call repeatedly.
func (b *FeedBundle) CanonicalBytes() ([]byte, error) {
	b.normalize()
	out, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("threatintel: marshal feed bundle: %w", err)
	}
	return out, nil
}

// Signer signs feed bundles with an Ed25519 private key. It mirrors the
// compliance-evidence / policy-bundle signing approach: the caller owns
// key custody (config / KMS / Postgres TDE); this type only performs
// the signing operation.
type Signer struct {
	priv ed25519.PrivateKey
}

// NewSigner wraps an Ed25519 private key, accepting either the 32-byte
// seed or the 64-byte expanded private key.
func NewSigner(key []byte) (*Signer, error) {
	switch len(key) {
	case ed25519.SeedSize:
		return &Signer{priv: ed25519.NewKeyFromSeed(key)}, nil
	case ed25519.PrivateKeySize:
		return &Signer{priv: ed25519.PrivateKey(bytes.Clone(key))}, nil
	default:
		return nil, fmt.Errorf("threatintel: invalid signing key length %d (want %d seed or %d expanded)",
			len(key), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// GenerateSigner creates a Signer backed by a fresh random key. Used by
// tests and as the dev/test fallback when no key is configured;
// production wires NewSigner from managed key material.
func GenerateSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("threatintel: generate signer: %w", err)
	}
	return &Signer{priv: priv}, nil
}

// Public returns the Ed25519 public key the edge pins to verify
// bundles.
func (s *Signer) Public() ed25519.PublicKey {
	pub, _ := s.priv.Public().(ed25519.PublicKey)
	return pub
}

// SignedBundle is the self-describing wire envelope distributed over
// NATS. Payload is the base64 (std) encoding of the FeedBundle's
// CanonicalBytes; Signature is the base64 Ed25519 signature over the
// DECODED payload bytes; PublicKey is the base64 32-byte verifying key
// (advisory — the consumer pins its own trusted key by KeyID and must
// not trust an embedded key blindly). All-base64 (rather than the
// MessagePack used by policy bundles) keeps the envelope trivially
// inspectable and language-agnostic for the Rust consumer.
type SignedBundle struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"key_id,omitempty"`
	PublicKey string `json:"public_key"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Sign produces a signed envelope over the bundle's canonical bytes.
// keyID labels which signing key was used so the consumer can select
// the matching pinned verifying key from its trust store.
func (b *FeedBundle) Sign(signer *Signer, keyID string) (SignedBundle, error) {
	if signer == nil {
		return SignedBundle{}, errors.New("threatintel: nil signer")
	}
	payload, err := b.CanonicalBytes()
	if err != nil {
		return SignedBundle{}, err
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

// Marshal serializes the envelope to JSON for publication.
func (e SignedBundle) Marshal() ([]byte, error) {
	out, err := json.Marshal(e)
	if err != nil {
		return nil, fmt.Errorf("threatintel: marshal signed bundle: %w", err)
	}
	return out, nil
}

// VerifyWith checks the envelope's signature against the supplied
// trusted public key and returns ErrSignatureMismatch on any failure.
// This is the authoritative verification path: it ignores the
// envelope's self-reported PublicKey and trusts only the pinned key the
// caller passes, exactly as the edge consumer does.
func (e SignedBundle) VerifyWith(pub ed25519.PublicKey) error {
	if e.Algorithm != Algorithm {
		return fmt.Errorf("%w: unexpected algorithm %q", ErrSignatureMismatch, e.Algorithm)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: invalid public key length %d", ErrSignatureMismatch, len(pub))
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return fmt.Errorf("%w: decode payload: %v", ErrSignatureMismatch, err)
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return fmt.Errorf("%w: decode signature: %v", ErrSignatureMismatch, err)
	}
	if !ed25519.Verify(pub, payload, sig) {
		return ErrSignatureMismatch
	}
	return nil
}

// DecodeVerified verifies the envelope against pub and, on success,
// returns the parsed FeedBundle. The signature is checked BEFORE the
// payload is parsed so a tampered or untrusted payload is never decoded
// into the consumer's data model — fail-closed, matching the policy
// bundle verifier.
func (e SignedBundle) DecodeVerified(pub ed25519.PublicKey) (*FeedBundle, error) {
	if err := e.VerifyWith(pub); err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("threatintel: decode payload: %w", err)
	}
	var b FeedBundle
	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, fmt.Errorf("threatintel: parse feed bundle: %w", err)
	}
	return &b, nil
}

// sortedUnique returns the canonical (lowercased non-empty) entries of
// in, sorted and de-duplicated. Inputs are already normalized by the
// parser; this is the final dedup/sort that makes the bytes canonical.
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
