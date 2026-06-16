package appid

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

// SchemaVersion is the version of the CatalogBundle payload schema. It
// is stamped into every bundle and re-checked by the data-plane
// consumer so a future incompatible layout change is rejected rather
// than silently mis-parsed. Bump it only on a breaking payload change.
const SchemaVersion = 1

// Algorithm is the signature algorithm identifier carried in the
// envelope. Only Ed25519 is supported, matching the threat-intel /
// policy / compliance-evidence bundles so the edge verifier speaks one
// curve.
const Algorithm = "ed25519"

// ErrSignatureMismatch is returned when an envelope's payload does not
// verify against the recorded signature — i.e. the bundle was tampered
// with, corrupted, or signed by a different key.
var ErrSignatureMismatch = errors.New("appid: bundle signature mismatch")

// BundleApp is one application signature inside a CatalogBundle. The
// JSON shape is deliberately the same as the Rust crate's catalog.json
// entry (snake_case, hex byte-prefixes) so the signed payload is itself
// a valid catalog the data plane can load directly once edge bundle
// verification is wired — the bundle is a superset (it adds the
// versioning envelope fields the static seed lacks).
type BundleApp struct {
	AppID        string   `json:"app_id"`
	Category     string   `json:"category"`
	SNISuffixes  []string `json:"sni_suffixes"`
	HostSuffixes []string `json:"host_suffixes"`
	JA3          []string `json:"ja3"`
	BytePrefixes []string `json:"byte_prefixes"`
	Ports        []int    `json:"ports"`
	Transport    string   `json:"transport"`
	Confidence   int      `json:"confidence"`
}

// CatalogBundle is the deterministic, signable catalog payload the
// control plane produces and the edge consumes. It is platform-global:
// application signatures are shared knowledge, not tenant data, so
// there is no tenant binding.
type CatalogBundle struct {
	// SchemaVersion is the payload layout version (see SchemaVersion).
	SchemaVersion int `json:"schema_version"`
	// Serial is a monotonically increasing generation counter. The
	// consumer pins the highest serial it has applied and ignores any
	// bundle with a lower one, so an out-of-order or replayed delivery
	// can never roll the catalog back to a stale version.
	Serial int64 `json:"serial"`
	// GeneratedAt is the producer timestamp (UTC). Advisory: for
	// telemetry / staleness display only — Serial is the authoritative
	// ordering key.
	GeneratedAt time.Time `json:"generated_at"`
	// Apps is the application signature set.
	Apps []BundleApp `json:"apps"`
}

// normalize sorts the app list by app_id and canonicalises every
// match-key list (sorted, de-duplicated, non-nil) so the canonical
// bytes are stable regardless of source ordering or duplication. It is
// idempotent.
func (b *CatalogBundle) normalize() {
	for i := range b.Apps {
		a := &b.Apps[i]
		a.SNISuffixes = sortedUniqueStrings(a.SNISuffixes)
		a.HostSuffixes = sortedUniqueStrings(a.HostSuffixes)
		a.JA3 = sortedUniqueStrings(a.JA3)
		a.BytePrefixes = sortedUniqueStrings(a.BytePrefixes)
		a.Ports = sortedUniqueInts(a.Ports)
	}
	sort.Slice(b.Apps, func(i, j int) bool { return b.Apps[i].AppID < b.Apps[j].AppID })
}

// CanonicalBytes returns the deterministic byte encoding of the bundle
// used both as the signed message and as the envelope payload.
//
// Determinism matters: the signature is computed over these exact bytes
// and re-verified on the edge, so the encoding must be stable across
// processes and machines. normalize() sorts every slice and the app
// list; encoding/json emits struct fields in declaration order, so the
// result is canonical. CanonicalBytes does not change the receiver's
// observable contents (normalize is idempotent), so it is safe to call
// repeatedly.
func (b *CatalogBundle) CanonicalBytes() ([]byte, error) {
	b.normalize()
	out, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("appid: marshal catalog bundle: %w", err)
	}
	return out, nil
}

// Signer signs catalog bundles with an Ed25519 private key. The caller
// owns key custody (config / KMS / Postgres TDE); this type only
// performs the signing operation.
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
		return nil, fmt.Errorf("appid: invalid signing key length %d (want %d seed or %d expanded)",
			len(key), ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// GenerateSigner creates a Signer backed by a fresh random key. Used by
// tests and as the dev/test fallback when no key is configured;
// production wires NewSigner from managed key material.
func GenerateSigner() (*Signer, error) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("appid: generate signer: %w", err)
	}
	return &Signer{priv: priv}, nil
}

// Public returns the Ed25519 public key the edge pins to verify
// bundles.
func (s *Signer) Public() ed25519.PublicKey {
	pub, _ := s.priv.Public().(ed25519.PublicKey)
	return pub
}

// sign returns the raw Ed25519 signature over msg. Used by the service
// to persist the signature bytes alongside the canonical payload
// without re-deriving them from the base64 envelope.
func (s *Signer) sign(msg []byte) []byte {
	return ed25519.Sign(s.priv, msg)
}

// SignedBundle is the self-describing wire envelope. Payload is the
// base64 (std) encoding of the CatalogBundle's CanonicalBytes;
// Signature is the base64 Ed25519 signature over the DECODED payload
// bytes; PublicKey is the base64 32-byte verifying key (advisory — the
// consumer pins its own trusted key by KeyID and must not trust an
// embedded key blindly). All-base64 keeps the envelope trivially
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
func (b *CatalogBundle) Sign(signer *Signer, keyID string) (SignedBundle, error) {
	if signer == nil {
		return SignedBundle{}, errors.New("appid: nil signer")
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
		return nil, fmt.Errorf("appid: marshal signed bundle: %w", err)
	}
	return out, nil
}

// UnmarshalSignedBundle parses an envelope from its JSON wire form.
func UnmarshalSignedBundle(data []byte) (SignedBundle, error) {
	var e SignedBundle
	if err := json.Unmarshal(data, &e); err != nil {
		return SignedBundle{}, fmt.Errorf("appid: parse signed bundle: %w", err)
	}
	return e, nil
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
// returns the parsed CatalogBundle. The signature is checked BEFORE the
// payload is parsed so a tampered or untrusted payload is never decoded
// into the consumer's data model — fail-closed, matching the threat
// intel and policy bundle verifiers.
func (e SignedBundle) DecodeVerified(pub ed25519.PublicKey) (*CatalogBundle, error) {
	if err := e.VerifyWith(pub); err != nil {
		return nil, err
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil {
		return nil, fmt.Errorf("appid: decode payload: %w", err)
	}
	var b CatalogBundle
	if err := json.Unmarshal(payload, &b); err != nil {
		return nil, fmt.Errorf("appid: parse catalog bundle: %w", err)
	}
	return &b, nil
}

// sortedUniqueStrings returns the non-empty entries of in, sorted and
// de-duplicated, as a non-nil slice (an empty input yields an empty,
// non-nil slice so the field marshals as [] rather than null — the
// Rust consumer's serde model rejects an explicit null array).
func sortedUniqueStrings(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
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

// sortedUniqueInts is the integer analogue of sortedUniqueStrings.
func sortedUniqueInts(in []int) []int {
	out := make([]int, 0, len(in))
	seen := make(map[int]struct{}, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}
