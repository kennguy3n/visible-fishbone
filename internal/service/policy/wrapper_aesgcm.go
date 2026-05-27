package policy

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	"github.com/google/uuid"
)

// AESGCMWrapper implements PrivateKeyWrapper using AES-256-GCM under
// a single operator-provided 32-byte master key.
//
// The wrapper is suitable for:
//
//   - Local development / single-host deployments where a KMS-backed
//     service is unavailable.
//   - Production deployments where the operator delivers a master
//     key via a sealed secret store (Kubernetes secret backed by
//     KMS, HashiCorp Vault transit, etc.) and the master itself is
//     never on disk in plaintext.
//
// Per-tenant key separation comes from the GCM AAD (additional
// authenticated data) which is set to the canonical bytes of the
// tenant UUID. A wrapped seed from tenant A cannot be unwrapped
// under tenant B's identity even with the same master key, because
// the AAD mismatch will fail authentication. The same applies if
// the master key rotates: ciphertext written under the old master
// cannot be decrypted under the new one — operators rotating the
// master are expected to re-wrap on the same boot by calling
// Rotate() through the KeyService.
//
// The on-wire format is `nonce || ciphertext || tag` where:
//
//   - nonce: 12 random bytes (NIST SP 800-38D §8.2.1, the standard
//     IV size for GCM with random nonces — the birthday bound at
//     12 bytes is large enough to wrap ~2^32 seeds without nonce
//     reuse in practice).
//   - ciphertext: same length as the plaintext seed (typically 32
//     bytes for Ed25519).
//   - tag: 16-byte GCM authentication tag.
//
// AEAD authentication is what lets us drop the explicit
// "is this still ours?" check on Unwrap — a wrong master key, a
// wrong tenant AAD, or any bit-flip in the ciphertext fail the tag
// check and return a generic ErrAESGCMUnwrap.
type AESGCMWrapper struct {
	aead cipher.AEAD
}

// ErrAESGCMUnwrap is the single error returned by Unwrap for any
// authentication-tag failure (wrong tenant, tampered ciphertext,
// wrong master key). The shape is deliberately generic so a hostile
// caller cannot distinguish "wrong master" from "wrong tenant" by
// timing or message.
var ErrAESGCMUnwrap = errors.New("policy: aes-gcm unwrap failed")

// NewAESGCMWrapper constructs an AESGCMWrapper bound to the given
// 32-byte AES-256 master key. Any other key length is rejected at
// construction time — there is no "best-effort fallback to AES-128"
// or padding rule.
func NewAESGCMWrapper(master []byte) (*AESGCMWrapper, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("policy: aes-gcm master key must be 32 bytes (got %d)", len(master))
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, fmt.Errorf("policy: aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("policy: gcm wrap: %w", err)
	}
	return &AESGCMWrapper{aead: aead}, nil
}

// Wrap encrypts seed under the master key, with the tenant UUID as
// AAD. The returned blob is `nonce || ciphertext || tag` and can be
// passed directly to the policy_signing_keys.private_key column.
func (w *AESGCMWrapper) Wrap(_ context.Context, tenantID uuid.UUID, seed []byte) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("policy: empty seed")
	}
	nonce := make([]byte, w.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("policy: gcm nonce: %w", err)
	}
	aad := tenantAAD(tenantID)
	// Seal returns nonce-prefix + ciphertext + tag; we explicitly
	// build the layout ourselves so the on-disk format is the
	// concatenation in that order regardless of Go's internal Seal
	// optimisation.
	out := make([]byte, 0, len(nonce)+len(seed)+w.aead.Overhead())
	out = append(out, nonce...)
	out = w.aead.Seal(out, nonce, seed, aad)
	return out, nil
}

// Unwrap decrypts wrapped under the master key. On any auth-tag
// failure (wrong tenant, wrong master, tampered ciphertext) returns
// ErrAESGCMUnwrap.
func (w *AESGCMWrapper) Unwrap(_ context.Context, tenantID uuid.UUID, wrapped []byte) ([]byte, error) {
	ns := w.aead.NonceSize()
	if len(wrapped) < ns+w.aead.Overhead() {
		return nil, ErrAESGCMUnwrap
	}
	nonce := wrapped[:ns]
	ct := wrapped[ns:]
	aad := tenantAAD(tenantID)
	out, err := w.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrAESGCMUnwrap
	}
	return out, nil
}

// tenantAAD renders the tenant UUID into a stable 16-byte byte
// slice for use as GCM additional authenticated data. Using the
// raw UUID bytes (NOT the textual representation) means callers
// cannot smuggle an alias of the same UUID through formatting
// quirks (e.g. dashed vs. undashed); the AEAD checks the canonical
// bytes.
func tenantAAD(tenantID uuid.UUID) []byte {
	out := make([]byte, 16)
	copy(out, tenantID[:])
	return out
}

// LoadAESGCMMasterFromEnv loads a 32-byte master key from one of:
//
//   - POLICY_KEY_WRAP_MASTER_B64 — base64 (std or raw) of 32 bytes
//   - POLICY_KEY_WRAP_MASTER_FILE — path to a file whose contents
//     are either a base64-encoded 32-byte master or the raw 32 bytes
//     directly. Bytes are detected by length.
//
// Returns (nil, nil) when neither env var is set, signalling that
// the caller should fall back to PassthroughWrapper. Returns an
// error when an env var IS set but the value cannot be parsed —
// silent fallback in that case would mean operators thinking they
// have at-rest encryption when they don't.
func LoadAESGCMMasterFromEnv() ([]byte, error) {
	if raw := os.Getenv("POLICY_KEY_WRAP_MASTER_B64"); raw != "" {
		return DecodeAESGCMMasterB64(raw)
	}
	if path := os.Getenv("POLICY_KEY_WRAP_MASTER_FILE"); path != "" {
		return LoadAESGCMMasterFromFile(path)
	}
	return nil, nil
}

// DecodeAESGCMMasterB64 decodes a base64-encoded 32-byte master
// key. Accepts std, raw, url-safe, and raw url-safe dialects so
// hand-pasted secrets work without operators having to remember
// which variant their secret store emits.
func DecodeAESGCMMasterB64(raw string) ([]byte, error) {
	return decodeMaster(raw)
}

// LoadAESGCMMasterFromFile reads a master key from a file. The
// file may contain 32 raw bytes (k8s Secret stringData with a
// raw-byte value) or a base64 encoding of 32 bytes (most secret
// managers default to base64 to preserve transit safety).
func LoadAESGCMMasterFromFile(path string) ([]byte, error) {
	return loadMasterFromFile(path)
}

func decodeMaster(raw string) ([]byte, error) {
	// Try standard base64 first, then raw (no padding). We accept
	// both because copy-pasted secrets often arrive with the
	// padding stripped.
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("policy: POLICY_KEY_WRAP_MASTER_B64 must base64-decode to exactly 32 bytes")
}

func loadMasterFromFile(path string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read POLICY_KEY_WRAP_MASTER_FILE: %w", err)
	}
	// Raw 32 bytes? Use as-is.
	if len(body) == 32 {
		return body, nil
	}
	// Strip trailing whitespace (newlines) and try base64.
	trimmed := stripASCIIWhitespace(body)
	if b, err := decodeMaster(string(trimmed)); err == nil {
		return b, nil
	}
	return nil, fmt.Errorf("policy: POLICY_KEY_WRAP_MASTER_FILE must contain either 32 raw bytes or a base64 encoding of 32 bytes (got %d bytes)", len(body))
}

func stripASCIIWhitespace(b []byte) []byte {
	out := b[:0:len(b)]
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		}
		out = append(out, c)
	}
	return out
}
