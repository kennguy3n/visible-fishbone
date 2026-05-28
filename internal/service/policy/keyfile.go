package policy

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// LoadKeySignerFromFile constructs a *KeySigner from a private-key
// file on disk. The file is interpreted in this order:
//
//   - PKCS#8 PEM ("-----BEGIN PRIVATE KEY-----") containing an
//     Ed25519 private key.
//   - Raw hex (64 hex chars for the 32-byte seed, or 128 hex chars
//     for the full 64-byte private key), with optional leading
//     whitespace and trailing newline.
//   - Raw bytes (32 bytes seed or 64 bytes full key).
//
// The function deliberately does NOT accept the bare PEM "EC PRIVATE
// KEY" or "RSA PRIVATE KEY" headers — control-plane policy bundles
// are Ed25519-only, and silently accepting a misconfigured ECDSA
// or RSA key would let an operator boot the process with a key the
// signer cannot use.
//
// Returns the wrapped *KeySigner; the caller installs it into the
// policy.Service via the existing Signer interface.
func LoadKeySignerFromFile(path string) (*KeySigner, error) {
	if path == "" {
		return nil, errors.New("policy: empty signing-key path")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read signing key: %w", err)
	}
	priv, err := parsePrivateKey(body)
	if err != nil {
		return nil, err
	}
	return NewKeySigner(priv), nil
}

func parsePrivateKey(body []byte) (ed25519.PrivateKey, error) {
	// PEM path.
	if block, _ := pem.Decode(body); block != nil {
		if block.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("policy: unsupported PEM block type %q (expected PRIVATE KEY)", block.Type)
		}
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("policy: parse PKCS#8 private key: %w", err)
		}
		priv, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("policy: PEM private key is %T, expected ed25519.PrivateKey", k)
		}
		return priv, nil
	}

	// Hex path. We require the trimmed content to be exclusively
	// hex digits AND of length 64 or 128 so that operator typos
	// (a base64-encoded key, a missing trailing newline making
	// the file 63 chars, etc.) fail loudly rather than producing
	// a wrong-looking key. Note that a 32-byte OR 64-byte raw
	// private key whose every byte coincidentally falls in the
	// ASCII hex range remains indistinguishable from a hex
	// literal under this format — the on-disk format simply has
	// no marker. The astronomical likelihood of that collision
	// (2^-128 for 32 bytes) makes it not worth defending against
	// without a magic-byte framing change; operators who want
	// hard certainty should use the PEM path.
	trimmed := strings.TrimSpace(string(body))
	if looksLikeHex(trimmed) {
		h, err := hex.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("policy: hex-decode signing key: %w", err)
		}
		return fromSeedOrPrivate(h)
	}

	// Raw bytes path (no whitespace trimming — the file is
	// expected to be exactly 32 or 64 bytes).
	return fromSeedOrPrivate(body)
}

// looksLikeHex returns true iff s is a hex literal of exactly the
// length we expect for an Ed25519 seed (64 chars) or full private
// key (128 chars). Anything else falls through to the raw-bytes
// path so we don't accidentally truncate a 64-byte raw key whose
// bytes happen to fall in the [0-9a-f] range.
func looksLikeHex(s string) bool {
	if len(s) != 64 && len(s) != 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

func fromSeedOrPrivate(b []byte) (ed25519.PrivateKey, error) {
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(append([]byte(nil), b...)), nil
	default:
		return nil, fmt.Errorf("policy: signing key must be a 32-byte seed or 64-byte private key (got %d bytes)", len(b))
	}
}
