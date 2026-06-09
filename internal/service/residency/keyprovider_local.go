package residency

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// LocalKeyProvider is an in-process TenantKeyProvider that wraps DEKs
// with AES-256-GCM under operator-provided master keys. It serves two
// real purposes:
//
//   - It is the production implementation of the ProviderPlatform
//     tier: the "no-CMK" default where the platform's own master key
//     (delivered via a sealed secret / KMS-decrypted env, never on
//     disk in plaintext) wraps tenant DEKs. This is the same
//     AES-256-GCM envelope the policy key wrapper and telemetry
//     cold-archive already rely on.
//   - It is a faithful test double for the cloud KMS providers: it
//     enforces the encryption-context AAD exactly as AWS KMS / GCP KMS
//     do, so the CMKService and data-plane integration logic can be
//     unit-tested without a cloud account.
//
// It holds a keyring: a default key (used when a ref's KeyURI is
// empty) plus any number of named keys (used to model per-tenant CMKs
// or platform-master rotation). Because the keyring is fixed after
// construction it needs no locking and is safe for concurrent use.
type LocalKeyProvider struct {
	kind       KeyProviderKind
	defaultKey cipher.AEAD
	named      map[string]cipher.AEAD
}

// LocalKeyProviderOption customises a LocalKeyProvider.
type LocalKeyProviderOption func(*localKeyProviderConfig)

type localKeyProviderConfig struct {
	named map[string][]byte
}

// WithLocalKey registers an additional named key under keyURI. Used to
// model multiple CMKs (or platform-master generations) addressed by a
// ref's KeyURI. The material must be exactly 32 bytes (AES-256).
func WithLocalKey(keyURI string, material []byte) LocalKeyProviderOption {
	return func(c *localKeyProviderConfig) {
		if c.named == nil {
			c.named = make(map[string][]byte)
		}
		c.named[keyURI] = material
	}
}

// NewLocalKeyProvider builds a LocalKeyProvider that reports the given
// kind (ProviderPlatform in production; any kind when used as a KMS
// test double) and wraps DEKs under the supplied 32-byte master key.
// Additional named keys may be registered via WithLocalKey.
func NewLocalKeyProvider(kind KeyProviderKind, master []byte, opts ...LocalKeyProviderOption) (*LocalKeyProvider, error) {
	if kind == "" {
		return nil, errors.New("residency: local key provider requires a kind")
	}
	def, err := newAES256GCM(master)
	if err != nil {
		return nil, fmt.Errorf("residency: local provider default key: %w", err)
	}
	cfg := localKeyProviderConfig{}
	for _, o := range opts {
		o(&cfg)
	}
	named := make(map[string]cipher.AEAD, len(cfg.named))
	for uri, mat := range cfg.named {
		aead, err := newAES256GCM(mat)
		if err != nil {
			return nil, fmt.Errorf("residency: local provider key %q: %w", uri, err)
		}
		named[uri] = aead
	}
	return &LocalKeyProvider{kind: kind, defaultKey: def, named: named}, nil
}

func newAES256GCM(master []byte) (cipher.AEAD, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("master key must be 32 bytes (got %d)", len(master))
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// Kind implements TenantKeyProvider.
func (p *LocalKeyProvider) Kind() KeyProviderKind { return p.kind }

// aeadFor selects the AEAD for a KeyURI: the named key when one is
// registered, otherwise the default. A non-empty KeyURI with no
// matching named key is rejected, so a wrap under a missing CMK fails
// closed instead of silently using the platform default.
func (p *LocalKeyProvider) aeadFor(keyURI string) (cipher.AEAD, error) {
	if keyURI == "" {
		return p.defaultKey, nil
	}
	if a, ok := p.named[keyURI]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("%w: no local key registered for %q", ErrInvalidKeyRef, keyURI)
}

// GenerateDataKey implements TenantKeyProvider. It generates a random
// 32-byte DEK and seals it under the ref's key with ec as AAD.
func (p *LocalKeyProvider) GenerateDataKey(_ context.Context, ref TenantKeyRef, ec EncryptionContext) (DataKey, error) {
	if ref.Kind != p.kind {
		return DataKey{}, fmt.Errorf("%w: provider %q got ref kind %q", ErrProviderKindMismatch, p.kind, ref.Kind)
	}
	aead, err := p.aeadFor(ref.KeyURI)
	if err != nil {
		return DataKey{}, err
	}
	dek := make([]byte, dekSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return DataKey{}, fmt.Errorf("%w: dek: %v", ErrWrapFailed, err)
	}
	ct, err := seal(aead, dek, ec.Canonical())
	if err != nil {
		Zeroize(dek)
		return DataKey{}, fmt.Errorf("%w: %v", ErrWrapFailed, err)
	}
	return DataKey{
		Plaintext: dek,
		Wrapped: WrappedDataKey{
			Kind:       p.kind,
			KeyURI:     ref.KeyURI,
			Ciphertext: ct,
		},
	}, nil
}

// UnwrapDataKey implements TenantKeyProvider. It opens the wrapped DEK
// under the wrapped key's KeyURI (not the ref's — they normally match,
// but unwrap must follow the KEK that actually produced the envelope,
// which is what survives a tenant rotating to a new KEK).
func (p *LocalKeyProvider) UnwrapDataKey(_ context.Context, ref TenantKeyRef, wrapped WrappedDataKey, ec EncryptionContext) ([]byte, error) {
	if ref.Kind != p.kind {
		return nil, fmt.Errorf("%w: provider %q got ref kind %q", ErrProviderKindMismatch, p.kind, ref.Kind)
	}
	if wrapped.Kind != p.kind {
		return nil, fmt.Errorf("%w: provider %q got wrapped kind %q", ErrProviderKindMismatch, p.kind, wrapped.Kind)
	}
	aead, err := p.aeadFor(wrapped.KeyURI)
	if err != nil {
		return nil, err
	}
	dek, err := open(aead, wrapped.Ciphertext, ec.Canonical())
	if err != nil {
		// Coarse error: do not leak whether it was a bad key, bad AAD,
		// or tampered ciphertext.
		return nil, ErrUnwrapFailed
	}
	if len(dek) != dekSize {
		Zeroize(dek)
		return nil, ErrUnwrapFailed
	}
	return dek, nil
}

// seal returns nonce||ciphertext||tag. The 12-byte random nonce is the
// NIST SP 800-38D §8.2.1 standard GCM IV size; the same layout the
// policy AES-GCM wrapper uses.
func seal(aead cipher.AEAD, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+aead.Overhead())
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

func open(aead cipher.AEAD, blob, aad []byte) ([]byte, error) {
	ns := aead.NonceSize()
	if len(blob) < ns+aead.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	return aead.Open(nil, blob[:ns:ns], blob[ns:], aad)
}
