package policy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// KeyService manages the per-tenant Ed25519 signing-key lifecycle
// the bundle compiler depends on. Each tenant has at most one
// active key at a time; older keys are kept around so receivers can
// still verify pre-rotation bundles.
//
// All operations are mediated by `PolicySigningKeyRepository`, which
// enforces the "one active key per tenant" invariant via a partial
// unique index. The service layer adds:
//
//   - Ed25519 keypair generation (delegated to crypto/ed25519 from
//     stdlib so the math is reviewed against the same FIPS-compatible
//     baseline the rest of the SN360 family uses).
//   - KMS-pluggable private-key wrapping. The default implementation
//     stores the raw 32-byte seed; production deployments can plug
//     in a wrapper that encrypts the seed with a cloud-KMS data key
//     before persistence. PR8 fills in the AWS-KMS / GCP-KMS / Azure
//     Key Vault variants — this PR provides the interface and a
//     pass-through implementation for tests.
//   - Audit-log writes for every key-state change so the rotation
//     trail is reconstructible without scraping the database
//     directly.
type KeyService struct {
	repo    repository.PolicySigningKeyRepository
	audit   repository.AuditLogRepository
	wrapper PrivateKeyWrapper
	now     func() time.Time
}

// PrivateKeyWrapper is the optional at-rest encryption layer for
// Ed25519 private-key seeds. The default implementation
// (`PassthroughWrapper`) writes the seed verbatim; a KMS-backed
// implementation wraps each seed under a KMS data key and unwraps
// it on read. Wrap is called with the raw seed; Unwrap returns the
// raw seed.
type PrivateKeyWrapper interface {
	Wrap(ctx context.Context, tenantID uuid.UUID, seed []byte) ([]byte, error)
	Unwrap(ctx context.Context, tenantID uuid.UUID, wrapped []byte) ([]byte, error)
}

// PassthroughWrapper writes the seed verbatim. Disk encryption /
// Postgres TDE provide the at-rest protection in this mode, matching
// the webhook signing-secret model from PR6.
type PassthroughWrapper struct{}

// Wrap returns the seed unchanged.
func (PassthroughWrapper) Wrap(_ context.Context, _ uuid.UUID, seed []byte) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("policy: empty seed")
	}
	out := make([]byte, len(seed))
	copy(out, seed)
	return out, nil
}

// Unwrap returns the wrapped bytes unchanged.
func (PassthroughWrapper) Unwrap(_ context.Context, _ uuid.UUID, wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 {
		return nil, errors.New("policy: empty wrapped key")
	}
	out := make([]byte, len(wrapped))
	copy(out, wrapped)
	return out, nil
}

// KeyOption configures NewKeyService.
type KeyOption func(*KeyService)

// WithKeyWrapper installs a non-default private-key wrapper.
func WithKeyWrapper(w PrivateKeyWrapper) KeyOption {
	return func(s *KeyService) { s.wrapper = w }
}

// WithKeyClock injects a clock function (tests use this for
// deterministic ActivatedAt / RotatedAt timestamps).
func WithKeyClock(fn func() time.Time) KeyOption {
	return func(s *KeyService) { s.now = fn }
}

// NewKeyService constructs the service.  Audit is optional — when
// nil, audit writes are skipped (used in unit tests that only
// exercise key rotation correctness).
func NewKeyService(repo repository.PolicySigningKeyRepository, audit repository.AuditLogRepository, opts ...KeyOption) *KeyService {
	s := &KeyService{
		repo:    repo,
		audit:   audit,
		wrapper: PassthroughWrapper{},
		now:     func() time.Time { return time.Now().UTC() },
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// CreateInitial provisions the first active signing key for a
// tenant. Returns ErrConflict (via the repository) if an active key
// already exists — callers should use Rotate to replace it.
func (s *KeyService) CreateInitial(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID) (repository.PolicySigningKey, error) {
	pub, seed, err := s.generateKey()
	if err != nil {
		return repository.PolicySigningKey{}, fmt.Errorf("generate key: %w", err)
	}
	wrapped, err := s.wrapper.Wrap(ctx, tenantID, seed)
	if err != nil {
		return repository.PolicySigningKey{}, fmt.Errorf("wrap key: %w", err)
	}
	keyID := newKeyID()
	saved, err := s.repo.Create(ctx, tenantID, repository.PolicySigningKey{
		KeyID:       keyID,
		Algorithm:   "ed25519",
		PublicKey:   pub,
		PrivateKey:  wrapped,
		Status:      repository.PolicySigningKeyStatusActive,
		ActivatedAt: s.now(),
	})
	if err != nil {
		return repository.PolicySigningKey{}, err
	}
	s.appendAudit(ctx, tenantID, actorID, "policy.signing_key_created", saved)
	return saved, nil
}

// Rotate atomically transitions the current active key to
// 'rotated' and provisions a new active key. Receivers can still
// verify bundles signed by the previous key until it is revoked.
func (s *KeyService) Rotate(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID) (repository.PolicySigningKey, error) {
	pub, seed, err := s.generateKey()
	if err != nil {
		return repository.PolicySigningKey{}, fmt.Errorf("generate key: %w", err)
	}
	wrapped, err := s.wrapper.Wrap(ctx, tenantID, seed)
	if err != nil {
		return repository.PolicySigningKey{}, fmt.Errorf("wrap key: %w", err)
	}
	keyID := newKeyID()
	saved, err := s.repo.Rotate(ctx, tenantID, repository.PolicySigningKey{
		KeyID:      keyID,
		Algorithm:  "ed25519",
		PublicKey:  pub,
		PrivateKey: wrapped,
	}, s.now())
	if err != nil {
		return repository.PolicySigningKey{}, err
	}
	s.appendAudit(ctx, tenantID, actorID, "policy.signing_key_rotated", saved)
	return saved, nil
}

// Revoke marks a specific key as compromised. Receivers MUST refuse
// bundles signed by a revoked key.
func (s *KeyService) Revoke(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, keyID string) (repository.PolicySigningKey, error) {
	saved, err := s.repo.Revoke(ctx, tenantID, keyID, s.now())
	if err != nil {
		return repository.PolicySigningKey{}, err
	}
	s.appendAudit(ctx, tenantID, actorID, "policy.signing_key_revoked", saved)
	return saved, nil
}

// GetActive returns the unique active key for the tenant, lazily
// creating one when no key has ever been provisioned. The lazy
// path lets the policy service compile bundles for a brand-new
// tenant without requiring an explicit admin call first — the
// initial key is provisioned on the first compile.
//
// Callers that DO NOT want the lazy-create behaviour (e.g. the
// admin handler distinguishing "no key yet → create initial" from
// "active key already exists → rotate") should use
// GetActiveNoCreate, which returns ErrNotFound verbatim.
func (s *KeyService) GetActive(ctx context.Context, tenantID uuid.UUID) (repository.PolicySigningKey, error) {
	active, err := s.repo.GetActive(ctx, tenantID)
	if err == nil {
		return active, nil
	}
	if !errors.Is(err, repository.ErrNotFound) {
		return repository.PolicySigningKey{}, err
	}
	created, err := s.CreateInitial(ctx, tenantID, nil)
	if err != nil {
		// Race: another goroutine provisioned the key between
		// our GetActive and CreateInitial. Re-read and return.
		if errors.Is(err, repository.ErrConflict) {
			return s.repo.GetActive(ctx, tenantID)
		}
		return repository.PolicySigningKey{}, err
	}
	return created, nil
}

// GetActiveNoCreate returns the unique active key for the tenant
// without the lazy-create fallback, propagating ErrNotFound when no
// key has been provisioned. Use this when the caller's branch logic
// depends on the existence of a key (e.g. "create initial vs.
// rotate" in the admin handler).
func (s *KeyService) GetActiveNoCreate(ctx context.Context, tenantID uuid.UUID) (repository.PolicySigningKey, error) {
	return s.repo.GetActive(ctx, tenantID)
}

// GetByKeyID returns a key by its stable short identifier, used by
// the public-key publication endpoint and the bundle distribution
// endpoint.
func (s *KeyService) GetByKeyID(ctx context.Context, tenantID uuid.UUID, keyID string) (repository.PolicySigningKey, error) {
	return s.repo.GetByKeyID(ctx, tenantID, keyID)
}

// List returns the full rotation history for the tenant. The
// public-key publication endpoint uses this to expose every public
// key (including rotated and revoked) so receivers can verify any
// bundle they might still hold.
func (s *KeyService) List(ctx context.Context, tenantID uuid.UUID) ([]repository.PolicySigningKey, error) {
	return s.repo.List(ctx, tenantID)
}

// Sign produces an Ed25519 signature over data using the active
// tenant key.  Returns ErrNotFound when the tenant has no active
// key (e.g. the active key was just revoked without a replacement
// being provisioned).
func (s *KeyService) Sign(ctx context.Context, tenantID uuid.UUID, data []byte) (signature []byte, keyID string, err error) {
	active, err := s.GetActive(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	if active.Status == repository.PolicySigningKeyStatusRevoked {
		return nil, "", fmt.Errorf("policy: active key revoked: %w", repository.ErrForbidden)
	}
	seed, err := s.wrapper.Unwrap(ctx, tenantID, active.PrivateKey)
	if err != nil {
		return nil, "", fmt.Errorf("unwrap key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, "", fmt.Errorf("policy: invalid seed size %d", len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return ed25519.Sign(priv, data), active.KeyID, nil
}

func (s *KeyService) generateKey() (pub []byte, seed []byte, err error) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pub = make([]byte, len(pubKey))
	copy(pub, pubKey)
	seed = make([]byte, ed25519.SeedSize)
	copy(seed, privKey.Seed())
	return pub, seed, nil
}

func (s *KeyService) appendAudit(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, action string, k repository.PolicySigningKey) {
	if s.audit == nil {
		return
	}
	details, _ := json.Marshal(map[string]any{
		"key_id":     k.KeyID,
		"algorithm":  k.Algorithm,
		"status":     k.Status,
		"public_key": hex.EncodeToString(k.PublicKey),
	})
	_, _ = s.audit.Append(ctx, tenantID, repository.AuditEntry{
		TenantID: tenantID, ActorID: actorID,
		Action: action, ResourceType: "policy_signing_key",
		ResourceID: &k.ID, Details: details,
	})
}

// newKeyID returns a 16-character lowercase hex identifier derived
// from a fresh UUID. Short enough to embed in the bundle envelope
// without bloating the wire size, long enough that collisions
// across a tenant's rotation history are vanishingly unlikely
// (≈80 bits of entropy).
func newKeyID() string {
	u := uuid.New()
	b := u[:]
	return hex.EncodeToString(b[:8])
}
