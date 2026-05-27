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

// GetActive returns the unique active key for the tenant.
// Propagates ErrNotFound when the tenant has no active key — the
// caller must explicitly provision (via CreateInitial / Rotate)
// or pre-flight with EnsureKey for the brand-new-tenant case.
//
// PR7 historically had this method lazy-create on ErrNotFound but
// that conflated two distinct states — "no key yet" and "key was
// revoked" — and silently bypassed the revocation incident
// semantics. Lazy-create is now scoped to EnsureKey, which only
// provisions when the tenant has no key history at all.
func (s *KeyService) GetActive(ctx context.Context, tenantID uuid.UUID) (repository.PolicySigningKey, error) {
	return s.repo.GetActive(ctx, tenantID)
}

// GetActiveNoCreate is an alias for GetActive preserved for call
// sites that documented the no-lazy-create intent explicitly. Both
// methods are now equivalent; prefer GetActive in new code.
func (s *KeyService) GetActiveNoCreate(ctx context.Context, tenantID uuid.UUID) (repository.PolicySigningKey, error) {
	return s.repo.GetActive(ctx, tenantID)
}

// EnsureKey guarantees the tenant has an active signing key,
// provisioning a fresh one only when the tenant has never had any
// signing key (brand-new tenant onboarding). When the tenant has
// historical keys but none currently active (every key revoked or
// rotated-and-not-replaced), EnsureKey refuses to lazy-create and
// returns ErrNotFound — this is the documented revocation-incident
// behaviour: an admin must explicitly Rotate (or CreateInitial via
// the admin handler) to resume compilation. Idempotent when an
// active key already exists.
//
// The history-check and the insert run inside a single repository
// call (CreateIfNoHistory) so a concurrent goroutine that creates
// then revokes a key cannot slip past the guard. The earlier
// implementation split this into List + CreateInitial which had a
// (vanishingly narrow but real) TOCTOU window between the two
// calls — Devin Review #3312683959 flagged it; this is the
// architectural fix.
func (s *KeyService) EnsureKey(ctx context.Context, tenantID uuid.UUID) error {
	if _, err := s.repo.GetActive(ctx, tenantID); err == nil {
		return nil
	} else if !errors.Is(err, repository.ErrNotFound) {
		return err
	}
	// No active key right now. Try the atomic if-no-history
	// insert. The repository performs the existence probe and the
	// insert under a single transaction, so:
	//   - brand-new tenant → insert succeeds → return nil.
	//   - tenant has any historical key (active, rotated, or
	//     revoked) → ErrConflict → return ErrNotFound with the
	//     admin-rotation-required hint.
	//   - concurrent CreateInitial / Rotate raced us → also
	//     surfaces as ErrConflict — we just confirm there's now an
	//     active key (idempotency for the happy race) and return
	//     ErrNotFound otherwise (incident race).
	pub, seed, err := s.generateKey()
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	wrapped, err := s.wrapper.Wrap(ctx, tenantID, seed)
	if err != nil {
		return fmt.Errorf("wrap key: %w", err)
	}
	saved, err := s.repo.CreateIfNoHistory(ctx, tenantID, repository.PolicySigningKey{
		KeyID:       newKeyID(),
		Algorithm:   "ed25519",
		PublicKey:   pub,
		PrivateKey:  wrapped,
		Status:      repository.PolicySigningKeyStatusActive,
		ActivatedAt: s.now(),
	})
	if err == nil {
		s.appendAudit(ctx, tenantID, nil, "policy.signing_key_created", saved)
		return nil
	}
	if !errors.Is(err, repository.ErrConflict) {
		return err
	}
	// Conflict could be either:
	//   (a) a concurrent caller just provisioned a key — confirm
	//       by re-reading the active key and return nil; or
	//   (b) the tenant has historical keys but no active one —
	//       refuse to auto-provision (admin rotation required).
	if _, err := s.repo.GetActive(ctx, tenantID); err == nil {
		return nil
	}
	return fmt.Errorf("policy: no active signing key (admin rotation required after revocation): %w", repository.ErrNotFound)
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
// tenant key. Returns ErrNotFound (via repo.GetActive) when the
// tenant has no active key — Sign never lazy-creates, so revoking
// the active key causes the next Sign call to fail until an admin
// explicitly rotates. Callers that want first-compile bootstrap on
// a brand-new tenant should call EnsureKey before Sign.
func (s *KeyService) Sign(ctx context.Context, tenantID uuid.UUID, data []byte) (signature []byte, keyID string, err error) {
	active, err := s.repo.GetActive(ctx, tenantID)
	if err != nil {
		return nil, "", err
	}
	// active.Status is guaranteed to be 'active' by repo.GetActive's
	// WHERE clause; no defensive status check needed here.
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

// RotateOutcome distinguishes the two terminal states of
// RotateOrCreate: whether the resulting key is the tenant's first
// ever (Created) or a successor to a previously active key
// (Rotated). Callers (typically the admin HTTP handler) translate
// the outcome to a status code (201 vs 200).
type RotateOutcome int

const (
	// RotateOutcomeCreated indicates the tenant had no active key
	// at the moment of the call and a fresh first key was
	// provisioned.
	RotateOutcomeCreated RotateOutcome = iota + 1
	// RotateOutcomeRotated indicates an existing active key was
	// transitioned to 'rotated' and a successor active key was
	// inserted in the same transaction.
	RotateOutcomeRotated
)

// rotateOrCreateMaxAttempts caps the bounded retry loop in
// RotateOrCreate. Realistic races between two concurrent admin
// rotates settle in at most 1 retry; we allow a few more for
// belt-and-braces.
const rotateOrCreateMaxAttempts = 4

// RotateOrCreate is the all-in-one admin "give me a fresh active
// signing key" operation used by the rotateSigningKey HTTP
// handler. It replaces the previous handler-side
// GetActiveNoCreate + branch pattern, which had a TOCTOU window
// between the existence probe and the per-branch repository call
// (Devin Review flagged this as a benign-but-confusing race that
// could surface 404 / 409 from what callers consider an
// idempotent operation).
//
// The retry loop is short (rotateOrCreateMaxAttempts) and
// deterministic: each iteration either commits via Rotate, commits
// via Create, or hits a repository ErrConflict / ErrNotFound and
// retries. Concurrent callers see at most one of them succeed per
// iteration; the others fall through to the next attempt.
//
// A fresh Ed25519 keypair is generated once outside the loop so
// retries don't burn CPU regenerating keys. The keypair is only
// committed when the underlying Rotate / Create succeeds.
func (s *KeyService) RotateOrCreate(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID) (repository.PolicySigningKey, RotateOutcome, error) {
	pub, seed, err := s.generateKey()
	if err != nil {
		return repository.PolicySigningKey{}, 0, fmt.Errorf("generate key: %w", err)
	}
	wrapped, err := s.wrapper.Wrap(ctx, tenantID, seed)
	if err != nil {
		return repository.PolicySigningKey{}, 0, fmt.Errorf("wrap key: %w", err)
	}
	keyID := newKeyID()
	candidate := repository.PolicySigningKey{
		KeyID:      keyID,
		Algorithm:  "ed25519",
		PublicKey:  pub,
		PrivateKey: wrapped,
	}
	var lastErr error
	for attempt := 0; attempt < rotateOrCreateMaxAttempts; attempt++ {
		// Try Rotate first — this is the common "tenant has an
		// active key" path and the atomic transaction in the
		// driver handles concurrent rotates via the partial
		// unique index (ErrConflict on race).
		rotated, err := s.repo.Rotate(ctx, tenantID, candidate, s.now())
		if err == nil {
			s.appendAudit(ctx, tenantID, actorID, "policy.signing_key_rotated", rotated)
			return rotated, RotateOutcomeRotated, nil
		}
		if errors.Is(err, repository.ErrNotFound) {
			// No active key — try the first-time Create path.
			candidate.Status = repository.PolicySigningKeyStatusActive
			candidate.ActivatedAt = s.now()
			created, cerr := s.repo.Create(ctx, tenantID, candidate)
			if cerr == nil {
				s.appendAudit(ctx, tenantID, actorID, "policy.signing_key_created", created)
				return created, RotateOutcomeCreated, nil
			}
			if errors.Is(cerr, repository.ErrConflict) {
				// Concurrent Create / Rotate raced us. Loop
				// back; the next iteration will see the
				// just-inserted active key and Rotate will
				// succeed.
				lastErr = cerr
				continue
			}
			return repository.PolicySigningKey{}, 0, cerr
		}
		if errors.Is(err, repository.ErrConflict) {
			// Race between two concurrent Rotate calls — the
			// partial unique index rejected our INSERT. Retry.
			lastErr = err
			continue
		}
		return repository.PolicySigningKey{}, 0, err
	}
	return repository.PolicySigningKey{}, 0, fmt.Errorf("policy: rotate-or-create raced %d times: %w", rotateOrCreateMaxAttempts, lastErr)
}

// PreparedSigner is an optional Signer extension exposing a
// prepare-once / sign-many idiom. The bundle compiler signs four
// per-target payloads in a tight loop against the same tenant
// key; without this interface every call hits the database for
// repo.GetActive and re-derives the Ed25519 private-key seed.
// With this interface the compiler resolves the key once and
// performs pure-CPU signs for each target.
//
// Devin Review (#3312683824) flagged the unprepared path as a
// non-correctness performance issue. The prepared path collapses
// 4× DB round-trips + 4× wrapper.Unwrap + 4× NewKeyFromSeed into
// a single round-trip + single Unwrap + single key derivation
// per compile.
type PreparedSigner interface {
	PrepareSigner(ctx context.Context, tenantID uuid.UUID) (PreparedSigning, error)
}

// PreparedSigning carries the resolved private key and key ID for
// the duration of one logical operation (e.g. one Compile run).
// Sign performs pure-CPU Ed25519 signing — no DB and no allocation
// of a fresh keypair per call.
type PreparedSigning interface {
	Sign(data []byte) (signature []byte, keyID string)
}

// PrepareSigner resolves the active key once and returns a
// PreparedSigning bound to it. KeyService is a PreparedSigner.
func (s *KeyService) PrepareSigner(ctx context.Context, tenantID uuid.UUID) (PreparedSigning, error) {
	active, err := s.repo.GetActive(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	seed, err := s.wrapper.Unwrap(ctx, tenantID, active.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unwrap key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("policy: invalid seed size %d", len(seed))
	}
	return &preparedSigning{
		priv:  ed25519.NewKeyFromSeed(seed),
		keyID: active.KeyID,
	}, nil
}

type preparedSigning struct {
	priv  ed25519.PrivateKey
	keyID string
}

func (p *preparedSigning) Sign(data []byte) ([]byte, string) {
	return ed25519.Sign(p.priv, data), p.keyID
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
// from a fresh UUID v4. Short enough to embed in the bundle
// envelope without bloating the wire size, long enough that
// collisions across a tenant's rotation history are vanishingly
// unlikely. We take the first 8 bytes of the UUID; UUID v4 places
// 4 version bits (0100) in byte 6, so the effective entropy is
// ≈60 bits (64 random bits minus the 4 version bits). 60 bits is
// far more than sufficient — even at one rotation per second for
// a century, the birthday-bound collision probability is < 2^-30.
//
// The companion file-backed signer derives its kid as
// `hex(sha256(public)[:8])` (see policy.deriveKeyID); both
// derivations land in the same 16-hex-char shape on purpose so
// the receiver's verification code and operator log filters do
// not need to know which signer produced a given kid. Cross-mode
// collision probability is bounded by the lower entropy source
// (≈2⁻⁶⁰ per pair); negligible in practice.
func newKeyID() string {
	u := uuid.New()
	b := u[:]
	return hex.EncodeToString(b[:8])
}
