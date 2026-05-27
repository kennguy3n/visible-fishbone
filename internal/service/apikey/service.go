// Package apikey is the production API-key service used by the
// auth middleware to authenticate machine-to-machine clients.
//
// API keys are tenant-scoped opaque secrets of the form
// `sng_<43-char base64url>`. The 32 random bytes after the prefix
// give 256 bits of entropy — well outside the reach of any offline
// cracker even against a deterministic SHA-256 lookup, which is why
// the storage layer hashes with SHA-256 rather than a slow KDF
// (the KDF would force a sequential per-row probe and add latency
// to every authenticated request for no marginal security benefit
// at this entropy budget).
//
// The plaintext secret is shown to the operator exactly once at
// creation time and never persisted. Revocation flips status to
// 'revoked' permanently; minting a new key is the only way to
// restore access — operators rotate, not unrevoke.
//
// Calls to Lookup are on the request-hot-path; the middleware
// invokes them once per authenticated request. Side-effect writes
// (last_used_at) are done asynchronously via a fire-and-forget
// goroutine so the auth path stays read-only.
package apikey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// KeyPrefix is the visible prefix on every API key plaintext. Both
// the leaked-secret scanners (GitHub Push Protection, GitLeaks,
// etc.) and operators eyeballing logs can recognise it without
// needing the full key.
const KeyPrefix = "sng_"

// secretBytes is the entropy budget of the random portion after
// the prefix. 32 bytes → 256 bits → 43 base64url chars after
// stripping the padding (since 32 is not a multiple of 3).
const secretBytes = 32

// MinExpiresIn is the lower bound on a freshly-minted key's
// validity window. Keys with very short TTLs are almost always a
// bug (operator typoed seconds vs. days), so we reject them at
// the service layer rather than let an expired-on-arrival key
// hit the lookup path.
const MinExpiresIn = time.Minute

// ErrInvalidKey is returned by Lookup when the presented key
// either has the wrong format or does not match a stored row.
// The middleware translates this to a generic 401 — we never tell
// the caller WHY auth failed.
var ErrInvalidKey = errors.New("apikey: invalid key")

// ErrKeyRevoked is returned by Lookup when a presented key matched
// a revoked row. Same external surface as ErrInvalidKey — only
// audit-log diagnostics distinguish the two.
var ErrKeyRevoked = errors.New("apikey: key revoked")

// ErrKeyExpired is returned by Lookup when a presented key matched
// a row whose expires_at is in the past. Same external surface as
// ErrInvalidKey.
var ErrKeyExpired = errors.New("apikey: key expired")

// Service owns the API-key lifecycle (create, revoke, list) and
// satisfies middleware.APIKeyLookup for authentication.
type Service struct {
	repo   repository.TenantAPIKeyRepository
	audit  repository.AuditLogRepository
	logger *slog.Logger
	now    func() time.Time
	// asyncTouch decouples last_used_at writes from the request
	// path. The auth middleware fires-and-forgets a touch; a
	// dropped touch is acceptable (it just means a key looks
	// stale-er than it is in the audit log) and a slow touch
	// must not slow auth.
	asyncTouch func(fn func())
}

// Option configures New.
type Option func(*Service)

// WithLogger installs a non-default slog.Logger. Defaults to
// slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithClock injects a deterministic clock for tests. Production
// callers should not override this.
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// WithAsyncTouch overrides the fire-and-forget runner used to
// update last_used_at after a successful Lookup. Defaults to
// `go fn()`. Tests inject a synchronous runner so they can
// assert the touch happened.
func WithAsyncTouch(run func(fn func())) Option {
	return func(s *Service) {
		if run != nil {
			s.asyncTouch = run
		}
	}
}

// New constructs the API-key service.
func New(repo repository.TenantAPIKeyRepository, audit repository.AuditLogRepository, opts ...Option) *Service {
	s := &Service{
		repo:       repo,
		audit:      audit,
		logger:     slog.Default(),
		now:        func() time.Time { return time.Now().UTC() },
		asyncTouch: func(fn func()) { go fn() },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// CreateResult is the return shape of Create. The plaintext key
// is exposed exactly once; the caller MUST surface it to the
// operator and then drop it.
type CreateResult struct {
	Record    repository.TenantAPIKey
	Plaintext string
}

// CreateInput is the operator-visible part of Create.
type CreateInput struct {
	Name      string
	Subject   string
	ExpiresAt *time.Time
}

// Create mints a fresh API key for tenantID. The plaintext key
// is returned to the caller exactly once.
//
// `actor` is the user ID that initiated the create; nil for
// bootstrap paths (CLI seeding, migrations).
func (s *Service) Create(ctx context.Context, tenantID uuid.UUID, actor *uuid.UUID, in CreateInput) (CreateResult, error) {
	if tenantID == uuid.Nil {
		return CreateResult{}, fmt.Errorf("tenant_id required: %w", repository.ErrInvalidArgument)
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return CreateResult{}, fmt.Errorf("name required: %w", repository.ErrInvalidArgument)
	}
	subject := strings.TrimSpace(in.Subject)
	if subject == "" {
		return CreateResult{}, fmt.Errorf("subject required: %w", repository.ErrInvalidArgument)
	}
	if in.ExpiresAt != nil {
		ttl := in.ExpiresAt.Sub(s.now())
		if ttl <= 0 {
			return CreateResult{}, fmt.Errorf("expires_at must be in the future: %w", repository.ErrInvalidArgument)
		}
		if ttl < MinExpiresIn {
			return CreateResult{}, fmt.Errorf("expires_at must be at least %s in the future: %w", MinExpiresIn, repository.ErrInvalidArgument)
		}
	}

	plaintext, hash, err := generateKey()
	if err != nil {
		return CreateResult{}, fmt.Errorf("apikey: generate: %w", err)
	}

	stored, err := s.repo.Create(ctx, tenantID, repository.TenantAPIKey{
		Name:      name,
		Subject:   subject,
		Hash:      hash,
		Status:    repository.TenantAPIKeyStatusActive,
		ExpiresAt: in.ExpiresAt,
		CreatedBy: actor,
	})
	if err != nil {
		return CreateResult{}, err
	}

	s.appendAudit(ctx, tenantID, actor, "apikey.create", stored.ID, map[string]any{
		"name":    stored.Name,
		"subject": stored.Subject,
	})

	return CreateResult{Record: stored, Plaintext: plaintext}, nil
}

// Revoke transitions a key to status='revoked'. Idempotent — a
// second Revoke on an already-revoked key is a no-op (no error)
// but is still audited so operators can correlate to a manual
// "rotate then revoke old" workflow.
func (s *Service) Revoke(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, actor *uuid.UUID) (repository.TenantAPIKey, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return repository.TenantAPIKey{}, fmt.Errorf("tenant_id and id required: %w", repository.ErrInvalidArgument)
	}
	out, err := s.repo.Revoke(ctx, tenantID, id, s.now())
	if err != nil {
		return repository.TenantAPIKey{}, err
	}
	s.appendAudit(ctx, tenantID, actor, "apikey.revoke", out.ID, map[string]any{
		"name":    out.Name,
		"subject": out.Subject,
	})
	return out, nil
}

// Get returns a key by id, scoped to tenantID.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.TenantAPIKey, error) {
	return s.repo.Get(ctx, tenantID, id)
}

// List returns all keys for tenantID ordered created-desc.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID) ([]repository.TenantAPIKey, error) {
	return s.repo.List(ctx, tenantID)
}

// Lookup resolves a presented API-key plaintext to an APIKeyInfo
// for the middleware. It rejects keys that are malformed, revoked,
// expired, or unknown. On success it fires an async touch to
// update last_used_at.
func (s *Service) Lookup(ctx context.Context, key string) (middleware.APIKeyInfo, error) {
	hash, ok := hashKey(key)
	if !ok {
		return middleware.APIKeyInfo{}, ErrInvalidKey
	}
	stored, err := s.repo.LookupByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return middleware.APIKeyInfo{}, ErrInvalidKey
		}
		return middleware.APIKeyInfo{}, err
	}
	// Constant-time hash compare. The repository found the row by
	// equality already, but doing the compare here guards against
	// any future driver that might match on prefix or substring.
	if subtle.ConstantTimeCompare(stored.Hash, hash) != 1 {
		return middleware.APIKeyInfo{}, ErrInvalidKey
	}
	if stored.Status == repository.TenantAPIKeyStatusRevoked {
		return middleware.APIKeyInfo{}, ErrKeyRevoked
	}
	if stored.ExpiresAt != nil && !stored.ExpiresAt.After(s.now()) {
		return middleware.APIKeyInfo{}, ErrKeyExpired
	}

	// Fire-and-forget the last_used_at update so auth latency is
	// not gated on a DB write. Errors are logged but do not bubble.
	id := stored.ID
	tenantID := stored.TenantID
	now := s.now()
	s.asyncTouch(func() {
		// Use a fresh context — the request context might be
		// cancelled by the time the goroutine runs, but we still
		// want to record the touch.
		bg, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := s.repo.TouchLastUsed(bg, tenantID, id, now); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			s.logger.Warn("apikey: touch last_used failed",
				slog.String("tenant_id", tenantID.String()),
				slog.String("api_key_id", id.String()),
				slog.Any("error", err),
			)
		}
	})

	return middleware.APIKeyInfo{
		ID:       stored.ID.String(),
		TenantID: stored.TenantID,
		Subject:  stored.Subject,
	}, nil
}

// generateKey produces a fresh plaintext + its SHA-256 hash. The
// plaintext shape is `sng_<base64url(32 bytes, no padding)>`.
func generateKey() (string, []byte, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", nil, err
	}
	plain := KeyPrefix + base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plain))
	return plain, sum[:], nil
}

// hashKey validates a presented plaintext and returns its SHA-256
// hash. Returns ok=false if the key has the wrong shape, so the
// caller can short-circuit before hitting the database.
func hashKey(key string) ([]byte, bool) {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, KeyPrefix) {
		return nil, false
	}
	body := key[len(KeyPrefix):]
	decoded, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, false
	}
	if len(decoded) != secretBytes {
		return nil, false
	}
	sum := sha256.Sum256([]byte(key))
	return sum[:], true
}

// appendAudit synchronously persists an audit entry. Runs inline
// with the primary operation so audit gaps are bounded by request
// duration, not by goroutine scheduling. Errors are logged and
// swallowed — audit failures must never block the user-visible
// outcome (consistent with tenant/site/identity/rbac services).
func (s *Service) appendAudit(ctx context.Context, tenantID uuid.UUID, actor *uuid.UUID, action string, resourceID uuid.UUID, details map[string]any) {
	if s.audit == nil {
		return
	}
	body, err := json.Marshal(details)
	if err != nil {
		s.logger.Warn("apikey: marshal audit details failed", slog.Any("error", err))
		body = json.RawMessage(`{}`)
	}
	if _, err := s.audit.Append(ctx, tenantID, repository.AuditEntry{
		ActorID:      actor,
		Action:       action,
		ResourceType: "tenant_api_key",
		ResourceID:   &resourceID,
		Details:      body,
	}); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return
		}
		s.logger.Warn("apikey: audit append failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("action", action),
			slog.Any("error", err),
		)
	}
}

// Compile-time interface compliance assertion. Keeping this here
// surfaces an obvious diff when the middleware interface evolves.
var _ middleware.APIKeyLookup = (*Service)(nil)
