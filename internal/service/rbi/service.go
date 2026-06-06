package rbi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Session is the service-level view of an RBI session.
type Session struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	UserID    uuid.UUID
	TargetURL string
	Status    string
	ProxyURL  string
	ExpiresAt time.Time
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateSessionInput is the validated input to CreateSession.
type CreateSessionInput struct {
	TargetURL string
	UserID    uuid.UUID
}

var (
	ErrInvalidArgument = repository.ErrInvalidArgument
	ErrNotConfigured   = errors.New("rbi: proxy not configured")
	// ErrArtifactBlocked is returned by RecordArtifact when the
	// artifact policy denies the transfer across the isolation
	// boundary. It is a policy decision, not an error condition — the
	// caller surfaces it as a 403 and the transfer is dropped.
	ErrArtifactBlocked = errors.New("rbi: artifact transfer blocked by policy")
	// ErrArtifactRepoUnavailable is returned when artifact recording
	// is requested but no artifact repository is wired.
	ErrArtifactRepoUnavailable = errors.New("rbi: artifact persistence not configured")
)

// ResidencyGuard reports whether a tenant's data may be persisted in
// the region this control plane writes to. The rbi package defines
// its own one-method interface (rather than importing the residency
// service) so the service stays free of any residency/repository
// dependency beyond what it already needs. *residency.Guard satisfies
// it. A nil guard means residency enforcement is not configured and
// artifact persistence proceeds unguarded.
type ResidencyGuard interface {
	Check(ctx context.Context, tenantID uuid.UUID) error
}

// Service manages tenant-scoped RBI sessions.
type Service struct {
	repo      repository.RBISessionRepository
	artifacts repository.RBIArtifactRepository
	guard     ResidencyGuard
	audit     repository.AuditLogRepository
	proxy     ProxyConfig
	policy    PolicyConfig
	artifact  ArtifactPolicy
	logger    *slog.Logger
	now       func() time.Time
	newID     func() uuid.UUID
	// SessionTTL is how long a session stays active.
	sessionTTL time.Duration
}

// Option configures the Service.
type Option func(*Service)

func WithAudit(a repository.AuditLogRepository) Option {
	return func(s *Service) { s.audit = a }
}

func WithProxy(p ProxyConfig) Option {
	return func(s *Service) { s.proxy = p }
}

func WithPolicy(p PolicyConfig) Option {
	return func(s *Service) { s.policy = p }
}

// WithArtifactRepo wires the artifact-record store so RecordArtifact
// can persist transfers that cross the isolation boundary. Without it
// RecordArtifact returns ErrArtifactRepoUnavailable.
func WithArtifactRepo(r repository.RBIArtifactRepository) Option {
	return func(s *Service) { s.artifacts = r }
}

// WithResidencyGuard wires the fail-closed data-residency guard that
// gates artifact persistence. Without it artifact rows are persisted
// unguarded (residency enforcement opt-in).
func WithResidencyGuard(g ResidencyGuard) Option {
	return func(s *Service) { s.guard = g }
}

// WithArtifactPolicy sets the clipboard/file-transfer gating policy.
// The zero value (the default) denies every transfer — isolation
// defaults to a sealed boundary.
func WithArtifactPolicy(p ArtifactPolicy) Option {
	return func(s *Service) { s.artifact = p }
}

func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

func WithSessionTTL(ttl time.Duration) Option {
	return func(s *Service) {
		if ttl > 0 {
			s.sessionTTL = ttl
		}
	}
}

func withClock(f func() time.Time) Option {
	return func(s *Service) {
		if f != nil {
			s.now = f
		}
	}
}

func withIDGen(f func() uuid.UUID) Option {
	return func(s *Service) {
		if f != nil {
			s.newID = f
		}
	}
}

// NewService constructs the RBI service.
func NewService(repo repository.RBISessionRepository, opts ...Option) *Service {
	s := &Service{
		repo:       repo,
		logger:     slog.Default(),
		now:        func() time.Time { return time.Now().UTC() },
		newID:      uuid.New,
		sessionTTL: 15 * time.Minute,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ProxyConfigured reports whether the RBI proxy is reachable.
func (s *Service) ProxyConfigured() bool { return s.proxy.Configured() }

// PolicyConfig returns the current trigger policy so the handler can
// expose it for operator inspection.
func (s *Service) PolicyConfig() PolicyConfig { return s.policy }

// EvaluateURL checks whether a URL should be isolated. Returns
// (true, reason) if isolation is triggered, (false, "") otherwise.
//
// This host-agnostic entry point cannot match the explicit host
// allow/deny lists; prefer [Service.Evaluate] when the destination
// host is known.
func (s *Service) EvaluateURL(category string, riskScore int) (bool, TriggerReason) {
	return s.policy.Evaluate(category, riskScore)
}

// Evaluate applies the full RBI trigger policy — including the
// explicit host allow/deny lists and their precedence — to a request.
func (s *Service) Evaluate(req Request) (bool, TriggerReason) {
	return s.policy.EvaluateRequest(req)
}

// CreateSession opens an RBI session for a target URL, returning the
// session with a filled ProxyURL. If the proxy is not configured the
// service returns ErrNotConfigured — the SWG falls back to a normal
// allow/block decision.
func (s *Service) CreateSession(ctx context.Context, tenantID uuid.UUID, input CreateSessionInput, actorID *uuid.UUID) (Session, error) {
	if input.TargetURL == "" {
		return Session{}, fmt.Errorf("%w: target_url is required", ErrInvalidArgument)
	}
	if !s.proxy.Configured() {
		return Session{}, ErrNotConfigured
	}
	now := s.now()
	row, err := s.repo.Create(ctx, tenantID, repository.RBISession{
		ID:        s.newID(),
		TenantID:  tenantID,
		UserID:    input.UserID,
		TargetURL: input.TargetURL,
		Status:    "active",
		ExpiresAt: now.Add(s.sessionTTL),
	})
	if err != nil {
		return Session{}, err
	}
	sess := fromRow(row, s.proxy)
	s.logAudit(ctx, tenantID, actorID, "rbi.session_created", sess)
	return sess, nil
}

// GetSession retrieves a session by ID.
func (s *Service) GetSession(ctx context.Context, tenantID, id uuid.UUID) (Session, error) {
	row, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return Session{}, err
	}
	return fromRow(row, s.proxy), nil
}

// ListSessions returns recent sessions for a tenant.
func (s *Service) ListSessions(ctx context.Context, tenantID uuid.UUID, limit int) ([]Session, error) {
	rows, err := s.repo.List(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(rows))
	for _, row := range rows {
		out = append(out, fromRow(row, s.proxy))
	}
	return out, nil
}

// CloseSession marks an active session as closed.
func (s *Service) CloseSession(ctx context.Context, tenantID, id uuid.UUID, actorID *uuid.UUID) error {
	if err := s.repo.Close(ctx, tenantID, id); err != nil {
		return err
	}
	s.logAudit(ctx, tenantID, actorID, "rbi.session_closed", Session{ID: id, TenantID: tenantID})
	return nil
}

// Artifact is the service-level view of a recorded artifact transfer.
type Artifact struct {
	ID        uuid.UUID
	SessionID uuid.UUID
	Kind      ArtifactKind
	Direction ArtifactDirection
	Filename  string
	SHA256    string
	SizeBytes int64
	CreatedAt time.Time
}

// ArtifactInput is the validated input to RecordArtifact.
type ArtifactInput struct {
	Kind      ArtifactKind
	Direction ArtifactDirection
	Filename  string
	SHA256    string
	SizeBytes int64
}

// ArtifactPolicy returns the configured artifact-gating policy so the
// handler can expose it for operator inspection.
func (s *Service) ArtifactPolicy() ArtifactPolicy { return s.artifact }

// RecordArtifact gates and persists a single artifact transfer that
// crossed the RBI isolation boundary. It enforces, in order:
//
//  1. the session exists, belongs to the tenant, and is still active;
//  2. the artifact policy permits this kind+direction (otherwise the
//     transfer is blocked and ErrArtifactBlocked is returned — no row
//     is written, but the block is audited);
//  3. the fail-closed data-residency Guard permits persisting the
//     tenant's data in this region (a residency violation aborts the
//     write — the artifact metadata is NEVER stored cross-region);
//
// only then is the row persisted and the transfer audited. This is the
// "persist artifacts only through the residency Guard, fail-closed"
// requirement: every artifact row that reaches storage has passed the
// guard.
func (s *Service) RecordArtifact(ctx context.Context, tenantID, sessionID uuid.UUID, in ArtifactInput, actorID *uuid.UUID) (Artifact, error) {
	if s.artifacts == nil {
		return Artifact{}, ErrArtifactRepoUnavailable
	}
	kind := normalizeKind(string(in.Kind))
	dir := normalizeDirection(string(in.Direction))
	if in.SizeBytes < 0 {
		return Artifact{}, fmt.Errorf("%w: size_bytes must not be negative", ErrInvalidArgument)
	}

	// The session must exist, belong to the tenant, and be active:
	// an artifact cannot cross a boundary that is already closed.
	sess, err := s.repo.Get(ctx, tenantID, sessionID)
	if err != nil {
		return Artifact{}, err
	}
	if sess.Status != "active" {
		return Artifact{}, fmt.Errorf("%w: session is not active", ErrInvalidArgument)
	}

	// Policy gate: is this transfer allowed across the boundary at all?
	allowed, reason := s.artifact.GateArtifact(kind, dir)
	if !allowed {
		s.logArtifactAudit(ctx, tenantID, actorID, "rbi.artifact_blocked", sessionID, kind, dir, reason)
		return Artifact{}, fmt.Errorf("%w: %s", ErrArtifactBlocked, reason)
	}

	// Residency gate (fail-closed): may we persist this tenant's data
	// in our region? A violation aborts the write entirely.
	if s.guard != nil {
		if err := s.guard.Check(ctx, tenantID); err != nil {
			return Artifact{}, err
		}
	}

	row, err := s.artifacts.Create(ctx, tenantID, repository.RBIArtifact{
		ID:        s.newID(),
		TenantID:  tenantID,
		SessionID: sessionID,
		Kind:      string(kind),
		Direction: string(dir),
		Filename:  in.Filename,
		SHA256:    in.SHA256,
		SizeBytes: in.SizeBytes,
	})
	if err != nil {
		return Artifact{}, err
	}
	art := artifactFromRow(row)
	s.logArtifactAudit(ctx, tenantID, actorID, "rbi.artifact_recorded", sessionID, kind, dir, "")
	return art, nil
}

// ListArtifacts returns recorded artifact transfers for a session,
// newest first.
func (s *Service) ListArtifacts(ctx context.Context, tenantID, sessionID uuid.UUID, limit int) ([]Artifact, error) {
	if s.artifacts == nil {
		return nil, ErrArtifactRepoUnavailable
	}
	// Confirm the session belongs to the tenant before listing.
	if _, err := s.repo.Get(ctx, tenantID, sessionID); err != nil {
		return nil, err
	}
	rows, err := s.artifacts.ListBySession(ctx, tenantID, sessionID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]Artifact, 0, len(rows))
	for _, row := range rows {
		out = append(out, artifactFromRow(row))
	}
	return out, nil
}

func artifactFromRow(row repository.RBIArtifact) Artifact {
	return Artifact{
		ID:        row.ID,
		SessionID: row.SessionID,
		Kind:      ArtifactKind(row.Kind),
		Direction: ArtifactDirection(row.Direction),
		Filename:  row.Filename,
		SHA256:    row.SHA256,
		SizeBytes: row.SizeBytes,
		CreatedAt: row.CreatedAt,
	}
}

func fromRow(row repository.RBISession, proxy ProxyConfig) Session {
	sess := Session{
		ID:        row.ID,
		TenantID:  row.TenantID,
		UserID:    row.UserID,
		TargetURL: row.TargetURL,
		Status:    row.Status,
		ExpiresAt: row.ExpiresAt,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
	if proxy.Configured() {
		sess.ProxyURL = proxy.SessionURL(row.ID.String())
	}
	return sess
}

func (s *Service) logAudit(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, action string, sess Session) {
	if s.audit == nil {
		return
	}
	var details json.RawMessage
	if b, err := json.Marshal(map[string]any{
		"session_id": sess.ID.String(),
		"target_url": sess.TargetURL,
	}); err == nil {
		details = b
	}
	entry := repository.AuditEntry{
		TenantID:     tenantID,
		ActorID:      actorID,
		Action:       action,
		ResourceType: "rbi_session",
		Details:      details,
	}
	if _, err := s.audit.Append(ctx, tenantID, entry); err != nil {
		s.logger.Warn("rbi: audit append failed",
			slog.String("action", action),
			slog.Any("error", err))
	}
}

func (s *Service) logArtifactAudit(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, action string, sessionID uuid.UUID, kind ArtifactKind, dir ArtifactDirection, reason string) {
	if s.audit == nil {
		return
	}
	fields := map[string]any{
		"session_id": sessionID.String(),
		"kind":       string(kind),
		"direction":  string(dir),
	}
	if reason != "" {
		fields["reason"] = reason
	}
	var details json.RawMessage
	if b, err := json.Marshal(fields); err == nil {
		details = b
	}
	entry := repository.AuditEntry{
		TenantID:     tenantID,
		ActorID:      actorID,
		Action:       action,
		ResourceType: "rbi_session_artifact",
		Details:      details,
	}
	if _, err := s.audit.Append(ctx, tenantID, entry); err != nil {
		s.logger.Warn("rbi: artifact audit append failed",
			slog.String("action", action),
			slog.Any("error", err))
	}
}
