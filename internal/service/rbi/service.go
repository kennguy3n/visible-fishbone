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
)

// Service manages tenant-scoped RBI sessions.
type Service struct {
	repo   repository.RBISessionRepository
	audit  repository.AuditLogRepository
	proxy  ProxyConfig
	policy PolicyConfig
	logger *slog.Logger
	now    func() time.Time
	newID  func() uuid.UUID
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
func (s *Service) EvaluateURL(category string, riskScore int) (bool, TriggerReason) {
	return s.policy.Evaluate(category, riskScore)
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
