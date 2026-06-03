package troubleshoot

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultMaxMessages is the maximum number of messages per session.
const DefaultMaxMessages = 50

// DefaultInactivityTimeout is the default session inactivity timeout.
const DefaultInactivityTimeout = 72 * time.Hour

// SessionService manages troubleshooting sessions.
type SessionService struct {
	repo              repository.TroubleshootSessionRepository
	assistant         *Assistant
	maxMessages       int
	inactivityTimeout time.Duration
}

// SessionConfig holds optional configuration for the session service.
type SessionConfig struct {
	MaxMessages       int
	InactivityTimeout time.Duration
}

// NewSessionService creates a session service.
func NewSessionService(
	repo repository.TroubleshootSessionRepository,
	assistant *Assistant,
	cfg *SessionConfig,
) *SessionService {
	maxMsgs := DefaultMaxMessages
	timeout := DefaultInactivityTimeout
	if cfg != nil {
		if cfg.MaxMessages > 0 {
			maxMsgs = cfg.MaxMessages
		}
		if cfg.InactivityTimeout > 0 {
			timeout = cfg.InactivityTimeout
		}
	}
	return &SessionService{
		repo:              repo,
		assistant:         assistant,
		maxMessages:       maxMsgs,
		inactivityTimeout: timeout,
	}
}

// StartSession creates a new troubleshooting session.
func (s *SessionService) StartSession(ctx context.Context, tenantID, operatorID uuid.UUID, issue string) (TroubleshootSession, error) {
	if issue == "" {
		return TroubleshootSession{}, fmt.Errorf("issue description is required: %w", repository.ErrInvalidArgument)
	}

	// Generate initial assistant response.
	assistantResp, err := s.assistant.Respond(ctx, tenantID, issue, issue)
	if err != nil {
		return TroubleshootSession{}, fmt.Errorf("assistant respond: %w", err)
	}

	now := nowFunc()
	messages := []SessionMessage{
		{Role: "operator", Content: issue, Timestamp: now, AIGenerated: false},
		{Role: "assistant", Content: assistantResp.Content, Timestamp: now, AIGenerated: assistantResp.AIGenerated},
	}

	sess := repository.TroubleshootSession{
		OperatorID:        operatorID,
		Issue:             issue,
		Status:            repository.TroubleshootSessionActive,
		Messages:          marshalMessages(messages),
		DiagnosticResults: marshalDiagnosticResults(assistantResp.DiagnosticResults),
	}

	created, err := s.repo.Create(ctx, tenantID, sess)
	if err != nil {
		return TroubleshootSession{}, err
	}

	return fromRepoSession(created), nil
}

// SendMessage adds a message to an existing session and generates
// an assistant response.
func (s *SessionService) SendMessage(ctx context.Context, tenantID uuid.UUID, sessionID uuid.UUID, content string) (TroubleshootSession, error) {
	existing, err := s.repo.Get(ctx, tenantID, sessionID)
	if err != nil {
		return TroubleshootSession{}, err
	}

	if existing.Status != repository.TroubleshootSessionActive {
		return TroubleshootSession{}, fmt.Errorf("session is %s: %w", existing.Status, repository.ErrForbidden)
	}

	messages := unmarshalMessages(existing.Messages)

	// Check max message limit (each SendMessage adds 2: operator + assistant).
	if len(messages)+2 > s.maxMessages {
		return TroubleshootSession{}, fmt.Errorf("session has reached maximum message limit (%d): %w", s.maxMessages, repository.ErrResourceExhausted)
	}

	now := nowFunc()

	// Check inactivity timeout.
	if len(messages) > 0 {
		lastMsg := messages[len(messages)-1]
		if now.Sub(lastMsg.Timestamp) > s.inactivityTimeout {
			existing.Status = repository.TroubleshootSessionResolved
			existing.Messages = marshalMessages(messages)
			updated, err := s.repo.Update(ctx, tenantID, sessionID, existing)
			if err != nil {
				return TroubleshootSession{}, err
			}
			return fromRepoSession(updated), fmt.Errorf("session expired due to inactivity: %w", repository.ErrForbidden)
		}
	}

	// Add operator message.
	messages = append(messages, SessionMessage{
		Role: "operator", Content: content, Timestamp: now, AIGenerated: false,
	})

	// Generate assistant response.
	assistantResp, err := s.assistant.Respond(ctx, tenantID, existing.Issue, content)
	if err != nil {
		return TroubleshootSession{}, fmt.Errorf("assistant respond: %w", err)
	}

	messages = append(messages, SessionMessage{
		Role: "assistant", Content: assistantResp.Content, Timestamp: now, AIGenerated: assistantResp.AIGenerated,
	})

	existing.Messages = marshalMessages(messages)
	existing.DiagnosticResults = marshalDiagnosticResults(assistantResp.DiagnosticResults)

	updated, err := s.repo.Update(ctx, tenantID, sessionID, existing)
	if err != nil {
		return TroubleshootSession{}, err
	}

	return fromRepoSession(updated), nil
}

// GetSession retrieves a session with its full history.
func (s *SessionService) GetSession(ctx context.Context, tenantID, sessionID uuid.UUID) (TroubleshootSession, error) {
	sess, err := s.repo.Get(ctx, tenantID, sessionID)
	if err != nil {
		return TroubleshootSession{}, err
	}
	return fromRepoSession(sess), nil
}

// ResolveSession marks a session as resolved.
func (s *SessionService) ResolveSession(ctx context.Context, tenantID, sessionID uuid.UUID) (TroubleshootSession, error) {
	existing, err := s.repo.Get(ctx, tenantID, sessionID)
	if err != nil {
		return TroubleshootSession{}, err
	}
	existing.Status = repository.TroubleshootSessionResolved
	updated, err := s.repo.Update(ctx, tenantID, sessionID, existing)
	if err != nil {
		return TroubleshootSession{}, err
	}
	return fromRepoSession(updated), nil
}

// ListSessions lists sessions for a tenant.
func (s *SessionService) ListSessions(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[TroubleshootSession], error) {
	result, err := s.repo.List(ctx, tenantID, page)
	if err != nil {
		return repository.PageResult[TroubleshootSession]{}, err
	}
	items := make([]TroubleshootSession, len(result.Items))
	for i, rs := range result.Items {
		items[i] = fromRepoSession(rs)
	}
	return repository.PageResult[TroubleshootSession]{Items: items, NextCursor: result.NextCursor}, nil
}

func fromRepoSession(s repository.TroubleshootSession) TroubleshootSession {
	return TroubleshootSession{
		ID:                s.ID,
		TenantID:          s.TenantID,
		OperatorID:        s.OperatorID,
		Issue:             s.Issue,
		Status:            SessionStatus(s.Status),
		Messages:          unmarshalMessages(s.Messages),
		DiagnosticResults: unmarshalDiagnosticResults(s.DiagnosticResults),
		CreatedAt:         s.CreatedAt,
		UpdatedAt:         s.UpdatedAt,
	}
}
