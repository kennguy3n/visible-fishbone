package dlpreview

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// SuspectedAppSentinel is the destination_app value used when the
// endpoint matched an AI app only by the long-tail heuristic (no curated
// catalog id). It keeps "we don't know which app, but it looked like
// one" first-class without inventing a fake vendor id.
const SuspectedAppSentinel = "suspected_ai_app"

// defaultSignal is stamped on an enqueued event when the caller does not
// specify one.
const defaultSignal = "ai_app_upload"

// systemActor is the audit actor for non-human actions (enqueue).
const systemActor = "system"

// Service is the human-in-the-loop DLP review queue. It is safe for
// concurrent use as long as the injected [Repository] and [AuditSink]
// are (the bundled implementations are).
type Service struct {
	repo  Repository
	audit AuditSink
	now   func() time.Time
}

// Option configures a [Service].
type Option func(*Service)

// WithAuditSink injects the audit sink. Defaults to [NoopAuditSink].
func WithAuditSink(sink AuditSink) Option {
	return func(s *Service) {
		if sink != nil {
			s.audit = sink
		}
	}
}

// WithClock injects the time source, for deterministic tests. Defaults
// to [time.Now] (UTC-normalised).
func WithClock(now func() time.Time) Option {
	return func(s *Service) {
		if now != nil {
			s.now = now
		}
	}
}

// New builds a Service over repo. repo must be non-nil.
func New(repo Repository, opts ...Option) (*Service, error) {
	if repo == nil {
		return nil, fmt.Errorf("dlpreview: %w: nil repository", repository.ErrInvalidArgument)
	}
	s := &Service{
		repo:  repo,
		audit: NoopAuditSink{},
		now:   func() time.Time { return time.Now().UTC() },
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// EnqueueInput is the redacted, validated description of a flagged
// upload to enqueue. It carries no raw payload by construction.
type EnqueueInput struct {
	// Signal is the producing signal; defaults to "ai_app_upload".
	Signal string
	// DestinationApp is the AI-app id or [SuspectedAppSentinel].
	DestinationApp string
	// Severity is the overall event severity.
	Severity Severity
	// Confidence is the detector confidence in [0,1].
	Confidence float64
	// Findings is the redacted evidence (may be empty).
	Findings []FindingAggregate
}

// maxDestinationAppLen bounds destination_app so a malformed caller
// cannot smuggle a full URL (with a path/query that might carry data)
// into the field. Catalog ids and the sentinel are well under this.
const maxDestinationAppLen = 128

// Enqueue validates input, stamps a fresh id/timestamp/pending state,
// persists the event, and records an audit entry. The stored event is
// returned.
func (s *Service) Enqueue(ctx context.Context, tenantID uuid.UUID, in EnqueueInput) (ReviewEvent, error) {
	if tenantID == uuid.Nil {
		return ReviewEvent{}, fmt.Errorf("dlpreview: %w: nil tenant", repository.ErrInvalidArgument)
	}
	if err := validateEnqueue(in); err != nil {
		return ReviewEvent{}, err
	}

	signal := in.Signal
	if signal == "" {
		signal = defaultSignal
	}

	ev := ReviewEvent{
		ID:             uuid.New(),
		TenantID:       tenantID,
		Signal:         signal,
		DestinationApp: in.DestinationApp,
		Severity:       in.Severity,
		Confidence:     in.Confidence,
		State:          StatePending,
		Findings:       normaliseFindings(in.Findings),
		CreatedAt:      s.now(),
	}

	stored, err := s.repo.Enqueue(ctx, tenantID, ev)
	if err != nil {
		return ReviewEvent{}, err
	}
	if err := s.audit.RecordReview(ctx, AuditRecord{
		TenantID:    tenantID,
		EventID:     stored.ID,
		Action:      AuditEnqueue,
		Actor:       systemActor,
		ResultState: stored.State,
		At:          stored.CreatedAt,
	}); err != nil {
		return ReviewEvent{}, fmt.Errorf("dlpreview: record enqueue audit: %w", err)
	}
	return stored, nil
}

// Get returns one event scoped to the tenant.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (ReviewEvent, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return ReviewEvent{}, fmt.Errorf("dlpreview: %w: nil id", repository.ErrInvalidArgument)
	}
	return s.repo.Get(ctx, tenantID, id)
}

// List returns the tenant's events, newest first, subject to f.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, f ListFilter) ([]ReviewEvent, error) {
	if tenantID == uuid.Nil {
		return nil, fmt.Errorf("dlpreview: %w: nil tenant", repository.ErrInvalidArgument)
	}
	if f.State != nil && !f.State.Valid() {
		return nil, fmt.Errorf("dlpreview: %w: invalid state filter %q", repository.ErrInvalidArgument, *f.State)
	}
	return s.repo.List(ctx, tenantID, f)
}

// Approve, Block, and Dismiss are the three terminal decisions. Each is
// a thin wrapper over [Service.decide] with the matching state/action.

// Approve marks a pending event approved.
func (s *Service) Approve(ctx context.Context, tenantID, id uuid.UUID, actor string) (ReviewEvent, error) {
	return s.decide(ctx, tenantID, id, StateApproved, AuditApprove, actor)
}

// Block marks a pending event blocked.
func (s *Service) Block(ctx context.Context, tenantID, id uuid.UUID, actor string) (ReviewEvent, error) {
	return s.decide(ctx, tenantID, id, StateBlocked, AuditBlock, actor)
}

// Dismiss marks a pending event dismissed.
func (s *Service) Dismiss(ctx context.Context, tenantID, id uuid.UUID, actor string) (ReviewEvent, error) {
	return s.decide(ctx, tenantID, id, StateDismissed, AuditDismiss, actor)
}

func (s *Service) decide(ctx context.Context, tenantID, id uuid.UUID, to ReviewState, action AuditAction, actor string) (ReviewEvent, error) {
	if tenantID == uuid.Nil || id == uuid.Nil {
		return ReviewEvent{}, fmt.Errorf("dlpreview: %w: nil id", repository.ErrInvalidArgument)
	}
	if actor == "" {
		return ReviewEvent{}, fmt.Errorf("dlpreview: %w: empty actor", repository.ErrInvalidArgument)
	}
	decidedAt := s.now()
	updated, err := s.repo.Transition(ctx, tenantID, id, to, actor, decidedAt)
	if err != nil {
		return ReviewEvent{}, err
	}
	if err := s.audit.RecordReview(ctx, AuditRecord{
		TenantID:    tenantID,
		EventID:     updated.ID,
		Action:      action,
		Actor:       actor,
		ResultState: updated.State,
		At:          decidedAt,
	}); err != nil {
		return ReviewEvent{}, fmt.Errorf("dlpreview: record %s audit: %w", action, err)
	}
	return updated, nil
}

// Digest is the non-blocking summary (NoOps): it reads aggregate counts
// for events created within `window` of now and takes no enforcement
// action. A non-positive window is rejected.
func (s *Service) Digest(ctx context.Context, tenantID uuid.UUID, window time.Duration) (Digest, error) {
	if tenantID == uuid.Nil {
		return Digest{}, fmt.Errorf("dlpreview: %w: nil tenant", repository.ErrInvalidArgument)
	}
	if window <= 0 {
		return Digest{}, fmt.Errorf("dlpreview: %w: non-positive window", repository.ErrInvalidArgument)
	}
	now := s.now()
	since := now.Add(-window)
	sum, err := s.repo.Summary(ctx, tenantID, since)
	if err != nil {
		return Digest{}, err
	}
	return Digest{
		TenantID:    tenantID,
		Window:      window,
		Since:       since,
		GeneratedAt: now,
		Summary:     sum,
	}, nil
}

// Digest is a point-in-time, non-blocking backlog summary for operators.
type Digest struct {
	// TenantID the digest is for.
	TenantID uuid.UUID
	// Window the digest covers (events created within `Window` of
	// `GeneratedAt`).
	Window time.Duration
	// Since is the inclusive lower bound on created_at (GeneratedAt-Window).
	Since time.Time
	// GeneratedAt is when the digest was produced.
	GeneratedAt time.Time
	// Summary holds the aggregate counts.
	Summary Summary
}

// validateEnqueue enforces the field invariants the storage layer also
// checks, so a bad input fails fast with a clear error rather than a
// constraint violation.
func validateEnqueue(in EnqueueInput) error {
	if in.DestinationApp == "" {
		return fmt.Errorf("dlpreview: %w: empty destination_app", repository.ErrInvalidArgument)
	}
	if len(in.DestinationApp) > maxDestinationAppLen {
		return fmt.Errorf("dlpreview: %w: destination_app too long", repository.ErrInvalidArgument)
	}
	if !in.Severity.Valid() {
		return fmt.Errorf("dlpreview: %w: invalid severity %q", repository.ErrInvalidArgument, in.Severity)
	}
	if in.Confidence < 0 || in.Confidence > 1 {
		return fmt.Errorf("dlpreview: %w: confidence %v out of [0,1]", repository.ErrInvalidArgument, in.Confidence)
	}
	for i, f := range in.Findings {
		if f.Kind != FindingPII && f.Kind != FindingSecret && f.Kind != FindingConfidential {
			return fmt.Errorf("dlpreview: %w: finding[%d] invalid kind %q", repository.ErrInvalidArgument, i, f.Kind)
		}
		if f.Label == "" {
			return fmt.Errorf("dlpreview: %w: finding[%d] empty label", repository.ErrInvalidArgument, i)
		}
		if f.Count <= 0 {
			return fmt.Errorf("dlpreview: %w: finding[%d] non-positive count", repository.ErrInvalidArgument, i)
		}
		if f.MaxConfidence < 0 || f.MaxConfidence > 1 {
			return fmt.Errorf("dlpreview: %w: finding[%d] confidence out of [0,1]", repository.ErrInvalidArgument, i)
		}
		if !f.Severity.Valid() {
			return fmt.Errorf("dlpreview: %w: finding[%d] invalid severity %q", repository.ErrInvalidArgument, i, f.Severity)
		}
	}
	return nil
}

// normaliseFindings returns a non-nil slice so the stored evidence is
// always a JSON array, never null, matching the column default.
func normaliseFindings(in []FindingAggregate) []FindingAggregate {
	if len(in) == 0 {
		return []FindingAggregate{}
	}
	return in
}

// ErrInvalidArgument re-exports the repository sentinel so callers of
// this package can classify validation errors without importing the
// repository package directly.
var ErrInvalidArgument = repository.ErrInvalidArgument

// assert at compile time that the sentinel wrapping above is wired to a
// real error (guards against an accidental nil during refactors).
var _ = errors.Is(ErrInvalidArgument, repository.ErrInvalidArgument)
