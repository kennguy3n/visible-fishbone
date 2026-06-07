package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sync/singleflight"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/sandbox/providers"
)

// sha256Pattern matches a lowercase hex SHA-256 digest. The service
// canonicalises to lowercase before validating so a caller passing
// an upper-case digest is accepted.
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrInvalidArgument and ErrNoProvider are the service-level
// sentinels. ErrInvalidArgument maps to HTTP 400 at the handler;
// ErrNoProvider means a detonation was requested but no sandbox
// provider is configured (the service degrades to "no verdict").
var (
	ErrInvalidArgument = repository.ErrInvalidArgument
	ErrNoProvider      = errors.New("sandbox: no provider configured")
)

// submitFlightTimeout is a defense-in-depth ceiling on a single
// coalesced detonation submission. The detached flight context (see
// Submit) drops the caller's deadline, so it would otherwise depend
// entirely on the provider implementing its own client timeout. Bound
// it here too so a provider that neglects to set one cannot occupy a
// (tenant, digest) singleflight key forever and wedge every future
// submission of that sample. It is deliberately well above the
// bundled providers' 30s http.Client timeout so it never preempts a
// healthy provider; it only backstops a misbehaving one.
const submitFlightTimeout = 2 * time.Minute

// Service orchestrates zero-day file analysis: dedup against the
// persistent verdict store, submission to the configured detonation
// provider, and verdict caching. It is safe for concurrent use.
//
// The provider may be nil: a deployment that has not configured a
// sandbox still runs (LookupVerdict serves persisted verdicts;
// Submit returns ErrNoProvider). This keeps the data-plane
// integration fail-open — the SWG submits unknowns opportunistically
// and never depends on a sandbox being wired.
type Service struct {
	repo     repository.SandboxVerdictRepository
	provider providers.Provider
	cache    *Cache
	audit    repository.AuditLogRepository
	logger   *slog.Logger
	now      func() time.Time
	newID    func() uuid.UUID
	// flight collapses concurrent Submit calls for the same
	// (tenant, digest) into a single in-flight detonation so the
	// SWG fleet does not stampede the provider with duplicate
	// submissions of the same sample. Keyed by "tenant:sha".
	flight singleflight.Group
}

// Option configures the Service.
type Option func(*Service)

// WithProvider wires the detonation-sandbox backend. Without it the
// service serves persisted verdicts only and Submit returns
// ErrNoProvider.
func WithProvider(p providers.Provider) Option {
	return func(s *Service) { s.provider = p }
}

// WithCache attaches an in-memory verdict cache in front of the
// repository. Without it every lookup hits the repository.
func WithCache(c *Cache) Option {
	return func(s *Service) { s.cache = c }
}

// WithAudit wires audit logging. Nil (the default) skips it.
func WithAudit(a repository.AuditLogRepository) Option {
	return func(s *Service) { s.audit = a }
}

// WithLogger sets the logger; defaults to slog.Default().
func WithLogger(l *slog.Logger) Option {
	return func(s *Service) {
		if l != nil {
			s.logger = l
		}
	}
}

// withClock / withIDGen are test seams.
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

// NewService constructs the sandbox service. repo is required.
func NewService(repo repository.SandboxVerdictRepository, opts ...Option) *Service {
	s := &Service{
		repo:   repo,
		logger: slog.Default(),
		now:    func() time.Time { return time.Now().UTC() },
		newID:  uuid.New,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ProviderID returns the configured provider id, or "" when no
// provider is wired. Used by the handler's provider-status endpoint.
func (s *Service) ProviderID() string {
	if s.provider == nil {
		return ""
	}
	return s.provider.ID()
}

// normalizeSHA lowercases/trims and validates a digest.
func normalizeSHA(sha string) (string, error) {
	sha = strings.ToLower(strings.TrimSpace(sha))
	if !sha256Pattern.MatchString(sha) {
		return "", fmt.Errorf("%w: sha256 must be 64 lowercase hex chars", ErrInvalidArgument)
	}
	return sha, nil
}

// LookupVerdict returns the resolved verdict for a file digest. The
// bool is true only when a *resolved* verdict exists (a pending
// submission reports false): the data plane only acts on resolved
// dispositions. Cache is consulted first, then the repository.
func (s *Service) LookupVerdict(ctx context.Context, tenantID uuid.UUID, sha string) (Verdict, bool, error) {
	sha, err := normalizeSHA(sha)
	if err != nil {
		return Verdict{}, false, err
	}
	if v, ok := s.cache.Get(tenantID, sha); ok {
		return v, true, nil
	}
	row, err := s.repo.GetBySHA256(ctx, tenantID, sha)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return Verdict{}, false, nil
		}
		return Verdict{}, false, err
	}
	v := fromRow(row)
	if row.Status != string(StatusComplete) || v.Classification == ClassUnknown {
		// Pending or errored submission: not an actionable verdict.
		return v, false, nil
	}
	s.cache.Put(tenantID, v)
	return v, true, nil
}

// Submit detonates a file. If a resolved verdict already exists for
// the digest it is returned without re-submitting (dedup). When no
// provider is configured Submit records a pending row and returns
// ErrNoProvider so the caller can distinguish "queued" from
// "nothing will ever resolve this".
func (s *Service) Submit(ctx context.Context, sub Submission, actorID *uuid.UUID) (Verdict, error) {
	sha, err := normalizeSHA(sub.SHA256)
	if err != nil {
		return Verdict{}, err
	}
	sub.SHA256 = sha
	if sub.TenantID == uuid.Nil {
		return Verdict{}, fmt.Errorf("%w: tenant_id is required", ErrInvalidArgument)
	}

	// Collapse concurrent submissions of the same sample (same
	// tenant + digest) into a single detonation. Without this the
	// SWG fleet would submit the same unknown file to the provider
	// many times in parallel before the first verdict is persisted.
	// The shared result (verdict + error, including ErrNoProvider)
	// is delivered to every concurrent caller.
	key := sub.TenantID.String() + ":" + sha
	res, _, _ := s.flight.Do(key, func() (any, error) {
		// Detach from the winning caller's cancellation. This
		// detonation is shared by every concurrent caller for the
		// same (tenant, digest), so it must not be torn down just
		// because the caller that happened to win the flight had its
		// request cancelled or timed out — the others' contexts may
		// still be valid. WithoutCancel preserves request-scoped
		// values (the tenant RLS binding, tracing span) while dropping
		// the deadline/cancellation; the provider's own http.Client
		// timeout (30s) bounds the call; submitFlightTimeout adds a
		// defense-in-depth ceiling so even a provider that neglects
		// its own timeout cannot hang the flight indefinitely.
		fctx := context.WithoutCancel(ctx)
		fctx, cancel := context.WithTimeout(fctx, submitFlightTimeout)
		defer cancel()
		v, serr := s.submitOnce(fctx, sub, sha, actorID)
		return submitResult{verdict: v, err: serr}, nil
	})
	r := res.(submitResult)
	return r.verdict, r.err
}

// submitResult bundles the verdict and error so both can travel
// through singleflight, which only carries a single value + error
// and would otherwise drop the verdict that Submit returns alongside
// the ErrNoProvider sentinel.
type submitResult struct {
	verdict Verdict
	err     error
}

// submitOnce performs one detonation submission. It is invoked under
// the singleflight group so at most one runs per (tenant, digest).
func (s *Service) submitOnce(ctx context.Context, sub Submission, sha string, actorID *uuid.UUID) (Verdict, error) {
	// Dedup: a resolved verdict short-circuits.
	if existing, ok, lerr := s.LookupVerdict(ctx, sub.TenantID, sha); lerr == nil && ok {
		return existing, nil
	}

	if s.provider == nil {
		// Record the unknown so operators can see it was seen, but
		// signal that nothing will resolve it.
		row, perr := s.persistPending(ctx, sub.TenantID, sha, "")
		if perr != nil {
			return Verdict{}, perr
		}
		return fromRow(row), ErrNoProvider
	}

	res, err := s.provider.Submit(ctx, providers.File{
		SHA256:   sha,
		Filename: sub.Filename,
		Content:  sub.Content,
	})
	if err != nil {
		if errors.Is(err, providers.ErrProviderUnavailable) {
			row, perr := s.persistPending(ctx, sub.TenantID, sha, "")
			if perr != nil {
				return Verdict{}, perr
			}
			return fromRow(row), ErrNoProvider
		}
		return Verdict{}, fmt.Errorf("sandbox: submit: %w", err)
	}

	// Synchronous providers may resolve immediately.
	if res.Status == providers.StatusComplete {
		v := s.verdictFromPoll(sha, res.SandboxID, res.Result)
		row, perr := s.persistResolved(ctx, sub.TenantID, v)
		if perr != nil {
			return Verdict{}, perr
		}
		out := fromRow(row)
		s.cache.Put(sub.TenantID, out)
		s.logAudit(ctx, sub.TenantID, actorID, "sandbox.verdict_resolved", out)
		return out, nil
	}

	row, perr := s.persistPending(ctx, sub.TenantID, sha, res.SandboxID)
	if perr != nil {
		return Verdict{}, perr
	}
	s.logAudit(ctx, sub.TenantID, actorID, "sandbox.submitted", fromRow(row))
	return fromRow(row), nil
}

// Poll advances a pending submission by querying the provider. It is
// a no-op (returns the current verdict) when the row is already
// resolved, has no provider-side id, or no provider is configured.
func (s *Service) Poll(ctx context.Context, tenantID uuid.UUID, sha string) (Verdict, error) {
	sha, err := normalizeSHA(sha)
	if err != nil {
		return Verdict{}, err
	}
	row, err := s.repo.GetBySHA256(ctx, tenantID, sha)
	if err != nil {
		return Verdict{}, err
	}
	if row.Status != string(StatusPending) || row.SandboxID == "" || s.provider == nil {
		return fromRow(row), nil
	}
	res, err := s.provider.Poll(ctx, row.SandboxID)
	if err != nil {
		if errors.Is(err, providers.ErrProviderUnavailable) {
			return fromRow(row), nil
		}
		return Verdict{}, fmt.Errorf("sandbox: poll: %w", err)
	}
	switch res.Status {
	case providers.StatusComplete:
		v := s.verdictFromPoll(sha, row.SandboxID, res)
		updated, perr := s.persistResolved(ctx, tenantID, v)
		if perr != nil {
			return Verdict{}, perr
		}
		out := fromRow(updated)
		s.cache.Put(tenantID, out)
		return out, nil
	case providers.StatusError:
		row.Status = string(StatusError)
		updated, perr := s.repo.Upsert(ctx, tenantID, row)
		if perr != nil {
			return Verdict{}, perr
		}
		return fromRow(updated), nil
	default:
		return fromRow(row), nil
	}
}

// ListVerdicts returns recent verdicts for a tenant, newest first.
func (s *Service) ListVerdicts(ctx context.Context, tenantID uuid.UUID, limit int) ([]Verdict, error) {
	rows, err := s.repo.List(ctx, tenantID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]Verdict, 0, len(rows))
	for _, row := range rows {
		out = append(out, fromRow(row))
	}
	return out, nil
}

// GetVerdict returns the verdict for a digest regardless of status
// (pending rows included), or repository.ErrNotFound.
func (s *Service) GetVerdict(ctx context.Context, tenantID uuid.UUID, sha string) (Verdict, error) {
	sha, err := normalizeSHA(sha)
	if err != nil {
		return Verdict{}, err
	}
	row, err := s.repo.GetBySHA256(ctx, tenantID, sha)
	if err != nil {
		return Verdict{}, err
	}
	return fromRow(row), nil
}

// Disposition resolves the fail-closed allow/deny decision for a
// file digest. It is the helper the SWG malware stage consults to
// decide whether a file may be released: only a resolved, clean
// verdict yields DispositionAllow. A still-pending submission yields
// DispositionPending; an unknown/never-seen file, a provider error,
// or a suspicious/malicious/timeout verdict all yield DispositionDeny
// (treat unknown as not-clean per policy). The Verdict is returned
// alongside for audit/telemetry.
func (s *Service) Disposition(ctx context.Context, tenantID uuid.UUID, sha string) (Disposition, Verdict, error) {
	sha, err := normalizeSHA(sha)
	if err != nil {
		return DispositionDeny, Verdict{}, err
	}
	// A cached verdict is always a resolved, complete one (only
	// persistResolved populates the cache), so treat it as complete.
	if v, ok := s.cache.Get(tenantID, sha); ok {
		return dispositionFor(StatusComplete, v), v, nil
	}
	row, err := s.repo.GetBySHA256(ctx, tenantID, sha)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			// Never submitted: nothing proves the file clean. Deny,
			// but echo the (normalized) digest the caller asked about
			// so the disposition response identifies the sample rather
			// than returning a blank sha256. Carry the explicit
			// ClassUnknown ("no verdict reached") rather than the empty
			// zero value, so the rendered verdict's classification is a
			// valid enum member instead of "" — which Classification.Valid
			// rejects and which would break enum dispatch in API consumers.
			return DispositionDeny, Verdict{SHA256: sha, Classification: ClassUnknown}, nil
		}
		// Store error: cannot prove the file clean, deny fail-closed.
		return DispositionDeny, Verdict{}, err
	}
	v := fromRow(row)
	return dispositionFor(Status(row.Status), v), v, nil
}

func (s *Service) persistPending(ctx context.Context, tenantID uuid.UUID, sha, sandboxID string) (repository.SandboxVerdict, error) {
	provider := ""
	if s.provider != nil {
		provider = s.provider.ID()
	}
	return s.repo.Upsert(ctx, tenantID, repository.SandboxVerdict{
		ID:             s.newID(),
		TenantID:       tenantID,
		SHA256:         sha,
		Classification: string(ClassUnknown),
		Provider:       provider,
		SandboxID:      sandboxID,
		Status:         string(StatusPending),
	})
}

func (s *Service) persistResolved(ctx context.Context, tenantID uuid.UUID, v Verdict) (repository.SandboxVerdict, error) {
	analyzed := v.AnalyzedAt
	return s.repo.Upsert(ctx, tenantID, repository.SandboxVerdict{
		ID:             s.newID(),
		TenantID:       tenantID,
		SHA256:         v.SHA256,
		Classification: string(v.Classification),
		Confidence:     v.Confidence,
		Provider:       v.Provider,
		SandboxID:      v.SandboxID,
		Summary:        v.Summary,
		Status:         string(StatusComplete),
		AnalyzedAt:     &analyzed,
	})
}

// verdictFromPoll maps a provider poll result onto a service Verdict.
func (s *Service) verdictFromPoll(sha, sandboxID string, res providers.PollResult) Verdict {
	analyzed := res.AnalyzedAt
	if analyzed.IsZero() {
		analyzed = s.now()
	}
	provider := ""
	if s.provider != nil {
		provider = s.provider.ID()
	}
	v := Verdict{
		SHA256:         sha,
		Classification: mapClassification(res.Classification),
		Confidence:     res.Confidence,
		Provider:       provider,
		SandboxID:      sandboxID,
		Summary:        res.Summary,
		AnalyzedAt:     analyzed,
	}
	// Canonicalise the digest + provider before the verdict is
	// persisted or handed back to the data plane so cache keys and
	// stored rows use one form regardless of how the provider cased
	// them in its poll response.
	v.normalize()
	return v
}

// mapClassification converts the providers package's string enum to
// the service's typed Classification, defaulting to suspicious for an
// unrecognised value (fail toward caution).
func mapClassification(c providers.Classification) Classification {
	switch c {
	case providers.ClassClean:
		return ClassClean
	case providers.ClassMalicious:
		return ClassMalicious
	case providers.ClassTimeout:
		return ClassTimeout
	case providers.ClassSuspicious:
		return ClassSuspicious
	case providers.ClassUnknown:
		return ClassUnknown
	default:
		return ClassSuspicious
	}
}

// fromRow maps a repository row onto a service Verdict.
func fromRow(row repository.SandboxVerdict) Verdict {
	v := Verdict{
		SHA256:         row.SHA256,
		Classification: Classification(row.Classification),
		Confidence:     row.Confidence,
		Provider:       row.Provider,
		SandboxID:      row.SandboxID,
		Summary:        row.Summary,
	}
	if row.AnalyzedAt != nil {
		v.AnalyzedAt = *row.AnalyzedAt
	}
	return v
}

func (s *Service) logAudit(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, action string, v Verdict) {
	if s.audit == nil {
		return
	}
	var details json.RawMessage
	if b, err := json.Marshal(map[string]any{
		"sha256":         v.SHA256,
		"classification": string(v.Classification),
		"provider":       v.Provider,
	}); err == nil {
		details = b
	}
	entry := repository.AuditEntry{
		TenantID:     tenantID,
		ActorID:      actorID,
		Action:       action,
		ResourceType: "sandbox_verdict",
		Details:      details,
	}
	if _, err := s.audit.Append(ctx, tenantID, entry); err != nil {
		s.logger.Warn("sandbox: audit append failed",
			slog.String("action", action),
			slog.Any("error", err))
	}
}
