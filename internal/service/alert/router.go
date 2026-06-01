// Package alert implements the alert routing + suppression +
// feedback layer documented in PROPOSAL §3 and the migration
// 013_alerts.sql.
//
// The Router is the canonical write path for any alert: it
// applies the tenant's active suppression rules, persists the
// alert in the resolved state, and (optionally) publishes a
// fan-out notification on NATS so the operator portal sees the
// alert in near-real time.
//
// The Suppression service owns CRUD over suppression rules.
// Suppression rules are operator-defined (kind, dimension)
// matchers that automatically push matching alerts into the
// terminal AlertStateSuppressed state at emit time, with an
// audit trail (Reason + CreatedBy + ExpiresAt) so future
// operators can see why a class of alerts is being filtered.
package alert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Publisher is the slice of the nats.Publisher API the Router
// uses. Defining the interface here lets tests stub the
// publisher without dragging in NATS / JetStream.
type Publisher interface {
	// Publish sends data on subject. The Router uses the
	// `sng.<tenant>.alerts.<kind>.<severity>` convention so
	// the operator portal can subscribe per-tenant + by
	// severity without filtering client-side.
	Publish(ctx context.Context, subject string, data []byte) error
}

// suppressionCacheTTL bounds how stale the Router's cached
// active-suppression slice can be. Short enough that an operator
// adding a suppression rule sees it take effect within a few
// seconds; long enough that the hot emit path doesn't hammer
// the suppression repo on every alert during a storm.
const suppressionCacheTTL = 5 * time.Second

// Router is the central alert emit/list/state-machine surface.
type Router struct {
	alerts        repository.AlertRepository
	suppressions  repository.AlertSuppressionRepository
	pub           Publisher
	logger        *slog.Logger
	subjectPrefix string
	now           func() time.Time

	cacheMu sync.RWMutex
	cache   map[uuid.UUID]suppressionCacheEntry
}

type suppressionCacheEntry struct {
	rules   []repository.AlertSuppression
	expires time.Time
}

// Options configure the Router.
type Options struct {
	// SubjectPrefix is the NATS subject prefix used for
	// alert fan-out. Defaults to "sng".
	SubjectPrefix string
	// Logger optionally receives operational events. When
	// nil, slog.Default() is used.
	Logger *slog.Logger
	// Clock overrides time.Now.UTC; used by tests.
	Clock func() time.Time
}

func (o Options) fillDefaults() Options {
	if o.SubjectPrefix == "" {
		o.SubjectPrefix = "sng"
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.Clock == nil {
		o.Clock = func() time.Time { return time.Now().UTC() }
	}
	return o
}

// NewRouter wires a Router. pub may be nil — the Router will
// persist the alert but skip NATS publication, which is the
// expected configuration in unit tests + air-gapped deployments
// where the operator portal polls the REST list endpoint
// instead.
func NewRouter(
	alerts repository.AlertRepository,
	suppressions repository.AlertSuppressionRepository,
	pub Publisher,
	opts Options,
) *Router {
	opts = opts.fillDefaults()
	return &Router{
		alerts:        alerts,
		suppressions:  suppressions,
		pub:           pub,
		logger:        opts.Logger,
		subjectPrefix: opts.SubjectPrefix,
		now:           opts.Clock,
		cache:         make(map[uuid.UUID]suppressionCacheEntry),
	}
}

// Emit is the canonical write path for any alert. It loads the
// tenant's active suppressions (cached for suppressionCacheTTL),
// stamps the alert's state to AlertStateSuppressed if any rule
// matches, persists the alert, and publishes a NATS
// notification on the per-(tenant, kind, severity) subject.
//
// Emit returns the persisted Alert with its assigned ID,
// CreatedAt, and final State. The caller can rely on the
// returned State being authoritative — a matched suppression
// will surface as State=AlertStateSuppressed and
// SuppressedBy=<rule_id>.
func (r *Router) Emit(
	ctx context.Context,
	tenantID uuid.UUID,
	a repository.Alert,
) (repository.Alert, error) {
	if tenantID == uuid.Nil {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	// Match suppressions before persistence so the Alert is
	// born in the terminal state — no operator ever sees a
	// suppressed alert as "open then immediately suppressed".
	rules, err := r.activeSuppressions(ctx, tenantID)
	if err != nil {
		return repository.Alert{}, fmt.Errorf("alert emit suppressions: %w", err)
	}
	now := r.now()
	for _, rule := range rules {
		if !rule.IsActive(now) {
			continue
		}
		if rule.Matches(a.Kind, a.Dimension) {
			ruleID := rule.ID
			a.State = repository.AlertStateSuppressed
			a.SuppressedBy = &ruleID
			break
		}
	}
	if a.State == "" {
		a.State = repository.AlertStateOpen
	}

	saved, err := r.alerts.Create(ctx, tenantID, a)
	if err != nil {
		return repository.Alert{}, fmt.Errorf("alert emit persist: %w", err)
	}

	// Publish even suppressed alerts: the portal can show a
	// "muted" stream and the suppression decision is itself
	// an auditable event.
	if r.pub != nil {
		subj := fmt.Sprintf("%s.%s.alerts.%s.%s",
			r.subjectPrefix, tenantID.String(), saved.Kind, saved.Severity,
		)
		payload, perr := json.Marshal(saved)
		if perr == nil {
			if perr := r.pub.Publish(ctx, subj, payload); perr != nil {
				// Publishing is best-effort: a NATS hiccup
				// must NOT roll back the persisted alert.
				r.logger.WarnContext(ctx, "alert publish failed",
					"alert_id", saved.ID, "subject", subj, "err", perr)
			}
		}
	}
	return saved, nil
}

// activeSuppressions returns the active suppression rules for
// tenantID, possibly serving from a short-lived cache. The
// cache is invalidated by ttl + by direct CreateSuppression /
// DeleteSuppression calls (those use the same Router instance
// to mutate, which clears the per-tenant entry).
//
// The slice returned to callers is a defensive copy — the
// cache retains the canonical slice and callers never see a
// pointer to it. Without this, a caller that mutated the
// returned slice (e.g. filtered in-place during Emit) would
// corrupt the cached entry for every subsequent caller, which
// is the kind of bug that surfaces under hot-path load and
// is excruciating to track down. The cost is one allocation
// per Emit; the suppression list is typically a handful of
// rules per tenant, so the bytes are trivial.
func (r *Router) activeSuppressions(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.AlertSuppression, error) {
	now := r.now()
	r.cacheMu.RLock()
	if entry, ok := r.cache[tenantID]; ok && entry.expires.After(now) {
		out := slices.Clone(entry.rules)
		r.cacheMu.RUnlock()
		return out, nil
	}
	r.cacheMu.RUnlock()
	fresh, err := r.suppressions.ListActive(ctx, tenantID, now)
	if err != nil {
		return nil, err
	}
	// Cache the canonical slice; hand out a copy.
	r.cacheMu.Lock()
	r.cache[tenantID] = suppressionCacheEntry{
		rules:   fresh,
		expires: now.Add(suppressionCacheTTL),
	}
	r.cacheMu.Unlock()
	return slices.Clone(fresh), nil
}

// InvalidateSuppressionCache drops the cached suppression rules
// for tenantID. Called from CreateSuppression /
// DeleteSuppression after a successful repository mutation so
// the next Emit picks up the change without waiting for the
// TTL.
func (r *Router) InvalidateSuppressionCache(tenantID uuid.UUID) {
	r.cacheMu.Lock()
	delete(r.cache, tenantID)
	r.cacheMu.Unlock()
}

// Acknowledge transitions an alert to AlertStateAcknowledged.
// Pass-through to the repository, but additionally publishes a
// `<prefix>.<tenant>.alerts.acknowledged` event so the portal
// can react.
func (r *Router) Acknowledge(
	ctx context.Context,
	tenantID, id uuid.UUID,
	by *uuid.UUID,
) (repository.Alert, error) {
	now := r.now()
	saved, err := r.alerts.Acknowledge(ctx, tenantID, id, by, now)
	if err != nil {
		return repository.Alert{}, err
	}
	r.publishLifecycle(ctx, tenantID, "acknowledged", saved)
	return saved, nil
}

// Resolve transitions an alert to AlertStateResolved.
func (r *Router) Resolve(
	ctx context.Context,
	tenantID, id uuid.UUID,
	by *uuid.UUID,
) (repository.Alert, error) {
	now := r.now()
	saved, err := r.alerts.Resolve(ctx, tenantID, id, by, now)
	if err != nil {
		return repository.Alert{}, err
	}
	r.publishLifecycle(ctx, tenantID, "resolved", saved)
	return saved, nil
}

func (r *Router) publishLifecycle(
	ctx context.Context,
	tenantID uuid.UUID,
	event string,
	a repository.Alert,
) {
	if r.pub == nil {
		return
	}
	subj := fmt.Sprintf("%s.%s.alerts.%s", r.subjectPrefix, tenantID.String(), event)
	payload, err := json.Marshal(a)
	if err != nil {
		return
	}
	if err := r.pub.Publish(ctx, subj, payload); err != nil {
		r.logger.WarnContext(ctx, "alert lifecycle publish failed",
			"alert_id", a.ID, "subject", subj, "err", err)
	}
}

// List is a thin pass-through to the repository for the REST
// handler.
func (r *Router) List(
	ctx context.Context,
	tenantID uuid.UUID,
	filter repository.AlertListFilter,
	page repository.Page,
) (repository.PageResult[repository.Alert], error) {
	return r.alerts.List(ctx, tenantID, filter, page)
}

// Get is a thin pass-through.
func (r *Router) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.Alert, error) {
	return r.alerts.Get(ctx, tenantID, id)
}

// CreateSuppression persists a new suppression rule and
// invalidates the cache. The returned rule includes the
// assigned ID + CreatedAt.
func (r *Router) CreateSuppression(
	ctx context.Context,
	tenantID uuid.UUID,
	s repository.AlertSuppression,
) (repository.AlertSuppression, error) {
	saved, err := r.suppressions.Create(ctx, tenantID, s)
	if err != nil {
		return repository.AlertSuppression{}, err
	}
	r.InvalidateSuppressionCache(tenantID)
	return saved, nil
}

// DeleteSuppression removes a rule + invalidates the cache.
func (r *Router) DeleteSuppression(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	if err := r.suppressions.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	r.InvalidateSuppressionCache(tenantID)
	return nil
}

// ListSuppressions is a thin pass-through.
func (r *Router) ListSuppressions(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.AlertSuppression], error) {
	return r.suppressions.List(ctx, tenantID, page)
}

// GetSuppression is a thin pass-through.
func (r *Router) GetSuppression(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.AlertSuppression, error) {
	return r.suppressions.Get(ctx, tenantID, id)
}

// ErrEmit is a sentinel returned by Emit when the configured
// repository surfaces a non-retryable persistence error.
var ErrEmit = errors.New("alert.Router: emit failed")
