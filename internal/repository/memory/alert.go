// Package memory — alert.go is the in-memory implementation of
// repository.AlertRepository, AlertSuppressionRepository and
// AlertFeedbackRepository.
//
// The alert state machine (open -> acknowledged | resolved;
// open|acknowledged -> resolved; suppressed terminal) is enforced
// here so the memory driver and the future Postgres driver agree
// on the same rejections. Acknowledge / Resolve return the
// row unchanged on idempotent calls so the operator portal can
// re-click without producing churn.
package memory

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// -----------------------------------------------------------------------
// AlertRepository
// -----------------------------------------------------------------------

// AlertRepository is the memory-backed AlertRepository.
type AlertRepository struct{ s *Store }

// NewAlertRepository wires a fresh repo over the shared Store.
func NewAlertRepository(s *Store) *AlertRepository {
	return &AlertRepository{s: s}
}

var _ repository.AlertRepository = (*AlertRepository)(nil)

// cloneAlert returns a deep copy so callers cannot mutate the
// row underneath the store.
func cloneAlert(a repository.Alert) repository.Alert {
	out := a
	out.Evidence = cloneBytes(a.Evidence)
	if a.SuppressedBy != nil {
		v := *a.SuppressedBy
		out.SuppressedBy = &v
	}
	if a.AcknowledgedBy != nil {
		v := *a.AcknowledgedBy
		out.AcknowledgedBy = &v
	}
	if a.AcknowledgedAt != nil {
		v := *a.AcknowledgedAt
		out.AcknowledgedAt = &v
	}
	if a.ResolvedBy != nil {
		v := *a.ResolvedBy
		out.ResolvedBy = &v
	}
	if a.ResolvedAt != nil {
		v := *a.ResolvedAt
		out.ResolvedAt = &v
	}
	return out
}

// Create persists a freshly-emitted alert. The caller supplies
// a fully-populated row (the Router has already snapshot-copied
// the statistical context off the baseline at emit time).
func (r *AlertRepository) Create(ctx context.Context, tenantID uuid.UUID, a repository.Alert) (repository.Alert, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Alert{}, err
	}
	if tenantID == uuid.Nil {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if a.Kind == "" || a.Dimension == "" || a.Summary == "" {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if !a.Severity.IsValid() {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if a.State == "" {
		a.State = repository.AlertStateOpen
	}
	if !a.State.IsValid() {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if a.WindowEnd.Before(a.WindowStart) {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	if a.WindowSeconds <= 0 {
		return repository.Alert{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if a.ID == uuid.Nil {
		a.ID = uuid.New()
	}
	a.TenantID = tenantID
	now := r.s.clock()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now
	a.Evidence = cloneBytes(a.Evidence)
	r.s.alerts[a.ID] = a
	return cloneAlert(a), nil
}

// Get returns one alert by ID, scoped to tenant.
func (r *AlertRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.Alert, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Alert{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	a, ok := r.s.alerts[id]
	if !ok || a.TenantID != tenantID {
		return repository.Alert{}, repository.ErrNotFound
	}
	return cloneAlert(a), nil
}

// List enumerates alerts in CreatedAt-DESC order. Filters are
// AND-composed; an empty filter slice matches everything.
func (r *AlertRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	filter repository.AlertListFilter,
	page repository.Page,
) (repository.PageResult[repository.Alert], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.Alert]{}, err
	}
	if tenantID == uuid.Nil {
		return repository.PageResult[repository.Alert]{}, repository.ErrInvalidArgument
	}
	stateSet := map[repository.AlertState]struct{}{}
	for _, s := range filter.States {
		stateSet[s] = struct{}{}
	}
	kindSet := map[string]struct{}{}
	for _, k := range filter.Kinds {
		kindSet[k] = struct{}{}
	}
	dimSet := map[string]struct{}{}
	for _, d := range filter.Dimensions {
		dimSet[d] = struct{}{}
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.Alert, 0, len(r.s.alerts))
	for _, a := range r.s.alerts {
		if a.TenantID != tenantID {
			continue
		}
		if len(stateSet) > 0 {
			if _, ok := stateSet[a.State]; !ok {
				continue
			}
		}
		if len(kindSet) > 0 {
			if _, ok := kindSet[a.Kind]; !ok {
				continue
			}
		}
		if len(dimSet) > 0 {
			if _, ok := dimSet[a.Dimension]; !ok {
				continue
			}
		}
		all = append(all, cloneAlert(a))
	}
	sorted := sortByCreatedAtDesc(all,
		func(a repository.Alert) time.Time { return a.CreatedAt },
		func(a repository.Alert) uuid.UUID { return a.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(a repository.Alert) cursor {
		return cursor{CreatedAt: a.CreatedAt, ID: a.ID}
	}), nil
}

// Acknowledge transitions an alert from Open to Acknowledged.
// Idempotent on already-acknowledged. Returns ErrConflict
// when the alert is terminal (resolved / suppressed) —
// terminal-state rejections are a state-machine conflict,
// not malformed input, so the handler can map this to 409
// per the OpenAPI contract.
func (r *AlertRepository) Acknowledge(
	ctx context.Context,
	tenantID, id uuid.UUID,
	by *uuid.UUID,
	at time.Time,
) (repository.Alert, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Alert{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	a, ok := r.s.alerts[id]
	if !ok || a.TenantID != tenantID {
		return repository.Alert{}, repository.ErrNotFound
	}
	if a.State == repository.AlertStateAcknowledged {
		return cloneAlert(a), nil
	}
	if a.State.IsTerminal() {
		return repository.Alert{}, repository.ErrConflict
	}
	a.State = repository.AlertStateAcknowledged
	if by != nil {
		v := *by
		a.AcknowledgedBy = &v
	}
	t := at.UTC()
	a.AcknowledgedAt = &t
	a.UpdatedAt = r.s.clock()
	r.s.alerts[id] = a
	return cloneAlert(a), nil
}

// Resolve transitions an alert to Resolved. Allowed from
// Open or Acknowledged; rejected when already terminal.
func (r *AlertRepository) Resolve(
	ctx context.Context,
	tenantID, id uuid.UUID,
	by *uuid.UUID,
	at time.Time,
) (repository.Alert, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.Alert{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	a, ok := r.s.alerts[id]
	if !ok || a.TenantID != tenantID {
		return repository.Alert{}, repository.ErrNotFound
	}
	if a.State.IsTerminal() {
		if a.State == repository.AlertStateResolved {
			return cloneAlert(a), nil
		}
		return repository.Alert{}, repository.ErrConflict
	}
	a.State = repository.AlertStateResolved
	if by != nil {
		v := *by
		a.ResolvedBy = &v
	}
	t := at.UTC()
	a.ResolvedAt = &t
	a.UpdatedAt = r.s.clock()
	r.s.alerts[id] = a
	return cloneAlert(a), nil
}

// -----------------------------------------------------------------------
// AlertSuppressionRepository
// -----------------------------------------------------------------------

// AlertSuppressionRepository is the memory-backed
// AlertSuppressionRepository.
type AlertSuppressionRepository struct{ s *Store }

// NewAlertSuppressionRepository wires a fresh repo.
func NewAlertSuppressionRepository(s *Store) *AlertSuppressionRepository {
	return &AlertSuppressionRepository{s: s}
}

var _ repository.AlertSuppressionRepository = (*AlertSuppressionRepository)(nil)

func cloneSuppression(s repository.AlertSuppression) repository.AlertSuppression {
	out := s
	if s.Kind != nil {
		v := *s.Kind
		out.Kind = &v
	}
	if s.Dimension != nil {
		v := *s.Dimension
		out.Dimension = &v
	}
	if s.CreatedBy != nil {
		v := *s.CreatedBy
		out.CreatedBy = &v
	}
	if s.ExpiresAt != nil {
		v := *s.ExpiresAt
		out.ExpiresAt = &v
	}
	return out
}

// Create persists a new suppression rule. Mirrors the
// alert_suppressions_scope_nonempty CHECK: at least one of
// Kind, Dimension must be set.
func (r *AlertSuppressionRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	s repository.AlertSuppression,
) (repository.AlertSuppression, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AlertSuppression{}, err
	}
	if tenantID == uuid.Nil {
		return repository.AlertSuppression{}, repository.ErrInvalidArgument
	}
	if s.Kind == nil && s.Dimension == nil {
		return repository.AlertSuppression{}, repository.ErrInvalidArgument
	}
	if s.Reason == "" {
		return repository.AlertSuppression{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	s.TenantID = tenantID
	if s.CreatedAt.IsZero() {
		s.CreatedAt = r.s.clock()
	}
	r.s.alertSuppressions[s.ID] = s
	return cloneSuppression(s), nil
}

// Get returns one suppression by ID.
func (r *AlertSuppressionRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.AlertSuppression, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AlertSuppression{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	s, ok := r.s.alertSuppressions[id]
	if !ok || s.TenantID != tenantID {
		return repository.AlertSuppression{}, repository.ErrNotFound
	}
	return cloneSuppression(s), nil
}

// List enumerates suppressions in CreatedAt-DESC order.
func (r *AlertSuppressionRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.AlertSuppression], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.AlertSuppression]{}, err
	}
	if tenantID == uuid.Nil {
		return repository.PageResult[repository.AlertSuppression]{}, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	all := make([]repository.AlertSuppression, 0, len(r.s.alertSuppressions))
	for _, s := range r.s.alertSuppressions {
		if s.TenantID != tenantID {
			continue
		}
		all = append(all, cloneSuppression(s))
	}
	sorted := sortByCreatedAtDesc(all,
		func(s repository.AlertSuppression) time.Time { return s.CreatedAt },
		func(s repository.AlertSuppression) uuid.UUID { return s.ID },
		page.Normalize().Order,
	)
	return paginate(sorted, page, func(s repository.AlertSuppression) cursor {
		return cursor{CreatedAt: s.CreatedAt, ID: s.ID}
	}), nil
}

// ListActive returns every currently-active suppression for a
// tenant. Used on every alert.Router.Emit; the router caches
// the slice for a short TTL.
func (r *AlertSuppressionRepository) ListActive(
	ctx context.Context,
	tenantID uuid.UUID,
	now time.Time,
) ([]repository.AlertSuppression, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if tenantID == uuid.Nil {
		return nil, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.AlertSuppression, 0, len(r.s.alertSuppressions))
	for _, s := range r.s.alertSuppressions {
		if s.TenantID != tenantID {
			continue
		}
		if !s.IsActive(now) {
			continue
		}
		out = append(out, cloneSuppression(s))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID.String() > out[j].ID.String()
	})
	return out, nil
}

// Delete removes a suppression rule.
func (r *AlertSuppressionRepository) Delete(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	s, ok := r.s.alertSuppressions[id]
	if !ok || s.TenantID != tenantID {
		return repository.ErrNotFound
	}
	delete(r.s.alertSuppressions, id)
	return nil
}

// -----------------------------------------------------------------------
// AlertFeedbackRepository
// -----------------------------------------------------------------------

// AlertFeedbackRepository is the memory-backed
// AlertFeedbackRepository.
type AlertFeedbackRepository struct{ s *Store }

// NewAlertFeedbackRepository wires a fresh repo.
func NewAlertFeedbackRepository(s *Store) *AlertFeedbackRepository {
	return &AlertFeedbackRepository{s: s}
}

var _ repository.AlertFeedbackRepository = (*AlertFeedbackRepository)(nil)

func cloneFeedback(f repository.AlertFeedback) repository.AlertFeedback {
	out := f
	if f.CreatedBy != nil {
		v := *f.CreatedBy
		out.CreatedBy = &v
	}
	return out
}

// Create persists feedback on an alert. Returns ErrConflict when
// feedback already exists for the alert (mirrors the UNIQUE
// constraint on alert_id).
func (r *AlertFeedbackRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	f repository.AlertFeedback,
) (repository.AlertFeedback, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AlertFeedback{}, err
	}
	if tenantID == uuid.Nil || f.AlertID == uuid.Nil {
		return repository.AlertFeedback{}, repository.ErrInvalidArgument
	}
	if !f.Decision.IsValid() {
		return repository.AlertFeedback{}, repository.ErrInvalidArgument
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	// AlertID UNIQUE constraint.
	for _, existing := range r.s.alertFeedback {
		if existing.TenantID == tenantID && existing.AlertID == f.AlertID {
			return repository.AlertFeedback{}, repository.ErrConflict
		}
	}
	// Verify the alert exists and belongs to the tenant (FK).
	a, ok := r.s.alerts[f.AlertID]
	if !ok || a.TenantID != tenantID {
		return repository.AlertFeedback{}, repository.ErrNotFound
	}
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	f.TenantID = tenantID
	if f.CreatedAt.IsZero() {
		f.CreatedAt = r.s.clock()
	}
	r.s.alertFeedback[f.ID] = f
	return cloneFeedback(f), nil
}

// GetForAlert returns the feedback for one alert.
func (r *AlertFeedbackRepository) GetForAlert(
	ctx context.Context,
	tenantID, alertID uuid.UUID,
) (repository.AlertFeedback, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.AlertFeedback{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	for _, f := range r.s.alertFeedback {
		if f.TenantID == tenantID && f.AlertID == alertID {
			return cloneFeedback(f), nil
		}
	}
	return repository.AlertFeedback{}, repository.ErrNotFound
}

// Delete removes the feedback for an alert.
func (r *AlertFeedbackRepository) Delete(
	ctx context.Context,
	tenantID, alertID uuid.UUID,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	for id, f := range r.s.alertFeedback {
		if f.TenantID == tenantID && f.AlertID == alertID {
			delete(r.s.alertFeedback, id)
			return nil
		}
	}
	return repository.ErrNotFound
}

// ListByDimension returns every feedback row for alerts in the
// supplied (dimension, windowSeconds) tuple, ordered by
// CreatedAt DESC. Implemented by joining feedback rows to alerts
// on AlertID and filtering by the alert's Dimension + (when
// windowSeconds > 0) WindowSeconds. Used by alert.Feedback.
// TuneDimension to compute the per-(tenant, dimension, window)
// FP rate.
//
// `windowSeconds <= 0` is the documented sentinel for "no window
// filter" — see the interface doc.
func (r *AlertFeedbackRepository) ListByDimension(
	ctx context.Context,
	tenantID uuid.UUID,
	dimension string,
	windowSeconds int,
	since time.Time,
) ([]repository.AlertFeedback, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if tenantID == uuid.Nil || dimension == "" {
		return nil, repository.ErrInvalidArgument
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	out := make([]repository.AlertFeedback, 0)
	for _, f := range r.s.alertFeedback {
		if f.TenantID != tenantID {
			continue
		}
		if !since.IsZero() && f.CreatedAt.Before(since) {
			continue
		}
		a, ok := r.s.alerts[f.AlertID]
		if !ok || a.Dimension != dimension {
			continue
		}
		if windowSeconds > 0 && a.WindowSeconds != windowSeconds {
			continue
		}
		out = append(out, cloneFeedback(f))
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID.String() > out[j].ID.String()
	})
	return out, nil
}
