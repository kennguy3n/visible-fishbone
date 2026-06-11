package memory

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

// defaultDLPReviewListLimit bounds List when the caller passes a
// non-positive limit, mirroring the Postgres implementation.
const defaultDLPReviewListLimit = 100

// DLPReviewRepository is the memory-backed implementation of
// dlpreview.Repository. Tenant isolation is enforced by filtering on
// tenant_id, mirroring the Postgres RLS policy in migration 060.
//
// Unlike the other memory repositories it does NOT hang off the shared
// Store: the DLP review queue is a self-contained feature whose table is
// introduced by migration 060, and keeping its state local avoids
// touching the shared Store struct. Construct one with
// [NewDLPReviewRepository] and share it like any other repo in a test.
type DLPReviewRepository struct {
	mu   sync.RWMutex
	rows map[uuid.UUID]dlpreview.ReviewEvent
}

// NewDLPReviewRepository returns an empty in-memory review queue.
func NewDLPReviewRepository() *DLPReviewRepository {
	return &DLPReviewRepository{rows: make(map[uuid.UUID]dlpreview.ReviewEvent)}
}

var _ dlpreview.Repository = (*DLPReviewRepository)(nil)

// Enqueue stores a copy of ev. It mirrors the Postgres column checks so
// a value Postgres would reject is rejected here too.
func (r *DLPReviewRepository) Enqueue(ctx context.Context, tenantID uuid.UUID, ev dlpreview.ReviewEvent) (dlpreview.ReviewEvent, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return dlpreview.ReviewEvent{}, err
	}
	if tenantID == uuid.Nil || ev.ID == uuid.Nil || ev.TenantID != tenantID {
		return dlpreview.ReviewEvent{}, repository.ErrInvalidArgument
	}
	if ev.Signal == "" || ev.DestinationApp == "" || !ev.Severity.Valid() {
		return dlpreview.ReviewEvent{}, repository.ErrInvalidArgument
	}
	if ev.Confidence < 0 || ev.Confidence > 1 {
		return dlpreview.ReviewEvent{}, repository.ErrInvalidArgument
	}
	if ev.State != dlpreview.StatePending {
		// A freshly enqueued event is always pending; a terminal state
		// here would also violate the decision-consistency CHECK.
		return dlpreview.ReviewEvent{}, repository.ErrInvalidArgument
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.rows[ev.ID]; exists {
		return dlpreview.ReviewEvent{}, repository.ErrConflict
	}
	stored := cloneReviewEvent(ev)
	// Pending rows carry no decision (the Postgres CHECK enforces this).
	stored.DecidedAt = nil
	stored.DecidedBy = nil
	r.rows[stored.ID] = stored
	return cloneReviewEvent(stored), nil
}

// Get returns the event by id within the tenant, or ErrNotFound.
func (r *DLPReviewRepository) Get(ctx context.Context, tenantID, id uuid.UUID) (dlpreview.ReviewEvent, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return dlpreview.ReviewEvent{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ev, ok := r.rows[id]
	if !ok || ev.TenantID != tenantID {
		return dlpreview.ReviewEvent{}, repository.ErrNotFound
	}
	return cloneReviewEvent(ev), nil
}

// List returns the tenant's events, newest first, subject to f.
func (r *DLPReviewRepository) List(ctx context.Context, tenantID uuid.UUID, f dlpreview.ListFilter) ([]dlpreview.ReviewEvent, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultDLPReviewListLimit
	}

	r.mu.RLock()
	out := make([]dlpreview.ReviewEvent, 0)
	for _, ev := range r.rows {
		if ev.TenantID != tenantID {
			continue
		}
		if f.State != nil && ev.State != *f.State {
			continue
		}
		out = append(out, cloneReviewEvent(ev))
	}
	r.mu.RUnlock()

	sortReviewEventsNewestFirst(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// Transition moves a pending event to the terminal state `to`. It
// returns ErrNotFound if the event is not the tenant's and ErrConflict
// if it is already terminal, so a decision is never overwritten.
func (r *DLPReviewRepository) Transition(ctx context.Context, tenantID, id uuid.UUID, to dlpreview.ReviewState, decidedBy string, decidedAt time.Time) (dlpreview.ReviewEvent, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return dlpreview.ReviewEvent{}, err
	}
	if !to.IsTerminal() || decidedBy == "" {
		return dlpreview.ReviewEvent{}, repository.ErrInvalidArgument
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	ev, ok := r.rows[id]
	if !ok || ev.TenantID != tenantID {
		return dlpreview.ReviewEvent{}, repository.ErrNotFound
	}
	if ev.State != dlpreview.StatePending {
		return dlpreview.ReviewEvent{}, repository.ErrConflict
	}
	at := decidedAt
	by := decidedBy
	ev.State = to
	ev.DecidedAt = &at
	ev.DecidedBy = &by
	r.rows[id] = cloneReviewEvent(ev)
	return cloneReviewEvent(ev), nil
}

// Summary aggregates the tenant's events created at/after `since`.
func (r *DLPReviewRepository) Summary(ctx context.Context, tenantID uuid.UUID, since time.Time) (dlpreview.Summary, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return dlpreview.Summary{}, err
	}
	sum := dlpreview.Summary{
		ByState:      make(map[dlpreview.ReviewState]int),
		BySeverity:   make(map[dlpreview.Severity]int),
		PendingByApp: make(map[string]int),
	}

	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ev := range r.rows {
		if ev.TenantID != tenantID {
			continue
		}
		// created_at >= since (inclusive lower bound), matching the
		// Postgres `created_at >= $since` predicate.
		if ev.CreatedAt.Before(since) {
			continue
		}
		sum.Total++
		sum.ByState[ev.State]++
		sum.BySeverity[ev.Severity]++
		if ev.State == dlpreview.StatePending {
			sum.Pending++
			sum.PendingByApp[ev.DestinationApp]++
		}
	}
	return sum, nil
}

// sortReviewEventsNewestFirst orders by created_at descending, breaking
// ties on id so the order is deterministic (mirrors the Postgres
// `ORDER BY created_at DESC, id`).
func sortReviewEventsNewestFirst(evs []dlpreview.ReviewEvent) {
	sort.Slice(evs, func(i, j int) bool {
		if !evs[i].CreatedAt.Equal(evs[j].CreatedAt) {
			return evs[i].CreatedAt.After(evs[j].CreatedAt)
		}
		return evs[i].ID.String() < evs[j].ID.String()
	})
}

// cloneReviewEvent returns a deep copy so callers cannot mutate stored
// state through the returned value's slice or pointer fields.
func cloneReviewEvent(ev dlpreview.ReviewEvent) dlpreview.ReviewEvent {
	out := ev
	if ev.Findings != nil {
		out.Findings = make([]dlpreview.FindingAggregate, len(ev.Findings))
		copy(out.Findings, ev.Findings)
	}
	if ev.DecidedAt != nil {
		at := *ev.DecidedAt
		out.DecidedAt = &at
	}
	if ev.DecidedBy != nil {
		by := *ev.DecidedBy
		out.DecidedBy = &by
	}
	return out
}
