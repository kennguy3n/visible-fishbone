package memory

import (
	"context"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// --- KBEntryRepository ----------------------------------------------------

// KBEntryRepository is the memory-backed KB entry store.
type KBEntryRepository struct{ s *Store }

// NewKBEntryRepository binds a Store.
func NewKBEntryRepository(s *Store) *KBEntryRepository {
	return &KBEntryRepository{s: s}
}

var _ repository.KBEntryRepository = (*KBEntryRepository)(nil)

func (r *KBEntryRepository) Create(
	ctx context.Context,
	tenantID *uuid.UUID,
	e repository.KBEntry,
) (repository.KBEntry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.KBEntry{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if e.Title == "" || e.Content == "" {
		return repository.KBEntry{}, repository.ErrInvalidArgument
	}
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	e.TenantID = tenantID
	now := r.s.clock()
	e.CreatedAt = now
	e.UpdatedAt = now
	if e.Tags == nil {
		e.Tags = []string{}
	}
	r.s.kbEntries[e.ID] = e
	return cloneKBEntry(e), nil
}

func (r *KBEntryRepository) Get(
	ctx context.Context,
	tenantID *uuid.UUID,
	id uuid.UUID,
) (repository.KBEntry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.KBEntry{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	e, ok := r.s.kbEntries[id]
	if !ok {
		return repository.KBEntry{}, repository.ErrNotFound
	}
	if !kbEntryVisible(e, tenantID) {
		return repository.KBEntry{}, repository.ErrNotFound
	}
	return cloneKBEntry(e), nil
}

func (r *KBEntryRepository) List(
	ctx context.Context,
	tenantID *uuid.UUID,
	category *string,
	page repository.Page,
) (repository.PageResult[repository.KBEntry], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.KBEntry]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var items []repository.KBEntry
	for _, e := range r.s.kbEntries {
		if !kbEntryVisible(e, tenantID) {
			continue
		}
		if category != nil && string(e.Category) != *category {
			continue
		}
		items = append(items, cloneKBEntry(e))
	}
	sort.Slice(items, func(i, j int) bool {
		return orderBefore(
			cursor{CreatedAt: items[i].CreatedAt, ID: items[i].ID},
			cursor{CreatedAt: items[j].CreatedAt, ID: items[j].ID},
			page.Normalize().Order,
		)
	})
	return paginate(items, page, func(e repository.KBEntry) cursor {
		return cursor{CreatedAt: e.CreatedAt, ID: e.ID}
	}), nil
}

func (r *KBEntryRepository) Update(
	ctx context.Context,
	tenantID *uuid.UUID,
	id uuid.UUID,
	patch repository.KBEntryPatch,
) (repository.KBEntry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.KBEntry{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	e, ok := r.s.kbEntries[id]
	if !ok {
		return repository.KBEntry{}, repository.ErrNotFound
	}
	if !kbEntryOwned(e, tenantID) {
		return repository.KBEntry{}, repository.ErrNotFound
	}
	if patch.Category != nil {
		e.Category = *patch.Category
	}
	if patch.Title != nil {
		e.Title = *patch.Title
	}
	if patch.Content != nil {
		e.Content = *patch.Content
	}
	if patch.Tags != nil {
		e.Tags = cloneStringSlice(*patch.Tags)
	}
	e.UpdatedAt = r.s.clock()
	r.s.kbEntries[id] = e
	return cloneKBEntry(e), nil
}

func (r *KBEntryRepository) Delete(
	ctx context.Context,
	tenantID *uuid.UUID,
	id uuid.UUID,
) error {
	if err := errCtxIfNeeded(ctx); err != nil {
		return err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	e, ok := r.s.kbEntries[id]
	if !ok {
		return repository.ErrNotFound
	}
	if !kbEntryOwned(e, tenantID) {
		return repository.ErrNotFound
	}
	delete(r.s.kbEntries, id)
	return nil
}

func (r *KBEntryRepository) Search(
	ctx context.Context,
	tenantID *uuid.UUID,
	query string,
	limit int,
) ([]repository.KBEntry, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 10
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	q := strings.ToLower(query)
	var items []repository.KBEntry
	for _, e := range r.s.kbEntries {
		if !kbEntryVisible(e, tenantID) {
			continue
		}
		if strings.Contains(strings.ToLower(e.Title), q) ||
			strings.Contains(strings.ToLower(e.Content), q) ||
			tagsContain(e.Tags, q) {
			items = append(items, cloneKBEntry(e))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

// kbEntryVisible checks if the entry should be visible to the tenant.
// Global entries (tenant_id = nil) are visible to everyone.
func kbEntryVisible(e repository.KBEntry, tenantID *uuid.UUID) bool {
	if e.TenantID == nil {
		return true
	}
	if tenantID == nil {
		return true
	}
	return *e.TenantID == *tenantID
}

// kbEntryOwned checks if the entry is owned by the given tenant for
// mutation purposes.
func kbEntryOwned(e repository.KBEntry, tenantID *uuid.UUID) bool {
	if e.TenantID == nil && tenantID == nil {
		return true
	}
	if e.TenantID == nil || tenantID == nil {
		return e.TenantID == nil && tenantID == nil
	}
	return *e.TenantID == *tenantID
}

func tagsContain(tags []string, q string) bool {
	for _, t := range tags {
		if strings.Contains(strings.ToLower(t), q) {
			return true
		}
	}
	return false
}

func cloneKBEntry(e repository.KBEntry) repository.KBEntry {
	out := e
	out.Tags = cloneStringSlice(e.Tags)
	if e.TenantID != nil {
		tid := *e.TenantID
		out.TenantID = &tid
	}
	return out
}

func cloneStringSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

// --- TroubleshootSessionRepository ----------------------------------------

// TroubleshootSessionRepository is the memory-backed session store.
type TroubleshootSessionRepository struct{ s *Store }

// NewTroubleshootSessionRepository binds a Store.
func NewTroubleshootSessionRepository(s *Store) *TroubleshootSessionRepository {
	return &TroubleshootSessionRepository{s: s}
}

var _ repository.TroubleshootSessionRepository = (*TroubleshootSessionRepository)(nil)

func (r *TroubleshootSessionRepository) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	s repository.TroubleshootSession,
) (repository.TroubleshootSession, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TroubleshootSession{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	if tenantID == uuid.Nil {
		return repository.TroubleshootSession{}, repository.ErrInvalidArgument
	}
	if s.Issue == "" {
		return repository.TroubleshootSession{}, repository.ErrInvalidArgument
	}
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	s.TenantID = tenantID
	now := r.s.clock()
	s.CreatedAt = now
	s.UpdatedAt = now
	if s.Status == "" {
		s.Status = repository.TroubleshootSessionActive
	}
	if s.Messages == nil {
		s.Messages = []byte("[]")
	}
	if s.DiagnosticResults == nil {
		s.DiagnosticResults = []byte("[]")
	}
	r.s.troubleshootSessions[s.ID] = s
	return cloneTroubleshootSession(s), nil
}

func (r *TroubleshootSessionRepository) Get(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.TroubleshootSession, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TroubleshootSession{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	s, ok := r.s.troubleshootSessions[id]
	if !ok || s.TenantID != tenantID {
		return repository.TroubleshootSession{}, repository.ErrNotFound
	}
	return cloneTroubleshootSession(s), nil
}

func (r *TroubleshootSessionRepository) Update(
	ctx context.Context,
	tenantID, id uuid.UUID,
	s repository.TroubleshootSession,
) (repository.TroubleshootSession, error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.TroubleshootSession{}, err
	}
	r.s.mu.Lock()
	defer r.s.mu.Unlock()
	existing, ok := r.s.troubleshootSessions[id]
	if !ok || existing.TenantID != tenantID {
		return repository.TroubleshootSession{}, repository.ErrNotFound
	}
	s.ID = id
	s.TenantID = tenantID
	s.CreatedAt = existing.CreatedAt
	s.UpdatedAt = r.s.clock()
	r.s.troubleshootSessions[id] = s
	return cloneTroubleshootSession(s), nil
}

func (r *TroubleshootSessionRepository) List(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.TroubleshootSession], error) {
	if err := errCtxIfNeeded(ctx); err != nil {
		return repository.PageResult[repository.TroubleshootSession]{}, err
	}
	r.s.mu.RLock()
	defer r.s.mu.RUnlock()
	var items []repository.TroubleshootSession
	for _, s := range r.s.troubleshootSessions {
		if s.TenantID == tenantID {
			items = append(items, cloneTroubleshootSession(s))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return orderBefore(
			cursor{CreatedAt: items[i].CreatedAt, ID: items[i].ID},
			cursor{CreatedAt: items[j].CreatedAt, ID: items[j].ID},
			page.Normalize().Order,
		)
	})
	return paginate(items, page, func(s repository.TroubleshootSession) cursor {
		return cursor{CreatedAt: s.CreatedAt, ID: s.ID}
	}), nil
}

func cloneTroubleshootSession(s repository.TroubleshootSession) repository.TroubleshootSession {
	out := s
	out.Messages = cloneJSON(s.Messages)
	out.DiagnosticResults = cloneJSON(s.DiagnosticResults)
	return out
}
