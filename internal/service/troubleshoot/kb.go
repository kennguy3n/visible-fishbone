package troubleshoot

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// KBService manages the knowledge base for the troubleshooting assistant.
type KBService struct {
	repo repository.KBEntryRepository
}

// NewKBService constructs a KBService.
func NewKBService(repo repository.KBEntryRepository) *KBService {
	return &KBService{repo: repo}
}

// Create adds a new KB entry.
func (s *KBService) Create(ctx context.Context, tenantID *uuid.UUID, entry KBEntry) (KBEntry, error) {
	if entry.Title == "" {
		return KBEntry{}, fmt.Errorf("title is required: %w", repository.ErrInvalidArgument)
	}
	if entry.Content == "" {
		return KBEntry{}, fmt.Errorf("content is required: %w", repository.ErrInvalidArgument)
	}
	if !validKBCategory(entry.Category) {
		return KBEntry{}, fmt.Errorf("invalid category %q: %w", entry.Category, repository.ErrInvalidArgument)
	}
	re := repository.KBEntry{
		Category: repository.KBCategory(entry.Category),
		Title:    entry.Title,
		Content:  entry.Content,
		Tags:     entry.Tags,
	}
	created, err := s.repo.Create(ctx, tenantID, re)
	if err != nil {
		return KBEntry{}, err
	}
	return fromRepoKBEntry(created), nil
}

// Get retrieves a single KB entry by ID.
func (s *KBService) Get(ctx context.Context, tenantID *uuid.UUID, id uuid.UUID) (KBEntry, error) {
	e, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return KBEntry{}, err
	}
	return fromRepoKBEntry(e), nil
}

// List returns a paginated list of KB entries, optionally filtered by category.
func (s *KBService) List(ctx context.Context, tenantID *uuid.UUID, category *string, page repository.Page) (repository.PageResult[KBEntry], error) {
	result, err := s.repo.List(ctx, tenantID, category, page)
	if err != nil {
		return repository.PageResult[KBEntry]{}, err
	}
	items := make([]KBEntry, len(result.Items))
	for i, e := range result.Items {
		items[i] = fromRepoKBEntry(e)
	}
	return repository.PageResult[KBEntry]{Items: items, NextCursor: result.NextCursor}, nil
}

// Update patches a KB entry.
func (s *KBService) Update(ctx context.Context, tenantID *uuid.UUID, id uuid.UUID, patch repository.KBEntryPatch) (KBEntry, error) {
	updated, err := s.repo.Update(ctx, tenantID, id, patch)
	if err != nil {
		return KBEntry{}, err
	}
	return fromRepoKBEntry(updated), nil
}

// Delete removes a KB entry.
func (s *KBService) Delete(ctx context.Context, tenantID *uuid.UUID, id uuid.UUID) error {
	return s.repo.Delete(ctx, tenantID, id)
}

// Search performs text search across KB entries.
func (s *KBService) Search(ctx context.Context, tenantID *uuid.UUID, query string, limit int) ([]KBEntry, error) {
	results, err := s.repo.Search(ctx, tenantID, query, limit)
	if err != nil {
		return nil, err
	}
	out := make([]KBEntry, len(results))
	for i, e := range results {
		out[i] = fromRepoKBEntry(e)
	}
	return out, nil
}

func fromRepoKBEntry(e repository.KBEntry) KBEntry {
	return KBEntry{
		ID:        e.ID,
		TenantID:  e.TenantID,
		Category:  KBCategory(e.Category),
		Title:     e.Title,
		Content:   e.Content,
		Tags:      e.Tags,
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
}

func validKBCategory(c KBCategory) bool {
	switch c {
	case KBCategoryConnectivity, KBCategoryPolicy, KBCategoryIdentity,
		KBCategoryPerformance, KBCategoryIntegration:
		return true
	}
	return false
}
