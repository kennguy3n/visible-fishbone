package casb

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// repoInlineRuleStore adapts a repository.InlineCASBRuleRepository
// (the persistence layer, which knows nothing about this package's
// typed enums) to the service-layer InlineRuleStore port. It maps
// between the strongly-typed InlineRule and the repository's plain
// projection, marshalling Conditions to/from the JSONB column.
//
// This adapter — not a direct repository import — is what keeps the
// repository package free of any dependency on this service
// package: the conversion lives here, on the service side of the
// boundary.
type repoInlineRuleStore struct {
	repo repository.InlineCASBRuleRepository
}

var _ InlineRuleStore = (*repoInlineRuleStore)(nil)

// NewRepositoryInlineRuleStore wraps a repository-backed
// InlineCASBRuleRepository as an InlineRuleStore. Production callers
// pass store.NewInlineCASBRuleRepository(); tests that need real
// persistence semantics can pass a memory-backed repository.
func NewRepositoryInlineRuleStore(repo repository.InlineCASBRuleRepository) InlineRuleStore {
	return &repoInlineRuleStore{repo: repo}
}

func (s *repoInlineRuleStore) List(ctx context.Context, tenantID uuid.UUID) ([]InlineRule, error) {
	rows, err := s.repo.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]InlineRule, 0, len(rows))
	for _, row := range rows {
		r, cerr := fromRepoInlineRule(row)
		if cerr != nil {
			return nil, cerr
		}
		out = append(out, r)
	}
	return out, nil
}

func (s *repoInlineRuleStore) Get(ctx context.Context, tenantID, id uuid.UUID) (InlineRule, error) {
	row, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return InlineRule{}, err
	}
	return fromRepoInlineRule(row)
}

func (s *repoInlineRuleStore) Create(ctx context.Context, tenantID uuid.UUID, rule InlineRule) (InlineRule, error) {
	row, err := toRepoInlineRule(rule)
	if err != nil {
		return InlineRule{}, err
	}
	created, err := s.repo.Create(ctx, tenantID, row)
	if err != nil {
		return InlineRule{}, err
	}
	return fromRepoInlineRule(created)
}

func (s *repoInlineRuleStore) Update(ctx context.Context, tenantID uuid.UUID, rule InlineRule) (InlineRule, error) {
	row, err := toRepoInlineRule(rule)
	if err != nil {
		return InlineRule{}, err
	}
	updated, err := s.repo.Update(ctx, tenantID, row)
	if err != nil {
		return InlineRule{}, err
	}
	return fromRepoInlineRule(updated)
}

func (s *repoInlineRuleStore) Delete(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.repo.Delete(ctx, tenantID, id)
}

// toRepoInlineRule projects a typed InlineRule onto the repository
// row, encoding Conditions as a JSON document.
func toRepoInlineRule(r InlineRule) (repository.InlineCASBRule, error) {
	conds, err := json.Marshal(r.Conditions)
	if err != nil {
		return repository.InlineCASBRule{}, fmt.Errorf("marshal inline casb conditions: %w", err)
	}
	return repository.InlineCASBRule{
		ID:         r.ID,
		TenantID:   r.TenantID,
		AppID:      r.AppID,
		Action:     string(r.Action),
		Verdict:    string(r.Verdict),
		Conditions: conds,
		Enabled:    r.Enabled,
		Priority:   r.Priority,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
	}, nil
}

// fromRepoInlineRule reconstitutes a typed InlineRule from a
// repository row, decoding the Conditions JSON document. A nil /
// empty Conditions column decodes to the zero InlineConditions
// ("match every request"), matching the table's '{}' default.
func fromRepoInlineRule(row repository.InlineCASBRule) (InlineRule, error) {
	var conds InlineConditions
	if len(row.Conditions) > 0 {
		if err := json.Unmarshal(row.Conditions, &conds); err != nil {
			return InlineRule{}, fmt.Errorf("unmarshal inline casb conditions: %w", err)
		}
	}
	return InlineRule{
		ID:         row.ID,
		TenantID:   row.TenantID,
		AppID:      row.AppID,
		Action:     InlineAction(row.Action),
		Verdict:    InlineVerdict(row.Verdict),
		Conditions: conds,
		Enabled:    row.Enabled,
		Priority:   row.Priority,
		CreatedAt:  row.CreatedAt,
		UpdatedAt:  row.UpdatedAt,
	}, nil
}
