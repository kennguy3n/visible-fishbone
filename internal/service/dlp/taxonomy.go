// Package dlp implements the data classification taxonomy engine
// (Phase 4, Task 46).
//
// The taxonomy defines a hierarchical classification scheme
// (Public → Internal → Confidential → Restricted → Top Secret)
// with per-tenant customization of labels and handling rules.
// DLP policy matches are mapped to classification levels, and
// classification metadata is attached to telemetry events.
package dlp

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultLevels is the out-of-the-box classification hierarchy.
var DefaultLevels = []struct {
	Label       string
	Level       repository.ClassificationLevel
	Description string
}{
	{"Public", repository.ClassificationLevelPublic, "Information approved for public release."},
	{"Internal", repository.ClassificationLevelInternal, "Internal use only; not for public distribution."},
	{"Confidential", repository.ClassificationLevelConfidential, "Sensitive business data requiring access controls."},
	{"Restricted", repository.ClassificationLevelRestricted, "Highly sensitive data with strict access controls."},
	{"Top Secret", repository.ClassificationLevelTopSecret, "Most sensitive data; need-to-know access only."},
}

// TaxonomyService manages the data classification taxonomy.
type TaxonomyService struct {
	classifications repository.DataClassificationRepository
	audit           repository.AuditLogRepository
	logger          *slog.Logger
}

// NewTaxonomyService returns a ready-to-use taxonomy service.
func NewTaxonomyService(
	classifications repository.DataClassificationRepository,
	audit repository.AuditLogRepository,
	logger *slog.Logger,
) *TaxonomyService {
	if logger == nil {
		logger = slog.Default()
	}
	return &TaxonomyService{classifications: classifications, audit: audit, logger: logger}
}

// SeedDefaults populates the default classification hierarchy for a
// tenant if no entries exist yet.
func (s *TaxonomyService) SeedDefaults(ctx context.Context, tenantID uuid.UUID) error {
	existing, err := s.classifications.List(ctx, tenantID, repository.Page{Limit: 1})
	if err != nil {
		return err
	}
	if len(existing.Items) > 0 {
		return nil
	}
	for _, d := range DefaultLevels {
		if _, err := s.classifications.Create(ctx, tenantID, repository.DataClassification{
			Label:         d.Label,
			Level:         d.Level,
			Description:   d.Description,
			HandlingRules: json.RawMessage(`{}`),
		}); err != nil {
			return fmt.Errorf("seed %s: %w", d.Level, err)
		}
	}
	return nil
}

// Create adds a custom classification entry.
func (s *TaxonomyService) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	dc repository.DataClassification,
) (repository.DataClassification, error) {
	if dc.Label == "" {
		return repository.DataClassification{}, fmt.Errorf("label is required: %w", repository.ErrInvalidArgument)
	}
	if !dc.Level.IsValid() {
		return repository.DataClassification{}, fmt.Errorf("invalid level %q: %w", dc.Level, repository.ErrInvalidArgument)
	}
	created, err := s.classifications.Create(ctx, tenantID, dc)
	if err != nil {
		return repository.DataClassification{}, err
	}
	s.logAudit(ctx, tenantID, actorID, "data_classification.created", "data_classification", &created.ID)
	return created, nil
}

// Get fetches a single classification entry.
func (s *TaxonomyService) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.DataClassification, error) {
	return s.classifications.Get(ctx, tenantID, id)
}

// List returns all classification entries for the tenant.
func (s *TaxonomyService) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.DataClassification], error) {
	return s.classifications.List(ctx, tenantID, page)
}

// Update applies a sparse patch to an existing classification.
func (s *TaxonomyService) Update(
	ctx context.Context,
	tenantID, id uuid.UUID,
	actorID *uuid.UUID,
	patch repository.DataClassificationPatch,
) (repository.DataClassification, error) {
	if patch.Level != nil && !patch.Level.IsValid() {
		return repository.DataClassification{}, fmt.Errorf("invalid level %q: %w", *patch.Level, repository.ErrInvalidArgument)
	}
	updated, err := s.classifications.Update(ctx, tenantID, id, patch)
	if err != nil {
		return repository.DataClassification{}, err
	}
	s.logAudit(ctx, tenantID, actorID, "data_classification.updated", "data_classification", &updated.ID)
	return updated, nil
}

// Delete removes a classification entry.
func (s *TaxonomyService) Delete(ctx context.Context, tenantID, id uuid.UUID, actorID *uuid.UUID) error {
	if err := s.classifications.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	s.logAudit(ctx, tenantID, actorID, "data_classification.deleted", "data_classification", &id)
	return nil
}

// Classify maps a DLP policy match to a classification level.
func (s *TaxonomyService) Classify(ctx context.Context, tenantID uuid.UUID, level repository.ClassificationLevel) (repository.DataClassification, error) {
	return s.classifications.GetByLevel(ctx, tenantID, level)
}

func (s *TaxonomyService) logAudit(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, action, resourceType string, resourceID *uuid.UUID) {
	if s.audit == nil {
		return
	}
	details := middleware.EnrichAuditDetails(ctx, json.RawMessage(`{}`))
	if _, err := s.audit.Append(ctx, tenantID, repository.AuditEntry{
		TenantID:     tenantID,
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	}); err != nil {
		s.logger.Error("audit log failed", "action", action, "err", err)
	}
}
