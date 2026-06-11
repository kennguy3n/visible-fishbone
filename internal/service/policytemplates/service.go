package policytemplates

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
)

// Service is the policy-templates API: browse the catalog, preview a
// rendered baseline, and idempotently apply one to a tenant.
//
// The catalog is immutable, code-defined data (buildCatalog); the
// repository persists it (for audit/queryability) and stores the
// per-tenant applied state. A nil repository yields a read-only
// service: ListTemplates/GetTemplate/Resolve still work, but
// Apply/GetApplied/SeedCatalog return ErrRepositoryUnavailable.
type Service struct {
	repo    Repository
	catalog []Template
	byID    map[string]Template
	logger  *slog.Logger
}

// ErrRepositoryUnavailable is returned by the persistence-backed
// methods when the service was constructed without a repository.
//
// It is a standalone sentinel that deliberately does NOT wrap
// repository.ErrInvalidArgument (or any other mapped sentinel): a
// missing repository is a server-side misconfiguration, so the
// standard handler error mapper (WriteRepositoryError) must fall
// through to HTTP 500, not report a client 400.
var ErrRepositoryUnavailable = errors.New("policytemplates: repository not configured")

// New constructs the service over a repository. Pass nil for a
// read-only (catalog-only) service.
func New(repo Repository, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	catalog := buildCatalog()
	byID := make(map[string]Template, len(catalog))
	for _, t := range catalog {
		byID[t.ID] = t
	}
	return &Service{repo: repo, catalog: catalog, byID: byID, logger: logger}
}

// ListTemplates returns the full catalog (baseline + every industry +
// every compliance regime), sorted by id. The returned Templates are
// deep copies; callers cannot mutate the catalog.
func (s *Service) ListTemplates() []Template {
	out := make([]Template, len(s.catalog))
	for i, t := range s.catalog {
		t.Spec = cloneSpec(t.Spec)
		out[i] = t
	}
	return out
}

// GetTemplate returns a single catalog template by id. Returns
// ErrNotFound for an unknown id.
func (s *Service) GetTemplate(id string) (Template, error) {
	t, ok := s.byID[id]
	if !ok {
		return Template{}, fmt.Errorf("template %q: %w", id, ErrNotFound)
	}
	t.Spec = cloneSpec(t.Spec)
	return t, nil
}

// Resolve renders the composed Policy-Graph intent for a Selection
// without persisting anything. Useful as a preview/dry-run.
func (s *Service) Resolve(sel Selection) (Resolved, error) {
	return Resolve(sel)
}

// SeedCatalog idempotently persists the code-defined catalog into the
// global policy_templates table. Safe to call on every boot.
func (s *Service) SeedCatalog(ctx context.Context) error {
	if s.repo == nil {
		return ErrRepositoryUnavailable
	}
	rows := make([]CatalogRow, len(s.catalog))
	for i, t := range s.catalog {
		row, err := toCatalogRow(t)
		if err != nil {
			return err
		}
		rows[i] = row
	}
	return s.repo.UpsertCatalog(ctx, rows)
}

// Apply renders the baseline for sel and idempotently persists it for
// tenantID. Re-applying the same selection (with an unchanged catalog)
// performs no write and returns the stored row; changing the selection
// or a catalog bump re-renders and replaces the row in place.
func (s *Service) Apply(ctx context.Context, tenantID uuid.UUID, sel Selection) (AppliedTemplate, error) {
	if s.repo == nil {
		return AppliedTemplate{}, ErrRepositoryUnavailable
	}
	if tenantID == uuid.Nil {
		return AppliedTemplate{}, fmt.Errorf("tenant id required: %w", errInvalidArgument)
	}
	resolved, err := Resolve(sel)
	if err != nil {
		return AppliedTemplate{}, err
	}

	// Idempotency: if the tenant already has this exact baseline
	// rendered (same hash + selection), return it without a write.
	existing, err := s.repo.GetApplied(ctx, tenantID)
	switch {
	case err == nil:
		if existing.GraphHash == resolved.GraphHash &&
			existing.Industry == string(resolved.Selection.Industry) &&
			existing.Country == string(resolved.Selection.Country) {
			return existing, nil
		}
	case isNotFound(err):
		// First apply for this tenant; fall through to upsert.
	default:
		return AppliedTemplate{}, err
	}

	applied := AppliedTemplate{
		TenantID:    tenantID,
		Industry:    string(resolved.Selection.Industry),
		Country:     string(resolved.Selection.Country),
		Regime:      string(resolved.Regime),
		TemplateIDs: resolved.TemplateIDs,
		GraphHash:   resolved.GraphHash,
		Graph:       resolved.GraphJSON,
		Version:     GraphVersion,
	}
	stored, err := s.repo.UpsertApplied(ctx, applied)
	if err != nil {
		return AppliedTemplate{}, err
	}
	s.logger.InfoContext(ctx, "applied policy template baseline",
		slog.String("tenant_id", tenantID.String()),
		slog.String("industry", applied.Industry),
		slog.String("country", applied.Country),
		slog.String("regime", applied.Regime),
		slog.String("graph_hash", applied.GraphHash),
	)
	return stored, nil
}

// GetApplied returns a tenant's current applied baseline, or
// ErrNotFound when none has been applied.
func (s *Service) GetApplied(ctx context.Context, tenantID uuid.UUID) (AppliedTemplate, error) {
	if s.repo == nil {
		return AppliedTemplate{}, ErrRepositoryUnavailable
	}
	if tenantID == uuid.Nil {
		return AppliedTemplate{}, fmt.Errorf("tenant id required: %w", errInvalidArgument)
	}
	return s.repo.GetApplied(ctx, tenantID)
}

// toCatalogRow projects a Template into its persisted primitive form,
// computing the content hash over EVERY persisted field (not just
// Spec). Both repository impls skip a write when the stored hash is
// unchanged, so hashing the full row ensures a metadata-only edit
// (e.g. a renamed Name/Description) still propagates to the database
// instead of being silently dropped.
func toCatalogRow(t Template) (CatalogRow, error) {
	spec, err := json.Marshal(t.Spec)
	if err != nil {
		return CatalogRow{}, fmt.Errorf("marshal spec for %q: %w", t.ID, err)
	}
	hashPayload, err := json.Marshal(struct {
		ID          string          `json:"id"`
		Kind        string          `json:"kind"`
		Industry    string          `json:"industry"`
		Regime      string          `json:"regime"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Version     int             `json:"version"`
		Spec        json.RawMessage `json:"spec"`
	}{t.ID, string(t.Kind), string(t.Industry), string(t.Regime), t.Name, t.Description, GraphVersion, spec})
	if err != nil {
		return CatalogRow{}, fmt.Errorf("marshal catalog row for %q: %w", t.ID, err)
	}
	sum := sha256.Sum256(hashPayload)
	return CatalogRow{
		ID:          t.ID,
		Kind:        string(t.Kind),
		Industry:    string(t.Industry),
		Regime:      string(t.Regime),
		Name:        t.Name,
		Description: t.Description,
		Spec:        spec,
		ContentHash: hex.EncodeToString(sum[:]),
		Version:     GraphVersion,
	}, nil
}

func isNotFound(err error) bool {
	return errors.Is(err, ErrNotFound)
}
