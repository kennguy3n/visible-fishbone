// Package terraform implements config-as-code export/import for
// the ShieldNet Gateway control plane (Phase 4, Task 47).
//
// ExportTenantConfig serializes the full tenant configuration into
// a versioned JSON document. ImportTenantConfig applies the
// document idempotently. The pair enables a Terraform provider to
// manage tenant config declaratively.
package terraform

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ConfigVersion is the schema version of the exported config.
const ConfigVersion = 1

// ExportedConfig is the versioned top-level wrapper.
type ExportedConfig struct {
	Version             int                          `json:"version"`
	ExportedAt          time.Time                    `json:"exported_at"`
	TenantID            string                       `json:"tenant_id"`
	Policies            []ExportedPolicy             `json:"policies,omitempty"`
	Sites               []ExportedSite               `json:"sites,omitempty"`
	BrowserPolicies     []ExportedBrowserPolicy      `json:"browser_policies,omitempty"`
	DataClassifications []ExportedDataClassification `json:"data_classifications,omitempty"`
	Integrations        []ExportedIntegration        `json:"integrations,omitempty"`
}

// ExportedPolicy is the serialized form of a policy graph.
type ExportedPolicy struct {
	Version int             `json:"version"`
	Graph   json.RawMessage `json:"graph"`
}

// ExportedSite is the serialized form of a site.
type ExportedSite struct {
	Name     string          `json:"name"`
	Slug     string          `json:"slug"`
	Template string          `json:"template"`
	Config   json.RawMessage `json:"config,omitempty"`
}

// ExportedBrowserPolicy is the serialized form of a browser policy.
type ExportedBrowserPolicy struct {
	Name    string                   `json:"name"`
	Rules   []repository.BrowserRule `json:"rules"`
	Action  string                   `json:"action"`
	Scope   string                   `json:"scope"`
	Enabled bool                     `json:"enabled"`
}

// ExportedDataClassification is the serialized form of a data
// classification entry.
type ExportedDataClassification struct {
	Label         string          `json:"label"`
	Level         string          `json:"level"`
	Description   string          `json:"description,omitempty"`
	HandlingRules json.RawMessage `json:"handling_rules,omitempty"`
}

// ExportedIntegration is the serialized form of an integration
// connector (secrets excluded).
type ExportedIntegration struct {
	Type        string          `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	EventTypes  []string        `json:"event_types,omitempty"`
	Config      json.RawMessage `json:"config,omitempty"`
	Status      string          `json:"status"`
}

// Deps bundles the repository dependencies the provider needs.
type Deps struct {
	Sites               repository.SiteRepository
	Policies            repository.PolicyRepository
	BrowserPolicies     repository.BrowserPolicyRepository
	DataClassifications repository.DataClassificationRepository
	Integrations        repository.IntegrationConnectorRepository
	Audit               repository.AuditLogRepository
}

// Provider implements config export/import.
type Provider struct {
	deps   Deps
	logger *slog.Logger
}

// New returns a ready-to-use provider.
func New(deps Deps, logger *slog.Logger) *Provider {
	if logger == nil {
		logger = slog.Default()
	}
	return &Provider{deps: deps, logger: logger}
}

// ExportTenantConfig exports the full tenant configuration.
func (p *Provider) ExportTenantConfig(ctx context.Context, tenantID uuid.UUID) (json.RawMessage, error) {
	cfg := ExportedConfig{
		Version:    ConfigVersion,
		ExportedAt: time.Now().UTC(),
		TenantID:   tenantID.String(),
	}

	allPages := repository.Page{Limit: repository.MaxPageLimit}

	// Sites.
	if p.deps.Sites != nil {
		sites, err := p.deps.Sites.List(ctx, tenantID, allPages)
		if err != nil {
			return nil, fmt.Errorf("export sites: %w", err)
		}
		for _, s := range sites.Items {
			cfg.Sites = append(cfg.Sites, ExportedSite{
				Name: s.Name, Slug: s.Slug,
				Template: string(s.Template), Config: s.Config,
			})
		}
	}

	// Policy graphs.
	if p.deps.Policies != nil {
		pg, err := p.deps.Policies.GetCurrentGraph(ctx, tenantID)
		if err == nil {
			cfg.Policies = append(cfg.Policies, ExportedPolicy{
				Version: pg.Version, Graph: pg.Graph,
			})
		}
	}

	// Browser policies.
	if p.deps.BrowserPolicies != nil {
		bps, err := p.deps.BrowserPolicies.List(ctx, tenantID, allPages)
		if err != nil {
			return nil, fmt.Errorf("export browser policies: %w", err)
		}
		for _, bp := range bps.Items {
			cfg.BrowserPolicies = append(cfg.BrowserPolicies, ExportedBrowserPolicy{
				Name: bp.Name, Rules: bp.Rules,
				Action: string(bp.Action), Scope: string(bp.Scope),
				Enabled: bp.Enabled,
			})
		}
	}

	// Data classifications.
	if p.deps.DataClassifications != nil {
		dcs, err := p.deps.DataClassifications.List(ctx, tenantID, allPages)
		if err != nil {
			return nil, fmt.Errorf("export data classifications: %w", err)
		}
		for _, dc := range dcs.Items {
			cfg.DataClassifications = append(cfg.DataClassifications, ExportedDataClassification{
				Label: dc.Label, Level: string(dc.Level),
				Description: dc.Description, HandlingRules: dc.HandlingRules,
			})
		}
	}

	// Integrations.
	if p.deps.Integrations != nil {
		ics, err := p.deps.Integrations.List(ctx, tenantID, allPages)
		if err != nil {
			return nil, fmt.Errorf("export integrations: %w", err)
		}
		for _, ic := range ics.Items {
			cfg.Integrations = append(cfg.Integrations, ExportedIntegration{
				Type: string(ic.Type), Name: ic.Name,
				Description: ic.Description, EventTypes: ic.EventTypes,
				Config: ic.Config, Status: string(ic.Status),
			})
		}
	}

	return json.Marshal(cfg)
}

// ImportTenantConfig idempotently imports a tenant configuration.
// Existing resources with matching names are updated; new ones are
// created.
func (p *Provider) ImportTenantConfig(ctx context.Context, tenantID uuid.UUID, config json.RawMessage) error {
	var cfg ExportedConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return fmt.Errorf("unmarshal config: %w", err)
	}
	if cfg.Version != ConfigVersion {
		return fmt.Errorf("unsupported config version %d (expected %d): %w",
			cfg.Version, ConfigVersion, repository.ErrInvalidArgument)
	}

	// Import sites.
	if p.deps.Sites != nil {
		for _, es := range cfg.Sites {
			_, err := p.deps.Sites.Create(ctx, tenantID, repository.Site{
				Name:     es.Name,
				Slug:     es.Slug,
				Template: repository.SiteTemplate(es.Template),
				Config:   es.Config,
			})
			if err != nil {
				p.logger.Warn("import site", "name", es.Name, "err", err)
			}
		}
	}

	// Import browser policies.
	if p.deps.BrowserPolicies != nil {
		for _, ebp := range cfg.BrowserPolicies {
			_, err := p.deps.BrowserPolicies.Create(ctx, tenantID, repository.BrowserPolicy{
				Name:    ebp.Name,
				Rules:   ebp.Rules,
				Action:  repository.BrowserPolicyAction(ebp.Action),
				Scope:   repository.BrowserPolicyScope(ebp.Scope),
				Enabled: ebp.Enabled,
			})
			if err != nil {
				p.logger.Warn("import browser policy", "name", ebp.Name, "err", err)
			}
		}
	}

	// Import data classifications.
	if p.deps.DataClassifications != nil {
		for _, edc := range cfg.DataClassifications {
			_, err := p.deps.DataClassifications.Create(ctx, tenantID, repository.DataClassification{
				Label:         edc.Label,
				Level:         repository.ClassificationLevel(edc.Level),
				Description:   edc.Description,
				HandlingRules: edc.HandlingRules,
			})
			if err != nil {
				p.logger.Warn("import data classification", "label", edc.Label, "err", err)
			}
		}
	}

	p.logAudit(ctx, tenantID, "config.imported")
	return nil
}

func (p *Provider) logAudit(ctx context.Context, tenantID uuid.UUID, action string) {
	if p.deps.Audit == nil {
		return
	}
	if _, err := p.deps.Audit.Append(ctx, tenantID, repository.AuditEntry{
		TenantID:     tenantID,
		Action:       action,
		ResourceType: "tenant_config",
		Details:      json.RawMessage(`{}`),
	}); err != nil {
		p.logger.Error("audit log failed", "action", action, "err", err)
	}
}
