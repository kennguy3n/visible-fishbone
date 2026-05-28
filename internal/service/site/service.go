// Package site implements CRUD for tenant sites. Site templates
// ship with default enforcement configs the caller can override at
// creation time:
//
//   - branch     — full NGFW + IPS + SWG + DNS + SD-WAN, dual-WAN
//   - hub        — NGFW + IPS + inter-site routing, high throughput
//   - cloud_only — SWG + DNS + ZTNA, no local edge appliance
//   - home_office— split-tunnel VPN replacement + DNS + posture only
package site

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/slug"
)

// TemplateConfig is the default config blob applied at site
// creation when the caller omits `config`. Each template returns a
// stable JSON object so audit log diffs are reviewable.
var TemplateConfig = map[repository.SiteTemplate]json.RawMessage{
	repository.SiteTemplateBranch: json.RawMessage(`{
  "ngfw": true,
  "ips": true,
  "swg": true,
  "dns": true,
  "sdwan": true,
  "wan_links": 2,
  "throughput_mbps": 1000,
  "traffic_classification": "full"
}`),
	repository.SiteTemplateHub: json.RawMessage(`{
  "ngfw": true,
  "ips": true,
  "inter_site_routing": true,
  "throughput_mbps": 10000,
  "traffic_classification": "routing_only"
}`),
	repository.SiteTemplateCloudOnly: json.RawMessage(`{
  "swg": true,
  "dns": true,
  "ztna": true,
  "local_appliance": false,
  "traffic_classification": "smart_bypass"
}`),
	repository.SiteTemplateHomeOffice: json.RawMessage(`{
  "split_tunnel": true,
  "dns": true,
  "posture_only": true,
  "traffic_classification": "split_tunnel_smart"
}`),
}

// Service implements site CRUD.
type Service struct {
	sites  repository.SiteRepository
	audit  repository.AuditLogRepository
	logger *slog.Logger
}

// New returns a ready-to-use site service.
func New(sites repository.SiteRepository, audit repository.AuditLogRepository, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{sites: sites, audit: audit, logger: logger}
}

// Create provisions a new site. If `s.Config` is empty the template
// default is applied. The slug is derived from the name if omitted.
func (svc *Service) Create(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	s repository.Site,
) (repository.Site, error) {
	if s.Name == "" {
		return repository.Site{}, fmt.Errorf("site name is required: %w", repository.ErrInvalidArgument)
	}
	if s.Template == "" {
		s.Template = repository.SiteTemplateBranch
	}
	if _, ok := TemplateConfig[s.Template]; !ok {
		return repository.Site{}, fmt.Errorf("unknown template %q: %w", s.Template, repository.ErrInvalidArgument)
	}
	if s.Slug == "" {
		s.Slug = slug.Derive(s.Name)
		if s.Slug == "" {
			s.Slug = "site-" + uuid.NewString()[:8]
		}
	}
	if len(s.Config) == 0 || string(s.Config) == "{}" {
		// Clone the template bytes so in-place mutations of the
		// returned Site.Config can never corrupt the shared
		// TemplateConfig entries.
		s.Config = append(json.RawMessage{}, TemplateConfig[s.Template]...)
	}

	created, err := svc.sites.Create(ctx, tenantID, s)
	if err != nil {
		return repository.Site{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID, "site.created", "site", &created.ID, nil))
	return created, nil
}

// Get fetches a site within the tenant.
func (svc *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.Site, error) {
	return svc.sites.Get(ctx, tenantID, id)
}

// List returns a cursor-paginated list of sites for the tenant.
func (svc *Service) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.Site], error) {
	return svc.sites.List(ctx, tenantID, page)
}

// Update applies a partial update.
func (svc *Service) Update(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	s repository.Site,
) (repository.Site, error) {
	if s.ID == uuid.Nil {
		return repository.Site{}, fmt.Errorf("site ID is required: %w", repository.ErrInvalidArgument)
	}
	updated, err := svc.sites.Update(ctx, tenantID, s)
	if err != nil {
		return repository.Site{}, err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID, "site.updated", "site", &updated.ID, nil))
	return updated, nil
}

// Delete removes a site from the tenant.
func (svc *Service) Delete(ctx context.Context, tenantID, id uuid.UUID, actorID *uuid.UUID) error {
	if err := svc.sites.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	svc.logAuditErr(svc.appendAudit(ctx, tenantID, actorID, "site.deleted", "site", &id, nil))
	return nil
}

func (svc *Service) appendAudit(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	action, resourceType string,
	resourceID *uuid.UUID,
	details json.RawMessage,
) error {
	if details == nil {
		details = json.RawMessage(`{}`)
	}
	// Stamp acting API-key ID into details for machine-to-machine
	// authenticated requests; see middleware.EnrichAuditDetails for
	// the rationale (actor_id is a *user* UUID and NULL on API-key
	// paths, so machine-actor attribution lives in details).
	details = middleware.EnrichAuditDetails(ctx, details)
	_, err := svc.audit.Append(ctx, tenantID, repository.AuditEntry{
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	})
	return err
}

func (svc *Service) logAuditErr(err error) {
	if err != nil {
		svc.logger.Warn("site: audit append failed", slog.Any("error", err))
	}
}
