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
	"strings"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
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
  "throughput_mbps": 1000
}`),
	repository.SiteTemplateHub: json.RawMessage(`{
  "ngfw": true,
  "ips": true,
  "inter_site_routing": true,
  "throughput_mbps": 10000
}`),
	repository.SiteTemplateCloudOnly: json.RawMessage(`{
  "swg": true,
  "dns": true,
  "ztna": true,
  "local_appliance": false
}`),
	repository.SiteTemplateHomeOffice: json.RawMessage(`{
  "split_tunnel": true,
  "dns": true,
  "posture_only": true
}`),
}

// Service implements site CRUD.
type Service struct {
	sites repository.SiteRepository
	audit repository.AuditLogRepository
}

// New returns a ready-to-use site service.
func New(sites repository.SiteRepository, audit repository.AuditLogRepository) *Service {
	return &Service{sites: sites, audit: audit}
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
		s.Slug = deriveSlug(s.Name)
		if s.Slug == "" {
			s.Slug = "site-" + uuid.NewString()[:8]
		}
	}
	if len(s.Config) == 0 || string(s.Config) == "{}" {
		s.Config = TemplateConfig[s.Template]
	}

	created, err := svc.sites.Create(ctx, tenantID, s)
	if err != nil {
		return repository.Site{}, err
	}
	_ = svc.appendAudit(ctx, tenantID, actorID, "site.created", "site", &created.ID, nil)
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
	_ = svc.appendAudit(ctx, tenantID, actorID, "site.updated", "site", &updated.ID, nil)
	return updated, nil
}

// Delete removes a site from the tenant.
func (svc *Service) Delete(ctx context.Context, tenantID, id uuid.UUID, actorID *uuid.UUID) error {
	if err := svc.sites.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	_ = svc.appendAudit(ctx, tenantID, actorID, "site.deleted", "site", &id, nil)
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
	_, err := svc.audit.Append(ctx, tenantID, repository.AuditEntry{
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      details,
	})
	return err
}

// deriveSlug is a small local copy of tenant.DeriveSlug to avoid an
// import cycle (tenant → audit chain) and keep the slug rules in
// sync.
func deriveSlug(name string) string {
	const maxLen = 63
	var b strings.Builder
	b.Grow(len(name))
	dashRun := false
	for _, r := range strings.ToLower(name) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			dashRun = false
		case !dashRun && b.Len() > 0:
			b.WriteByte('-')
			dashRun = true
		}
	}
	out := strings.TrimRight(b.String(), "-")
	if len(out) > maxLen {
		out = strings.TrimRight(out[:maxLen], "-")
	}
	return out
}
