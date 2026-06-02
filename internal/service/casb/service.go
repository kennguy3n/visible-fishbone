package casb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

var (
	ErrNotFound        = repository.ErrNotFound
	ErrInvalidArgument = repository.ErrInvalidArgument
	ErrConnectorFailed = errors.New("casb: connector operation failed")
)

// Service orchestrates CASB discovery: connector lifecycle, SaaS
// app enumeration, and posture assessment.
type Service struct {
	connectors repository.CASBConnectorRepository
	apps       repository.CASBDiscoveredAppRepository
	posture    repository.CASBPostureCheckRepository
	audit      repository.AuditLogRepository
	plugins    PluginRegistry
	logger     *slog.Logger
	nowFunc    func() time.Time
}

// New constructs a ready-to-use CASB service.
func New(
	connectors repository.CASBConnectorRepository,
	apps repository.CASBDiscoveredAppRepository,
	posture repository.CASBPostureCheckRepository,
	audit repository.AuditLogRepository,
	plugins PluginRegistry,
	logger *slog.Logger,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	if plugins == nil {
		plugins = PluginRegistry{}
	}
	return &Service{
		connectors: connectors,
		apps:       apps,
		posture:    posture,
		audit:      audit,
		plugins:    plugins,
		logger:     logger,
		nowFunc:    func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the wall clock for tests.
func (svc *Service) SetClock(f func() time.Time) { svc.nowFunc = f }

// ListConnectors returns all CASB connectors for a tenant.
func (svc *Service) ListConnectors(
	ctx context.Context,
	tenantID uuid.UUID,
	page repository.Page,
) (repository.PageResult[repository.CASBConnector], error) {
	return svc.connectors.List(ctx, tenantID, page)
}

// GetConnector returns a single CASB connector.
func (svc *Service) GetConnector(
	ctx context.Context,
	tenantID, id uuid.UUID,
) (repository.CASBConnector, error) {
	return svc.connectors.Get(ctx, tenantID, id)
}

// CreateConnectorInput is the validated input to CreateConnector.
type CreateConnectorInput struct {
	Type   repository.CASBConnectorType
	Name   string
	Config json.RawMessage
	Secret []byte
}

// CreateConnector persists a new CASB connector for the tenant.
func (svc *Service) CreateConnector(
	ctx context.Context,
	tenantID uuid.UUID,
	in CreateConnectorInput,
	actorID *uuid.UUID,
) (repository.CASBConnector, error) {
	if !in.Type.IsValid() {
		return repository.CASBConnector{}, fmt.Errorf("%w: unsupported connector type %q", ErrInvalidArgument, in.Type)
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return repository.CASBConnector{}, fmt.Errorf("%w: name is required", ErrInvalidArgument)
	}
	row := repository.CASBConnector{
		TenantID: tenantID,
		Type:     in.Type,
		Name:     name,
		Status:   repository.CASBConnectorStatusConfiguring,
		Config:   in.Config,
		Secret:   in.Secret,
	}
	created, err := svc.connectors.Create(ctx, tenantID, row)
	if err != nil {
		return repository.CASBConnector{}, err
	}
	svc.logAudit(ctx, tenantID, actorID, "casb.connector_created",
		"casb_connector", &created.ID, map[string]any{
			"type": string(in.Type),
			"name": created.Name,
		})
	return created, nil
}

// UpdateConnectorInput is the partial-update payload.
type UpdateConnectorInput struct {
	Name   string
	Config json.RawMessage
	Secret []byte
	Status *repository.CASBConnectorStatus
}

// UpdateConnector applies a partial update.
func (svc *Service) UpdateConnector(
	ctx context.Context,
	tenantID, id uuid.UUID,
	in UpdateConnectorInput,
	actorID *uuid.UUID,
) (repository.CASBConnector, error) {
	existing, err := svc.connectors.Get(ctx, tenantID, id)
	if err != nil {
		return repository.CASBConnector{}, err
	}
	if n := strings.TrimSpace(in.Name); n != "" {
		existing.Name = n
	}
	if len(in.Config) > 0 {
		existing.Config = in.Config
	}
	if len(in.Secret) > 0 {
		existing.Secret = in.Secret
	}
	if in.Status != nil && in.Status.IsValid() {
		existing.Status = *in.Status
	}
	updated, err := svc.connectors.Update(ctx, tenantID, existing)
	if err != nil {
		return repository.CASBConnector{}, err
	}
	svc.logAudit(ctx, tenantID, actorID, "casb.connector_updated",
		"casb_connector", &updated.ID, map[string]any{
			"name": updated.Name,
		})
	return updated, nil
}

// DeleteConnector removes a CASB connector.
func (svc *Service) DeleteConnector(
	ctx context.Context,
	tenantID, id uuid.UUID,
	actorID *uuid.UUID,
) error {
	if err := svc.connectors.Delete(ctx, tenantID, id); err != nil {
		return err
	}
	svc.logAudit(ctx, tenantID, actorID, "casb.connector_deleted",
		"casb_connector", &id, nil)
	return nil
}

// TestConnector probes the connector's external connectivity.
func (svc *Service) TestConnector(
	ctx context.Context,
	tenantID, id uuid.UUID,
) error {
	c, err := svc.connectors.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	plugin, ok := svc.plugins[c.Type]
	if !ok {
		return fmt.Errorf("%w: no plugin for type %q", ErrConnectorFailed, c.Type)
	}
	return plugin.Test(ctx, c.Config, c.Secret)
}

// SyncConnector triggers a full sync: list users, discover apps,
// assess posture. Persists results to the discovered-apps and
// posture-checks tables.
func (svc *Service) SyncConnector(
	ctx context.Context,
	tenantID uuid.UUID,
	connectorID uuid.UUID,
) error {
	c, err := svc.connectors.Get(ctx, tenantID, connectorID)
	if err != nil {
		return err
	}
	plugin, ok := svc.plugins[c.Type]
	if !ok {
		return fmt.Errorf("%w: no plugin for type %q", ErrConnectorFailed, c.Type)
	}

	users, err := plugin.ListUsers(ctx, c.Config, c.Secret)
	if err != nil {
		svc.logger.Warn("casb: sync list-users failed",
			slog.String("connector_id", connectorID.String()),
			slog.Any("error", err))
		return fmt.Errorf("%w: list users: %v", ErrConnectorFailed, err)
	}

	now := svc.nowFunc()
	app := repository.CASBDiscoveredApp{
		TenantID:   tenantID,
		Name:       c.Name,
		Vendor:     string(c.Type),
		Category:   "saas",
		UsersCount: len(users),
		FirstSeen:  now,
		LastSeen:   now,
	}

	report, err := plugin.AssessPosture(ctx, c.Config, c.Secret)
	if err != nil {
		svc.logger.Warn("casb: sync posture assessment failed",
			slog.String("connector_id", connectorID.String()),
			slog.Any("error", err))
	} else {
		score := report.Score
		app.RiskScore = &score
	}

	savedApp, err := svc.apps.Upsert(ctx, tenantID, app)
	if err != nil {
		return fmt.Errorf("upsert discovered app: %w", err)
	}

	if report.Checks != nil {
		report.AppID = savedApp.ID
		checks := make([]repository.CASBPostureCheck, 0, len(report.Checks))
		for _, pc := range report.Checks {
			checks = append(checks, repository.CASBPostureCheck{
				TenantID:   tenantID,
				AppID:      savedApp.ID,
				CheckName:  pc.CheckName,
				Status:     repository.CASBPostureCheckStatus(pc.Status),
				Details:    pc.Details,
				AssessedAt: report.AssessedAt,
			})
		}
		if err := svc.posture.Save(ctx, tenantID, savedApp.ID, checks); err != nil {
			svc.logger.Warn("casb: save posture checks failed",
				slog.String("connector_id", connectorID.String()),
				slog.Any("error", err))
		}
	}

	newStatus := repository.CASBConnectorStatusActive
	if c.Status == repository.CASBConnectorStatusDisabled {
		newStatus = c.Status
	}
	syncAt := svc.nowFunc()
	if err := svc.connectors.UpdateSyncStatus(ctx, tenantID, connectorID,
		newStatus, syncAt); err != nil {
		svc.logger.Warn("casb: update connector sync timestamp failed",
			slog.String("connector_id", connectorID.String()),
			slog.Any("error", err))
	}
	return nil
}

// DiscoverSaaSApps returns all discovered SaaS apps for a tenant.
func (svc *Service) DiscoverSaaSApps(
	ctx context.Context,
	tenantID uuid.UUID,
) ([]repository.CASBDiscoveredApp, error) {
	return svc.apps.List(ctx, tenantID)
}

// GetSaaSPosture returns the latest posture report for a SaaS app.
func (svc *Service) GetSaaSPosture(
	ctx context.Context,
	tenantID uuid.UUID,
	appID uuid.UUID,
) (PostureReport, error) {
	checks, err := svc.posture.GetLatest(ctx, tenantID, appID)
	if err != nil {
		return PostureReport{}, err
	}
	report := PostureReport{
		AppID:  appID,
		Score:  computeScore(checks),
		Checks: make([]PostureCheck, 0, len(checks)),
	}
	for _, c := range checks {
		report.Checks = append(report.Checks, PostureCheck{
			CheckName: c.CheckName,
			Status:    string(c.Status),
			Details:   c.Details,
		})
		if !c.AssessedAt.IsZero() && report.AssessedAt.Before(c.AssessedAt) {
			report.AssessedAt = c.AssessedAt
		}
	}
	if report.AssessedAt.IsZero() {
		report.AssessedAt = svc.nowFunc()
	}
	return report, nil
}

func computeScore(checks []repository.CASBPostureCheck) int {
	if len(checks) == 0 {
		return 0
	}
	total := 0
	for _, c := range checks {
		switch c.Status {
		case repository.CASBPosturePass:
			total += 100
		case repository.CASBPostureWarn:
			total += 50
		}
	}
	return total / len(checks)
}

func (svc *Service) logAudit(
	ctx context.Context,
	tenantID uuid.UUID,
	actorID *uuid.UUID,
	action, resourceType string,
	resourceID *uuid.UUID,
	details map[string]any,
) {
	var detailsJSON json.RawMessage
	if details != nil {
		b, _ := json.Marshal(details)
		detailsJSON = b
	}
	entry := repository.AuditEntry{
		TenantID:     tenantID,
		ActorID:      actorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      detailsJSON,
	}
	if _, err := svc.audit.Append(ctx, tenantID, entry); err != nil {
		svc.logger.Warn("casb: audit append failed",
			slog.String("action", action),
			slog.Any("error", err))
	}
}
