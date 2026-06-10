package identity

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

// DefaultSyncInterval is how often the IdP sync runner reconciles every
// tenant's directory when no explicit interval is configured.
const DefaultSyncInterval = 5 * time.Minute

// DirectoryUser is the normalized projection of a user as a provider's
// directory API reports it, independent of the Okta / Entra / Google
// wire shapes. Groups are the provider's group/role display names.
type DirectoryUser struct {
	// ExternalID is the provider's stable user id (Okta user id, Entra
	// objectId, Google id). Persisted on the local user's IDPSubject so
	// subsequent syncs and OIDC logins address the same identity.
	ExternalID string
	// Email is the primary email / userPrincipalName, lower-cased by
	// the client. It is the natural key used to reconcile against the
	// local user store.
	Email string
	// DisplayName is the human-readable name, when the directory
	// exposes one.
	DisplayName string
	// Active is the provider's lifecycle state mapped to a boolean: a
	// deactivated / suspended / deprovisioned directory user is
	// Active=false and is treated as off-boarded.
	Active bool
	// Groups is the set of group / role names the user belongs to in
	// the directory.
	Groups []string
}

// DirectoryClient pulls the full user + group snapshot for one tenant's
// IdP directory. Implementations are provider-specific (Okta, Microsoft
// Graph, Google Admin SDK) and handle their own pagination.
type DirectoryClient interface {
	// ListUsers returns every user in the directory scope, with group
	// membership resolved. The snapshot is authoritative: users absent
	// from it (or returned Active=false) are considered off-boarded.
	ListUsers(ctx context.Context) ([]DirectoryUser, error)
}

// DirectoryCredential carries the per-tenant secrets and coordinates
// needed to call a provider directory API. It is resolved out of band
// (from the platform secret store) because IDPConfig persists only
// token-validation material, never directory API secrets.
type DirectoryCredential struct {
	// BaseURL overrides the provider API base (e.g. an Okta org URL
	// "https://acme.okta.com"). Empty uses the provider default.
	BaseURL string
	// Token is the bearer credential for the directory API (Okta SSWS
	// token, a Graph / Google OAuth2 access token minted by the
	// resolver).
	Token string
	// Subject is the principal a Google service account impersonates
	// via domain-wide delegation (the admin user whose directory is
	// read). Ignored by other providers.
	Subject string
}

// CredentialResolver fetches directory API credentials for a tenant's
// IdP config from the platform secret store. Implementations MUST scope
// the lookup to tenantID so one tenant can never read another's
// directory credentials.
type CredentialResolver interface {
	Resolve(ctx context.Context, tenantID uuid.UUID, cfg repository.IDPConfig) (DirectoryCredential, error)
}

// DirectoryClientFactory builds a DirectoryClient for a resolved
// provider config + credential pair.
type DirectoryClientFactory interface {
	Build(cfg repository.IDPConfig, cred DirectoryCredential) (DirectoryClient, error)
}

// RevocationPublisher pushes a revocation for an off-boarded user
// downstream to the ZTNA enforcement plane, so active sessions and
// access grants are cut immediately rather than waiting for token
// expiry.
type RevocationPublisher interface {
	PublishRevocation(ctx context.Context, tenantID, userID uuid.UUID, reason string) error
}

// TenantSource enumerates the tenants the sync runner reconciles.
type TenantSource interface {
	ListTenants(ctx context.Context) ([]uuid.UUID, error)
}

// SyncReport summarizes the outcome of reconciling one tenant.
type SyncReport struct {
	TenantID         uuid.UUID
	ConfigsProcessed int
	UsersSeen        int
	UsersProvisioned int
	UsersOffboarded  int
	GroupsAssigned   int
	GroupsRevoked    int
	// Errors are per-config / per-user failures that did not abort the
	// whole tenant sync. The reconcile is best-effort: one provider or
	// user failing must not stall the rest.
	Errors []error
}

// SyncService periodically pulls each tenant's IdP directory and
// reconciles it against the local identity store: it (just-in-time)
// provisions newly-seen users, refreshes group memberships, and detects
// off-boarded users — deactivating them locally and pushing a
// revocation so the ZTNA plane drops their access at once.
//
// Every operation is strictly tenant-scoped: directory clients are
// built per tenant config, and every repository call carries the
// tenant id, so a sync can neither read nor mutate another tenant's
// data.
type SyncService struct {
	configs repository.IDPConfigRepository
	users   repository.UserRepository
	roles   repository.RoleRepository
	audit   repository.AuditLogRepository
	tenants TenantSource
	creds   CredentialResolver
	factory DirectoryClientFactory
	revoker RevocationPublisher
	logger  *slog.Logger
	nowFunc func() time.Time
}

// NewSyncService wires an IdP directory sync service.
func NewSyncService(
	configs repository.IDPConfigRepository,
	users repository.UserRepository,
	roles repository.RoleRepository,
	audit repository.AuditLogRepository,
	tenants TenantSource,
	creds CredentialResolver,
	factory DirectoryClientFactory,
	revoker RevocationPublisher,
	logger *slog.Logger,
) *SyncService {
	if logger == nil {
		logger = slog.Default()
	}
	return &SyncService{
		configs: configs,
		users:   users,
		roles:   roles,
		audit:   audit,
		tenants: tenants,
		creds:   creds,
		factory: factory,
		revoker: revoker,
		logger:  logger,
		nowFunc: func() time.Time { return time.Now().UTC() },
	}
}

// Run reconciles every tenant on an interval until ctx is cancelled. It
// runs one pass immediately, then on each tick. interval <= 0 falls back
// to DefaultSyncInterval.
func (s *SyncService) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = DefaultSyncInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	s.syncAll(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.syncAll(ctx)
		}
	}
}

// syncAll reconciles every tenant once, logging (never propagating)
// per-tenant failures so one bad tenant cannot stall the runner.
func (s *SyncService) syncAll(ctx context.Context) {
	tenants, err := s.tenants.ListTenants(ctx)
	if err != nil {
		s.logger.Error("idp_sync: list tenants failed", slog.Any("error", err))
		return
	}
	for _, tid := range tenants {
		if ctx.Err() != nil {
			return
		}
		report, err := s.SyncTenant(ctx, tid)
		if err != nil {
			s.logger.Error("idp_sync: tenant sync failed",
				slog.String("tenant_id", tid.String()), slog.Any("error", err))
			continue
		}
		if report.UsersOffboarded > 0 || report.UsersProvisioned > 0 || len(report.Errors) > 0 {
			s.logger.Info("idp_sync: tenant reconciled",
				slog.String("tenant_id", tid.String()),
				slog.Int("seen", report.UsersSeen),
				slog.Int("provisioned", report.UsersProvisioned),
				slog.Int("offboarded", report.UsersOffboarded),
				slog.Int("groups_assigned", report.GroupsAssigned),
				slog.Int("groups_revoked", report.GroupsRevoked),
				slog.Int("errors", len(report.Errors)),
			)
		}
	}
}

// SyncTenant reconciles all of a tenant's enabled IdP directories. It
// returns a report; per-config and per-user errors are collected in
// report.Errors rather than aborting, so a single failure does not
// leave the tenant half-reconciled.
func (s *SyncService) SyncTenant(ctx context.Context, tenantID uuid.UUID) (SyncReport, error) {
	report := SyncReport{TenantID: tenantID}

	cfgs, err := s.configs.List(ctx, tenantID)
	if err != nil {
		return report, fmt.Errorf("list idp configs: %w", err)
	}

	for _, cfg := range cfgs {
		if !cfg.Enabled {
			continue
		}
		report.ConfigsProcessed++
		if err := s.syncConfig(ctx, tenantID, cfg, &report); err != nil {
			report.Errors = append(report.Errors,
				fmt.Errorf("provider %s (%s): %w", cfg.ProviderType, cfg.IssuerURL, err))
		}
	}
	return report, nil
}

// syncConfig reconciles one provider directory for a tenant.
func (s *SyncService) syncConfig(ctx context.Context, tenantID uuid.UUID, cfg repository.IDPConfig, report *SyncReport) error {
	cred, err := s.creds.Resolve(ctx, tenantID, cfg)
	if err != nil {
		return fmt.Errorf("resolve credentials: %w", err)
	}
	client, err := s.factory.Build(cfg, cred)
	if err != nil {
		return fmt.Errorf("build directory client: %w", err)
	}
	dirUsers, err := client.ListUsers(ctx)
	if err != nil {
		return fmt.Errorf("list directory users: %w", err)
	}
	return s.reconcile(ctx, tenantID, dirUsers, report)
}

// reconcile applies a directory snapshot to the local store: provision
// / refresh active users (and their group memberships) and off-board
// users that are gone or deactivated upstream.
func (s *SyncService) reconcile(ctx context.Context, tenantID uuid.UUID, dirUsers []DirectoryUser, report *SyncReport) error {
	locals, err := s.listLocalUsers(ctx, tenantID)
	if err != nil {
		return err
	}
	localByEmail := make(map[string]repository.User, len(locals))
	for _, u := range locals {
		localByEmail[strings.ToLower(u.Email)] = u
	}

	// roleCtx caches the tenant's role table and tracks every role the
	// directory governs this pass, so off-boarding from a group only
	// ever revokes directory-managed roles (never locally-granted ones).
	rc, err := s.newRoleReconciler(ctx, tenantID, dirUsers)
	if err != nil {
		return err
	}

	seenEmails := make(map[string]struct{}, len(dirUsers))
	for _, du := range dirUsers {
		email := strings.ToLower(strings.TrimSpace(du.Email))
		if email == "" {
			report.Errors = append(report.Errors, fmt.Errorf("directory user %q has no email", du.ExternalID))
			continue
		}
		seenEmails[email] = struct{}{}
		report.UsersSeen++

		if !du.Active {
			// Deactivated upstream: handle as an off-board if we know them.
			if local, ok := localByEmail[email]; ok {
				s.offboard(ctx, tenantID, local, "idp_directory_deactivated", report)
			}
			continue
		}

		local, ok := localByEmail[email]
		if !ok {
			created, perr := s.provisionUser(ctx, tenantID, du)
			if perr != nil {
				report.Errors = append(report.Errors, fmt.Errorf("provision %s: %w", email, perr))
				continue
			}
			local = created
			report.UsersProvisioned++
		} else if local.Status != repository.UserStatusActive {
			// Reactivated upstream: restore local active status.
			if reactivated, uerr := s.users.Update(ctx, tenantID, repository.User{
				ID:     local.ID,
				Status: repository.UserStatusActive,
			}); uerr != nil {
				report.Errors = append(report.Errors, fmt.Errorf("reactivate %s: %w", email, uerr))
			} else {
				local = reactivated
			}
		}

		if rerr := rc.reconcileUserGroups(ctx, local.ID, du.Groups, report); rerr != nil {
			report.Errors = append(report.Errors, fmt.Errorf("groups %s: %w", email, rerr))
		}
	}

	// Off-board active local users the directory no longer lists.
	for email, local := range localByEmail {
		if _, seen := seenEmails[email]; seen {
			continue
		}
		if local.Status != repository.UserStatusActive {
			continue
		}
		s.offboard(ctx, tenantID, local, "idp_directory_absent", report)
	}
	return nil
}

// listLocalUsers pages the tenant's full user set via the repository
// cursor, never materialising more than one page at a time on the
// backend before appending.
func (s *SyncService) listLocalUsers(ctx context.Context, tenantID uuid.UUID) ([]repository.User, error) {
	var out []repository.User
	cursor := ""
	for {
		page, err := s.users.List(ctx, tenantID, repository.Page{
			After: cursor,
			Limit: repository.MaxPageLimit,
			Order: repository.SortDesc,
		})
		if err != nil {
			return nil, fmt.Errorf("list users: %w", err)
		}
		out = append(out, page.Items...)
		if page.NextCursor == "" {
			return out, nil
		}
		cursor = page.NextCursor
	}
}

// provisionUser just-in-time creates a local user from a directory
// record, mirroring the SCIM/OIDC user shape (email as the natural key,
// external id on IDPSubject, active status). A concurrent create is
// tolerated by falling back to the existing record.
func (s *SyncService) provisionUser(ctx context.Context, tenantID uuid.UUID, du DirectoryUser) (repository.User, error) {
	name := du.DisplayName
	if name == "" {
		name = du.Email
	}
	u, err := s.users.Create(ctx, tenantID, repository.User{
		Email:      strings.ToLower(strings.TrimSpace(du.Email)),
		Name:       name,
		ExternalID: du.ExternalID,
		IDPSubject: du.ExternalID,
		Status:     repository.UserStatusActive,
	})
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			if existing, gerr := s.users.GetByEmail(ctx, tenantID, strings.ToLower(du.Email)); gerr == nil {
				return existing, nil
			}
		}
		return repository.User{}, err
	}
	return u, nil
}

// offboard deactivates a local user and pushes a revocation so the ZTNA
// plane drops the user's sessions immediately. It is best-effort and
// idempotent: a soft-delete of an already-deleted user is a no-op and a
// failed revocation is recorded but never blocks the deactivation.
func (s *SyncService) offboard(ctx context.Context, tenantID uuid.UUID, local repository.User, reason string, report *SyncReport) {
	if _, err := s.users.Update(ctx, tenantID, repository.User{
		ID:     local.ID,
		Status: repository.UserStatusDeleted,
	}); err != nil {
		report.Errors = append(report.Errors, fmt.Errorf("offboard %s: %w", local.Email, err))
		return
	}
	report.UsersOffboarded++

	if s.revoker != nil {
		if err := s.revoker.PublishRevocation(ctx, tenantID, local.ID, reason); err != nil {
			report.Errors = append(report.Errors, fmt.Errorf("revoke %s: %w", local.Email, err))
		}
	}
	s.recordOffboardAudit(ctx, tenantID, local, reason)
}

func (s *SyncService) recordOffboardAudit(ctx context.Context, tenantID uuid.UUID, local repository.User, reason string) {
	details, _ := json.Marshal(map[string]string{
		"email":  local.Email,
		"reason": reason,
	})
	uid := local.ID
	if _, err := s.audit.Append(ctx, tenantID, repository.AuditEntry{
		ActorID:      &uid,
		Action:       "idp_sync.user.offboarded",
		ResourceType: "user",
		ResourceID:   &uid,
		Details:      details,
	}); err != nil {
		s.logger.Warn("idp_sync: audit append failed",
			slog.String("tenant_id", tenantID.String()), slog.Any("error", err))
	}
}
