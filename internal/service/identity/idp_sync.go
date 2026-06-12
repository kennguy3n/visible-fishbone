package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

// RolloutGate is the staged-enablement seam for the IdP directory-sync
// capability (#177, rollout.CapabilityIDPDirectorySync). SyncTenant
// consults it per tenant so enabling directory sync is a rehearsed
// monitor -> enforce progression rather than a binary flag:
//
//   - enforce — full sync: provision, reactivate, group-reconcile and
//     off-board exactly as before.
//   - monitor — dry-run: compute and report the would-have provisions /
//     off-boards but mutate NOTHING (no user create/update, no
//     revocation, no audit off-board row).
//   - off     — the tenant is skipped entirely (no directory read, no
//     mutation).
//
// GateState additionally reports whether the tenant is explicitly MANAGED
// by the framework (has a rollout row). An UNMANAGED tenant keeps the
// legacy full-sync behavior, so wiring the gate never silently stops
// directory sync — and the off-boarding it performs — for tenants that
// were already syncing; sync continues until an operator opts the tenant
// into the staged progression. GateState fails closed to (off, managed)
// on any read error, so an unreadable state can never silently off-board
// a tenant's users. EvaluateAutoRollback lets the monitor (dry-run) pass
// feed its observed error rate back to the framework so a capability that
// errors past the configured threshold is rolled back to off rather than
// promoted. A nil gate preserves the legacy behavior unconditionally.
type RolloutGate interface {
	GateState(ctx context.Context, tenantID uuid.UUID, c rollout.Capability) (rollout.State, bool)
	EvaluateAutoRollback(ctx context.Context, tenantID uuid.UUID, c rollout.Capability, m rollout.MonitorMetrics) (rollout.Record, bool, error)
}

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

// TenantActivitySource yields the cheap (id, last_active_at) projection
// the dormancy planner buckets by recency. repository.TenantRepository
// satisfies it; supplying one (via WithDormancyPlanner) switches the
// runner from "reconcile every tenant every cycle" to activity-tiered
// cadence, so dormant trials no longer cost a full fan-out each cycle.
type TenantActivitySource interface {
	ListTenantActivity(ctx context.Context) ([]repository.TenantActivity, error)
}

// SyncReport summarizes the outcome of reconciling one tenant.
type SyncReport struct {
	TenantID         uuid.UUID
	ConfigsProcessed int
	// ConfigsSkipped counts enabled provider configs that have no
	// directory credential stored. They are skipped (not synced and not
	// errored): an idp_configs row enables mobile native-SSO token
	// validation, which is independent of opting that provider into
	// directory sync.
	ConfigsSkipped   int
	UsersSeen        int
	UsersProvisioned int
	UsersOffboarded  int
	GroupsAssigned   int
	GroupsRevoked    int
	// State is the tenant's effective rollout state for the directory-sync
	// capability this pass ("off", "monitor", or "enforce"). Empty when no
	// rollout gate is wired (legacy full-sync behavior).
	State string
	// Skipped is true when the tenant was not synced at all because its
	// rollout state was off (the fail-closed default). No directory read
	// or mutation happened.
	Skipped bool
	// DryRun is true when the sync ran in monitor mode: the Would* counts
	// below are populated and NO mutation (provision/offboard/revocation/
	// audit) was performed. The UsersProvisioned / UsersOffboarded /
	// Groups* counters stay zero in a dry run.
	DryRun bool
	// WouldProvision / WouldOffboard are the provisions / off-boards a
	// monitor-mode (dry-run) pass would have performed had it been
	// enforcing. They give an operator the blast radius of promoting the
	// tenant to enforce.
	WouldProvision int
	WouldOffboard  int
	// AutoRolledBack is true when a monitor (dry-run) pass observed an
	// error rate past the framework's configured threshold and the gate
	// automatically rolled the directory-sync capability back to off for
	// this tenant. State then reflects the post-rollback state ("off").
	AutoRolledBack bool
	// MonitorErrorSamples counts dry-run error observations that did NOT
	// increment UsersSeen: a provider config that could not be read at all
	// (credential / client / list failure) or a directory entry with no
	// email. The auto-rollback denominator is UsersSeen + MonitorErrorSamples
	// so each such failure contributes to BOTH the numerator and the
	// denominator of the monitor error rate. Without it, an errored
	// observation would inflate the rate against a sample count it never
	// joined (e.g. one config failure beside healthy users), and a provider
	// that wholly fails (zero users, one error) would divide by zero and
	// escape rollback entirely instead of reading as a 100% error rate.
	MonitorErrorSamples int
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

	// Optional activity-tiered planning (see WithDormancyPlanner).
	// When planner+activity are both set, syncAll consults the planner
	// each cycle to skip tenants not yet due for their tier. When nil,
	// the runner falls back to the legacy "every tenant every cycle"
	// fan-out via tenants.ListTenants.
	planner  *tenancy.SweepPlanner
	activity TenantActivitySource
	// cycle is the monotonic 0-based sweep counter consumed by the
	// planner's cadence gate. Atomic because Run drives it but tests
	// may invoke syncAll concurrently.
	cycle atomic.Uint64

	// rolloutGate gates directory sync through the staged-enablement
	// framework (see RolloutGate). Optional: nil preserves the legacy
	// full-sync-every-tenant behavior.
	rolloutGate RolloutGate
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

// WithDormancyPlanner enables activity-tiered sweep cadence. Once set,
// each pass loads the cheap (id, last_active_at) projection from
// `activity` and lets `planner` decide which tenants are due this
// cycle: active tenants every cycle, idle/dormant ones at a reduced
// cadence. Cycle 0 (the immediate startup pass) always reconciles
// every tenant, so enabling this never delays a tenant's first sync.
// Passing a nil planner or activity source is a no-op (legacy
// every-tenant fan-out is retained), so wiring is fail-safe. Returns
// the receiver for chaining at construction.
func (s *SyncService) WithDormancyPlanner(planner *tenancy.SweepPlanner, activity TenantActivitySource) *SyncService {
	if planner != nil && activity != nil {
		s.planner = planner
		s.activity = activity
	}
	return s
}

// WithRolloutGate wires the staged-enablement gate for directory sync.
// Once set, each MANAGED tenant is synced per its rollout state for
// CapabilityIDPDirectorySync: off skips the tenant, monitor dry-runs the
// reconcile (no mutations) and feeds its error rate to the framework's
// auto-rollback guardrail, and enforce runs the full sync. A tenant the
// framework does not yet manage (no rollout row) keeps the legacy
// full-sync behavior, so wiring the gate never silently stops an
// already-syncing tenant. A nil gate is a no-op (legacy full-sync
// behavior retained), so wiring is fail-safe. Returns the receiver for
// chaining at construction.
func (s *SyncService) WithRolloutGate(gate RolloutGate) *SyncService {
	if gate != nil {
		s.rolloutGate = gate
	}
	return s
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

// syncAll reconciles the tenants due this cycle, logging (never
// propagating) per-tenant failures so one bad tenant cannot stall the
// runner. When a dormancy planner is configured it enumerates via the
// cheap activity projection and skips tenants not yet due for their
// tier; otherwise it falls back to the legacy full fan-out.
func (s *SyncService) syncAll(ctx context.Context) {
	cycle := int64(s.cycle.Add(1) - 1) // 0-based: first pass is cycle 0
	tenants, err := s.dueTenants(ctx, cycle)
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
		// Log when there is something to report: actual mutations (enforce),
		// would-have mutations (monitor dry-run blast radius), an automatic
		// rollback, or errors. Pure off/idle tenants stay quiet so the log
		// is not flooded at 5000-tenant scale. Including the would_* counts
		// and dry_run/state flags makes the monitor phase observable — the
		// whole point of the staged progression.
		if report.UsersOffboarded > 0 || report.UsersProvisioned > 0 ||
			report.WouldProvision > 0 || report.WouldOffboard > 0 ||
			report.AutoRolledBack || len(report.Errors) > 0 {
			s.logger.Info("idp_sync: tenant reconciled",
				slog.String("tenant_id", tid.String()),
				slog.String("state", report.State),
				slog.Bool("dry_run", report.DryRun),
				slog.Bool("auto_rolled_back", report.AutoRolledBack),
				slog.Int("seen", report.UsersSeen),
				slog.Int("provisioned", report.UsersProvisioned),
				slog.Int("offboarded", report.UsersOffboarded),
				slog.Int("would_provision", report.WouldProvision),
				slog.Int("would_offboard", report.WouldOffboard),
				slog.Int("groups_assigned", report.GroupsAssigned),
				slog.Int("groups_revoked", report.GroupsRevoked),
				slog.Int("errors", len(report.Errors)),
			)
		}
	}
}

// dueTenants returns the tenant ids to reconcile on `cycle`. With a
// dormancy planner configured it loads the cheap (id, last_active_at)
// projection and lets the planner gate by activity tier, logging how
// many tenants were skipped this cycle so the saving is observable.
// Without a planner it returns the full tenant list (legacy fan-out).
func (s *SyncService) dueTenants(ctx context.Context, cycle int64) ([]uuid.UUID, error) {
	if s.planner == nil || s.activity == nil {
		return s.tenants.ListTenants(ctx)
	}
	acts, err := s.activity.ListTenantActivity(ctx)
	if err != nil {
		return nil, err
	}
	now := s.nowFunc()
	due := s.planner.Plan(now, cycle, acts)
	if skipped := len(acts) - len(due); skipped > 0 {
		summary := s.planner.Summarize(now, cycle, acts)
		s.logger.Debug("idp_sync: activity-tiered sweep",
			slog.Int64("cycle", cycle),
			slog.Int("total", summary.Total),
			slog.Int("visited", summary.Visited),
			slog.Int("skipped", summary.Skipped),
			slog.Int("active", summary.Active),
			slog.Int("idle", summary.Idle),
			slog.Int("dormant", summary.Dormant),
		)
	}
	return due, nil
}

// SyncTenant reconciles all of a tenant's enabled IdP directories. It
// returns a report; per-config and per-user errors are collected in
// report.Errors rather than aborting, so a single failure does not
// leave the tenant half-reconciled.
func (s *SyncService) SyncTenant(ctx context.Context, tenantID uuid.UUID) (SyncReport, error) {
	report := SyncReport{TenantID: tenantID}

	// Staged-enablement gate: decide whether this tenant syncs at all,
	// and if so whether it enforces or only dry-runs. With no gate wired,
	// or for a tenant the framework does not yet manage (no rollout row),
	// the legacy full-sync behavior is preserved so wiring the gate never
	// silently stops an already-syncing tenant.
	if s.rolloutGate != nil {
		state, managed := s.rolloutGate.GateState(ctx, tenantID, rollout.CapabilityIDPDirectorySync)
		if managed {
			report.State = string(state)
			switch state {
			case rollout.StateOff:
				// Fail-closed default: do not read the directory or mutate
				// anything for an off tenant.
				report.Skipped = true
				return report, nil
			case rollout.StateMonitor:
				report.DryRun = true
			}
		}
	}

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
			// A config that could not be read is one failed observation
			// with no user behind it; fold it into the monitor sample space.
			report.MonitorErrorSamples++
		}
	}

	// Monitor-phase auto-rollback: feed the dry-run's observed error rate
	// back to the framework. An observation is one attempt to process a
	// directory entry or read a provider: the denominator is the users seen
	// PLUS the failures that had no user behind them (MonitorErrorSamples),
	// so the numerator (every error) and denominator are in the same unit.
	// Deny-rate does not apply (a would-off-board is the expected outcome,
	// not an error), so only the error-rate guardrail governs the rollback.
	// If it breaches the configured threshold the gate rolls the capability
	// back to off, preventing an operator from promoting a directory
	// integration that is erroring under dry-run to enforce. It only ever
	// acts in monitor and only moves the capability toward safety.
	if report.DryRun && s.rolloutGate != nil {
		metrics := rollout.MonitorMetrics{
			Samples: report.UsersSeen + report.MonitorErrorSamples,
			Errors:  len(report.Errors),
		}
		rec, rolled, rbErr := s.rolloutGate.EvaluateAutoRollback(ctx, tenantID, rollout.CapabilityIDPDirectorySync, metrics)
		switch {
		case rbErr != nil:
			s.logger.Warn("idp_sync: auto-rollback evaluation failed",
				slog.String("tenant_id", tenantID.String()), slog.Any("error", rbErr))
		case rolled:
			report.AutoRolledBack = true
			report.State = string(rec.State)
			s.logger.Warn("idp_sync: directory sync auto-rolled back to off",
				slog.String("tenant_id", tenantID.String()),
				slog.Int("seen", report.UsersSeen),
				slog.Int("errors", len(report.Errors)),
				slog.String("reason", rec.Reason))
		}
	}
	return report, nil
}

// syncConfig reconciles one provider directory for a tenant.
func (s *SyncService) syncConfig(ctx context.Context, tenantID uuid.UUID, cfg repository.IDPConfig, report *SyncReport) error {
	cred, err := s.creds.Resolve(ctx, tenantID, cfg)
	if errors.Is(err, ErrNoDirectoryCredential) {
		// Provider is enabled for token validation but not opted into
		// directory sync. Skip it quietly rather than erroring every cycle.
		report.ConfigsSkipped++
		return nil
	}
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

	// Monitor (dry-run): compute the would-have provisions / off-boards
	// and return WITHOUT building the role reconciler or taking any
	// mutating action. Branching here keeps the dry run provably
	// side-effect-free (no user/role writes, no revocation, no audit).
	if report.DryRun {
		s.reconcileDryRun(dirUsers, localByEmail, report)
		return nil
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

// reconcileDryRun is the monitor-phase counterpart of reconcile: it
// walks the same directory snapshot and local user set and counts the
// provisions and off-boards the enforce path WOULD perform, without
// mutating anything. The would-have arithmetic mirrors reconcile so the
// reported blast radius is exactly what promoting the tenant to enforce
// would do:
//   - an active directory user with no active local match -> provision.
//   - a deactivated directory user whose local user is still active ->
//     off-board.
//   - an active local user the directory no longer lists -> off-board.
//
// Group reconciliation and reactivation are not counted: they refine an
// already-provisioned user rather than provisioning or off-boarding one,
// so they do not change the off-board blast radius an operator weighs
// before promoting to enforce.
func (s *SyncService) reconcileDryRun(dirUsers []DirectoryUser, localByEmail map[string]repository.User, report *SyncReport) {
	seen := make(map[string]struct{}, len(dirUsers))
	for _, du := range dirUsers {
		email := strings.ToLower(strings.TrimSpace(du.Email))
		if email == "" {
			report.Errors = append(report.Errors, fmt.Errorf("directory user %q has no email", du.ExternalID))
			// An entry we could not process is one failed observation with
			// no usable user behind it; fold it into the monitor sample
			// space so it is not counted in the numerator alone.
			report.MonitorErrorSamples++
			continue
		}
		seen[email] = struct{}{}
		report.UsersSeen++

		local, ok := localByEmail[email]
		if !du.Active {
			// Deactivated upstream: would off-board only a still-active
			// local user (deactivating an already-inactive user is a no-op).
			if ok && local.Status == repository.UserStatusActive {
				report.WouldOffboard++
			}
			continue
		}
		if !ok {
			report.WouldProvision++
		}
	}

	// Active local users the directory no longer lists would be off-boarded.
	for email, local := range localByEmail {
		if _, ok := seen[email]; ok {
			continue
		}
		if local.Status != repository.UserStatusActive {
			continue
		}
		report.WouldOffboard++
	}
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
