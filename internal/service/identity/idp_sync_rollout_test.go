package identity

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/rollout"
)

// perIssuerFactory hands out a distinct fake directory client per provider
// issuer URL, so a multi-config tenant can mix a healthy provider with one
// that fails to list users.
type perIssuerFactory struct {
	clients map[string]*fakeDirectoryClient
}

func (f perIssuerFactory) Build(cfg repository.IDPConfig, _ DirectoryCredential) (DirectoryClient, error) {
	if c, ok := f.clients[cfg.IssuerURL]; ok {
		return c, nil
	}
	return &fakeDirectoryClient{}, nil
}

// rolloutSyncFixture wires a SyncService to a real rollout.Service gate so
// the staged-enablement seam is exercised end-to-end (not against a stub).
type rolloutSyncFixture struct {
	svc    *SyncService
	gate   *rollout.Service
	users  repository.UserRepository
	client *fakeDirectoryClient
	tid    uuid.UUID
}

func newRolloutSyncFixture(t *testing.T, opts ...rollout.Option) *rolloutSyncFixture {
	t.Helper()
	store := memory.NewStore()
	tn, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "Rollout Sync", Slug: "rollout-sync", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	configs := memory.NewIDPConfigRepository(store)
	if _, err := configs.Create(context.Background(), tn.ID, repository.IDPConfig{
		ProviderType: repository.IDPProviderOkta,
		IssuerURL:    "https://acme.okta.com",
		ClientID:     "client-okta",
		Enabled:      true,
	}); err != nil {
		t.Fatalf("seed idp config: %v", err)
	}

	gate, err := rollout.New(memory.NewCapabilityRolloutRepository(), opts...)
	if err != nil {
		t.Fatalf("new rollout service: %v", err)
	}
	client := &fakeDirectoryClient{}
	users := memory.NewUserRepository(store)
	svc := NewSyncService(
		configs, users, memory.NewRoleRepository(store), memory.NewAuditLogRepository(store),
		singleTenant{id: tn.ID}, staticCreds{}, fakeFactory{client: client}, newCapturePublisher(), nil,
	).WithRolloutGate(gate)

	return &rolloutSyncFixture{svc: svc, gate: gate, users: users, client: client, tid: tn.ID}
}

func (f *rolloutSyncFixture) transition(t *testing.T, to rollout.State, allowSkip bool) {
	t.Helper()
	if _, err := f.gate.Transition(context.Background(), f.tid, rollout.CapabilityIDPDirectorySync,
		rollout.TransitionInput{To: to, AllowSkip: allowSkip, Actor: "op"}); err != nil {
		t.Fatalf("transition to %s: %v", to, err)
	}
}

// A tenant the framework does not yet manage (no rollout row) must keep
// the legacy full-sync behavior even with the gate wired — wiring the gate
// cannot silently stop directory sync for an already-syncing tenant. This
// is the regression Devin Review flagged.
func TestSyncTenant_UnmanagedKeepsLegacyFullSync(t *testing.T) {
	f := newRolloutSyncFixture(t)
	f.client.users = []DirectoryUser{{ExternalID: "okta-1", Email: "alice@example.com", Active: true}}

	report, err := f.svc.SyncTenant(context.Background(), f.tid)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if report.Skipped || report.DryRun {
		t.Fatalf("unmanaged tenant must full-sync; got skipped=%v dry_run=%v", report.Skipped, report.DryRun)
	}
	if report.UsersProvisioned != 1 {
		t.Fatalf("unmanaged tenant provisioned = %d, want 1 (legacy full sync)", report.UsersProvisioned)
	}
	if report.State != "" {
		t.Fatalf("unmanaged tenant State = %q, want empty (not framework-managed)", report.State)
	}
}

// A MANAGED tenant explicitly at off is skipped: no directory read, no
// mutation.
func TestSyncTenant_ManagedOffSkips(t *testing.T) {
	f := newRolloutSyncFixture(t)
	// monitor -> off makes the tenant managed-and-off.
	f.transition(t, rollout.StateMonitor, false)
	f.transition(t, rollout.StateOff, false)
	f.client.users = []DirectoryUser{{ExternalID: "okta-1", Email: "alice@example.com", Active: true}}

	report, err := f.svc.SyncTenant(context.Background(), f.tid)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if !report.Skipped || report.UsersProvisioned != 0 || report.UsersSeen != 0 {
		t.Fatalf("managed-off tenant must be skipped with no work; got %+v", report)
	}
	if report.State != string(rollout.StateOff) {
		t.Fatalf("State = %q, want off", report.State)
	}
}

// A MANAGED tenant in monitor dry-runs: it reports the would-have blast
// radius but provisions nothing.
func TestSyncTenant_ManagedMonitorDryRuns(t *testing.T) {
	f := newRolloutSyncFixture(t)
	f.transition(t, rollout.StateMonitor, false)
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: true},
		{ExternalID: "okta-2", Email: "bob@example.com", Active: true},
	}

	report, err := f.svc.SyncTenant(context.Background(), f.tid)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if !report.DryRun || report.State != string(rollout.StateMonitor) {
		t.Fatalf("monitor tenant must dry-run; got dry_run=%v state=%q", report.DryRun, report.State)
	}
	if report.WouldProvision != 2 {
		t.Fatalf("WouldProvision = %d, want 2 (blast radius)", report.WouldProvision)
	}
	if report.UsersProvisioned != 0 {
		t.Fatalf("dry-run must not provision; got %d", report.UsersProvisioned)
	}
	// No user was actually written.
	if _, err := f.users.GetByEmail(context.Background(), f.tid, "alice@example.com"); err == nil {
		t.Fatal("dry-run provisioned a user; want no mutation")
	}
}

// A monitor pass whose error rate breaches the configured threshold must
// auto-roll the capability back to off — the framework's only automatic
// transition, and only ever toward safety. This proves the threshold is
// live (Devin Review flagged it as configured-but-never-called).
func TestSyncTenant_MonitorAutoRollsBackOnErrorBreach(t *testing.T) {
	f := newRolloutSyncFixture(t, rollout.WithThreshold(rollout.Threshold{
		MaxErrorRate: 0.1,
		MinSamples:   1,
	}))
	f.transition(t, rollout.StateMonitor, false)
	// One valid user (UsersSeen=1) and one empty-email entry. The empty
	// entry is both an error and a sample (MonitorErrorSamples=1), so the
	// rate is 1/(1+1)=0.5 > 0.1, which breaches over 2 coherent samples.
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: true},
		{ExternalID: "okta-broken", Email: "", Active: true},
	}

	report, err := f.svc.SyncTenant(context.Background(), f.tid)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if !report.AutoRolledBack {
		t.Fatalf("expected auto-rollback on error breach; report=%+v", report)
	}
	if report.State != string(rollout.StateOff) {
		t.Fatalf("post-rollback State = %q, want off", report.State)
	}
	// The capability is now persisted as off, by the system actor.
	rec, err := f.gate.Get(context.Background(), f.tid, rollout.CapabilityIDPDirectorySync)
	if err != nil {
		t.Fatalf("get post-rollback record: %v", err)
	}
	if rec.State != rollout.StateOff || rec.UpdatedBy != rollout.SystemActor {
		t.Fatalf("persisted record = %+v, want off by system actor", rec)
	}
}

// A healthy monitor pass under a configured threshold does NOT roll back:
// auto-rollback only fires on a breach.
func TestSyncTenant_MonitorHealthyDoesNotRollBack(t *testing.T) {
	f := newRolloutSyncFixture(t, rollout.WithThreshold(rollout.Threshold{
		MaxErrorRate: 0.5,
		MinSamples:   1,
	}))
	f.transition(t, rollout.StateMonitor, false)
	f.client.users = []DirectoryUser{
		{ExternalID: "okta-1", Email: "alice@example.com", Active: true},
		{ExternalID: "okta-2", Email: "bob@example.com", Active: true},
	}

	report, err := f.svc.SyncTenant(context.Background(), f.tid)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if report.AutoRolledBack {
		t.Fatalf("healthy monitor pass must not roll back; report=%+v", report)
	}
	if report.State != string(rollout.StateMonitor) {
		t.Fatalf("State = %q, want monitor (unchanged)", report.State)
	}
}

// A provider that wholly fails to read (a config-level error, zero users
// seen) must still auto-roll-back: the failed read is one errored sample,
// so the rate is 1/1=100%. The earlier denominator of UsersSeen alone made
// this divide by zero and escape rollback entirely — the coherence fix
// Devin Review flagged.
func TestSyncTenant_MonitorConfigErrorCountsAsSample(t *testing.T) {
	f := newRolloutSyncFixture(t, rollout.WithThreshold(rollout.Threshold{
		MaxErrorRate: 0.5,
		MinSamples:   1,
	}))
	f.transition(t, rollout.StateMonitor, false)
	// The only provider fails to list users: a config-level error with no
	// user behind it. UsersSeen=0, MonitorErrorSamples=1, Errors=1.
	f.client.err = errors.New("directory unreachable")

	report, err := f.svc.SyncTenant(context.Background(), f.tid)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	if report.UsersSeen != 0 || report.MonitorErrorSamples != 1 || len(report.Errors) != 1 {
		t.Fatalf("want 0 seen / 1 error-sample / 1 error; got %+v", report)
	}
	if !report.AutoRolledBack {
		t.Fatalf("a wholly-failing provider must roll back (rate 1/1); report=%+v", report)
	}
	if report.State != string(rollout.StateOff) {
		t.Fatalf("post-rollback State = %q, want off", report.State)
	}
}

// A single config-level failure beside healthy users must NOT breach a
// threshold it would only cross if the failure were counted in the
// numerator alone. Here the error joins the denominator too, keeping the
// rate proportional. (Two configs: one fails to list, one returns users.)
func TestSyncTenant_MonitorConfigErrorDoesNotInflateRate(t *testing.T) {
	store := memory.NewStore()
	tn, err := memory.NewTenantRepository(store).Create(context.Background(), repository.Tenant{
		Name: "Coherent Rate", Slug: "coherent-rate", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	configs := memory.NewIDPConfigRepository(store)
	// Healthy provider: returns four active users.
	if _, err := configs.Create(context.Background(), tn.ID, repository.IDPConfig{
		ProviderType: repository.IDPProviderOkta, IssuerURL: "https://ok.okta.com", ClientID: "ok", Enabled: true,
	}); err != nil {
		t.Fatalf("seed healthy config: %v", err)
	}
	// Broken provider: fails to list users (one config-level error).
	if _, err := configs.Create(context.Background(), tn.ID, repository.IDPConfig{
		ProviderType: repository.IDPProviderMicrosoft365, IssuerURL: "https://bad.example.com", ClientID: "bad", Enabled: true,
	}); err != nil {
		t.Fatalf("seed broken config: %v", err)
	}

	gate, err := rollout.New(memory.NewCapabilityRolloutRepository(), rollout.WithThreshold(rollout.Threshold{
		MaxErrorRate: 0.2, MinSamples: 1,
	}))
	if err != nil {
		t.Fatalf("new rollout service: %v", err)
	}
	users := memory.NewUserRepository(store)
	svc := NewSyncService(
		configs, users, memory.NewRoleRepository(store), memory.NewAuditLogRepository(store),
		singleTenant{id: tn.ID}, staticCreds{}, perIssuerFactory{
			clients: map[string]*fakeDirectoryClient{
				"https://ok.okta.com": {users: []DirectoryUser{
					{ExternalID: "u1", Email: "a@x.com", Active: true},
					{ExternalID: "u2", Email: "b@x.com", Active: true},
					{ExternalID: "u3", Email: "c@x.com", Active: true},
					{ExternalID: "u4", Email: "d@x.com", Active: true},
				}},
				"https://bad.example.com": {err: errors.New("directory unreachable")},
			},
		}, newCapturePublisher(), nil,
	).WithRolloutGate(gate)
	if _, err := gate.Transition(context.Background(), tn.ID, rollout.CapabilityIDPDirectorySync,
		rollout.TransitionInput{To: rollout.StateMonitor, Actor: "op"}); err != nil {
		t.Fatalf("transition: %v", err)
	}

	report, err := svc.SyncTenant(context.Background(), tn.ID)
	if err != nil {
		t.Fatalf("SyncTenant: %v", err)
	}
	// 1 error over (4 seen + 1 error-sample) = 0.2, which is NOT > 0.2.
	if report.UsersSeen != 4 || report.MonitorErrorSamples != 1 || len(report.Errors) != 1 {
		t.Fatalf("want 4 seen / 1 error-sample / 1 error; got %+v", report)
	}
	if report.AutoRolledBack {
		t.Fatalf("one config failure beside 4 healthy users must not breach 20%%; report=%+v", report)
	}
}
