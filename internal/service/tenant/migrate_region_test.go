package tenant_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

// --- fakes -----------------------------------------------------------------

// recordingPlane is a fake that satisfies all five plane ports at once
// (each method is independently selectable in a MigrationPlanes literal)
// and records the order of forward/rollback calls. A failAt name makes
// that step's forward return an error; failRollback makes that step's
// rollback return an error.
type recordingPlane struct {
	mu           sync.Mutex
	calls        []string
	failForward  map[string]error
	failRollback map[string]error
}

func newRecordingPlane() *recordingPlane {
	return &recordingPlane{failForward: map[string]error{}, failRollback: map[string]error{}}
}

func (r *recordingPlane) log(s string) {
	r.mu.Lock()
	r.calls = append(r.calls, s)
	r.mu.Unlock()
}

func (r *recordingPlane) sequence() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

func (r *recordingPlane) fwd(name string, meta json.RawMessage) (json.RawMessage, error) {
	r.log("forward:" + name)
	if err := r.failForward[name]; err != nil {
		return nil, err
	}
	return meta, nil
}

func (r *recordingPlane) rbk(name string) error {
	r.log("rollback:" + name)
	return r.failRollback[name]
}

// Keys plane.
func (r *recordingPlane) Rewrap(_ context.Context, _ uuid.UUID, _, _ string) (json.RawMessage, error) {
	return r.fwd("rewrap_keys", json.RawMessage(`{"rewrapped":3}`))
}
func (r *recordingPlane) Restore(_ context.Context, _ uuid.UUID, _, _ string) error {
	return r.rbk("rewrap_keys")
}

// Telemetry plane.
func (r *recordingPlane) Copy(_ context.Context, _ uuid.UUID, _, _ string) (json.RawMessage, error) {
	return r.fwd("copy_telemetry", nil)
}

// Purge satisfies both TelemetryCopyPlane and ObjectCopyPlane; we route
// by a per-instance flag set when used as the object plane. To keep the
// two distinct in a single struct we instead use separate wrappers
// below, so this method is for the telemetry plane.
func (r *recordingPlane) Purge(_ context.Context, _ uuid.UUID, _, _ string) error {
	return r.rbk("copy_telemetry")
}

// objectPlane wraps recordingPlane to provide the object Copy/Purge
// under distinct step names, since ObjectCopyPlane and TelemetryCopyPlane
// share method signatures.
type objectPlane struct{ r *recordingPlane }

func (o objectPlane) Copy(_ context.Context, _ uuid.UUID, _, _ string) (json.RawMessage, error) {
	return o.r.fwd("copy_objects", nil)
}
func (o objectPlane) Purge(_ context.Context, _ uuid.UUID, _, _ string) error {
	return o.r.rbk("copy_objects")
}

// popPlane.
type popPlane struct{ r *recordingPlane }

func (p popPlane) Reassign(_ context.Context, _ uuid.UUID, _ string) (json.RawMessage, error) {
	return p.r.fwd("reassign_pop", json.RawMessage(`{"new_pop_id":"x"}`))
}
func (p popPlane) Restore(_ context.Context, _ uuid.UUID, _ json.RawMessage) error {
	return p.r.rbk("reassign_pop")
}

// regionPlane records the region set and, optionally, persists it into a
// backing tenant repo so the happy-path test can assert the column flip.
type regionPlane struct {
	r        *recordingPlane
	tenants  repository.TenantRepository
	mu       sync.Mutex
	lastSet  string
	setCalls []string
}

func (g *regionPlane) SetRegion(ctx context.Context, tenantID uuid.UUID, region string) error {
	g.r.log("forward:update_region:" + region)
	g.mu.Lock()
	g.lastSet = region
	g.setCalls = append(g.setCalls, region)
	g.mu.Unlock()
	if g.tenants != nil {
		reg := region
		if _, err := g.tenants.Update(ctx, tenantID, repository.TenantPatch{Region: &reg}); err != nil {
			return err
		}
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

func newMigrator(t *testing.T, planes tenant.MigrationPlanes) (*tenant.RegionMigrator, *memory.Store, repository.TenantRepository) {
	t.Helper()
	s := memory.NewStore()
	tenants := memory.NewTenantRepository(s)
	migs := memory.NewTenantMigrationRepository(s)
	audit := memory.NewAuditLogRepository(s)
	m, err := tenant.NewRegionMigrator(migs, tenants, audit, planes, nil)
	if err != nil {
		t.Fatalf("NewRegionMigrator: %v", err)
	}
	return m, s, tenants
}

func seedTenant(t *testing.T, tenants repository.TenantRepository, region string) repository.Tenant {
	t.Helper()
	tnt, err := tenants.Create(context.Background(), repository.Tenant{
		Name:   "Acme",
		Slug:   "acme-" + uuid.NewString()[:8],
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
		Region: region,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return tnt
}

// --- tests -----------------------------------------------------------------

func TestRegionMigration_HappyPath(t *testing.T) {
	t.Parallel()
	rec := newRecordingPlane()
	m, _, tenants := func() (*tenant.RegionMigrator, *memory.Store, repository.TenantRepository) {
		s := memory.NewStore()
		tenants := memory.NewTenantRepository(s)
		migs := memory.NewTenantMigrationRepository(s)
		audit := memory.NewAuditLogRepository(s)
		gp := &regionPlane{r: rec, tenants: tenants}
		m, err := tenant.NewRegionMigrator(migs, tenants, audit, tenant.MigrationPlanes{
			Keys:      rec,
			Telemetry: rec,
			Objects:   objectPlane{rec},
			PoP:       popPlane{rec},
			Region:    gp,
		}, nil)
		if err != nil {
			t.Fatalf("NewRegionMigrator: %v", err)
		}
		return m, s, tenants
	}()

	tnt := seedTenant(t, tenants, "us-east-1")
	ctx := context.Background()

	got, err := m.Start(ctx, tnt.ID, "eu-central-1")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if got.State != repository.MigrationStateCompleted {
		t.Fatalf("final state = %q, want completed", got.State)
	}
	if got.DualRead {
		t.Errorf("dual_read should be cleared on completion")
	}
	if got.CompletedAt == nil {
		t.Errorf("completed_at should be set")
	}
	if got.SourceRegion != "us-east-1" || got.TargetRegion != "eu-central-1" {
		t.Errorf("regions = %q -> %q", got.SourceRegion, got.TargetRegion)
	}

	// Forward steps ran in pipeline order; no rollbacks.
	want := []string{
		"forward:rewrap_keys",
		"forward:copy_telemetry",
		"forward:copy_objects",
		"forward:reassign_pop",
		"forward:update_region:eu-central-1",
	}
	if got := rec.sequence(); !equalSeq(got, want) {
		t.Errorf("call sequence = %v, want %v", got, want)
	}

	// Region column was actually flipped.
	after, err := tenants.Get(ctx, tnt.ID)
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if after.Region != "eu-central-1" {
		t.Errorf("tenant region = %q, want eu-central-1", after.Region)
	}

	// Checkpoint records every step done.
	var cp struct {
		Steps map[string]struct {
			Status string `json:"status"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(got.Checkpoint, &cp); err != nil {
		t.Fatalf("decode checkpoint: %v", err)
	}
	for _, name := range []string{"rewrap_keys", "copy_telemetry", "copy_objects", "reassign_pop", "update_region"} {
		if cp.Steps[name].Status != "done" {
			t.Errorf("step %q status = %q, want done", name, cp.Steps[name].Status)
		}
	}
}

func TestRegionMigration_Conflict(t *testing.T) {
	t.Parallel()
	rec := newRecordingPlane()
	m, s, tenants := newMigrator(t, tenant.MigrationPlanes{Region: &regionPlane{r: rec}})
	tnt := seedTenant(t, tenants, "us-east-1")
	ctx := context.Background()

	// Seed an in-flight (non-terminal) migration directly so a fresh
	// Start collides with the single-in-flight invariant.
	migs := memory.NewTenantMigrationRepository(s)
	if _, err := migs.Create(ctx, tnt.ID, repository.TenantMigration{
		SourceRegion: "us-east-1", TargetRegion: "eu-central-1",
		State: repository.MigrationStateCopyingObjects, DualRead: true,
	}); err != nil {
		t.Fatalf("seed migration: %v", err)
	}

	_, err := m.Start(ctx, tnt.ID, "eu-central-2")
	if !errors.Is(err, tenant.ErrMigrationInProgress) {
		t.Fatalf("Start err = %v, want ErrMigrationInProgress", err)
	}
}

func TestRegionMigration_SourceUnset(t *testing.T) {
	t.Parallel()
	rec := newRecordingPlane()
	m, _, tenants := newMigrator(t, tenant.MigrationPlanes{Region: &regionPlane{r: rec}})
	tnt := seedTenant(t, tenants, "")
	_, err := m.Start(context.Background(), tnt.ID, "eu-central-1")
	if !errors.Is(err, tenant.ErrSourceRegionUnset) {
		t.Fatalf("Start err = %v, want ErrSourceRegionUnset", err)
	}
}

func TestRegionMigration_SameRegionRejected(t *testing.T) {
	t.Parallel()
	rec := newRecordingPlane()
	m, _, tenants := newMigrator(t, tenant.MigrationPlanes{Region: &regionPlane{r: rec}})
	tnt := seedTenant(t, tenants, "us-east-1")
	_, err := m.Start(context.Background(), tnt.ID, "US-East-1") // case-insensitive
	if !errors.Is(err, repository.ErrInvalidArgument) {
		t.Fatalf("Start err = %v, want ErrInvalidArgument", err)
	}
}

func TestRegionMigration_RollbackOnFailure(t *testing.T) {
	t.Parallel()
	rec := newRecordingPlane()
	rec.failForward["copy_objects"] = errors.New("boom: s3 copy failed")
	gp := &regionPlane{r: rec}
	m, _, tenants := newMigrator(t, tenant.MigrationPlanes{
		Keys:      rec,
		Telemetry: rec,
		Objects:   objectPlane{rec},
		PoP:       popPlane{rec},
		Region:    gp,
	})
	tnt := seedTenant(t, tenants, "us-east-1")
	ctx := context.Background()

	got, err := m.Start(ctx, tnt.ID, "eu-central-1")
	if err == nil || err.Error() != "boom: s3 copy failed" {
		t.Fatalf("Start err = %v, want the original cause", err)
	}
	if got.State != repository.MigrationStateRolledBack {
		t.Fatalf("final state = %q, want rolled_back", got.State)
	}
	if got.DualRead {
		t.Errorf("dual_read should be cleared on terminal state")
	}
	// region step never ran (it is after copy_objects), so no region flip.
	if gp.lastSet != "" {
		t.Errorf("region should not have been changed, got %q", gp.lastSet)
	}
	// Completed forward steps (keys, telemetry) rolled back in reverse;
	// the failing step (copy_objects forward) is recorded but its
	// forward failed so it is NOT rolled back.
	seq := rec.sequence()
	wantPrefix := []string{
		"forward:rewrap_keys",
		"forward:copy_telemetry",
		"forward:copy_objects", // failed
		"rollback:copy_telemetry",
		"rollback:rewrap_keys",
	}
	if !equalSeq(seq, wantPrefix) {
		t.Errorf("call sequence = %v, want %v", seq, wantPrefix)
	}
}

func TestRegionMigration_RollbackFailureMarksFailed(t *testing.T) {
	t.Parallel()
	rec := newRecordingPlane()
	rec.failForward["reassign_pop"] = errors.New("pop boom")
	rec.failRollback["copy_telemetry"] = errors.New("cannot purge telemetry")
	gp := &regionPlane{r: rec}
	m, _, tenants := newMigrator(t, tenant.MigrationPlanes{
		Keys:      rec,
		Telemetry: rec,
		Objects:   objectPlane{rec},
		PoP:       popPlane{rec},
		Region:    gp,
	})
	tnt := seedTenant(t, tenants, "us-east-1")
	got, err := m.Start(context.Background(), tnt.ID, "eu-central-1")
	if err == nil || err.Error() != "pop boom" {
		t.Fatalf("Start err = %v, want original cause 'pop boom'", err)
	}
	if got.State != repository.MigrationStateFailed {
		t.Fatalf("final state = %q, want failed", got.State)
	}
}

func TestRegionMigration_ResumeIdempotent(t *testing.T) {
	t.Parallel()
	rec := newRecordingPlane()
	gp := &regionPlane{r: rec}
	m, s, tenants := newMigrator(t, tenant.MigrationPlanes{
		Keys:      rec,
		Telemetry: rec,
		Objects:   objectPlane{rec},
		PoP:       popPlane{rec},
		Region:    gp,
	})
	tnt := seedTenant(t, tenants, "us-east-1")
	ctx := context.Background()

	// Seed a migration whose first two steps already completed.
	migs := memory.NewTenantMigrationRepository(s)
	cp := `{"steps":{"rewrap_keys":{"status":"done"},"copy_telemetry":{"status":"done"}}}`
	if _, err := migs.Create(ctx, tnt.ID, repository.TenantMigration{
		SourceRegion: "us-east-1", TargetRegion: "eu-central-1",
		State: repository.MigrationStateCopyingTelemetry, DualRead: true,
		Checkpoint: json.RawMessage(cp),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	got, err := m.Resume(ctx, tnt.ID)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if got.State != repository.MigrationStateCompleted {
		t.Fatalf("state = %q, want completed", got.State)
	}
	// Only the not-yet-done steps ran.
	want := []string{
		"forward:copy_objects",
		"forward:reassign_pop",
		"forward:update_region:eu-central-1",
	}
	if seq := rec.sequence(); !equalSeq(seq, want) {
		t.Errorf("resume sequence = %v, want %v", seq, want)
	}
}

func TestRegionMigration_DualReadReporting(t *testing.T) {
	t.Parallel()
	rec := newRecordingPlane()
	m, s, tenants := newMigrator(t, tenant.MigrationPlanes{Region: &regionPlane{r: rec}})
	tnt := seedTenant(t, tenants, "us-east-1")
	ctx := context.Background()

	// No migration yet: not dual-reading.
	if _, _, active, err := m.DualRead(ctx, tnt.ID); err != nil || active {
		t.Fatalf("DualRead active=%v err=%v, want inactive", active, err)
	}

	migs := memory.NewTenantMigrationRepository(s)
	if _, err := migs.Create(ctx, tnt.ID, repository.TenantMigration{
		SourceRegion: "us-east-1", TargetRegion: "eu-central-1",
		State: repository.MigrationStateCopyingObjects, DualRead: true,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	src, tgt, active, err := m.DualRead(ctx, tnt.ID)
	if err != nil || !active || src != "us-east-1" || tgt != "eu-central-1" {
		t.Fatalf("DualRead = (%q,%q,%v,%v), want (us-east-1,eu-central-1,true,nil)", src, tgt, active, err)
	}
}

func TestRegionMigration_StatusNotFound(t *testing.T) {
	t.Parallel()
	rec := newRecordingPlane()
	m, _, tenants := newMigrator(t, tenant.MigrationPlanes{Region: &regionPlane{r: rec}})
	tnt := seedTenant(t, tenants, "us-east-1")
	_, err := m.MigrationStatus(context.Background(), tnt.ID)
	if !errors.Is(err, tenant.ErrNoMigration) {
		t.Fatalf("MigrationStatus err = %v, want ErrNoMigration", err)
	}
}

func TestRegionMigration_ResumeAll(t *testing.T) {
	t.Parallel()
	rec := newRecordingPlane()
	gp := &regionPlane{r: rec}
	m, s, tenants := newMigrator(t, tenant.MigrationPlanes{
		Keys: rec, Telemetry: rec, Objects: objectPlane{rec}, PoP: popPlane{rec}, Region: gp,
	})
	ctx := context.Background()
	migs := memory.NewTenantMigrationRepository(s)
	for i := 0; i < 3; i++ {
		tnt := seedTenant(t, tenants, "us-east-1")
		if _, err := migs.Create(ctx, tnt.ID, repository.TenantMigration{
			SourceRegion: "us-east-1", TargetRegion: "eu-central-1",
			State: repository.MigrationStatePending, DualRead: true,
		}); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
	n, err := m.ResumeAll(ctx)
	if err != nil {
		t.Fatalf("ResumeAll: %v", err)
	}
	if n != 3 {
		t.Fatalf("ResumeAll drove %d, want 3", n)
	}
	// All three reach completed; none left resumable.
	left, err := migs.ListResumable(ctx)
	if err != nil {
		t.Fatalf("ListResumable: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("resumable left = %d, want 0", len(left))
	}
}

// --- PoP reassigner adapter ------------------------------------------------

type fakePoPControl struct {
	pops       []tenant.PoPInfo
	assignment map[uuid.UUID]uuid.UUID
	setCalls   []string
}

func (f *fakePoPControl) AvailablePoPs() []tenant.PoPInfo { return f.pops }
func (f *fakePoPControl) CurrentAssignment(_ context.Context, tenantID uuid.UUID) (uuid.UUID, bool, error) {
	id, ok := f.assignment[tenantID]
	return id, ok, nil
}
func (f *fakePoPControl) SetAssignment(_ context.Context, tenantID, popID uuid.UUID) error {
	if f.assignment == nil {
		f.assignment = map[uuid.UUID]uuid.UUID{}
	}
	f.assignment[tenantID] = popID
	f.setCalls = append(f.setCalls, fmt.Sprintf("%s->%s", tenantID, popID))
	return nil
}

func TestPoPReassigner_ReassignAndRestore(t *testing.T) {
	t.Parallel()
	srcPoP := uuid.New()
	tgtPoP := uuid.New()
	tnt := uuid.New()
	ctrl := &fakePoPControl{
		pops: []tenant.PoPInfo{
			{ID: srcPoP, Region: "us-east-1"},
			{ID: tgtPoP, Region: "eu-central-1"},
		},
		assignment: map[uuid.UUID]uuid.UUID{tnt: srcPoP},
	}
	p := tenant.NewPoPReassigner(ctrl)
	ctx := context.Background()

	meta, err := p.Reassign(ctx, tnt, "eu-central-1")
	if err != nil {
		t.Fatalf("Reassign: %v", err)
	}
	if ctrl.assignment[tnt] != tgtPoP {
		t.Fatalf("tenant pinned to %v, want target %v", ctrl.assignment[tnt], tgtPoP)
	}
	// Restore puts it back.
	if err := p.Restore(ctx, tnt, meta); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if ctrl.assignment[tnt] != srcPoP {
		t.Fatalf("after restore pinned to %v, want source %v", ctrl.assignment[tnt], srcPoP)
	}
}

func TestPoPReassigner_NoTargetRegionPoPIsNoOp(t *testing.T) {
	t.Parallel()
	srcPoP := uuid.New()
	tnt := uuid.New()
	ctrl := &fakePoPControl{
		pops:       []tenant.PoPInfo{{ID: srcPoP, Region: "us-east-1"}},
		assignment: map[uuid.UUID]uuid.UUID{tnt: srcPoP},
	}
	p := tenant.NewPoPReassigner(ctrl)
	if _, err := p.Reassign(context.Background(), tnt, "eu-central-1"); err != nil {
		t.Fatalf("Reassign: %v", err)
	}
	if ctrl.assignment[tnt] != srcPoP {
		t.Errorf("tenant should stay on source PoP when no target-region PoP exists")
	}
}

// --- region column plane adapter -------------------------------------------

func TestRegionColumnPlane_SetsRegion(t *testing.T) {
	t.Parallel()
	s := memory.NewStore()
	tenants := memory.NewTenantRepository(s)
	tnt := seedTenant(t, tenants, "us-east-1")
	p := tenant.NewRegionColumnPlane(tenants)
	if err := p.SetRegion(context.Background(), tnt.ID, "eu-central-1"); err != nil {
		t.Fatalf("SetRegion: %v", err)
	}
	got, err := tenants.Get(context.Background(), tnt.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Region != "eu-central-1" {
		t.Errorf("region = %q, want eu-central-1", got.Region)
	}
}

// --- helpers ---------------------------------------------------------------

func equalSeq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
