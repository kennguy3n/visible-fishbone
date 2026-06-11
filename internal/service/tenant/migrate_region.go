package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/residency"
)

// ErrMigrationInProgress is returned by Start when the tenant already
// has a non-terminal migration. Callers (the HTTP handler) map it to
// 409 Conflict.
var ErrMigrationInProgress = errors.New("tenant: a migration is already in progress")

// ErrNoMigration is returned by MigrationStatus / Resume when the
// tenant has no migration on record.
var ErrNoMigration = errors.New("tenant: no migration found")

// ErrSourceRegionUnset is returned by Start when the tenant has no
// residency region designated. A cross-region migration moves data
// FROM a known region; without a source there is nothing to migrate
// (the operator should simply set the tenant's region instead).
var ErrSourceRegionUnset = errors.New("tenant: tenant has no source region (residency) to migrate from")

// errResumedMidRollback is the synthetic cause used when a migration is
// resumed while already in the rolling_back state but its persisted
// Detail (which carries the original forward-step cause) is empty. It
// only ever surfaces in logs/audit for a migration whose original cause
// was somehow lost, never to an API caller.
var errResumedMidRollback = errors.New("tenant: migration resumed while rolling back")

// Step lifecycle statuses persisted inside the migration checkpoint.
//   - stepStatusDone: the forward step completed; a resumed run skips it
//     and a rollback undoes it.
//   - stepStatusAttempted: the forward step started but errored partway,
//     so it may have produced partial side-effects in the target region
//     (e.g. some ClickHouse partitions or S3 objects copied). It is NOT
//     "done", but rollback MUST still invoke its undo so those partial
//     side-effects are purged rather than orphaned.
//   - stepStatusRolledBack: the step (done or attempted) was undone.
const (
	stepStatusDone       = "done"
	stepStatusAttempted  = "attempted"
	stepStatusRolledBack = "rolled_back"
)

// checkpoint is the JSON document persisted in
// tenant_migrations.checkpoint. It records, per step name, whether the
// step completed and any metadata the step needs to prove idempotency
// on resume or to roll itself back (e.g. the previous PoP id, the
// count of objects copied).
type checkpoint struct {
	Steps map[string]stepRecord `json:"steps"`
}

type stepRecord struct {
	Status string          `json:"status"`
	Meta   json.RawMessage `json:"meta,omitempty"`
}

func (c *checkpoint) record(name string) (stepRecord, bool) {
	if c == nil || c.Steps == nil {
		return stepRecord{}, false
	}
	r, ok := c.Steps[name]
	return r, ok
}

func (c *checkpoint) set(name string, r stepRecord) {
	if c.Steps == nil {
		c.Steps = map[string]stepRecord{}
	}
	c.Steps[name] = r
}

func decodeCheckpoint(raw json.RawMessage) (checkpoint, error) {
	cp := checkpoint{Steps: map[string]stepRecord{}}
	if len(raw) == 0 {
		return cp, nil
	}
	if err := json.Unmarshal(raw, &cp); err != nil {
		return checkpoint{}, fmt.Errorf("tenant: decode migration checkpoint: %w", err)
	}
	if cp.Steps == nil {
		cp.Steps = map[string]stepRecord{}
	}
	return cp, nil
}

func (c checkpoint) encode() (json.RawMessage, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("tenant: encode migration checkpoint: %w", err)
	}
	return b, nil
}

// --- Plane ports -----------------------------------------------------------
//
// A migration touches five independent planes. Each is modelled as a
// narrow port so the orchestration is testable in isolation and so a
// deployment that has not provisioned a given plane (e.g. no second-
// region object store) can leave it unwired — a nil plane is a
// deliberate, logged no-op, exactly like the optional residency Guard
// in cmd/sng-control. Every Forward MUST be idempotent (safe to re-run
// after a crash mid-step) and every rollback MUST tolerate being called
// for a step that only partially ran.

// KeyRewrapPlane re-seals a tenant's DEK envelopes from the source
// region's KEK onto the target region's KEK (envelope re-wrap; the bulk
// ciphertext the DEKs protect is untouched). It is the most
// security-sensitive plane: it must never expose plaintext DEKs and
// must keep the source envelopes intact until the migration commits, so
// rollback is a no-data-loss revert.
type KeyRewrapPlane interface {
	// Rewrap re-wraps every DEK envelope for the tenant under the
	// target-region KEK, persisting the new envelopes alongside (not
	// replacing) the source ones. Returns opaque metadata to checkpoint
	// (e.g. count re-wrapped) and must be idempotent.
	Rewrap(ctx context.Context, tenantID uuid.UUID, sourceRegion, targetRegion string) (json.RawMessage, error)
	// Restore discards target-region envelopes produced by Rewrap,
	// leaving the tenant on its source-region envelopes. Must be safe
	// if Rewrap never ran or only partially completed.
	Restore(ctx context.Context, tenantID uuid.UUID, sourceRegion, targetRegion string) error
}

// TelemetryCopyPlane copies a tenant's ClickHouse telemetry partitions
// from the source-region cluster to the target-region cluster.
type TelemetryCopyPlane interface {
	Copy(ctx context.Context, tenantID uuid.UUID, sourceRegion, targetRegion string) (json.RawMessage, error)
	// Purge removes telemetry written to the target by Copy, so a
	// rolled-back migration leaves no orphaned cross-region data.
	Purge(ctx context.Context, tenantID uuid.UUID, sourceRegion, targetRegion string) error
}

// ObjectCopyPlane copies a tenant's S3 cold-archive objects from the
// source-region bucket/prefix to the target-region bucket/prefix.
type ObjectCopyPlane interface {
	Copy(ctx context.Context, tenantID uuid.UUID, sourceRegion, targetRegion string) (json.RawMessage, error)
	Purge(ctx context.Context, tenantID uuid.UUID, sourceRegion, targetRegion string) error
}

// PoPReassignPlane re-pins a tenant onto a Point-of-Presence in the
// target region. Reassign returns metadata that includes the previous
// PoP id so Restore can put it back exactly.
type PoPReassignPlane interface {
	Reassign(ctx context.Context, tenantID uuid.UUID, targetRegion string) (json.RawMessage, error)
	Restore(ctx context.Context, tenantID uuid.UUID, meta json.RawMessage) error
}

// RegionUpdatePlane flips the tenant's authoritative region column.
// This is the commit point of the migration; rollback flips it back.
type RegionUpdatePlane interface {
	SetRegion(ctx context.Context, tenantID uuid.UUID, region string) error
}

// MigrationPlanes bundles the optional plane ports. Any nil field is a
// logged no-op step (the plane is not provisioned in this deployment).
// RegionUpdate is the one plane that should always be wired in
// production — without it the migration never actually commits the
// region flip — but it too is optional so the orchestration can be
// unit-tested without a tenant store.
type MigrationPlanes struct {
	Keys      KeyRewrapPlane
	Telemetry TelemetryCopyPlane
	Objects   ObjectCopyPlane
	PoP       PoPReassignPlane
	Region    RegionUpdatePlane
}

// --- RegionMigrator --------------------------------------------------------

// RegionMigrator drives the cross-region tenant-migration state machine
// (WS11). It is resumable (a crashed run is picked up from the durable
// checkpoint), fail-safe (any forward-step error rolls back the
// completed steps in reverse), and dual-read-safe (the tenant is marked
// dual_read for the whole in-flight window so reads see both regions
// and no traffic is lost; the region column is flipped only as the
// final step).
type RegionMigrator struct {
	migrations repository.TenantMigrationRepository
	tenants    repository.TenantRepository
	audit      repository.AuditLogRepository
	planes     MigrationPlanes
	logger     *slog.Logger
	clock      func() time.Time

	steps []migrationStep

	// Asynchronous drive (WS11). When asyncCtx is non-nil
	// (EnableAsyncDrive was called by the control-plane wiring) Start
	// creates the migration row and returns the pending record
	// immediately, then drives the pipeline on asyncCtx — a background
	// context independent of the HTTP request that started it, whose own
	// context is cancelled the instant the 202 response is written. The
	// handler therefore replies 202 Accepted and clients poll
	// migration-status. asyncWG tracks in-flight background drives so
	// graceful shutdown can drain them (see Shutdown); the leader resume
	// loop is the crash-recovery net if the process dies mid-drive. When
	// asyncCtx is nil (the default, used by tests and any embedding that
	// wants a blocking call) Start drives synchronously and returns the
	// terminal record.
	asyncCtx    context.Context
	asyncCancel context.CancelFunc
	asyncWG     sync.WaitGroup
}

// EnableAsyncDrive switches Start into asynchronous mode: Start creates
// the migration row, launches the pipeline on a background context, and
// returns the pending record so the HTTP handler can reply 202 Accepted
// while the client polls migration-status. Without it (the default)
// Start drives the pipeline synchronously and returns the terminal
// record.
//
// The background context is deliberately independent of the server's
// root context so an in-flight migration gets a bounded drain window on
// shutdown (see Shutdown) instead of being cancelled the instant a
// SIGTERM arrives. Call once during wiring, before the server starts
// accepting requests; it is not safe to call concurrently with Start.
// A second call is a no-op.
func (m *RegionMigrator) EnableAsyncDrive() {
	if m.asyncCtx != nil {
		return
	}
	m.asyncCtx, m.asyncCancel = context.WithCancel(context.Background())
}

// Shutdown drains the background drives started by an async-mode Start,
// blocking until they finish or ctx is done. If ctx expires first the
// background context is cancelled so the drives abort promptly, leaving
// their migrations non-terminal for the leader resume loop to pick up
// (every step is idempotent, so an interrupted drive re-completes
// safely on resume). Safe to call when async drive was never enabled
// (no-op) and safe to call more than once.
func (m *RegionMigrator) Shutdown(ctx context.Context) {
	if m.asyncCtx == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		m.asyncWG.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	m.asyncCancel()
}

// NewRegionMigrator builds a RegionMigrator. migrations and tenants are
// required; a nil logger defaults to slog.Default(); audit may be nil
// to disable audit logging. The step pipeline order is fixed here and
// mirrors the state vocabulary in migration 059.
func NewRegionMigrator(
	migrations repository.TenantMigrationRepository,
	tenants repository.TenantRepository,
	audit repository.AuditLogRepository,
	planes MigrationPlanes,
	logger *slog.Logger,
) (*RegionMigrator, error) {
	if migrations == nil || tenants == nil {
		return nil, errors.New("tenant: NewRegionMigrator requires migrations and tenants repositories")
	}
	if logger == nil {
		logger = slog.Default()
	}
	m := &RegionMigrator{
		migrations: migrations,
		tenants:    tenants,
		audit:      audit,
		planes:     planes,
		logger:     logger,
		clock:      func() time.Time { return time.Now().UTC() },
	}
	m.steps = m.buildSteps()
	return m, nil
}

// migrationStep is one node of the forward pipeline. state is the
// tenant_migrations.state the migration occupies while the step runs;
// forward executes it (idempotently) and returns metadata to
// checkpoint; rollback undoes a previously-recorded step.
type migrationStep struct {
	name     string
	state    string
	forward  func(ctx context.Context, mig repository.TenantMigration) (json.RawMessage, error)
	rollback func(ctx context.Context, mig repository.TenantMigration, meta json.RawMessage) error
}

func (m *RegionMigrator) buildSteps() []migrationStep {
	return []migrationStep{
		{
			name:  "rewrap_keys",
			state: repository.MigrationStateRewrappingKeys,
			forward: func(ctx context.Context, mig repository.TenantMigration) (json.RawMessage, error) {
				if m.planes.Keys == nil {
					return nil, nil
				}
				return m.planes.Keys.Rewrap(ctx, mig.TenantID, mig.SourceRegion, mig.TargetRegion)
			},
			rollback: func(ctx context.Context, mig repository.TenantMigration, _ json.RawMessage) error {
				if m.planes.Keys == nil {
					return nil
				}
				return m.planes.Keys.Restore(ctx, mig.TenantID, mig.SourceRegion, mig.TargetRegion)
			},
		},
		{
			name:  "copy_telemetry",
			state: repository.MigrationStateCopyingTelemetry,
			forward: func(ctx context.Context, mig repository.TenantMigration) (json.RawMessage, error) {
				if m.planes.Telemetry == nil {
					return nil, nil
				}
				return m.planes.Telemetry.Copy(ctx, mig.TenantID, mig.SourceRegion, mig.TargetRegion)
			},
			rollback: func(ctx context.Context, mig repository.TenantMigration, _ json.RawMessage) error {
				if m.planes.Telemetry == nil {
					return nil
				}
				return m.planes.Telemetry.Purge(ctx, mig.TenantID, mig.SourceRegion, mig.TargetRegion)
			},
		},
		{
			name:  "copy_objects",
			state: repository.MigrationStateCopyingObjects,
			forward: func(ctx context.Context, mig repository.TenantMigration) (json.RawMessage, error) {
				if m.planes.Objects == nil {
					return nil, nil
				}
				return m.planes.Objects.Copy(ctx, mig.TenantID, mig.SourceRegion, mig.TargetRegion)
			},
			rollback: func(ctx context.Context, mig repository.TenantMigration, _ json.RawMessage) error {
				if m.planes.Objects == nil {
					return nil
				}
				return m.planes.Objects.Purge(ctx, mig.TenantID, mig.SourceRegion, mig.TargetRegion)
			},
		},
		{
			name:  "reassign_pop",
			state: repository.MigrationStateReassigningPoP,
			forward: func(ctx context.Context, mig repository.TenantMigration) (json.RawMessage, error) {
				if m.planes.PoP == nil {
					return nil, nil
				}
				return m.planes.PoP.Reassign(ctx, mig.TenantID, mig.TargetRegion)
			},
			rollback: func(ctx context.Context, mig repository.TenantMigration, meta json.RawMessage) error {
				if m.planes.PoP == nil {
					return nil
				}
				return m.planes.PoP.Restore(ctx, mig.TenantID, meta)
			},
		},
		{
			name:  "update_region",
			state: repository.MigrationStateUpdatingRegion,
			forward: func(ctx context.Context, mig repository.TenantMigration) (json.RawMessage, error) {
				if m.planes.Region == nil {
					return nil, nil
				}
				return nil, m.planes.Region.SetRegion(ctx, mig.TenantID, mig.TargetRegion)
			},
			rollback: func(ctx context.Context, mig repository.TenantMigration, _ json.RawMessage) error {
				if m.planes.Region == nil {
					return nil
				}
				return m.planes.Region.SetRegion(ctx, mig.TenantID, mig.SourceRegion)
			},
		},
	}
}

// Start opens a new cross-region migration for tenantID toward
// targetRegion. The pre-flight (validation, source/target resolution,
// row creation) always runs synchronously on ctx, so its errors are
// returned to the caller: ErrMigrationInProgress if one is already
// running, ErrSourceRegionUnset if the tenant has no residency region,
// ErrInvalidArgument (wrapped) for a malformed/identical target region,
// and any store error creating the row.
//
// The pipeline drive then runs in one of two modes (see
// EnableAsyncDrive):
//   - async (control-plane default): the freshly-created pending record
//     is returned immediately and the pipeline is driven on a
//     background context, so the HTTP handler replies 202 Accepted and
//     the client polls migration-status.
//   - sync (default for embeddings/tests): the pipeline is driven to a
//     terminal state on ctx and the final record is returned, with the
//     original forward-step cause surfaced for a rolled_back/failed
//     migration.
func (m *RegionMigrator) Start(ctx context.Context, tenantID uuid.UUID, targetRegion string) (repository.TenantMigration, error) {
	if tenantID == uuid.Nil {
		return repository.TenantMigration{}, fmt.Errorf("tenant ID is required: %w", repository.ErrInvalidArgument)
	}
	if err := residency.ValidateRegion(residency.Region(targetRegion)); err != nil {
		return repository.TenantMigration{}, fmt.Errorf("invalid target region %q: %w", targetRegion, repository.ErrInvalidArgument)
	}
	target := string(residency.Normalize(residency.Region(targetRegion)))

	tnt, err := m.tenants.Get(ctx, tenantID)
	if err != nil {
		return repository.TenantMigration{}, err
	}
	source := string(residency.Normalize(residency.Region(tnt.Region)))
	if source == "" {
		return repository.TenantMigration{}, ErrSourceRegionUnset
	}
	if source == target {
		return repository.TenantMigration{}, fmt.Errorf("tenant already in region %q: %w", target, repository.ErrInvalidArgument)
	}

	now := m.clock()
	created, err := m.migrations.Create(ctx, tenantID, repository.TenantMigration{
		SourceRegion: source,
		TargetRegion: target,
		State:        repository.MigrationStatePending,
		// Dual-read is armed for the entire in-flight window so read
		// paths consult both regions and no tenant traffic is lost
		// while data is mid-copy.
		DualRead:   true,
		Checkpoint: json.RawMessage(`{}`),
		StartedAt:  &now,
	})
	if err != nil {
		if errors.Is(err, repository.ErrConflict) {
			return repository.TenantMigration{}, ErrMigrationInProgress
		}
		return repository.TenantMigration{}, err
	}
	m.auditEvent(ctx, tenantID, "tenant.migration.started", created.ID, map[string]string{
		"source_region": source,
		"target_region": target,
	})
	if m.asyncCtx != nil {
		// Async mode: hand the freshly-created (pending) record to a
		// background drive decoupled from the request context and return
		// it immediately so the handler replies 202 Accepted; the client
		// observes progress via migration-status.
		m.launchBackgroundDrive(created)
		return created, nil
	}
	return m.drive(ctx, created)
}

// launchBackgroundDrive drives a freshly-created migration to a terminal
// state on the background async context, decoupled from the HTTP request
// that created it (whose context is cancelled the instant the 202
// response is written). No caller observes the return, so the outcome is
// logged at the same levels as a resume — a clean rollback is an
// expected terminal outcome (warn), a failed rollback needs operator
// attention (error). If the process dies mid-drive the leader resume
// loop recovers the migration from its durable checkpoint.
func (m *RegionMigrator) launchBackgroundDrive(mig repository.TenantMigration) {
	m.asyncWG.Add(1)
	go func() {
		defer m.asyncWG.Done()
		final, derr := m.drive(m.asyncCtx, mig)
		m.logDriveOutcome(m.asyncCtx, mig, final, derr, "background drive")
	}()
}

// Resume re-drives a tenant's in-flight migration from its durable
// checkpoint — used after a control-plane restart, or to retry a
// migration that is stuck mid-pipeline. ErrNoMigration if the tenant
// has no active migration.
func (m *RegionMigrator) Resume(ctx context.Context, tenantID uuid.UUID) (repository.TenantMigration, error) {
	active, err := m.migrations.GetActive(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.TenantMigration{}, ErrNoMigration
		}
		return repository.TenantMigration{}, err
	}
	return m.drive(ctx, active)
}

// ResumeAll picks up every in-flight migration across all tenants and
// drives each to a terminal state. Intended to be called once on
// control-plane boot. It returns the number of migrations driven and
// the first error encountered (every migration is attempted regardless
// of earlier errors).
func (m *RegionMigrator) ResumeAll(ctx context.Context) (int, error) {
	pending, err := m.migrations.ListResumable(ctx)
	if err != nil {
		return 0, err
	}
	var firstErr error
	for _, mig := range pending {
		if _, derr := m.resumeOne(ctx, mig); derr != nil && firstErr == nil {
			firstErr = derr
		}
	}
	return len(pending), firstErr
}

// resumeOne drives a single in-flight migration to a terminal state and
// logs the outcome at the appropriate level. It returns a non-nil error
// ONLY when the migration did not reach a safe terminal state — i.e. the
// rollback itself failed (state=failed) or the state machine could not
// be driven (a persist/store error). A clean rollback (state=rolled_back)
// is an expected, safe outcome: the original forward-step cause is
// surfaced by drive for the synchronous Start caller, but here it is
// logged at warn and reported as success, so ResumeAll does not mislead
// operators into thinking the rollback failed.
func (m *RegionMigrator) resumeOne(ctx context.Context, mig repository.TenantMigration) (repository.TenantMigration, error) {
	final, derr := m.drive(ctx, mig)
	m.logDriveOutcome(ctx, mig, final, derr, "resume")
	switch {
	case derr == nil:
		return final, nil
	case final.State == repository.MigrationStateRolledBack:
		// A clean rollback is an expected, safe terminal outcome — the
		// original cause was surfaced by drive for a synchronous Start
		// caller, but ResumeAll must not treat it as a resume failure.
		return final, nil
	default:
		return final, derr
	}
}

// logDriveOutcome logs the result of a non-synchronous drive (the leader
// resume loop or an async background drive) at the level its terminal
// state warrants. phase names the driver for the message ("resume",
// "background drive"). A nil error is a clean completion and logs
// nothing.
func (m *RegionMigrator) logDriveOutcome(ctx context.Context, orig, final repository.TenantMigration, derr error, phase string) {
	switch {
	case derr == nil:
		return
	case final.State == repository.MigrationStateRolledBack:
		m.logger.WarnContext(ctx, "tenant: in-flight migration rolled back during "+phase,
			"tenant_id", orig.TenantID, "migration_id", orig.ID, "detail", final.Detail)
	case final.State == repository.MigrationStateFailed:
		m.logger.ErrorContext(ctx, "tenant: in-flight migration failed during "+phase+" (rollback incomplete; needs operator intervention)",
			"tenant_id", orig.TenantID, "migration_id", orig.ID, "detail", final.Detail, "error", derr)
	default:
		m.logger.ErrorContext(ctx, "tenant: could not drive in-flight migration during "+phase,
			"tenant_id", orig.TenantID, "migration_id", orig.ID, "state", final.State, "error", derr)
	}
}

// MigrationStatus returns the tenant's most recent migration in any
// state. ErrNoMigration if the tenant has never been migrated.
func (m *RegionMigrator) MigrationStatus(ctx context.Context, tenantID uuid.UUID) (repository.TenantMigration, error) {
	latest, err := m.migrations.Latest(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return repository.TenantMigration{}, ErrNoMigration
		}
		return repository.TenantMigration{}, err
	}
	return latest, nil
}

// DualRead reports, for a tenant, whether an in-flight migration is
// currently dual-reading and the (source, target) regions a read path
// must union over. When active is false the caller reads only the
// tenant's committed region as usual. This is the hook read paths use
// so no tenant traffic is lost mid-migration.
func (m *RegionMigrator) DualRead(ctx context.Context, tenantID uuid.UUID) (sourceRegion, targetRegion string, active bool, err error) {
	mig, err := m.migrations.GetActive(ctx, tenantID)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			return "", "", false, nil
		}
		return "", "", false, err
	}
	if !mig.DualRead {
		return "", "", false, nil
	}
	return mig.SourceRegion, mig.TargetRegion, true, nil
}

// drive runs driveOnce and absorbs the optimistic-concurrency race: if
// another driver (a concurrent Start/Resume or the leader resume loop
// working from a stale ListResumable snapshot) advanced this same
// migration first, our version-locked write is rejected before it can
// clobber the winner's state, surfacing as ErrConcurrentUpdate. There
// is nothing to undo — every forward/undo step is idempotent and the
// rejected write committed nothing — so we simply YIELD: log, re-read
// the latest persisted record, and report it without error. The winner
// drives the migration to its terminal state. This eliminates the
// re-drive / transient dual_read re-arm the resume loop could otherwise
// cause on an already-completed migration.
func (m *RegionMigrator) drive(ctx context.Context, mig repository.TenantMigration) (repository.TenantMigration, error) {
	final, err := m.driveOnce(ctx, mig)
	if err == nil || !errors.Is(err, repository.ErrConcurrentUpdate) {
		return final, err
	}
	m.logger.InfoContext(ctx, "tenant: migration concurrently driven by another worker; yielding",
		"tenant_id", mig.TenantID, "migration_id", mig.ID)
	if latest, gerr := m.migrations.Get(ctx, mig.TenantID, mig.ID); gerr == nil {
		return latest, nil
	}
	// Could not re-read the winner's record (e.g. transient store
	// error); fall back to the last in-memory copy. Still no error —
	// the migration is owned by the winning driver.
	return final, nil
}

// driveOnce runs the forward pipeline from the migration's current
// checkpoint. On the first forward-step error it transitions to
// rolling_back and unwinds the completed steps in reverse; the
// migration ends rolled_back (clean revert) or failed (rollback itself
// errored — needs operator intervention).
func (m *RegionMigrator) driveOnce(ctx context.Context, mig repository.TenantMigration) (repository.TenantMigration, error) {
	// A terminal migration is never re-driven (ResumeAll only ever
	// hands us non-terminal rows, but Resume/Start callers and tests
	// may not).
	if repository.IsTerminalMigrationState(mig.State) {
		return mig, nil
	}
	cp, err := decodeCheckpoint(mig.Checkpoint)
	if err != nil {
		return mig, err
	}
	// A migration already in rolling_back was stranded by a crash mid
	// unwind (the state is non-terminal and therefore resumable). It
	// must CONTINUE the rollback, not restart the forward pipeline:
	// forward steps marked rolled_back are not "done", so the forward
	// loop below would re-execute them and re-apply changes onto an
	// already-reverted state (re-wrapping keys, re-copying data),
	// risking a forward/rollback cycle that never terminates. Route
	// straight to rollback, which only undoes steps still marked done
	// and is therefore idempotent across resumes. The original
	// forward-step cause was persisted to Detail when the rollback
	// began; reconstruct it so the terminal record still explains why
	// the migration is unwinding.
	if mig.State == repository.MigrationStateRollingBack {
		cause := errResumedMidRollback
		if mig.Detail != "" {
			cause = errors.New(mig.Detail)
		}
		return m.rollback(ctx, mig, cp, cause)
	}
	// Count this as a fresh attempt of the forward pipeline.
	mig.Attempts++
	for _, step := range m.steps {
		if rec, ok := cp.record(step.name); ok && rec.Status == stepStatusDone {
			// Already completed in a previous run — skip (idempotent
			// resume).
			continue
		}
		var updated repository.TenantMigration
		if updated, err = m.transition(ctx, mig, step.state, cp, ""); err != nil {
			return mig, err
		}
		mig = updated

		meta, ferr := step.forward(ctx, mig)
		if ferr != nil {
			// The step errored partway, so it may have written partial
			// side-effects to the target region (e.g. some telemetry
			// partitions or S3 objects copied) before failing. Record it
			// as attempted — distinct from done — so the rollback sweep
			// below still invokes its undo (Purge/Restore) and no partial
			// cross-region data is left orphaned. The record is persisted
			// durably when rollback transitions to rolling_back, so even a
			// crash mid-rollback resumes with the attempted step still in
			// the sweep. Any metadata the forward produced before failing
			// is preserved for the undo.
			cp.set(step.name, stepRecord{Status: stepStatusAttempted, Meta: meta})
			m.logger.ErrorContext(ctx, "tenant: migration step failed; rolling back",
				"tenant_id", mig.TenantID, "migration_id", mig.ID, "step", step.name, "error", ferr)
			return m.rollback(ctx, mig, cp, ferr)
		}
		cp.set(step.name, stepRecord{Status: stepStatusDone, Meta: meta})
		if updated, err = m.transition(ctx, mig, step.state, cp, ""); err != nil {
			return mig, err
		}
		mig = updated
	}
	return m.complete(ctx, mig, cp)
}

// rollback unwinds every step recorded done OR attempted, in reverse
// pipeline order. Attempted steps (a forward step that errored partway)
// are included so their partial target-region side-effects are purged,
// not orphaned. It ends the migration rolled_back when every undo
// succeeds, or failed when any undo errors (the failure detail is
// preserved for operators).
func (m *RegionMigrator) rollback(ctx context.Context, mig repository.TenantMigration, cp checkpoint, cause error) (repository.TenantMigration, error) {
	updated, err := m.transition(ctx, mig, repository.MigrationStateRollingBack, cp, cause.Error())
	if err != nil {
		return mig, err
	}
	mig = updated

	var rollbackErr error
	for i := len(m.steps) - 1; i >= 0; i-- {
		step := m.steps[i]
		rec, ok := cp.record(step.name)
		if !ok || (rec.Status != stepStatusDone && rec.Status != stepStatusAttempted) {
			continue
		}
		if rerr := step.rollback(ctx, mig, rec.Meta); rerr != nil {
			m.logger.ErrorContext(ctx, "tenant: migration rollback step failed",
				"tenant_id", mig.TenantID, "migration_id", mig.ID, "step", step.name, "error", rerr)
			if rollbackErr == nil {
				rollbackErr = rerr
			}
			continue
		}
		cp.set(step.name, stepRecord{Status: stepStatusRolledBack, Meta: rec.Meta})
		if updated, err = m.transition(ctx, mig, repository.MigrationStateRollingBack, cp, cause.Error()); err != nil {
			return mig, err
		}
		mig = updated
	}

	// Build the terminal record in a copy and only adopt it once it is
	// durably persisted. If the final write fails the migration is still
	// rolling_back in the store (dual_read on), so we must return THAT
	// non-terminal record — never the in-memory terminal copy — otherwise
	// a caller (the HTTP handler) would see a terminal state and report a
	// successful rollback while the store still has the tenant mid-unwind,
	// leaving dual_read armed and ResumeAll bound to retry it.
	now := m.clock()
	terminal := mig
	terminal.CompletedAt = &now
	// Dual-read is cleared on any terminal state — the in-flight window
	// is over whether we reverted cleanly or wedged.
	terminal.DualRead = false
	if rollbackErr != nil {
		terminal.State = repository.MigrationStateFailed
		terminal.Detail = fmt.Sprintf("rollback failed: %v (original cause: %v)", rollbackErr, cause)
	} else {
		terminal.State = repository.MigrationStateRolledBack
		terminal.Detail = fmt.Sprintf("rolled back: %v", cause)
	}
	final, perr := m.persist(ctx, terminal, cp)
	if perr != nil {
		// mig is unchanged (still rolling_back, dual_read on) — return it
		// with the persist error so callers treat this as an
		// infrastructure failure (5xx), not a completed rollback.
		return mig, fmt.Errorf("tenant: persist terminal rollback state: %w", perr)
	}
	action := "tenant.migration.rolled_back"
	if final.State == repository.MigrationStateFailed {
		action = "tenant.migration.failed"
	}
	m.auditEvent(ctx, final.TenantID, action, final.ID, map[string]string{
		"source_region": final.SourceRegion,
		"target_region": final.TargetRegion,
		"detail":        final.Detail,
	})
	// Surface the original cause to the caller so a synchronous Start
	// reports why the migration did not complete.
	return final, cause
}

// complete marks a fully-migrated tenant: dual-read off, region already
// flipped by the final step, completed_at stamped.
func (m *RegionMigrator) complete(ctx context.Context, mig repository.TenantMigration, cp checkpoint) (repository.TenantMigration, error) {
	now := m.clock()
	terminal := mig
	terminal.State = repository.MigrationStateCompleted
	terminal.DualRead = false
	terminal.Detail = ""
	terminal.CompletedAt = &now
	final, err := m.persist(ctx, terminal, cp)
	if err != nil {
		// The completion could not be made durable: the store still has
		// the migration in its last non-terminal step (dual_read on).
		// Return that record (mig, unchanged) with the persist error so
		// the caller does not mistake an un-persisted "completed" state
		// for success and ResumeAll re-drives the final step.
		return mig, fmt.Errorf("tenant: persist completed state: %w", err)
	}
	m.auditEvent(ctx, final.TenantID, "tenant.migration.completed", final.ID, map[string]string{
		"source_region": final.SourceRegion,
		"target_region": final.TargetRegion,
	})
	return final, nil
}

// transition writes an intermediate state + checkpoint update without
// touching the terminal-only fields (completed_at / dual_read clear).
func (m *RegionMigrator) transition(ctx context.Context, mig repository.TenantMigration, state string, cp checkpoint, detail string) (repository.TenantMigration, error) {
	mig.State = state
	mig.Detail = detail
	return m.persist(ctx, mig, cp)
}

// persist encodes the checkpoint and writes the migration row,
// refreshing the in-memory copy from the store (so updated_at and any
// store-side normalisation are reflected).
func (m *RegionMigrator) persist(ctx context.Context, mig repository.TenantMigration, cp checkpoint) (repository.TenantMigration, error) {
	raw, err := cp.encode()
	if err != nil {
		return mig, err
	}
	mig.Checkpoint = raw
	saved, err := m.migrations.Update(ctx, mig.TenantID, mig)
	if err != nil {
		return mig, fmt.Errorf("tenant: persist migration %s: %w", mig.ID, err)
	}
	return saved, nil
}

func (m *RegionMigrator) auditEvent(ctx context.Context, tenantID uuid.UUID, action string, migrationID uuid.UUID, fields map[string]string) {
	if m.audit == nil {
		return
	}
	payload := map[string]any{"migration_id": migrationID.String()}
	for k, v := range fields {
		payload[k] = v
	}
	details, err := json.Marshal(payload)
	if err != nil {
		m.logger.WarnContext(ctx, "tenant: marshal migration audit details failed", "error", err)
		return
	}
	mid := migrationID
	if _, err := m.audit.Append(ctx, tenantID, repository.AuditEntry{
		Action:       action,
		ResourceType: "tenant_migration",
		ResourceID:   &mid,
		Details:      details,
	}); err != nil {
		m.logger.WarnContext(ctx, "tenant: migration audit append failed", "error", err)
	}
}
