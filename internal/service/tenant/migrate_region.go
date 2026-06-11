package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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

// stepStatusDone marks a forward step that completed; stepStatusRolledBack
// marks one that was subsequently undone. Persisted inside the
// migration checkpoint so a resumed run skips completed steps and a
// rollback only touches steps that actually ran.
const (
	stepStatusDone       = "done"
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
// targetRegion and drives it to a terminal state synchronously. It
// returns the final migration record. ErrMigrationInProgress if one is
// already running, ErrSourceRegionUnset if the tenant has no residency
// region, and ErrInvalidArgument (wrapped) for a malformed/identical
// target region.
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
	return m.drive(ctx, created)
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
	switch {
	case derr == nil:
		return final, nil
	case final.State == repository.MigrationStateRolledBack:
		m.logger.WarnContext(ctx, "tenant: in-flight migration rolled back during resume",
			"tenant_id", mig.TenantID, "migration_id", mig.ID, "detail", final.Detail)
		return final, nil
	case final.State == repository.MigrationStateFailed:
		m.logger.ErrorContext(ctx, "tenant: in-flight migration failed during resume (rollback incomplete; needs operator intervention)",
			"tenant_id", mig.TenantID, "migration_id", mig.ID, "detail", final.Detail, "error", derr)
		return final, derr
	default:
		m.logger.ErrorContext(ctx, "tenant: could not drive in-flight migration during resume",
			"tenant_id", mig.TenantID, "migration_id", mig.ID, "state", final.State, "error", derr)
		return final, derr
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

// drive runs the forward pipeline from the migration's current
// checkpoint. On the first forward-step error it transitions to
// rolling_back and unwinds the completed steps in reverse; the
// migration ends rolled_back (clean revert) or failed (rollback itself
// errored — needs operator intervention).
func (m *RegionMigrator) drive(ctx context.Context, mig repository.TenantMigration) (repository.TenantMigration, error) {
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

// rollback unwinds every step recorded done, in reverse pipeline order.
// It ends the migration rolled_back when every undo succeeds, or failed
// when any undo errors (the failure detail is preserved for operators).
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
		if !ok || rec.Status != stepStatusDone {
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

	now := m.clock()
	mig.CompletedAt = &now
	// Dual-read is cleared on any terminal state — the in-flight window
	// is over whether we reverted cleanly or wedged.
	mig.DualRead = false
	if rollbackErr != nil {
		mig.State = repository.MigrationStateFailed
		mig.Detail = fmt.Sprintf("rollback failed: %v (original cause: %v)", rollbackErr, cause)
	} else {
		mig.State = repository.MigrationStateRolledBack
		mig.Detail = fmt.Sprintf("rolled back: %v", cause)
	}
	final, perr := m.persist(ctx, mig, cp)
	if perr != nil {
		return mig, perr
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
	mig.State = repository.MigrationStateCompleted
	mig.DualRead = false
	mig.Detail = ""
	mig.CompletedAt = &now
	final, err := m.persist(ctx, mig, cp)
	if err != nil {
		return mig, err
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
