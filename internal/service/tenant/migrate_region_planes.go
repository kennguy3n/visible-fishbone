package tenant

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/residency"
)

// --- Region-update plane ---------------------------------------------------

// tenantRegionUpdater is the slice of the tenant repository the
// region-update plane needs: a sparse patch of the region column.
type tenantRegionUpdater interface {
	Update(ctx context.Context, id uuid.UUID, patch repository.TenantPatch) (repository.Tenant, error)
}

// RegionColumnPlane is the production RegionUpdatePlane: it flips the
// tenant's authoritative `tenants.region` column via the repository's
// sparse patch. This is the migration's commit point — once the column
// is flipped, residency enforcement and PoP biasing resolve the new
// region — so it runs last in the pipeline, and its rollback flips the
// column back to the source region.
type RegionColumnPlane struct {
	tenants tenantRegionUpdater
}

// NewRegionColumnPlane binds the tenant repository to the plane.
func NewRegionColumnPlane(tenants tenantRegionUpdater) *RegionColumnPlane {
	return &RegionColumnPlane{tenants: tenants}
}

var _ RegionUpdatePlane = (*RegionColumnPlane)(nil)

// SetRegion patches tenants.region to region. The repository persists
// the value verbatim (it is already normalised by the migrator at
// Start), so the column matches what residency enforcement compares
// against.
func (p *RegionColumnPlane) SetRegion(ctx context.Context, tenantID uuid.UUID, region string) error {
	if p == nil || p.tenants == nil {
		return nil
	}
	r := region
	if _, err := p.tenants.Update(ctx, tenantID, repository.TenantPatch{Region: &r}); err != nil {
		return fmt.Errorf("tenant: set region %q: %w", region, err)
	}
	return nil
}

// --- PoP-reassignment plane ------------------------------------------------

// PoPInfo is the minimal PoP projection the reassignment plane needs to
// pick a target-region PoP, decoupling the tenant package from the pop
// package's full PoP type.
type PoPInfo struct {
	ID     uuid.UUID
	Region string
}

// PoPControl is the slice of the PoP control plane the reassignment
// step needs. The production wiring adapts *pop.Service (+ its store)
// to this interface; tests supply a fake. Keeping it local to the
// tenant package avoids a hard dependency on the pop package and keeps
// the migrator unit-testable.
type PoPControl interface {
	// AvailablePoPs returns the currently enabled PoPs.
	AvailablePoPs() []PoPInfo
	// CurrentAssignment returns the tenant's pinned PoP id, found=false
	// if the tenant is not pinned to any PoP.
	CurrentAssignment(ctx context.Context, tenantID uuid.UUID) (popID uuid.UUID, found bool, err error)
	// SetAssignment pins the tenant to popID as an operator override.
	SetAssignment(ctx context.Context, tenantID, popID uuid.UUID) error
}

// popReassignMeta is the checkpoint metadata for the reassignment step:
// it records the PoP the tenant was on before (so rollback restores it
// exactly) and whether the tenant had any pin at all.
type popReassignMeta struct {
	PreviousPoPID string `json:"previous_pop_id,omitempty"`
	HadAssignment bool   `json:"had_assignment"`
	NewPoPID      string `json:"new_pop_id,omitempty"`
}

// PoPReassigner is the production PoPReassignPlane: on Reassign it pins
// the tenant to an enabled PoP in the target region (recording the
// previous pin for rollback); on Restore it re-pins the tenant to the
// PoP it was on before the migration. A tenant with no PoP in the
// target region is left where it is (logged by the caller via the
// returned metadata) rather than failing the whole migration — PoP
// assignment is advisory routing, not data, so a missing target-region
// PoP must not strand a tenant's data mid-move.
type PoPReassigner struct {
	ctrl PoPControl
}

// NewPoPReassigner binds the PoP control plane to the plane.
func NewPoPReassigner(ctrl PoPControl) *PoPReassigner {
	return &PoPReassigner{ctrl: ctrl}
}

var _ PoPReassignPlane = (*PoPReassigner)(nil)

func (p *PoPReassigner) Reassign(ctx context.Context, tenantID uuid.UUID, targetRegion string) (json.RawMessage, error) {
	if p == nil || p.ctrl == nil {
		return nil, nil
	}
	prevID, had, err := p.ctrl.CurrentAssignment(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant: read current PoP assignment: %w", err)
	}
	target, ok := pickPoPInRegion(p.ctrl.AvailablePoPs(), targetRegion)
	if !ok {
		// No PoP in the target region — leave the tenant on its current
		// PoP. Idempotent and non-fatal; recorded in the checkpoint so
		// rollback can restore the (unchanged) original pin.
		meta := popReassignMeta{HadAssignment: had}
		if had {
			meta.PreviousPoPID = prevID.String()
		}
		return marshalMeta(meta)
	}
	if had && prevID == target {
		// The tenant is already pinned to the deterministically-chosen
		// target-region PoP. This is the idempotent-resume case: the
		// forward step already ran SetAssignment but crashed before its
		// checkpoint was durably written, so on replay we can no longer
		// observe the *original* pre-migration PoP. Recording the target
		// PoP as the "previous" one would make a later rollback re-pin
		// the tenant to a TARGET-region PoP while the region column
		// reverts to the source — a routing inconsistency. Instead we
		// record no restorable previous (HadAssignment=false): on
		// rollback the reassignment step becomes a no-op and the tenant
		// is left for lazy reassignment, which re-pins it to a
		// source-region PoP once the region flips back. (This also
		// covers the benign case where an operator had manually pinned
		// the tenant to the target PoP before the migration.)
		return marshalMeta(popReassignMeta{HadAssignment: false, NewPoPID: target.String()})
	}
	meta := popReassignMeta{HadAssignment: had}
	if had {
		meta.PreviousPoPID = prevID.String()
	}
	if err := p.ctrl.SetAssignment(ctx, tenantID, target); err != nil {
		return nil, fmt.Errorf("tenant: pin tenant to target-region PoP: %w", err)
	}
	meta.NewPoPID = target.String()
	return marshalMeta(meta)
}

func (p *PoPReassigner) Restore(ctx context.Context, tenantID uuid.UUID, raw json.RawMessage) error {
	if p == nil || p.ctrl == nil {
		return nil
	}
	var meta popReassignMeta
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &meta); err != nil {
			return fmt.Errorf("tenant: decode PoP rollback metadata: %w", err)
		}
	}
	// The tenant had no pin before the migration: nothing to restore.
	// (We intentionally do not unpin here; an unpinned tenant is
	// re-assigned lazily by AssignPoP on its next connection.)
	if !meta.HadAssignment || meta.PreviousPoPID == "" {
		return nil
	}
	prev, err := uuid.Parse(meta.PreviousPoPID)
	if err != nil {
		return fmt.Errorf("tenant: parse previous PoP id %q: %w", meta.PreviousPoPID, err)
	}
	if err := p.ctrl.SetAssignment(ctx, tenantID, prev); err != nil {
		return fmt.Errorf("tenant: restore previous PoP assignment: %w", err)
	}
	return nil
}

// pickPoPInRegion returns a stable, enabled PoP in targetRegion: the one
// with the lexicographically-smallest id among all enabled PoPs in that
// region. Selecting by id rather than trusting the iteration order of
// AvailablePoPs() (which is ultimately a map-backed registry, so its
// order is not guaranteed stable across calls) is what actually makes
// resume idempotent — a replay picks the same PoP as the original run as
// long as that PoP is still enabled. If it was disabled between runs the
// already-pinned-to-target guard in Reassign still keeps the rollback
// metadata correct.
//
// Region matching goes through residency.Normalize on BOTH sides: the
// migrator's targetRegion is already normalized (lower-cased, trimmed) at
// Start, but the PoP registry stores regions verbatim (e.g.
// "EU-Central-1"), so a raw == comparison would silently fail to match a
// perfectly good target-region PoP and strand the tenant on a
// source-region PoP. Normalizing both sides is exactly how residency
// enforcement compares regions elsewhere, so the two stay consistent.
func pickPoPInRegion(pops []PoPInfo, targetRegion string) (uuid.UUID, bool) {
	want := residency.Normalize(residency.Region(targetRegion))
	var (
		best  uuid.UUID
		found bool
	)
	for _, p := range pops {
		if residency.Normalize(residency.Region(p.Region)) != want {
			continue
		}
		if !found || p.ID.String() < best.String() {
			best = p.ID
			found = true
		}
	}
	return best, found
}

func marshalMeta(meta popReassignMeta) (json.RawMessage, error) {
	b, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("tenant: marshal PoP metadata: %w", err)
	}
	return b, nil
}
