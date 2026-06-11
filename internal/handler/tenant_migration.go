package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenant"
)

// TenantMigrationHandler exposes the cross-region tenant-migration
// endpoints (WS11): start a migration and read its status. It is a
// separate handler from TenantHandler so a deployment that has not
// wired a RegionMigrator simply never registers these routes (the CRUD
// surface is unaffected).
type TenantMigrationHandler struct {
	migrator *tenant.RegionMigrator
}

// NewTenantMigrationHandler wires the handler.
func NewTenantMigrationHandler(migrator *tenant.RegionMigrator) *TenantMigrationHandler {
	return &TenantMigrationHandler{migrator: migrator}
}

// Register attaches the migration routes. Both live under the
// /api/v1/tenants/{tenant_id} prefix so the router-level TenantScope
// middleware binds sng.tenant_id for RLS exactly as for the CRUD
// routes.
func (h *TenantMigrationHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/migrate-region", h.start)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/migration-status", h.status)
}

// MigrateRegionRequest is the JSON body for POST
// /tenants/{tenant_id}/migrate-region.
type MigrateRegionRequest struct {
	// TargetRegion is the region to move the tenant to. Required; must
	// be a well-formed region token and differ from the tenant's
	// current region.
	TargetRegion string `json:"target_region"`
}

// MigrationResponse is the JSON projection of repository.TenantMigration.
type MigrationResponse struct {
	ID           string          `json:"id"`
	TenantID     string          `json:"tenant_id"`
	SourceRegion string          `json:"source_region"`
	TargetRegion string          `json:"target_region"`
	State        string          `json:"state"`
	DualRead     bool            `json:"dual_read"`
	Detail       string          `json:"detail,omitempty"`
	Attempts     int             `json:"attempts"`
	Checkpoint   json.RawMessage `json:"checkpoint"`
	CreatedAt    string          `json:"created_at"`
	UpdatedAt    string          `json:"updated_at"`
	StartedAt    string          `json:"started_at,omitempty"`
	CompletedAt  string          `json:"completed_at,omitempty"`
}

const migrationTimeFormat = "2006-01-02T15:04:05.000000000Z07:00"

func toMigrationResponse(m repository.TenantMigration) MigrationResponse {
	cp := m.Checkpoint
	if len(cp) == 0 {
		cp = json.RawMessage(`{}`)
	}
	resp := MigrationResponse{
		ID:           m.ID.String(),
		TenantID:     m.TenantID.String(),
		SourceRegion: m.SourceRegion,
		TargetRegion: m.TargetRegion,
		State:        m.State,
		DualRead:     m.DualRead,
		Detail:       m.Detail,
		Attempts:     m.Attempts,
		Checkpoint:   cp,
		CreatedAt:    m.CreatedAt.Format(migrationTimeFormat),
		UpdatedAt:    m.UpdatedAt.Format(migrationTimeFormat),
	}
	if m.StartedAt != nil {
		resp.StartedAt = m.StartedAt.Format(migrationTimeFormat)
	}
	if m.CompletedAt != nil {
		resp.CompletedAt = m.CompletedAt.Format(migrationTimeFormat)
	}
	return resp
}

func (h *TenantMigrationHandler) start(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req MigrateRegionRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.TargetRegion == "" {
		WriteError(w, http.StatusBadRequest, "missing_target_region", "target_region is required")
		return
	}
	// In the control-plane's async mode (EnableAsyncDrive) Start returns
	// the freshly-created pending record once it is durably persisted and
	// drives the pipeline on a background context; the response below is
	// then a 202 Accepted and the client polls migration-status for
	// progress. In sync mode (tests/embeddings) Start instead drives to a
	// terminal state and returns the final record: a rolled_back/failed
	// migration comes back with the original forward-step cause, a
	// defined terminal outcome (not a server error) surfaced as a 200 via
	// the isTerminalRollback branch below. Either way, only pre-flight
	// errors (validation, conflict, not-found) and infrastructure errors
	// map to non-2xx.
	mig, err := h.migrator.Start(r.Context(), id, req.TargetRegion)
	if err != nil {
		// A migration that ran but rolled back is reported through the
		// record (state=rolled_back/failed) with a 200 — the request
		// itself succeeded in reaching a defined terminal state. Only
		// pre-flight errors (validation, conflict, not-found) and
		// infrastructure errors map to non-2xx.
		if isTerminalRollback(mig.State) {
			WriteJSON(w, http.StatusOK, toMigrationResponse(mig))
			return
		}
		writeMigrationError(w, err)
		return
	}
	WriteJSON(w, http.StatusAccepted, toMigrationResponse(mig))
}

func (h *TenantMigrationHandler) status(w http.ResponseWriter, r *http.Request) {
	id, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	mig, err := h.migrator.MigrationStatus(r.Context(), id)
	if err != nil {
		writeMigrationError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toMigrationResponse(mig))
}

func isTerminalRollback(state string) bool {
	return state == repository.MigrationStateRolledBack || state == repository.MigrationStateFailed
}

// writeMigrationError maps the tenant-package migration sentinels to
// HTTP statuses, falling back to the shared repository-error mapper for
// repository sentinels (ErrInvalidArgument, ErrNotFound, ...).
func writeMigrationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, tenant.ErrMigrationInProgress):
		WriteError(w, http.StatusConflict, "migration_in_progress",
			"a migration is already in progress for this tenant")
	case errors.Is(err, tenant.ErrSourceRegionUnset):
		WriteError(w, http.StatusUnprocessableEntity, "source_region_unset",
			"tenant has no residency region to migrate from")
	case errors.Is(err, tenant.ErrNoMigration):
		WriteError(w, http.StatusNotFound, "no_migration",
			"no migration found for this tenant")
	default:
		WriteRepositoryError(w, err)
	}
}
