package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// OpsHealthHistoryResponse wraps a list of historical snapshots.
type OpsHealthHistoryResponse struct {
	Snapshots []OpsHealthSnapshotDTO `json:"snapshots"`
}

// OpsHealthSnapshotDTO is the API representation of a snapshot.
type OpsHealthSnapshotDTO struct {
	ID              uuid.UUID              `json:"id"`
	TenantID        uuid.UUID              `json:"tenant_id"`
	HealthScore     int                    `json:"health_score"`
	ComponentScores json.RawMessage        `json:"component_scores"`
	CreatedAt       time.Time              `json:"created_at"`
}

// OpsHealthRecordRequest is the body for recording a health snapshot.
type OpsHealthRecordRequest struct {
	HealthScore     int             `json:"health_score"`
	ComponentScores json.RawMessage `json:"component_scores"`
}

// OpsHealthHandler exposes operational health endpoints.
type OpsHealthHandler struct {
	snapshots repository.OpsHealthSnapshotRepository
	logger    *slog.Logger
}

// NewOpsHealthHandler returns a ready-to-use handler.
func NewOpsHealthHandler(
	snapshots repository.OpsHealthSnapshotRepository,
	logger *slog.Logger,
) *OpsHealthHandler {
	if logger == nil {
		logger = slog.Default()
	}
	return &OpsHealthHandler{
		snapshots: snapshots,
		logger:    logger,
	}
}

// Register wires the handler routes onto the mux.
func (h *OpsHealthHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/ops/health", h.getLatest)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/ops/health/history", h.history)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/ops/health", h.record)
}

func (h *OpsHealthHandler) getLatest(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	snap, err := h.snapshots.GetLatest(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, OpsHealthSnapshotDTO{
		ID:              snap.ID,
		TenantID:        snap.TenantID,
		HealthScore:     snap.HealthScore,
		ComponentScores: snap.ComponentScores,
		CreatedAt:       snap.CreatedAt,
	})
}

func (h *OpsHealthHandler) history(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	days := 7
	if q := r.URL.Query().Get("days"); q == "30" {
		days = 30
	}
	since := time.Now().UTC().AddDate(0, 0, -days)
	snaps, err := h.snapshots.ListHistory(r.Context(), tenantID, since)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	dtos := make([]OpsHealthSnapshotDTO, 0, len(snaps))
	for _, s := range snaps {
		dtos = append(dtos, OpsHealthSnapshotDTO{
			ID:              s.ID,
			TenantID:        s.TenantID,
			HealthScore:     s.HealthScore,
			ComponentScores: s.ComponentScores,
			CreatedAt:       s.CreatedAt,
		})
	}
	WriteJSON(w, http.StatusOK, OpsHealthHistoryResponse{Snapshots: dtos})
}

func (h *OpsHealthHandler) record(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req OpsHealthRecordRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.HealthScore < 0 || req.HealthScore > 100 {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "health_score must be 0-100")
		return
	}
	snap, err := h.snapshots.Create(r.Context(), tenantID, repository.OpsHealthSnapshot{
		HealthScore:     req.HealthScore,
		ComponentScores: req.ComponentScores,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, OpsHealthSnapshotDTO{
		ID:              snap.ID,
		TenantID:        snap.TenantID,
		HealthScore:     snap.HealthScore,
		ComponentScores: snap.ComponentScores,
		CreatedAt:       snap.CreatedAt,
	})
}
