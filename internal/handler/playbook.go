package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/playbook"
)

// PlaybookHandler exposes the Playbook Engine REST surface.
type PlaybookHandler struct {
	engine   *playbook.Engine
	approval *playbook.ApprovalService
}

// NewPlaybookHandler wires the handler.
func NewPlaybookHandler(engine *playbook.Engine, approval *playbook.ApprovalService) *PlaybookHandler {
	return &PlaybookHandler{engine: engine, approval: approval}
}

// Register attaches playbook routes.
func (h *PlaybookHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/playbooks", h.listPlaybooks)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/playbooks", h.createPlaybook)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/playbooks/{id}", h.getPlaybook)
	MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/playbooks/{id}", h.updatePlaybook)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/playbooks/{id}", h.deletePlaybook)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/playbooks/{id}/dry-run", h.dryRun)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/playbooks/executions", h.listExecutions)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/playbooks/executions/{id}", h.getExecution)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/playbooks/approvals/pending", h.listPendingApprovals)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/playbooks/approvals/{id}/approve", h.approveExecution)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/playbooks/approvals/{id}/reject", h.rejectExecution)
}

// --- wire types -----------------------------------------------------------

type playbookResponse struct {
	ID               uuid.UUID       `json:"id"`
	TenantID         uuid.UUID       `json:"tenant_id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	TriggerCondition string          `json:"trigger_condition"`
	Steps            json.RawMessage `json:"steps"`
	Enabled          bool            `json:"enabled"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

func toPlaybookResponse(p repository.Playbook) playbookResponse {
	return playbookResponse{
		ID:               p.ID,
		TenantID:         p.TenantID,
		Name:             p.Name,
		Description:      p.Description,
		TriggerCondition: p.TriggerCondition,
		Steps:            p.Steps,
		Enabled:          p.Enabled,
		CreatedAt:        p.CreatedAt,
		UpdatedAt:        p.UpdatedAt,
	}
}

type executionResponse struct {
	ID           uuid.UUID       `json:"id"`
	TenantID     uuid.UUID       `json:"tenant_id"`
	PlaybookID   uuid.UUID       `json:"playbook_id"`
	Status       string          `json:"status"`
	TriggerEvent json.RawMessage `json:"trigger_event,omitempty"`
	StartedAt    time.Time       `json:"started_at"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

func toExecutionResponse(e repository.PlaybookExecution) executionResponse {
	return executionResponse{
		ID:           e.ID,
		TenantID:     e.TenantID,
		PlaybookID:   e.PlaybookID,
		Status:       e.Status,
		TriggerEvent: e.TriggerEvent,
		StartedAt:    e.StartedAt,
		CompletedAt:  e.CompletedAt,
		CreatedAt:    e.CreatedAt,
	}
}

type approvalResponse struct {
	ID          uuid.UUID  `json:"id"`
	TenantID    uuid.UUID  `json:"tenant_id"`
	ExecutionID uuid.UUID  `json:"execution_id"`
	ApproverID  *uuid.UUID `json:"approver_id,omitempty"`
	Status      string     `json:"status"`
	ExpiresAt   time.Time  `json:"expires_at"`
	DecidedAt   *time.Time `json:"decided_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func toApprovalResponse(a repository.PlaybookApproval) approvalResponse {
	return approvalResponse{
		ID:          a.ID,
		TenantID:    a.TenantID,
		ExecutionID: a.ExecutionID,
		ApproverID:  a.ApproverID,
		Status:      a.Status,
		ExpiresAt:   a.ExpiresAt,
		DecidedAt:   a.DecidedAt,
		CreatedAt:   a.CreatedAt,
	}
}

type createPlaybookRequest struct {
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	TriggerCondition string          `json:"trigger_condition"`
	Steps            json.RawMessage `json:"steps"`
	Enabled          bool            `json:"enabled"`
}

type updatePlaybookRequest struct {
	Name             *string          `json:"name,omitempty"`
	Description      *string          `json:"description,omitempty"`
	TriggerCondition *string          `json:"trigger_condition,omitempty"`
	Steps            *json.RawMessage `json:"steps,omitempty"`
	Enabled          *bool            `json:"enabled,omitempty"`
}

// --- handlers -------------------------------------------------------------

func (h *PlaybookHandler) listPlaybooks(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("after"),
	}
	result, err := h.engine.ListPlaybooks(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]playbookResponse, len(result.Items))
	for i, item := range result.Items {
		items[i] = toPlaybookResponse(item)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": result.NextCursor,
	})
}

func (h *PlaybookHandler) createPlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}

	var req createPlaybookRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		WriteError(w, http.StatusBadRequest, "invalid_argument", "name is required")
		return
	}

	pb, err := h.engine.CreatePlaybook(r.Context(), tenantID, repository.Playbook{
		TenantID:         tenantID,
		Name:             req.Name,
		Description:      req.Description,
		TriggerCondition: req.TriggerCondition,
		Steps:            req.Steps,
		Enabled:          req.Enabled,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toPlaybookResponse(pb))
}

func (h *PlaybookHandler) getPlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	pb, err := h.engine.GetPlaybook(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toPlaybookResponse(pb))
}

func (h *PlaybookHandler) updatePlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	var req updatePlaybookRequest
	if !DecodeJSON(w, r, &req) {
		return
	}

	patch := repository.PlaybookPatch{
		Name:             req.Name,
		Description:      req.Description,
		TriggerCondition: req.TriggerCondition,
		Enabled:          req.Enabled,
		Steps:            req.Steps,
	}

	pb, err := h.engine.UpdatePlaybook(r.Context(), tenantID, id, patch)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toPlaybookResponse(pb))
}

func (h *PlaybookHandler) deletePlaybook(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	if err := h.engine.DeletePlaybook(r.Context(), tenantID, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PlaybookHandler) dryRun(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	results, err := h.engine.DryRun(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"step_results": results})
}

func (h *PlaybookHandler) listExecutions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("after"),
	}
	result, err := h.engine.ListExecutions(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]executionResponse, len(result.Items))
	for i, item := range result.Items {
		items[i] = toExecutionResponse(item)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": result.NextCursor,
	})
}

func (h *PlaybookHandler) getExecution(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}

	exec, err := h.engine.GetExecution(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toExecutionResponse(exec))
}

func (h *PlaybookHandler) listPendingApprovals(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	approvals, err := h.approval.ListPending(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]approvalResponse, len(approvals))
	for i, a := range approvals {
		items[i] = toApprovalResponse(a)
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *PlaybookHandler) approveExecution(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	actor := actorFromCtx(r)

	approval, err := h.approval.Approve(r.Context(), tenantID, id, actor)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toApprovalResponse(approval))
}

func (h *PlaybookHandler) rejectExecution(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	actor := actorFromCtx(r)

	approval, err := h.approval.Reject(r.Context(), tenantID, id, actor)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toApprovalResponse(approval))
}
