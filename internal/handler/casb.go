package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// CASBNoOpsReader is the read-only slice of the NoOps store the handler
// needs to surface the shadow-IT verdict (classification + the action
// the engine decided) alongside the discovered-app inventory. Both the
// postgres and memory NoOps stores satisfy it. Kept as a narrow
// read-only interface so the discovery handler never gains a write path
// into the NoOps pipeline (which is owned by the leader-only engine).
type CASBNoOpsReader interface {
	ListClassifications(ctx context.Context, tenantID uuid.UUID) ([]repository.AppClassification, error)
	ListActions(ctx context.Context, tenantID uuid.UUID, limit int) ([]repository.CASBAppAction, error)
}

// CASBHandler exposes the CASB discovery REST surface: connector
// CRUD, test/sync triggers, discovered-apps listing, and posture
// reports. When an inline-CASB service is wired via
// SetInlineService it also serves inline-rule CRUD. When a NoOps
// reader is wired via SetNoOpsReader the discovered-apps listing is
// enriched with the per-app verdict and a NoOps action timeline is
// served.
type CASBHandler struct {
	svc    *casb.Service
	inline *casb.InlineCASBService
	noops  CASBNoOpsReader
	logger *slog.Logger
}

// NewCASBHandler wires the handler.
func NewCASBHandler(svc *casb.Service) *CASBHandler {
	return &CASBHandler{svc: svc}
}

// SetInlineService attaches the inline-CASB rule service so the
// inline-rule CRUD routes become live. Kept as a post-construction
// setter (mirroring DeviceHandler.SetEnrollmentService) so the
// constructor signature stays stable for the many call sites and
// tests that only exercise discovery.
func (h *CASBHandler) SetInlineService(svc *casb.InlineCASBService) {
	h.inline = svc
}

// SetNoOpsReader attaches the shadow-IT NoOps store reader so the
// discovered-apps listing carries each app's classification + decided
// action inline, and the NoOps action timeline route becomes live.
// Kept as a post-construction setter (mirroring SetInlineService) so
// the constructor stays stable; when unset the handler serves the
// discovery surface only and verdict fields are omitted.
func (h *CASBHandler) SetNoOpsReader(r CASBNoOpsReader) {
	h.noops = r
}

// SetLogger attaches a logger so the otherwise-silent NoOps verdict
// degradation paths (a store error in attachVerdicts drops to the bare
// inventory) emit an observability signal instead of failing dark.
// Optional and nil-safe: every logging call guards on a non-nil logger,
// so handlers constructed without one (e.g. discovery-only tests) keep
// working.
func (h *CASBHandler) SetLogger(l *slog.Logger) {
	h.logger = l
}

// Register attaches routes.
func (h *CASBHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/connectors", h.listConnectors)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/casb/connectors", h.createConnector)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/connectors/{id}", h.getConnector)
	MountTenantScoped(mux, "PATCH /api/v1/tenants/{tenant_id}/casb/connectors/{id}", h.updateConnector)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/casb/connectors/{id}", h.deleteConnector)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/casb/connectors/{id}/test", h.testConnector)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/casb/connectors/{id}/sync", h.syncConnector)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/apps", h.listApps)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/apps/{app_id}/posture", h.getPosture)

	// NoOps action timeline. Only mounted when a NoOps reader is wired;
	// deployments without the shadow-IT pipeline keep the discovery
	// surface only.
	if h.noops != nil {
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/noops/actions", h.listNoOpsActions)
	}

	// Inline-CASB rule CRUD. Only mounted when an inline service is
	// wired; deployments without it keep the discovery surface only.
	if h.inline != nil {
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/inline-rules", h.listInlineRules)
		MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/casb/inline-rules", h.createInlineRule)
		MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/casb/inline-rules/{id}", h.getInlineRule)
		MountTenantScoped(mux, "PATCH /api/v1/tenants/{tenant_id}/casb/inline-rules/{id}", h.updateInlineRule)
		MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/casb/inline-rules/{id}", h.deleteInlineRule)
	}
}

// --- JSON request/response projections ---

type casbConnectorCreateRequest struct {
	Type   string          `json:"type"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config,omitempty"`
	Secret json.RawMessage `json:"secret,omitempty"`
}

type casbConnectorUpdateRequest struct {
	Name   string          `json:"name,omitempty"`
	Config json.RawMessage `json:"config,omitempty"`
	Secret json.RawMessage `json:"secret,omitempty"`
	Status string          `json:"status,omitempty"`
}

type casbConnectorResponse struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	Type       string          `json:"type"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	Config     json.RawMessage `json:"config,omitempty"`
	SecretSet  bool            `json:"secret_set"`
	LastSyncAt *string         `json:"last_sync_at,omitempty"`
	CreatedAt  string          `json:"created_at"`
	UpdatedAt  string          `json:"updated_at"`
}

func toCASBConnectorResponse(c repository.CASBConnector) casbConnectorResponse {
	r := casbConnectorResponse{
		ID:        c.ID.String(),
		TenantID:  c.TenantID.String(),
		Type:      string(c.Type),
		Name:      c.Name,
		Status:    string(c.Status),
		Config:    c.Config,
		SecretSet: isSecretSet(c.Secret),
		CreatedAt: c.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt: c.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if c.LastSyncAt != nil {
		s := c.LastSyncAt.Format("2006-01-02T15:04:05Z")
		r.LastSyncAt = &s
	}
	return r
}

type casbAppResponse struct {
	ID                string `json:"id"`
	TenantID          string `json:"tenant_id"`
	Name              string `json:"name"`
	Vendor            string `json:"vendor"`
	Category          string `json:"category"`
	RiskScore         int    `json:"risk_score"`
	UsersCount        int    `json:"users_count"`
	ActiveDeviceCount int    `json:"active_device_count"`
	FirstSeen         string `json:"first_seen"`
	LastSeen          string `json:"last_seen"`
	// Verdict is the shadow-IT NoOps decision for this app: its
	// classification (sanction, risk, confidence, source, rationale)
	// and, when the engine emitted one, the action it decided. Omitted
	// when no NoOps reader is wired or the app has not been classified
	// yet (e.g. discovered since the last reconcile sweep).
	Verdict *casbAppVerdict `json:"verdict,omitempty"`
}

// casbAppVerdict is the per-app shadow-IT decision projected for the
// console: the classification the engine computed plus the most recent
// action it decided (when risk cleared the action floor). It is
// metadata only — no upload content, just the verdict and its rationale.
type casbAppVerdict struct {
	Sanction     string             `json:"sanction"`
	RiskScore    int                `json:"risk_score"`
	Confidence   int                `json:"confidence"`
	Source       string             `json:"source"` // heuristic | ai_refined
	Rationale    string             `json:"rationale"`
	ClassifiedAt string             `json:"classified_at"`
	Action       *casbAppActionView `json:"action,omitempty"`
}

// casbAppActionView is the latest NoOps action the engine decided for an
// app: what it would do (or did, when auto-applied), and why.
type casbAppActionView struct {
	Enforcement  string `json:"enforcement"`
	Mode         string `json:"mode"` // auto | recommend
	TrafficClass string `json:"traffic_class,omitempty"`
	Applied      bool   `json:"applied"`
	Reason       string `json:"reason,omitempty"`
	DecidedAt    string `json:"decided_at"`
}

func toCASBAppResponse(a repository.CASBDiscoveredApp) casbAppResponse {
	return casbAppResponse{
		ID:                a.ID.String(),
		TenantID:          a.TenantID.String(),
		Name:              a.Name,
		Vendor:            a.Vendor,
		Category:          a.Category,
		RiskScore:         derefInt(a.RiskScore),
		UsersCount:        derefInt(a.UsersCount),
		ActiveDeviceCount: derefInt(a.ActiveDeviceCount),
		FirstSeen:         a.FirstSeen.Format("2006-01-02T15:04:05Z"),
		LastSeen:          a.LastSeen.Format("2006-01-02T15:04:05Z"),
	}
}

// derefInt returns the pointed-to value, or 0 when p is nil.
func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// --- handlers ---

func (h *CASBHandler) listConnectors(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		Limit: QueryLimit(r),
		After: r.URL.Query().Get("cursor"),
	}
	result, err := h.svc.ListConnectors(r.Context(), tenantID, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := struct {
		Items      []casbConnectorResponse `json:"items"`
		NextCursor string                  `json:"next_cursor,omitempty"`
	}{
		Items:      make([]casbConnectorResponse, 0, len(result.Items)),
		NextCursor: result.NextCursor,
	}
	for _, c := range result.Items {
		out.Items = append(out.Items, toCASBConnectorResponse(c))
	}
	WriteJSON(w, http.StatusOK, out)
}

func (h *CASBHandler) createConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req casbConnectorCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	if req.Type == "" || req.Name == "" {
		WriteError(w, http.StatusBadRequest, "invalid_body", "type and name are required")
		return
	}
	created, err := h.svc.CreateConnector(r.Context(), tenantID, casb.CreateConnectorInput{
		Type:   repository.CASBConnectorType(req.Type),
		Name:   req.Name,
		Config: req.Config,
		Secret: req.Secret,
	}, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toCASBConnectorResponse(created))
}

func (h *CASBHandler) getConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	c, err := h.svc.GetConnector(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toCASBConnectorResponse(c))
}

func (h *CASBHandler) updateConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req casbConnectorUpdateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	input := casb.UpdateConnectorInput{
		Name:   req.Name,
		Config: req.Config,
		Secret: req.Secret,
	}
	if req.Status != "" {
		s := repository.CASBConnectorStatus(req.Status)
		if !s.IsValid() {
			WriteError(w, http.StatusBadRequest, "invalid_param",
				"status must be one of: active, disabled, error, configuring")
			return
		}
		input.Status = &s
	}
	updated, err := h.svc.UpdateConnector(r.Context(), tenantID, id, input, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toCASBConnectorResponse(updated))
}

func (h *CASBHandler) deleteConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeleteConnector(r.Context(), tenantID, id, actorFromCtx(r)); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *CASBHandler) testConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.TestConnector(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
			WriteRepositoryError(w, err)
			return
		}
		WriteError(w, http.StatusBadGateway, "connector_test_failed", "external service unavailable")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *CASBHandler) syncConnector(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.SyncConnector(r.Context(), tenantID, id); err != nil {
		if errors.Is(err, repository.ErrNotFound) || errors.Is(err, repository.ErrInvalidArgument) {
			WriteRepositoryError(w, err)
			return
		}
		WriteError(w, http.StatusBadGateway, "sync_failed", "external service unavailable")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]string{"status": "synced"})
}

func (h *CASBHandler) listApps(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	apps, err := h.svc.DiscoverSaaSApps(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]casbAppResponse, 0, len(apps))
	for _, a := range apps {
		items = append(items, toCASBAppResponse(a))
	}
	// Enrich each app with its shadow-IT NoOps verdict when the
	// pipeline is wired. A reader error degrades to the bare inventory
	// rather than failing the listing — discovery must keep working
	// even if the NoOps store hiccups.
	if h.noops != nil {
		h.attachVerdicts(r.Context(), tenantID, items)
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// noopsActionScanLimit bounds how many recent NoOps actions listApps
// scans to find the latest decision per app. Generous enough to cover a
// tenant's active inventory in one page; apps whose last action predates
// this window still show their (authoritative) classification, just
// without the supplementary action context.
const noopsActionScanLimit = 500

// attachVerdicts folds the NoOps classification (authoritative current
// verdict, one per app) and the most recent decided action into the
// matching discovered-app rows, joined by app name (the classification's
// AppName is the discovered app's Name by construction). A missing
// classification leaves Verdict nil (app discovered but not yet swept).
// A store error degrades to the bare inventory rather than failing the
// listing, but is logged (when a logger is wired) so the degradation is
// observable instead of silent.
func (h *CASBHandler) attachVerdicts(ctx context.Context, tenantID uuid.UUID, items []casbAppResponse) {
	classes, err := h.noops.ListClassifications(ctx, tenantID)
	if err != nil {
		if h.logger != nil {
			h.logger.WarnContext(ctx, "casb: NoOps classifications unavailable; serving discovered apps without verdict",
				slog.String("tenant_id", tenantID.String()),
				slog.String("error", err.Error()))
		}
		return
	}
	if len(classes) == 0 {
		return
	}
	byName := make(map[string]repository.AppClassification, len(classes))
	for _, c := range classes {
		byName[c.AppName] = c
	}
	// ListActions is newest-first, so the first row seen for a name is
	// its most recent decision.
	latestAction := make(map[string]repository.CASBAppAction)
	if actions, aErr := h.noops.ListActions(ctx, tenantID, noopsActionScanLimit); aErr == nil {
		for _, a := range actions {
			if _, seen := latestAction[a.AppName]; !seen {
				latestAction[a.AppName] = a
			}
		}
	} else if h.logger != nil {
		// Classifications succeeded; only the supplementary action
		// context is missing. Surface the verdict anyway (action
		// omitted) but record why the badge will be absent.
		h.logger.WarnContext(ctx, "casb: NoOps actions unavailable; serving verdicts without decided-action context",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", aErr.Error()))
	}
	for i := range items {
		c, ok := byName[items[i].Name]
		if !ok {
			continue
		}
		v := &casbAppVerdict{
			Sanction:     string(c.Sanction),
			RiskScore:    c.RiskScore,
			Confidence:   c.Confidence,
			Source:       c.Source,
			Rationale:    c.Rationale,
			ClassifiedAt: c.ClassifiedAt.UTC().Format(time.RFC3339),
		}
		if a, ok := latestAction[items[i].Name]; ok {
			v.Action = toCASBAppActionView(a)
		}
		items[i].Verdict = v
	}
}

func (h *CASBHandler) getPosture(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	appID, ok := PathUUID(w, r, "app_id")
	if !ok {
		return
	}
	report, err := h.svc.GetSaaSPosture(r.Context(), tenantID, appID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, report)
}

// --- NoOps action timeline ---

// casbNoOpsActionResponse is one row in the shadow-IT NoOps audit
// timeline: an action the engine emitted for a discovered app, with the
// classification snapshot that drove it. Metadata only.
type casbNoOpsActionResponse struct {
	ID           string `json:"id"`
	AppName      string `json:"app_name"`
	Category     string `json:"category"`
	Enforcement  string `json:"enforcement"`
	TrafficClass string `json:"traffic_class,omitempty"`
	Mode         string `json:"mode"`
	RiskScore    int    `json:"risk_score"`
	Confidence   int    `json:"confidence"`
	Sanction     string `json:"sanction"`
	Applied      bool   `json:"applied"`
	Reason       string `json:"reason,omitempty"`
	CreatedAt    string `json:"created_at"`
}

func toCASBNoOpsActionResponse(a repository.CASBAppAction) casbNoOpsActionResponse {
	return casbNoOpsActionResponse{
		ID:           a.ID.String(),
		AppName:      a.AppName,
		Category:     a.Category,
		Enforcement:  string(a.Enforcement),
		TrafficClass: string(a.TrafficClass),
		Mode:         string(a.Mode),
		RiskScore:    a.RiskScore,
		Confidence:   a.Confidence,
		Sanction:     string(a.Sanction),
		Applied:      a.Applied,
		Reason:       a.Reason,
		CreatedAt:    a.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// toCASBAppActionView projects the latest action onto the compact view
// embedded in a discovered app's verdict block.
func toCASBAppActionView(a repository.CASBAppAction) *casbAppActionView {
	return &casbAppActionView{
		Enforcement:  string(a.Enforcement),
		Mode:         string(a.Mode),
		TrafficClass: string(a.TrafficClass),
		Applied:      a.Applied,
		Reason:       a.Reason,
		DecidedAt:    a.CreatedAt.UTC().Format(time.RFC3339),
	}
}

// listNoOpsActions serves the per-tenant NoOps action audit timeline,
// newest first. Only mounted when a NoOps reader is wired.
func (h *CASBHandler) listNoOpsActions(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	actions, err := h.noops.ListActions(r.Context(), tenantID, QueryLimit(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]casbNoOpsActionResponse, 0, len(actions))
	for _, a := range actions {
		items = append(items, toCASBNoOpsActionResponse(a))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// --- inline-CASB rule CRUD ---

type casbInlineRuleCreateRequest struct {
	AppID      string                `json:"app_id"`
	Action     string                `json:"action"`
	Verdict    string                `json:"verdict"`
	Conditions casb.InlineConditions `json:"conditions"`
	Enabled    bool                  `json:"enabled"`
	Priority   int32                 `json:"priority"`
}

// casbInlineRuleUpdateRequest is a partial update: nil fields are
// left unchanged. Action/Verdict are validated by the service.
type casbInlineRuleUpdateRequest struct {
	AppID      *string                `json:"app_id"`
	Action     *string                `json:"action"`
	Verdict    *string                `json:"verdict"`
	Conditions *casb.InlineConditions `json:"conditions"`
	Enabled    *bool                  `json:"enabled"`
	Priority   *int32                 `json:"priority"`
}

type casbInlineRuleResponse struct {
	ID         string                `json:"id"`
	TenantID   string                `json:"tenant_id"`
	AppID      string                `json:"app_id"`
	Action     string                `json:"action"`
	Verdict    string                `json:"verdict"`
	Conditions casb.InlineConditions `json:"conditions"`
	Enabled    bool                  `json:"enabled"`
	Priority   int32                 `json:"priority"`
	CreatedAt  string                `json:"created_at"`
	UpdatedAt  string                `json:"updated_at"`
}

func toCASBInlineRuleResponse(r casb.InlineRule) casbInlineRuleResponse {
	return casbInlineRuleResponse{
		ID:         r.ID.String(),
		TenantID:   r.TenantID.String(),
		AppID:      r.AppID,
		Action:     string(r.Action),
		Verdict:    string(r.Verdict),
		Conditions: r.Conditions,
		Enabled:    r.Enabled,
		Priority:   r.Priority,
		CreatedAt:  r.CreatedAt.Format("2006-01-02T15:04:05Z"),
		UpdatedAt:  r.UpdatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

func (h *CASBHandler) listInlineRules(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	rules, err := h.inline.ListInlineRules(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]casbInlineRuleResponse, 0, len(rules))
	for _, rule := range rules {
		items = append(items, toCASBInlineRuleResponse(rule))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *CASBHandler) createInlineRule(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req casbInlineRuleCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	created, err := h.inline.CreateInlineRule(r.Context(), tenantID, casb.CreateInlineRuleInput{
		AppID:      req.AppID,
		Action:     casb.InlineAction(req.Action),
		Verdict:    casb.InlineVerdict(req.Verdict),
		Conditions: req.Conditions,
		Enabled:    req.Enabled,
		Priority:   req.Priority,
	}, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toCASBInlineRuleResponse(created))
}

func (h *CASBHandler) getInlineRule(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	rule, err := h.inline.GetInlineRule(r.Context(), tenantID, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toCASBInlineRuleResponse(rule))
}

func (h *CASBHandler) updateInlineRule(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req casbInlineRuleUpdateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	input := casb.UpdateInlineRuleInput{
		AppID:      req.AppID,
		Conditions: req.Conditions,
		Enabled:    req.Enabled,
		Priority:   req.Priority,
	}
	if req.Action != nil {
		a := casb.InlineAction(*req.Action)
		input.Action = &a
	}
	if req.Verdict != nil {
		v := casb.InlineVerdict(*req.Verdict)
		input.Verdict = &v
	}
	updated, err := h.inline.UpdateInlineRule(r.Context(), tenantID, id, input, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toCASBInlineRuleResponse(updated))
}

func (h *CASBHandler) deleteInlineRule(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.inline.DeleteInlineRule(r.Context(), tenantID, id, actorFromCtx(r)); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
