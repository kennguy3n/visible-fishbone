// Package handler — dlp.go owns the REST surface for DLP policies,
// fingerprints, templates, and the classify debug endpoint.
//
// Endpoints (all tenant-scoped):
//
//	GET/POST /api/v1/tenants/{tenant_id}/dlp/policies
//	GET/PATCH/DELETE /api/v1/tenants/{tenant_id}/dlp/policies/{id}
//	POST /api/v1/tenants/{tenant_id}/dlp/policies/{id}/test
//	POST /api/v1/tenants/{tenant_id}/dlp/rules/advise
//	GET /api/v1/tenants/{tenant_id}/dlp/templates
//	POST /api/v1/tenants/{tenant_id}/dlp/templates/{template_id}/apply
//	POST /api/v1/tenants/{tenant_id}/dlp/classify
//	GET/POST /api/v1/tenants/{tenant_id}/dlp/fingerprints
package handler

import (
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlp"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlp/engine"
)

// DLPHandler exposes the DLP REST surface.
type DLPHandler struct {
	svc *dlp.Service
}

// NewDLPHandler wires the handler.
func NewDLPHandler(svc *dlp.Service) *DLPHandler {
	return &DLPHandler{svc: svc}
}

// Register attaches DLP routes.
func (h *DLPHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/policies", h.listPolicies)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dlp/policies", h.createPolicy)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/policies/{id}", h.getPolicy)
	MountTenantScoped(mux, "PATCH /api/v1/tenants/{tenant_id}/dlp/policies/{id}", h.updatePolicy)
	MountTenantScoped(mux, "DELETE /api/v1/tenants/{tenant_id}/dlp/policies/{id}", h.deletePolicy)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dlp/policies/{id}/test", h.testPolicy)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dlp/rules/advise", h.adviseRule)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/templates", h.listTemplates)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dlp/templates/{template_id}/apply", h.applyTemplate)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dlp/classify", h.classify)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/dlp/fingerprints", h.listFingerprints)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/dlp/fingerprints", h.registerFingerprint)
}

// --- wire types -----------------------------------------------------------

type dlpPolicyResponse struct {
	ID          uuid.UUID            `json:"id"`
	TenantID    uuid.UUID            `json:"tenant_id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Rules       []repository.DLPRule `json:"rules"`
	Action      string               `json:"action"`
	Enabled     bool                 `json:"enabled"`
	CreatedAt   time.Time            `json:"created_at"`
	UpdatedAt   time.Time            `json:"updated_at"`
}

func toDLPPolicyResponse(p repository.DLPPolicy) dlpPolicyResponse {
	return dlpPolicyResponse{
		ID:          p.ID,
		TenantID:    p.TenantID,
		Name:        p.Name,
		Description: p.Description,
		Rules:       p.Rules,
		Action:      string(p.Action),
		Enabled:     p.Enabled,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

type dlpPolicyCreateRequest struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Rules       []repository.DLPRule `json:"rules"`
	Action      string               `json:"action"`
	Enabled     *bool                `json:"enabled,omitempty"`
}

type dlpPolicyUpdateRequest struct {
	Name        *string               `json:"name,omitempty"`
	Description *string               `json:"description,omitempty"`
	Rules       *[]repository.DLPRule `json:"rules,omitempty"`
	Action      *string               `json:"action,omitempty"`
	Enabled     *bool                 `json:"enabled,omitempty"`
}

type dlpTestRequest struct {
	Content string `json:"content"`
}

type dlpTestResponse struct {
	Matched bool       `json:"matched"`
	Action  string     `json:"action"`
	Matches []dlpMatch `json:"matches"`
}

type dlpMatch struct {
	RuleType   string  `json:"rule_type"`
	Pattern    string  `json:"pattern"`
	Offset     int     `json:"offset"`
	Length     int     `json:"length"`
	Snippet    string  `json:"snippet"`
	Confidence float64 `json:"confidence"`
}

type dlpAdviseRequest struct {
	Rule    dlpAdviseRule      `json:"rule"`
	Samples []dlpLabeledSample `json:"samples"`
}

type dlpAdviseRule struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

type dlpLabeledSample struct {
	Text        string `json:"text"`
	ShouldMatch bool   `json:"should_match"`
}

type dlpAdviseResponse struct {
	Quality      dlpRuleQuality  `json:"quality"`
	Suggestions  []dlpSuggestion `json:"suggestions"`
	SafeToEnable bool            `json:"safe_to_enable"`
}

type dlpRuleQuality struct {
	Positives         int     `json:"positives"`
	Negatives         int     `json:"negatives"`
	TruePositives     int     `json:"true_positives"`
	FalsePositives    int     `json:"false_positives"`
	FalseNegatives    int     `json:"false_negatives"`
	TrueNegatives     int     `json:"true_negatives"`
	Precision         float64 `json:"precision"`
	Recall            float64 `json:"recall"`
	FalsePositiveRate float64 `json:"false_positive_rate"`
	FalseNegativeRate float64 `json:"false_negative_rate"`
	F1                float64 `json:"f1"`
}

type dlpSuggestion struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

func toDLPAdviseResponse(a engine.Advice) dlpAdviseResponse {
	suggestions := make([]dlpSuggestion, len(a.Suggestions))
	for i, s := range a.Suggestions {
		suggestions[i] = dlpSuggestion{
			Code:     string(s.Code),
			Severity: s.Severity,
			Message:  s.Message,
		}
	}
	return dlpAdviseResponse{
		Quality: dlpRuleQuality{
			Positives:         a.Quality.Positives,
			Negatives:         a.Quality.Negatives,
			TruePositives:     a.Quality.TruePositives,
			FalsePositives:    a.Quality.FalsePositives,
			FalseNegatives:    a.Quality.FalseNegatives,
			TrueNegatives:     a.Quality.TrueNegatives,
			Precision:         a.Quality.Precision,
			Recall:            a.Quality.Recall,
			FalsePositiveRate: a.Quality.FalsePositiveRate,
			FalseNegativeRate: a.Quality.FalseNegativeRate,
			F1:                a.Quality.F1,
		},
		Suggestions:  suggestions,
		SafeToEnable: a.SafeToEnable,
	}
}

type dlpClassifyRequest struct {
	ContentType string                    `json:"content_type"`
	Content     string                    `json:"content"`
	Metadata    dlpClassificationMetadata `json:"metadata"`
}

type dlpClassificationMetadata struct {
	Filename string `json:"filename"`
	Source   string `json:"source"`
	User     string `json:"user"`
}

type dlpClassifyResponse struct {
	Matches    []dlpMatch  `json:"matches"`
	PolicyIDs  []uuid.UUID `json:"policy_ids"`
	Action     string      `json:"action"`
	Confidence float64     `json:"confidence"`
}

type dlpTemplateResponse struct {
	ID          string               `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Category    string               `json:"category"`
	Rules       []repository.DLPRule `json:"rules"`
	Action      string               `json:"action"`
}

type dlpFingerprintResponse struct {
	ID           uuid.UUID `json:"id"`
	TenantID     uuid.UUID `json:"tenant_id"`
	Name         string    `json:"name"`
	ContentType  string    `json:"content_type"`
	RegisteredAt time.Time `json:"registered_at"`
}

type dlpFingerprintCreateRequest struct {
	Name        string `json:"name"`
	ContentType string `json:"content_type"`
	Content     string `json:"content"`
}

// --- handlers -------------------------------------------------------------

func (h *DLPHandler) listPolicies(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		After: r.URL.Query().Get("cursor"),
		Limit: QueryLimit(r),
	}
	result, err := h.svc.ListPolicies(r.Context(), tid, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]dlpPolicyResponse, len(result.Items))
	for i, p := range result.Items {
		items[i] = toDLPPolicyResponse(p)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": result.NextCursor,
	})
}

func (h *DLPHandler) createPolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req dlpPolicyCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	p, err := h.svc.CreatePolicy(r.Context(), tid, repository.DLPPolicy{
		Name:        req.Name,
		Description: req.Description,
		Rules:       req.Rules,
		Action:      repository.DLPAction(req.Action),
		Enabled:     enabled,
	})
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toDLPPolicyResponse(p))
}

func (h *DLPHandler) getPolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	p, err := h.svc.GetPolicy(r.Context(), tid, id)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDLPPolicyResponse(p))
}

func (h *DLPHandler) updatePolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req dlpPolicyUpdateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	patch := repository.DLPPolicyPatch{
		Name:        req.Name,
		Description: req.Description,
		Rules:       req.Rules,
		Enabled:     req.Enabled,
	}
	if req.Action != nil {
		a := repository.DLPAction(*req.Action)
		patch.Action = &a
	}
	p, err := h.svc.UpdatePolicy(r.Context(), tid, id, patch)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDLPPolicyResponse(p))
}

func (h *DLPHandler) deletePolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	if err := h.svc.DeletePolicy(r.Context(), tid, id); err != nil {
		WriteRepositoryError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *DLPHandler) testPolicy(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	id, ok := PathUUID(w, r, "id")
	if !ok {
		return
	}
	var req dlpTestRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	result, err := h.svc.TestPolicy(r.Context(), tid, id, []byte(req.Content))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, dlpTestResponse{
		Matched: result.Matched,
		Action:  string(result.Action),
		Matches: toDLPMatches(result.Matches),
	})
}

func (h *DLPHandler) adviseRule(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req dlpAdviseRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	rule := repository.DLPRule{
		Type:    repository.DLPRuleType(req.Rule.Type),
		Pattern: req.Rule.Pattern,
	}
	samples := make([]engine.LabeledSample, len(req.Samples))
	for i, s := range req.Samples {
		samples[i] = engine.LabeledSample{Text: s.Text, ShouldMatch: s.ShouldMatch}
	}
	advice, err := h.svc.AdviseRule(r.Context(), tid, rule, samples)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toDLPAdviseResponse(advice))
}

func (h *DLPHandler) listTemplates(w http.ResponseWriter, _ *http.Request) {
	templates := h.svc.ListTemplates()
	items := make([]dlpTemplateResponse, len(templates))
	for i, t := range templates {
		items[i] = dlpTemplateResponse{
			ID:          t.ID,
			Name:        t.Name,
			Description: t.Description,
			Category:    t.Category,
			Rules:       t.Rules,
			Action:      string(t.Action),
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *DLPHandler) applyTemplate(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	templateID := r.PathValue("template_id")
	if templateID == "" {
		WriteError(w, http.StatusBadRequest, "missing_param", "template_id is required")
		return
	}
	p, err := h.svc.ApplyTemplate(r.Context(), tid, templateID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toDLPPolicyResponse(p))
}

func (h *DLPHandler) classify(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req dlpClassifyRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	input := dlp.ClassificationInput{
		ContentType: req.ContentType,
		Content:     []byte(req.Content),
		Metadata: dlp.ClassificationMetadata{
			Filename: req.Metadata.Filename,
			Source:   req.Metadata.Source,
			User:     req.Metadata.User,
		},
	}
	result, err := h.svc.Classify(r.Context(), tid, input)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	policyIDs := result.PolicyIDs
	if policyIDs == nil {
		policyIDs = []uuid.UUID{}
	}
	WriteJSON(w, http.StatusOK, dlpClassifyResponse{
		Matches:    toDLPMatches(result.Matches),
		PolicyIDs:  policyIDs,
		Action:     string(result.Action),
		Confidence: result.Confidence,
	})
}

func (h *DLPHandler) listFingerprints(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	page := repository.Page{
		After: r.URL.Query().Get("cursor"),
		Limit: QueryLimit(r),
	}
	result, err := h.svc.ListFingerprints(r.Context(), tid, page)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]dlpFingerprintResponse, len(result.Items))
	for i, f := range result.Items {
		items[i] = dlpFingerprintResponse{
			ID:           f.ID,
			TenantID:     f.TenantID,
			Name:         f.Name,
			ContentType:  f.ContentType,
			RegisteredAt: f.RegisteredAt,
		}
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"items":       items,
		"next_cursor": result.NextCursor,
	})
}

func (h *DLPHandler) registerFingerprint(w http.ResponseWriter, r *http.Request) {
	tid, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req dlpFingerprintCreateRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	f, err := h.svc.RegisterFingerprint(r.Context(), tid, req.Name, req.ContentType, []byte(req.Content))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, dlpFingerprintResponse{
		ID:           f.ID,
		TenantID:     f.TenantID,
		Name:         f.Name,
		ContentType:  f.ContentType,
		RegisteredAt: f.RegisteredAt,
	})
}

func toDLPMatches(in []dlp.Match) []dlpMatch {
	out := make([]dlpMatch, len(in))
	for i, m := range in {
		out[i] = dlpMatch{
			RuleType:   string(m.RuleType),
			Pattern:    m.Pattern,
			Offset:     m.Offset,
			Length:     m.Length,
			Snippet:    m.Snippet,
			Confidence: m.Confidence,
		}
	}
	return out
}
