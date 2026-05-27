package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// PolicyHandler exposes the policy graph + bundle endpoints.
type PolicyHandler struct {
	svc *policy.Service
}

// NewPolicyHandler wires the handler.
func NewPolicyHandler(svc *policy.Service) *PolicyHandler {
	return &PolicyHandler{svc: svc}
}

// Register attaches routes.
func (h *PolicyHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/tenants/{tenant_id}/policy", h.getGraph)
	mux.HandleFunc("PUT /api/v1/tenants/{tenant_id}/policy", h.putGraph)
	mux.HandleFunc("POST /api/v1/tenants/{tenant_id}/policy/compile", h.compile)
	mux.HandleFunc("GET /api/v1/tenants/{tenant_id}/policy/bundles/{target_type}", h.getBundle)
}

// PolicyGraphResponse is the JSON projection of repository.PolicyGraph.
type PolicyGraphResponse struct {
	ID              string          `json:"id"`
	TenantID        string          `json:"tenant_id"`
	Version         int             `json:"version"`
	Graph           json.RawMessage `json:"graph"`
	CompiledAt      *string         `json:"compiled_at,omitempty"`
	CompilerVersion string          `json:"compiler_version,omitempty"`
	CreatedAt       string          `json:"created_at"`
}

func toPolicyGraphResponse(g repository.PolicyGraph) PolicyGraphResponse {
	resp := PolicyGraphResponse{
		ID: g.ID.String(), TenantID: g.TenantID.String(),
		Version: g.Version, Graph: g.Graph,
		CompilerVersion: g.CompilerVersion,
		CreatedAt:       g.CreatedAt.Format(time.RFC3339Nano),
	}
	if g.CompiledAt != nil {
		s := g.CompiledAt.Format(time.RFC3339Nano)
		resp.CompiledAt = &s
	}
	if len(resp.Graph) == 0 {
		resp.Graph = json.RawMessage(`{}`)
	}
	return resp
}

func (h *PolicyHandler) getGraph(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	g, err := h.svc.GetCurrentGraph(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toPolicyGraphResponse(g))
}

func (h *PolicyHandler) putGraph(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	// Read raw body so the caller can submit any shape of graph
	// document (PR7's typed model is a subset of free-form JSON).
	var raw json.RawMessage
	if !DecodeJSON(w, r, &raw) {
		return
	}
	g, err := h.svc.PutGraph(r.Context(), tenantID, actorFromCtx(r), raw)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusCreated, toPolicyGraphResponse(g))
}

// PolicyCompileResponse is the JSON response from POST /policy/compile.
type PolicyCompileResponse struct {
	GraphID    string                 `json:"graph_id"`
	CompiledAt string                 `json:"compiled_at"`
	Bundles    []PolicyBundleResponse `json:"bundles"`
}

// PolicyBundleResponse is the metadata-only projection of a
// PolicyBundle. The full bundle bytes are fetched via the
// separate GET /policy/bundles/{target_type} endpoint.
type PolicyBundleResponse struct {
	ID            string `json:"id"`
	PolicyGraphID string `json:"policy_graph_id"`
	TargetType    string `json:"target_type"`
	Bundle        string `json:"bundle,omitempty"`    // base64
	Signature     string `json:"signature,omitempty"` // base64
	CreatedAt     string `json:"created_at"`
}

func toPolicyBundleResponse(b repository.PolicyBundle, includeBytes bool) PolicyBundleResponse {
	resp := PolicyBundleResponse{
		ID: b.ID.String(), PolicyGraphID: b.PolicyGraphID.String(),
		TargetType: string(b.TargetType),
		CreatedAt:  b.CreatedAt.Format(time.RFC3339Nano),
	}
	if includeBytes {
		resp.Bundle = base64.StdEncoding.EncodeToString(b.Bundle)
		resp.Signature = base64.StdEncoding.EncodeToString(b.Signature)
	}
	return resp
}

func (h *PolicyHandler) compile(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	res, err := h.svc.Compile(r.Context(), tenantID, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	bundles := make([]PolicyBundleResponse, 0, len(res.Bundles))
	for _, b := range res.Bundles {
		bundles = append(bundles, toPolicyBundleResponse(b, false))
	}
	WriteJSON(w, http.StatusAccepted, PolicyCompileResponse{
		GraphID:    res.GraphID.String(),
		CompiledAt: res.Compiled.Format(time.RFC3339Nano),
		Bundles:    bundles,
	})
}

func (h *PolicyHandler) getBundle(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	target := repository.PolicyBundleTarget(r.PathValue("target_type"))
	switch target {
	case repository.PolicyBundleTargetEdge, repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud, repository.PolicyBundleTargetMobile:
	default:
		WriteError(w, http.StatusBadRequest, "invalid_target", "target_type must be one of edge|endpoint|cloud|mobile")
		return
	}
	b, err := h.svc.GetLatestBundle(r.Context(), tenantID, target)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toPolicyBundleResponse(b, true))
}
