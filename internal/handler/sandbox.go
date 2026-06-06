package handler

import (
	"encoding/base64"
	"errors"
	"net/http"

	"github.com/kennguy3n/visible-fishbone/internal/service/sandbox"
)

// SandboxHandler exposes the zero-day file-analysis REST surface:
// verdict lookup by SHA-256, recent-verdict listing, manual poll of
// a pending submission, file submission for detonation, and a
// provider-status probe. Verdicts are produced by the configured
// detonation provider (Cuckoo / CAPEv2 / BYO webhook) and persisted
// per tenant so a file is detonated at most once across the fleet.
type SandboxHandler struct {
	svc *sandbox.Service
}

// NewSandboxHandler wires the handler.
func NewSandboxHandler(svc *sandbox.Service) *SandboxHandler {
	return &SandboxHandler{svc: svc}
}

// Register attaches routes.
func (h *SandboxHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/sandbox/verdicts", h.listVerdicts)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/sandbox/submit", h.submit)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/sandbox/verdicts/{sha256}", h.getVerdict)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/sandbox/verdicts/{sha256}/disposition", h.getDisposition)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/sandbox/verdicts/{sha256}/poll", h.pollVerdict)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/sandbox/provider", h.providerStatus)
}

// --- JSON projections ---

type sandboxSubmitRequest struct {
	SHA256 string `json:"sha256"`
	// Filename is forwarded to the provider for report context.
	Filename string `json:"filename,omitempty"`
	// ContentBase64 is the raw file bytes, base64-encoded. Required
	// when a provider is configured; the digest is taken from
	// SHA256 (the caller already computed it), not recomputed here.
	ContentBase64 string `json:"content_base64,omitempty"`
}

type sandboxVerdictResponse struct {
	SHA256         string  `json:"sha256"`
	Classification string  `json:"classification"`
	Confidence     float64 `json:"confidence"`
	Provider       string  `json:"provider,omitempty"`
	SandboxID      string  `json:"sandbox_id,omitempty"`
	Summary        string  `json:"summary,omitempty"`
	Blocking       bool    `json:"blocking"`
	AnalyzedAt     *string `json:"analyzed_at,omitempty"`
}

func toSandboxVerdictResponse(v sandbox.Verdict) sandboxVerdictResponse {
	out := sandboxVerdictResponse{
		SHA256:         v.SHA256,
		Classification: string(v.Classification),
		Confidence:     v.Confidence,
		Provider:       v.Provider,
		SandboxID:      v.SandboxID,
		Summary:        v.Summary,
		Blocking:       v.Blocking(),
	}
	if !v.AnalyzedAt.IsZero() {
		s := v.AnalyzedAt.Format("2006-01-02T15:04:05Z")
		out.AnalyzedAt = &s
	}
	return out
}

func (h *SandboxHandler) listVerdicts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	verdicts, err := h.svc.ListVerdicts(r.Context(), tenantID, QueryLimit(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	items := make([]sandboxVerdictResponse, 0, len(verdicts))
	for _, v := range verdicts {
		items = append(items, toSandboxVerdictResponse(v))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (h *SandboxHandler) getVerdict(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	v, err := h.svc.GetVerdict(r.Context(), tenantID, r.PathValue("sha256"))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toSandboxVerdictResponse(v))
}

func (h *SandboxHandler) submit(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	var req sandboxSubmitRequest
	if !DecodeJSON(w, r, &req) {
		return
	}
	var content []byte
	if req.ContentBase64 != "" {
		decoded, derr := base64.StdEncoding.DecodeString(req.ContentBase64)
		if derr != nil {
			WriteError(w, http.StatusBadRequest, "invalid_body", "content_base64 is not valid base64")
			return
		}
		content = decoded
	}
	v, err := h.svc.Submit(r.Context(), sandbox.Submission{
		TenantID: tenantID,
		SHA256:   req.SHA256,
		Filename: req.Filename,
		Content:  content,
	}, actorFromCtx(r))
	if err != nil {
		// No provider configured is not a client error: the
		// submission was recorded as pending, there is simply no
		// backend to resolve it. Report 202 with the pending verdict.
		if errors.Is(err, sandbox.ErrNoProvider) {
			WriteJSON(w, http.StatusAccepted, toSandboxVerdictResponse(v))
			return
		}
		WriteRepositoryError(w, err)
		return
	}
	// A resolved verdict (synchronous provider) returns 200; a
	// queued submission returns 202.
	status := http.StatusAccepted
	if v.Classification != sandbox.ClassUnknown {
		status = http.StatusOK
	}
	WriteJSON(w, status, toSandboxVerdictResponse(v))
}

func (h *SandboxHandler) getDisposition(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	d, v, err := h.svc.Disposition(r.Context(), tenantID, r.PathValue("sha256"))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"sha256":      v.SHA256,
		"disposition": string(d),
		// clean is the single fail-closed boolean the data plane acts
		// on: true only when a resolved, clean verdict exists.
		"clean":   d.Clean(),
		"verdict": toSandboxVerdictResponse(v),
	})
}

func (h *SandboxHandler) pollVerdict(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	v, err := h.svc.Poll(r.Context(), tenantID, r.PathValue("sha256"))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toSandboxVerdictResponse(v))
}

func (h *SandboxHandler) providerStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := PathUUID(w, r, "tenant_id"); !ok {
		return
	}
	id := h.svc.ProviderID()
	WriteJSON(w, http.StatusOK, map[string]any{
		"configured": id != "",
		"provider":   id,
	})
}
