package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// PolicyHandler exposes the policy graph + bundle + signing-key
// endpoints. The signing-key surface is the PR7 addition: per-tenant
// Ed25519 keypair management, public-key publication, and an
// agent-pull endpoint for compiled bundles that honours
// HEAD / If-None-Match / If-Modified-Since so receivers don't
// re-download a bundle they already cache.
type PolicyHandler struct {
	svc  *policy.Service
	keys *policy.KeyService
}

// NewPolicyHandler wires the handler.
func NewPolicyHandler(svc *policy.Service, keys *policy.KeyService) *PolicyHandler {
	return &PolicyHandler{svc: svc, keys: keys}
}

// Register attaches routes.
func (h *PolicyHandler) Register(mux *http.ServeMux) {
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy", h.getGraph)
	MountTenantScoped(mux, "PUT /api/v1/tenants/{tenant_id}/policy", h.putGraph)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy/compile", h.compile)
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy/bundles/{target_type}", h.getBundle)
	// Agent-pull endpoint for the bundle payload itself. Returns
	// application/vnd.sng.policy-bundle (MessagePack) with an
	// ETag derived from the bundle bytes so HEAD / If-None-Match
	// requests short-circuit on the agent path.
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy/bundles/{target_type}/payload", h.downloadBundle)
	MountTenantScoped(mux, "HEAD /api/v1/tenants/{tenant_id}/policy/bundles/{target_type}/payload", h.downloadBundle)
	// Signing key management.
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy/signing-keys", h.listSigningKeys)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy/signing-keys/rotate", h.rotateSigningKey)
	MountTenantScoped(mux, "POST /api/v1/tenants/{tenant_id}/policy/signing-keys/{key_id}/revoke", h.revokeSigningKey)
	// Public-key publication (no tenant prefix consumer is the
	// receiver, but we keep the route tenant-scoped so signed
	// bundles cannot be cross-verified between tenants).
	MountTenantScoped(mux, "GET /api/v1/tenants/{tenant_id}/policy/signing-keys/{key_id}/public-key", h.getPublicKey)
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
// separate GET /policy/bundles/{target_type}/payload endpoint so
// admin UIs can paginate metadata without downloading every
// bundle blob.
type PolicyBundleResponse struct {
	ID            string `json:"id"`
	PolicyGraphID string `json:"policy_graph_id"`
	TargetType    string `json:"target_type"`
	KeyID         string `json:"key_id,omitempty"`
	Bundle        string `json:"bundle,omitempty"`    // base64
	Signature     string `json:"signature,omitempty"` // base64
	CreatedAt     string `json:"created_at"`
}

func toPolicyBundleResponse(b repository.PolicyBundle, includeBytes bool) PolicyBundleResponse {
	resp := PolicyBundleResponse{
		ID: b.ID.String(), PolicyGraphID: b.PolicyGraphID.String(),
		TargetType: string(b.TargetType),
		KeyID:      b.KeyID,
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

func parseTarget(w http.ResponseWriter, r *http.Request) (repository.PolicyBundleTarget, bool) {
	target := repository.PolicyBundleTarget(r.PathValue("target_type"))
	switch target {
	case repository.PolicyBundleTargetEdge, repository.PolicyBundleTargetEndpoint,
		repository.PolicyBundleTargetCloud, repository.PolicyBundleTargetMobile:
		return target, true
	default:
		WriteError(w, http.StatusBadRequest, "invalid_target", "target_type must be one of edge|endpoint|cloud|mobile")
		return "", false
	}
}

func (h *PolicyHandler) getBundle(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	target, ok := parseTarget(w, r)
	if !ok {
		return
	}
	b, err := h.svc.GetLatestBundle(r.Context(), tenantID, target)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toPolicyBundleResponse(b, true))
}

// bundleContentType is the wire MIME type for a compiled bundle.
// Agents recognise the vendored subtype so caches can be configured
// independently of generic application/octet-stream.
const bundleContentType = "application/vnd.sng.policy-bundle"

// downloadBundle serves the raw MessagePack-encoded bundle bytes
// for agent consumption. Supports HEAD + If-None-Match so a polling
// agent that already has the current bundle gets 304 instead of
// re-downloading. The Ed25519 signature ships in the X-Sng-Policy-
// Signature header (base64) along with X-Sng-Policy-Key-Id so the
// agent knows which public key to verify against.
func (h *PolicyHandler) downloadBundle(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	target, ok := parseTarget(w, r)
	if !ok {
		return
	}
	b, err := h.svc.GetLatestBundle(r.Context(), tenantID, target)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	// Strong ETag = sha256(bundle bytes) hex-encoded, double-quoted
	// per RFC 7232. Strong because the bundle bytes are byte-stable:
	// compiling the same graph twice produces identical bytes (the
	// canonical-JSON + msgpack pipeline is deterministic).
	sum := sha256.Sum256(b.Bundle)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Last-Modified", b.CreatedAt.UTC().Format(http.TimeFormat))
	w.Header().Set("X-Sng-Policy-Signature", base64.StdEncoding.EncodeToString(b.Signature))
	w.Header().Set("X-Sng-Policy-Bundle-Id", b.ID.String())
	w.Header().Set("X-Sng-Policy-Graph-Id", b.PolicyGraphID.String())
	if b.KeyID != "" {
		w.Header().Set("X-Sng-Policy-Key-Id", b.KeyID)
	}
	// Conditional-request handling.
	if match := r.Header.Get("If-None-Match"); match != "" && etagMatches(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", bundleContentType)
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b.Bundle)
}

// etagMatches implements a minimal RFC 7232 If-None-Match parser:
// "*" matches anything; otherwise we split on comma and compare
// against the strong ETag we just rendered. We deliberately do not
// strip the W/ prefix because all our ETags are strong.
func etagMatches(headerVal, etag string) bool {
	if headerVal == "*" {
		return true
	}
	for _, tok := range splitCommaTrim(headerVal) {
		if tok == etag {
			return true
		}
	}
	return false
}

func splitCommaTrim(s string) []string {
	out := make([]string, 0, 2)
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			tok := s[start:i]
			// Trim spaces manually to avoid pulling in strings.
			for len(tok) > 0 && (tok[0] == ' ' || tok[0] == '\t') {
				tok = tok[1:]
			}
			for len(tok) > 0 && (tok[len(tok)-1] == ' ' || tok[len(tok)-1] == '\t') {
				tok = tok[:len(tok)-1]
			}
			if tok != "" {
				out = append(out, tok)
			}
			start = i + 1
		}
	}
	return out
}

// --- Signing-key endpoints -------------------------------------------------

// PolicySigningKeyResponse is the JSON projection of a signing key.
// The private-key material is NEVER included; the admin surface
// exposes the public-key bytes, the key_id, and lifecycle metadata.
type PolicySigningKeyResponse struct {
	ID          string  `json:"id"`
	TenantID    string  `json:"tenant_id"`
	KeyID       string  `json:"key_id"`
	Algorithm   string  `json:"algorithm"`
	PublicKey   string  `json:"public_key"` // base64
	Status      string  `json:"status"`
	ActivatedAt string  `json:"activated_at"`
	RotatedAt   *string `json:"rotated_at,omitempty"`
	RevokedAt   *string `json:"revoked_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

func toPolicySigningKeyResponse(k repository.PolicySigningKey) PolicySigningKeyResponse {
	resp := PolicySigningKeyResponse{
		ID:          k.ID.String(),
		TenantID:    k.TenantID.String(),
		KeyID:       k.KeyID,
		Algorithm:   k.Algorithm,
		PublicKey:   base64.StdEncoding.EncodeToString(k.PublicKey),
		Status:      string(k.Status),
		ActivatedAt: k.ActivatedAt.Format(time.RFC3339Nano),
		CreatedAt:   k.CreatedAt.Format(time.RFC3339Nano),
	}
	if k.RotatedAt != nil {
		s := k.RotatedAt.Format(time.RFC3339Nano)
		resp.RotatedAt = &s
	}
	if k.RevokedAt != nil {
		s := k.RevokedAt.Format(time.RFC3339Nano)
		resp.RevokedAt = &s
	}
	return resp
}

func (h *PolicyHandler) listSigningKeys(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	keys, err := h.keys.List(r.Context(), tenantID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	out := make([]PolicySigningKeyResponse, 0, len(keys))
	for _, k := range keys {
		out = append(out, toPolicySigningKeyResponse(k))
	}
	WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (h *PolicyHandler) rotateSigningKey(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	// Provision an initial key if the tenant has none, otherwise
	// rotate. The KeyService can't make this decision on its own
	// because Rotate semantically requires an existing active key.
	// We use GetActiveNoCreate (not GetActive) so the existence
	// probe does NOT itself lazy-create a key — otherwise the
	// "no key yet" branch would silently no-op into the rotate
	// branch and double-provision on the very first call.
	_, err := h.keys.GetActiveNoCreate(r.Context(), tenantID)
	if errors.Is(err, repository.ErrNotFound) {
		created, cerr := h.keys.CreateInitial(r.Context(), tenantID, actorFromCtx(r))
		if cerr != nil {
			WriteRepositoryError(w, cerr)
			return
		}
		WriteJSON(w, http.StatusCreated, toPolicySigningKeyResponse(created))
		return
	}
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	rotated, err := h.keys.Rotate(r.Context(), tenantID, actorFromCtx(r))
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toPolicySigningKeyResponse(rotated))
}

func (h *PolicyHandler) revokeSigningKey(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	keyID := r.PathValue("key_id")
	if keyID == "" {
		WriteError(w, http.StatusBadRequest, "missing_key_id", "key_id path parameter is required")
		return
	}
	revoked, err := h.keys.Revoke(r.Context(), tenantID, actorFromCtx(r), keyID)
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, toPolicySigningKeyResponse(revoked))
}

// PolicyPublicKeyResponse is the public-key publication shape.
type PolicyPublicKeyResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"` // base64
	Status    string `json:"status"`
}

func (h *PolicyHandler) getPublicKey(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := PathUUID(w, r, "tenant_id")
	if !ok {
		return
	}
	keyID := r.PathValue("key_id")
	if keyID == "" {
		WriteError(w, http.StatusBadRequest, "missing_key_id", "key_id path parameter is required")
		return
	}
	var (
		k   repository.PolicySigningKey
		err error
	)
	// Fetching the public key must never have the side effect of
	// minting a new key. GetActiveNoCreate surfaces ErrNotFound
	// for callers that hit /public-key on a tenant that has not
	// yet rotated/provisioned a key.
	if keyID == "active" {
		k, err = h.keys.GetActiveNoCreate(r.Context(), tenantID)
	} else {
		k, err = h.keys.GetByKeyID(r.Context(), tenantID, keyID)
	}
	if err != nil {
		WriteRepositoryError(w, err)
		return
	}
	WriteJSON(w, http.StatusOK, PolicyPublicKeyResponse{
		KeyID:     k.KeyID,
		Algorithm: k.Algorithm,
		PublicKey: base64.StdEncoding.EncodeToString(k.PublicKey),
		Status:    string(k.Status),
	})
}
