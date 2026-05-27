package handler

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

func newTestPolicyHandler(t *testing.T) (*PolicyHandler, repository.Tenant) {
	t.Helper()
	store := memory.NewStore()
	tenantRepo := memory.NewTenantRepository(store)
	tnt, err := tenantRepo.Create(context.Background(), repository.Tenant{
		Name: "Acme", Slug: "acme",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	policyRepo := memory.NewPolicyRepository(store)
	keyRepo := memory.NewPolicySigningKeyRepository(store)
	auditRepo := memory.NewAuditLogRepository(store)
	keys := policy.NewKeyService(keyRepo, auditRepo)
	svc := policy.New(policyRepo, auditRepo, keys)
	return NewPolicyHandler(svc, keys), tnt
}

func doRequest(t *testing.T, h *PolicyHandler, method, urlPath string, body []byte, tenantID, target, keyID string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *http.Request
	if body != nil {
		reader = httptest.NewRequest(method, urlPath, bytesReader(body))
		reader.Header.Set("Content-Type", "application/json")
	} else {
		reader = httptest.NewRequest(method, urlPath, nil)
	}
	if tenantID != "" {
		reader.SetPathValue("tenant_id", tenantID)
	}
	if target != "" {
		reader.SetPathValue("target_type", target)
	}
	if keyID != "" {
		reader.SetPathValue("key_id", keyID)
	}
	rec := httptest.NewRecorder()
	switch {
	case method == http.MethodGet && urlPath == "/api/v1/tenants/"+tenantID+"/policy/signing-keys":
		h.listSigningKeys(rec, reader)
	case method == http.MethodPost && urlPath == "/api/v1/tenants/"+tenantID+"/policy/signing-keys/rotate":
		h.rotateSigningKey(rec, reader)
	case method == http.MethodPost && keyID != "":
		h.revokeSigningKey(rec, reader)
	case method == http.MethodPut && urlPath == "/api/v1/tenants/"+tenantID+"/policy":
		h.putGraph(rec, reader)
	case method == http.MethodPost && urlPath == "/api/v1/tenants/"+tenantID+"/policy/compile":
		h.compile(rec, reader)
	case method == http.MethodGet && target != "" && keyID == "":
		h.downloadBundle(rec, reader)
	case method == http.MethodHead:
		h.downloadBundle(rec, reader)
	case method == http.MethodGet && keyID != "":
		h.getPublicKey(rec, reader)
	}
	return rec
}

type byteReader struct {
	b   []byte
	off int
}

func (r *byteReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, errEOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}

var errEOF = errReadErr("EOF")

type errReadErr string

func (e errReadErr) Error() string { return string(e) }

func bytesReader(b []byte) *byteReader { return &byteReader{b: b} }

// TestPolicy_BundleDownload_ETagFlow exercises the agent-pull
// happy path: compile → GET payload → ETag header → second GET
// with If-None-Match returns 304 without re-sending the bytes.
func TestPolicy_BundleDownload_ETagFlow(t *testing.T) {
	t.Parallel()
	h, tnt := newTestPolicyHandler(t)
	if rec := doRequest(t, h, http.MethodPut,
		"/api/v1/tenants/"+tnt.ID.String()+"/policy",
		[]byte(`{"default_action":"deny","rules":[{"id":"r","domain":"ztna","verb":"allow"}]}`),
		tnt.ID.String(), "", ""); rec.Code != http.StatusCreated {
		t.Fatalf("put graph: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRequest(t, h, http.MethodPost,
		"/api/v1/tenants/"+tnt.ID.String()+"/policy/compile",
		nil, tnt.ID.String(), "", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("compile: %d %s", rec.Code, rec.Body.String())
	}
	tid := tnt.ID.String()
	urlPath := "/api/v1/tenants/" + tid + "/policy/bundles/edge/payload"
	rec := doRequest(t, h, http.MethodGet, urlPath, nil, tid, "edge", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get bundle: %d %s", rec.Code, rec.Body.String())
	}
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag header")
	}
	body := rec.Body.Bytes()
	want := `"` + hex.EncodeToString(sha256SumPolicy(body)) + `"`
	if etag != want {
		t.Errorf("etag mismatch:\n  got:  %q\n  want: %q", etag, want)
	}
	if rec.Header().Get("X-Sng-Policy-Signature") == "" {
		t.Error("missing X-Sng-Policy-Signature")
	}
	if rec.Header().Get("X-Sng-Policy-Key-Id") == "" {
		t.Error("missing X-Sng-Policy-Key-Id")
	}
	if rec.Header().Get("Content-Type") != bundleContentType {
		t.Errorf("content-type: %q", rec.Header().Get("Content-Type"))
	}

	// Now repeat with If-None-Match: ETag — expect 304 + no body.
	rec2 := httptest.NewRequest(http.MethodGet, urlPath, nil)
	rec2.SetPathValue("tenant_id", tid)
	rec2.SetPathValue("target_type", "edge")
	rec2.Header.Set("If-None-Match", etag)
	w2 := httptest.NewRecorder()
	h.downloadBundle(w2, rec2)
	if w2.Code != http.StatusNotModified {
		t.Errorf("expected 304, got %d body=%s", w2.Code, w2.Body.String())
	}
	if w2.Body.Len() != 0 {
		t.Errorf("304 with body: %s", w2.Body.String())
	}
}

func sha256SumPolicy(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

// TestPolicy_BundleDownload_HEAD verifies the agent can perform a
// HEAD request to check the current bundle's ETag without paying
// for the full transfer.
func TestPolicy_BundleDownload_HEAD(t *testing.T) {
	t.Parallel()
	h, tnt := newTestPolicyHandler(t)
	if rec := doRequest(t, h, http.MethodPut,
		"/api/v1/tenants/"+tnt.ID.String()+"/policy",
		[]byte(`{"default_action":"deny"}`),
		tnt.ID.String(), "", ""); rec.Code != http.StatusCreated {
		t.Fatalf("put graph: %d", rec.Code)
	}
	if rec := doRequest(t, h, http.MethodPost,
		"/api/v1/tenants/"+tnt.ID.String()+"/policy/compile",
		nil, tnt.ID.String(), "", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("compile: %d", rec.Code)
	}
	rec := doRequest(t, h, http.MethodHead, "/api/v1/tenants/"+tnt.ID.String()+"/policy/bundles/endpoint/payload",
		nil, tnt.ID.String(), "endpoint", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD: %d", rec.Code)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("HEAD response missing ETag")
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD response has body: %d bytes", rec.Body.Len())
	}
}

// TestPolicy_SigningKey_LifecycleEndToEnd exercises rotate +
// public-key publication + verifying the active signature against
// the published key.
func TestPolicy_SigningKey_LifecycleEndToEnd(t *testing.T) {
	t.Parallel()
	h, tnt := newTestPolicyHandler(t)
	tid := tnt.ID.String()

	// Initial rotate provisions the first active key.
	rec := doRequest(t, h, http.MethodPost,
		"/api/v1/tenants/"+tid+"/policy/signing-keys/rotate",
		nil, tid, "", "")
	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("rotate (initial): %d %s", rec.Code, rec.Body.String())
	}
	var first PolicySigningKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if first.Status != string(repository.PolicySigningKeyStatusActive) {
		t.Errorf("first key status: %q", first.Status)
	}

	// Compile so we have a bundle signed by the first key.
	if rec := doRequest(t, h, http.MethodPut,
		"/api/v1/tenants/"+tid+"/policy", []byte(`{"default_action":"deny"}`),
		tid, "", ""); rec.Code != http.StatusCreated {
		t.Fatalf("put graph: %d", rec.Code)
	}
	if rec := doRequest(t, h, http.MethodPost,
		"/api/v1/tenants/"+tid+"/policy/compile",
		nil, tid, "", ""); rec.Code != http.StatusAccepted {
		t.Fatalf("compile: %d", rec.Code)
	}

	// Fetch the public key via the publication endpoint.
	rec = doRequest(t, h, http.MethodGet,
		"/api/v1/tenants/"+tid+"/policy/signing-keys/"+first.KeyID+"/public-key",
		nil, tid, "", first.KeyID)
	if rec.Code != http.StatusOK {
		t.Fatalf("get public key: %d %s", rec.Code, rec.Body.String())
	}
	var pub PolicyPublicKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pub); err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if pub.KeyID != first.KeyID {
		t.Errorf("public key id mismatch")
	}
	pkBytes, err := base64.StdEncoding.DecodeString(pub.PublicKey)
	if err != nil {
		t.Fatalf("decode pubkey b64: %v", err)
	}
	if len(pkBytes) != ed25519.PublicKeySize {
		t.Errorf("public key size: %d", len(pkBytes))
	}

	// Download the edge bundle and verify the signature
	// against the published public key.
	rec = doRequest(t, h, http.MethodGet,
		"/api/v1/tenants/"+tid+"/policy/bundles/edge/payload",
		nil, tid, "edge", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get bundle: %d", rec.Code)
	}
	sigB64 := rec.Header().Get("X-Sng-Policy-Signature")
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pkBytes), rec.Body.Bytes(), sig) {
		t.Error("bundle signature did not verify against published public key")
	}

	// Second rotate produces a new active key; first key
	// transitions to 'rotated'.
	rec = doRequest(t, h, http.MethodPost,
		"/api/v1/tenants/"+tid+"/policy/signing-keys/rotate",
		nil, tid, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("rotate (second): %d %s", rec.Code, rec.Body.String())
	}
	var second PolicySigningKeyResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("decode second: %v", err)
	}
	if second.KeyID == first.KeyID {
		t.Errorf("rotate returned same key id")
	}

	// Revoke the first key.
	urlPath := "/api/v1/tenants/" + tid + "/policy/signing-keys/" + first.KeyID + "/revoke"
	revReq := httptest.NewRequest(http.MethodPost, urlPath, nil)
	revReq.SetPathValue("tenant_id", tid)
	revReq.SetPathValue("key_id", first.KeyID)
	revRec := httptest.NewRecorder()
	h.revokeSigningKey(revRec, revReq)
	if revRec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", revRec.Code, revRec.Body.String())
	}
	var revoked PolicySigningKeyResponse
	if err := json.Unmarshal(revRec.Body.Bytes(), &revoked); err != nil {
		t.Fatalf("decode revoke: %v", err)
	}
	if revoked.Status != string(repository.PolicySigningKeyStatusRevoked) {
		t.Errorf("revoke status: %q", revoked.Status)
	}

	// List the rotation history; should contain both keys.
	rec = doRequest(t, h, http.MethodGet,
		"/api/v1/tenants/"+tid+"/policy/signing-keys", nil, tid, "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list keys: %d", rec.Code)
	}
	var list struct {
		Items []PolicySigningKeyResponse `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Items) != 2 {
		t.Errorf("expected 2 keys, got %d", len(list.Items))
	}
}

// TestPolicy_GetPublicKey_ActiveAliasNoLazyCreate confirms the
// public-key publication endpoint never side-effects a key into
// existence. Hitting /public-key with keyID="active" on a tenant
// that has never rotated must return 404, not 201/200 — otherwise
// any unauthenticated client could provoke key generation.
func TestPolicy_GetPublicKey_ActiveAliasNoLazyCreate(t *testing.T) {
	t.Parallel()
	h, tnt := newTestPolicyHandler(t)
	tid := tnt.ID.String()
	rec := doRequest(t, h, http.MethodGet,
		"/api/v1/tenants/"+tid+"/policy/signing-keys/active/public-key",
		nil, tid, "", "active")
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
	// And after rotation, the same call must succeed and return
	// the freshly-active key.
	if rec := doRequest(t, h, http.MethodPost,
		"/api/v1/tenants/"+tid+"/policy/signing-keys/rotate",
		nil, tid, "", ""); rec.Code != http.StatusCreated {
		t.Fatalf("rotate: %d", rec.Code)
	}
	rec = doRequest(t, h, http.MethodGet,
		"/api/v1/tenants/"+tid+"/policy/signing-keys/active/public-key",
		nil, tid, "", "active")
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 after rotate, got %d", rec.Code)
	}
}

// TestPolicy_BundleDownload_BadTarget rejects unknown target names.
func TestPolicy_BundleDownload_BadTarget(t *testing.T) {
	t.Parallel()
	h, tnt := newTestPolicyHandler(t)
	rec := doRequest(t, h, http.MethodGet,
		"/api/v1/tenants/"+tnt.ID.String()+"/policy/bundles/sky/payload",
		nil, tnt.ID.String(), "sky", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}
