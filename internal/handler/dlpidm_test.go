package handler_test

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpidm"
)

// protectedDoc is long enough to yield a non-empty winnowed fingerprint
// set under the default shingle/window parameters.
const protectedDoc = "The quarterly revenue report is strictly confidential and " +
	"must not be shared outside the finance department under any circumstances. " +
	"Distribution of this document to third parties is prohibited by company policy."

func newDLPIDMTestRouter(t *testing.T) (http.Handler, uuid.UUID, string) {
	t.Helper()
	store := memory.NewStore()
	store.SetClock(func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) })
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(t.Context(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t-dlpidm",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	userID := uuid.New()

	svc := dlpidm.New(memory.NewDLPIDMRepository(store), nil)

	jwtSecret := "test-jwt-secret-key"
	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret:    jwtSecret,
			JWTIssuer:    "sng-control",
			JWTAudience:  "sng-control",
			APIKeyHeader: "X-SNG-API-Key",
		},
	}
	router := handler.NewRouter(handler.RouterDeps{
		Config: cfg,
		DLPIDM: handler.NewDLPIDMHandler(svc),
	})

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "sng-control",
		"aud":       "sng-control",
		"sub":       userID.String(),
		"tenant_id": tenantID.String(),
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
	})
	signed, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return router, tenantID, signed
}

func TestDLPIDMHandler_FingerprintSetCRUD(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPIDMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/idm/fingerprint-sets"

	// CREATE — upload raw text, server fingerprints it.
	rec := doJSON(t, router, http.MethodPost, base, token, map[string]any{
		"name":        "Q4 Revenue",
		"description": "confidential finance doc",
		"content":     protectedDoc,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d — %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal create: %v", err)
	}
	setID, _ := created["id"].(string)
	if setID == "" {
		t.Fatalf("create: missing id in %s", rec.Body.String())
	}
	// The raw fingerprint hashes must never be returned over the API —
	// only the count.
	if _, leaked := created["fingerprints"]; leaked {
		t.Fatalf("create response leaked raw fingerprints: %s", rec.Body.String())
	}
	if fc, _ := created["fingerprint_count"].(float64); fc <= 0 {
		t.Fatalf("create: expected positive fingerprint_count, got %v", created["fingerprint_count"])
	}
	// Raw content must not be echoed back either.
	if _, leaked := created["content"]; leaked {
		t.Fatalf("create response leaked raw content: %s", rec.Body.String())
	}

	// GET
	rec = doJSON(t, router, http.MethodGet, base+"/"+setID, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d — %s", rec.Code, rec.Body.String())
	}

	// LIST
	rec = doJSON(t, router, http.MethodGet, base, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d", rec.Code)
	}
	var listResp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	items, _ := listResp["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("list: expected 1 item, got %d", len(items))
	}

	// PATCH metadata.
	rec = doJSON(t, router, http.MethodPatch, base+"/"+setID, token, map[string]any{
		"name": "Q4 Revenue (renamed)",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("patch: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var patched map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &patched); err != nil {
		t.Fatalf("unmarshal patch: %v", err)
	}
	if patched["name"] != "Q4 Revenue (renamed)" {
		t.Fatalf("patch: name not updated: %v", patched["name"])
	}

	// DELETE
	rec = doJSON(t, router, http.MethodDelete, base+"/"+setID, token, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", rec.Code)
	}

	// GET after delete → 404.
	rec = doJSON(t, router, http.MethodGet, base+"/"+setID, token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get-after-delete: want 404, got %d", rec.Code)
	}
}

func TestDLPIDMHandler_CreateRejectsEmptyName(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPIDMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/idm/fingerprint-sets"

	rec := doJSON(t, router, http.MethodPost, base, token, map[string]any{
		"name":    "",
		"content": protectedDoc,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty name: want 400, got %d — %s", rec.Code, rec.Body.String())
	}
}

func TestDLPIDMHandler_CreateRejectsBadParamOverride(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPIDMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/idm/fingerprint-sets"

	zero := 0
	rec := doJSON(t, router, http.MethodPost, base, token, map[string]any{
		"name":         "bad",
		"content":      protectedDoc,
		"shingle_size": &zero,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad shingle_size: want 400, got %d — %s", rec.Code, rec.Body.String())
	}
}

func TestDLPIDMHandler_GetSetNotFound(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPIDMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/idm/fingerprint-sets"

	rec := doJSON(t, router, http.MethodGet, base+"/"+uuid.New().String(), token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing set: want 404, got %d", rec.Code)
	}
}

func TestDLPIDMHandler_ConfigDefaultsAndPartialUpdate(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPIDMTestRouter(t)
	cfgPath := "/api/v1/tenants/" + tenantID.String() + "/dlp/ocr-idm/config"

	// GET returns compiled-in defaults when the tenant has never
	// customized the config.
	rec := doJSON(t, router, http.MethodGet, cfgPath, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get config: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if got["ocr_enabled"] != true {
		t.Fatalf("default ocr_enabled: want true, got %v", got["ocr_enabled"])
	}

	// PUT a partial update (single field); omitted fields retain their
	// effective value.
	rec = doJSON(t, router, http.MethodPut, cfgPath, token, map[string]any{
		"ocr_enabled": false,
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("put config: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var updated map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("unmarshal updated: %v", err)
	}
	if updated["ocr_enabled"] != false {
		t.Fatalf("put: ocr_enabled not updated: %v", updated["ocr_enabled"])
	}
	// idm_enabled was omitted → must retain its default (true).
	if updated["idm_enabled"] != true {
		t.Fatalf("put: omitted idm_enabled should remain true, got %v", updated["idm_enabled"])
	}

	// Read-back persists.
	rec = doJSON(t, router, http.MethodGet, cfgPath, token, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal reread: %v", err)
	}
	if got["ocr_enabled"] != false {
		t.Fatalf("reread: ocr_enabled should be false, got %v", got["ocr_enabled"])
	}
}

func TestDLPIDMHandler_PutConfigRejectsOutOfRange(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPIDMTestRouter(t)
	cfgPath := "/api/v1/tenants/" + tenantID.String() + "/dlp/ocr-idm/config"

	rec := doJSON(t, router, http.MethodPut, cfgPath, token, map[string]any{
		"idm_similarity_threshold": 1.5,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("out-of-range threshold: want 400, got %d — %s", rec.Code, rec.Body.String())
	}
}

func TestDLPIDMHandler_Status(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newDLPIDMTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/idm/fingerprint-sets"
	statusPath := "/api/v1/tenants/" + tenantID.String() + "/dlp/ocr-idm/status"

	rec := doJSON(t, router, http.MethodPost, base, token, map[string]any{
		"name":    "doc",
		"content": protectedDoc,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed set: want 201, got %d — %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, router, http.MethodGet, statusPath, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var st map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if sc, _ := st["set_count"].(float64); sc != 1 {
		t.Fatalf("status: want set_count 1, got %v", st["set_count"])
	}
	if _, ok := st["config"].(map[string]any); !ok {
		t.Fatalf("status: missing config object: %s", rec.Body.String())
	}
}
