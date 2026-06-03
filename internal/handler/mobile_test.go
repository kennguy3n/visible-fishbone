package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

func newTestMobileHandler(t *testing.T) (*MobileHandler, uuid.UUID) {
	t.Helper()
	s := memory.NewStore()
	tn, err := memory.NewTenantRepository(s).Create(context.Background(), repository.Tenant{
		Name: "Test", Slug: "test", Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	svc := identity.New(
		memory.NewDeviceRepository(s),
		memory.NewClaimTokenRepository(s),
		memory.NewAuditLogRepository(s),
		nil,
	)
	return NewMobileHandler(svc), tn.ID
}

func testMobileKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

// mobileReq builds a request whose context carries a verified mobile
// session (token_type=mobile + device_key), mimicking what the auth
// middleware stashes after validating the JWT. When deviceKey is "",
// no mobile claims are attached (simulating an operator/API-key
// session).
func mobileReq(t *testing.T, method, path, body string, tenantID uuid.UUID, deviceKey string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("tenant_id", tenantID.String())
	if deviceKey != "" {
		ctx := middleware.WithMobileClaimsForTest(r.Context(), middleware.MobileClaims{
			TokenType:   "mobile",
			DeviceKey:   deviceKey,
			OIDCSubject: "google|abc",
		})
		r = r.WithContext(ctx)
	}
	return r
}

func TestMobileEnroll_CreatesThenIdempotent(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestMobileHandler(t)
	key := testMobileKey(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/enroll"

	rec := httptest.NewRecorder()
	h.enroll(rec, mobileReq(t, http.MethodPost, path, `{"platform":"ios","name":"iPhone"}`, tenantID, key))
	if rec.Code != http.StatusCreated {
		t.Fatalf("first enroll status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp MobileEnrollResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Created || resp.Device.Platform != "ios" {
		t.Fatalf("resp = %+v", resp)
	}

	// Re-enroll same key → 200, idempotent.
	rec2 := httptest.NewRecorder()
	h.enroll(rec2, mobileReq(t, http.MethodPost, path, `{"platform":"ios"}`, tenantID, key))
	if rec2.Code != http.StatusOK {
		t.Fatalf("re-enroll status = %d, want 200; body = %s", rec2.Code, rec2.Body.String())
	}
	var resp2 MobileEnrollResponse
	if err := json.NewDecoder(rec2.Body).Decode(&resp2); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp2.Created {
		t.Error("re-enroll Created = true, want false")
	}
	if resp2.Device.ID != resp.Device.ID {
		t.Errorf("re-enroll device id = %s, want %s", resp2.Device.ID, resp.Device.ID)
	}
}

func TestMobileEnroll_RejectsNonMobileSession(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestMobileHandler(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/enroll"
	rec := httptest.NewRecorder()
	// deviceKey "" → no mobile claims on context (operator/API-key).
	h.enroll(rec, mobileReq(t, http.MethodPost, path, `{"platform":"ios"}`, tenantID, ""))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
}

func TestMobileEnroll_RejectsNonMobileTokenType(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestMobileHandler(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/enroll"
	r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader([]byte(`{"platform":"ios"}`)))
	r.Header.Set("Content-Type", "application/json")
	r.SetPathValue("tenant_id", tenantID.String())
	// An operator-console JWT: claims present but token_type != mobile.
	r = r.WithContext(middleware.WithMobileClaimsForTest(r.Context(), middleware.MobileClaims{
		TokenType: "operator", DeviceKey: testMobileKey(t),
	}))
	rec := httptest.NewRecorder()
	h.enroll(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body = %s", rec.Code, rec.Body.String())
	}
}

func TestMobileEnroll_RejectsKeyMismatch(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestMobileHandler(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/enroll"
	body := `{"platform":"ios","device_public_key":"` + testMobileKey(t) + `"}`
	rec := httptest.NewRecorder()
	// Token's device_key differs from the body-supplied one.
	h.enroll(rec, mobileReq(t, http.MethodPost, path, body, tenantID, testMobileKey(t)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
	}
}

func TestMobileEnroll_RejectsBadPlatform(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestMobileHandler(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/enroll"
	cases := []string{`{"platform":"windows"}`, `{}`}
	for _, body := range cases {
		rec := httptest.NewRecorder()
		h.enroll(rec, mobileReq(t, http.MethodPost, path, body, tenantID, testMobileKey(t)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %s: status = %d, want 400; body = %s", body, rec.Code, rec.Body.String())
		}
	}
}

func TestMobilePosture_HappyPath(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestMobileHandler(t)
	key := testMobileKey(t)
	enrollPath := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/enroll"
	posturePath := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/posture"

	rec := httptest.NewRecorder()
	h.enroll(rec, mobileReq(t, http.MethodPost, enrollPath, `{"platform":"android"}`, tenantID, key))
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d; body = %s", rec.Code, rec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	h.reportPosture(rec2, mobileReq(t, http.MethodPost, posturePath,
		`{"posture":{"os_version":"14","root_detected":false,"passcode_set":true}}`, tenantID, key))
	if rec2.Code != http.StatusOK {
		t.Fatalf("posture status = %d, want 200; body = %s", rec2.Code, rec2.Body.String())
	}
	var dev DeviceResponse
	if err := json.NewDecoder(rec2.Body).Decode(&dev); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dev.Posture.OSVersion != "14" {
		t.Errorf("os_version = %q", dev.Posture.OSVersion)
	}
}

func TestMobilePosture_DeviceNotEnrolled(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestMobileHandler(t)
	posturePath := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/posture"
	rec := httptest.NewRecorder()
	h.reportPosture(rec, mobileReq(t, http.MethodPost, posturePath,
		`{"posture":{"os_version":"14"}}`, tenantID, testMobileKey(t)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body = %s", rec.Code, rec.Body.String())
	}
}

func TestMobilePosture_CrossPlatformSignalRejected(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestMobileHandler(t)
	key := testMobileKey(t)
	enrollPath := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/enroll"
	posturePath := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/posture"

	rec := httptest.NewRecorder()
	h.enroll(rec, mobileReq(t, http.MethodPost, enrollPath, `{"platform":"ios"}`, tenantID, key))
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d; body = %s", rec.Code, rec.Body.String())
	}
	// root_detected is Android-only; rejected for an iOS device.
	rec2 := httptest.NewRecorder()
	h.reportPosture(rec2, mobileReq(t, http.MethodPost, posturePath,
		`{"posture":{"root_detected":true}}`, tenantID, key))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", rec2.Code, rec2.Body.String())
	}
}
