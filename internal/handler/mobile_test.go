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
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
)

func newTestMobileHandler(t *testing.T) (*MobileHandler, uuid.UUID) {
	t.Helper()
	h, _, tenantID := newTestMobileHandlerWithStore(t)
	return h, tenantID
}

// newTestMobileHandlerWithStore is like newTestMobileHandler but also
// returns the backing store, so a test can mutate device state
// out-of-band (e.g. simulate an admin suspend/delete).
func newTestMobileHandlerWithStore(t *testing.T) (*MobileHandler, *memory.Store, uuid.UUID) {
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
	return NewMobileHandler(svc), s, tn.ID
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

// TestMobileEnroll_RejectsDisabledDevice verifies the admin
// kill-switch is honoured end-to-end through the handler: once a
// device is suspended out-of-band, a re-enrolment from a still-valid
// mobile session is rejected with 403 (ErrForbidden → forbidden).
func TestMobileEnroll_RejectsDisabledDevice(t *testing.T) {
	t.Parallel()
	h, store, tenantID := newTestMobileHandlerWithStore(t)
	key := testMobileKey(t)
	path := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/enroll"

	rec := httptest.NewRecorder()
	h.enroll(rec, mobileReq(t, http.MethodPost, path, `{"platform":"ios"}`, tenantID, key))
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp MobileEnrollResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Admin suspends the device.
	devID, err := uuid.Parse(resp.Device.ID)
	if err != nil {
		t.Fatalf("parse device id %q: %v", resp.Device.ID, err)
	}
	if _, err := memory.NewDeviceRepository(store).UpdateStatus(
		context.Background(), tenantID, devID, repository.DeviceStatusSuspended,
	); err != nil {
		t.Fatalf("suspend device: %v", err)
	}

	rec2 := httptest.NewRecorder()
	h.enroll(rec2, mobileReq(t, http.MethodPost, path, `{"platform":"ios"}`, tenantID, key))
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("re-enroll status = %d, want 403; body = %s", rec2.Code, rec2.Body.String())
	}
}

const testJWTSecret = "test-jwt-secret-please-ignore"

// signMobileSessionJWT mints an HS256 mobile session token the real
// middleware.Auth chain will accept: it carries the iss/aud the
// middleware validates plus the token_type=mobile + device_key custom
// claims that extractMobileClaims surfaces.
func signMobileSessionJWT(t *testing.T, tenantID uuid.UUID, deviceKey string) string {
	t.Helper()
	now := time.Now()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":        "sng-control",
		"aud":        "sng-control",
		"sub":        uuid.NewString(),
		"tenant_id":  tenantID.String(),
		"iat":        now.Unix(),
		"exp":        now.Add(time.Hour).Unix(),
		"token_type": "mobile",
		"device_key": deviceKey,
		"oidc_sub":   "google|abc",
	})
	signed, err := tok.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signed
}

// TestMobileEnroll_ThroughAuthMiddleware is the regression guard for
// the kill-switch promotion (commit 5b52a5f). It exercises the REAL
// request path — middleware.Auth → WithMobileDeviceStatus resolver →
// MobileDeviceRevoked → RequireTenant → handler — which the other
// handler tests bypass by calling h.enroll directly. A prior revision
// treated "device not yet enrolled" (ErrNotFound) as revoked, so the
// middleware 403'd first-time enrolment before the handler ever ran;
// this test fails against that bug and passes once not-yet-enrolled
// keys are allowed through. It also confirms the kill-switch still
// fires once the device exists and is suspended.
func TestMobileEnroll_ThroughAuthMiddleware(t *testing.T) {
	t.Parallel()
	h, store, tenantID := newTestMobileHandlerWithStore(t)
	key := testMobileKey(t)

	cfg := &config.Auth{JWTSecret: testJWTSecret, JWTIssuer: "sng-control", JWTAudience: "sng-control"}
	mux := http.NewServeMux()
	h.Register(mux)
	stack := middleware.Auth(cfg, nil, middleware.WithMobileDeviceStatus(NewMobileDeviceStatusResolver(h.identity)))(mux)

	path := "/api/v1/tenants/" + tenantID.String() + "/devices/mobile/enroll"
	token := signMobileSessionJWT(t, tenantID, key)

	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"platform":"ios","name":"iPhone"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}

	// First-time enrolment: no device exists yet. The middleware
	// kill-switch must NOT block it — the request must reach the handler
	// and create the device (201).
	rec := httptest.NewRecorder()
	stack.ServeHTTP(rec, newReq())
	if rec.Code != http.StatusCreated {
		t.Fatalf("first enrol through middleware = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp MobileEnrollResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	devID, err := uuid.Parse(resp.Device.ID)
	if err != nil {
		t.Fatalf("parse device id %q: %v", resp.Device.ID, err)
	}

	// Admin suspends the device out-of-band. The same still-valid token
	// must now be rejected by the middleware kill-switch with 403
	// device_revoked, BEFORE reaching the handler.
	if _, err := memory.NewDeviceRepository(store).UpdateStatus(
		context.Background(), tenantID, devID, repository.DeviceStatusSuspended,
	); err != nil {
		t.Fatalf("suspend device: %v", err)
	}
	rec2 := httptest.NewRecorder()
	stack.ServeHTTP(rec2, newReq())
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("suspended device through middleware = %d, want 403; body = %s", rec2.Code, rec2.Body.String())
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec2.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode 403 body: %v", err)
	}
	if envelope.Error.Code != "device_revoked" {
		t.Fatalf("403 error code = %q, want device_revoked; body = %s", envelope.Error.Code, rec2.Body.String())
	}
}
