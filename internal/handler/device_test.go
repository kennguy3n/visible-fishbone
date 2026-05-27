package handler

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
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

// newTestDeviceHandler wires a DeviceHandler against the in-memory
// repositories so the test exercises the real handler→service→repo
// path (per project rule: real implementation, mock only when
// strictly necessary — memory.Store is the production-grade
// in-memory implementation used by unit tests across the codebase).
func newTestDeviceHandler(t *testing.T) (*DeviceHandler, uuid.UUID) {
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
	return NewDeviceHandler(svc, memory.NewDeviceRepository(s), 0), tn.ID
}

// reqWithTenant builds a request with the tenant path value set in
// the same way Go's pattern mux populates it after a route match;
// the handler reads it via PathUUID and we want to exercise the
// real path-extraction code.
func reqWithTenant(t *testing.T, method, body string, tenantID uuid.UUID) *http.Request {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, "/api/v1/tenants/"+tenantID.String()+"/claim-tokens", nil)
	} else {
		r = httptest.NewRequest(method, "/api/v1/tenants/"+tenantID.String()+"/claim-tokens",
			bytes.NewReader([]byte(body)))
		r.Header.Set("Content-Type", "application/json")
	}
	r.SetPathValue("tenant_id", tenantID.String())
	return r
}

// TestCreateClaimTokenDefaultTTL — body omitted falls through to
// the handler's configured default; must succeed with 201.
func TestCreateClaimTokenDefaultTTL(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestDeviceHandler(t)
	rec := httptest.NewRecorder()
	h.createClaimToken(rec, reqWithTenant(t, http.MethodPost, "", tenantID))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp ClaimTokenCreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Token == "" {
		t.Error("plaintext token must be returned on success")
	}
}

// TestCreateClaimTokenAtMinimum — ttl_seconds == 60 (the
// OpenAPI-published minimum) must be accepted. Regression guard
// against an off-by-one (`< 60` vs `<= 60`) that would silently
// reject the boundary value.
func TestCreateClaimTokenAtMinimum(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestDeviceHandler(t)
	rec := httptest.NewRecorder()
	h.createClaimToken(rec, reqWithTenant(t, http.MethodPost, `{"ttl_seconds":60}`, tenantID))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
}

// TestCreateClaimTokenBelowMinimum — ttl_seconds < 60 must be
// rejected with 400. The OpenAPI spec declares `minimum: 60` on
// the field; previously the handler accepted any positive value,
// silently violating the documented contract.
func TestCreateClaimTokenBelowMinimum(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
	}{
		{"one second", `{"ttl_seconds":1}`},
		{"thirty seconds", `{"ttl_seconds":30}`},
		{"fifty nine seconds", `{"ttl_seconds":59}`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, tenantID := newTestDeviceHandler(t)
			rec := httptest.NewRecorder()
			h.createClaimToken(rec, reqWithTenant(t, http.MethodPost, tc.body, tenantID))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body = %s", rec.Code, rec.Body.String())
			}
			// JSON encoders HTML-escape `>` to `\u003e`, so match on
			// the literal field name + a stable substring of the error
			// message rather than the rendered `>=`.
			if !strings.Contains(rec.Body.String(), "ttl_seconds must be") {
				t.Errorf("body should mention ttl_seconds minimum, got: %s", rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "invalid_argument") {
				t.Errorf("error code should be invalid_argument, got: %s", rec.Body.String())
			}
		})
	}
}

// TestCreateClaimTokenChunkedBody is the regression test for the
// PR6 round-3 Devin Review finding: when a client sends the body
// with Transfer-Encoding: chunked, r.ContentLength is -1, not the
// byte count. The previous guard `r.ContentLength > 0` silently
// skipped DecodeJSON in that case, so a client streaming
// `{"ttl_seconds": 600}` over chunked encoding got the
// compiled-in default TTL applied with NO error and no log line.
//
// The fix is `r.ContentLength != 0` plus an io.EOF guard for the
// empty-chunked-body case (preserving the "body is optional"
// contract). This test wires httptest with a chunked body and
// asserts the requested TTL is honoured.
func TestCreateClaimTokenChunkedBody(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestDeviceHandler(t)

	// httptest.NewRequest forces ContentLength when given a
	// *bytes.Reader; using an io.Pipe + goroutine writer makes
	// the Go http server treat the body as chunked
	// (ContentLength = -1). io.NopCloser around a *bytes.Buffer
	// also yields ContentLength = -1.
	body := io.NopCloser(bytes.NewBufferString(`{"ttl_seconds":600}`))
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/claim-tokens", body)
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Transfer-Encoding", "chunked")
	req.SetPathValue("tenant_id", tenantID.String())

	rec := httptest.NewRecorder()
	h.createClaimToken(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
	var resp ClaimTokenCreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	exp, err := time.Parse(time.RFC3339Nano, resp.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at %q: %v", resp.ExpiresAt, err)
	}
	// Caller requested 600s; allow a 30s slack for test
	// scheduling, but the value MUST be ~600s, not the handler's
	// default of 24h (would round to ~86400s).
	dur := time.Until(exp)
	if dur < 9*time.Minute || dur > 11*time.Minute {
		t.Errorf("expires_at %s implies TTL %v, want ~10m (requested 600s); the body was silently ignored",
			resp.ExpiresAt, dur)
	}
}

// TestCreateClaimTokenChunkedEmptyBody covers the boundary where a
// chunked transfer carries zero bytes — the decoder hits io.EOF
// immediately, and the handler must treat that as "no body" (apply
// defaults) rather than 400 malformed-body.
func TestCreateClaimTokenChunkedEmptyBody(t *testing.T) {
	t.Parallel()
	h, tenantID := newTestDeviceHandler(t)

	body := io.NopCloser(bytes.NewBuffer(nil))
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tenantID.String()+"/claim-tokens", body)
	req.ContentLength = -1
	req.Header.Set("Transfer-Encoding", "chunked")
	req.SetPathValue("tenant_id", tenantID.String())

	rec := httptest.NewRecorder()
	h.createClaimToken(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}
}

// TestCreateClaimTokenStampsAuthenticatedActor is the regression
// test for the PR6 round-4 Devin Review finding: createClaimToken
// hardcoded `nil` as the audited actor instead of resolving the
// authenticated user via actorFromCtx(r). The result was that
// every claim token ever issued through the API was attributed to
// "<nil>" in the audit log and on the ClaimToken.CreatedBy field —
// destroying the audit trail of which operator minted which
// enrolment credential.
//
// We exercise the full real path: build a valid HS256 JWT, run it
// through the real middleware.Auth so the user UUID lands in
// r.Context() the same way it does in production, then call the
// handler and read the persisted ClaimToken back from the in-memory
// claim-token repo via its hash to confirm CreatedBy was populated.
func TestCreateClaimTokenStampsAuthenticatedActor(t *testing.T) {
	t.Parallel()

	// Build the stack manually (instead of using
	// newTestDeviceHandler) so we keep handles on the claim-token
	// repo and the seeded tenant ID — newTestDeviceHandler hides
	// both behind its return signature.
	store := memory.NewStore()
	tenants := memory.NewTenantRepository(store)
	tn, err := tenants.Create(context.Background(), repository.Tenant{
		Name: "Test", Slug: "test",
		Status: repository.TenantStatusActive,
		Tier:   repository.TenantTierStarter,
	})
	if err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	tokenRepo := memory.NewClaimTokenRepository(store)
	identitySvc := identity.New(
		memory.NewDeviceRepository(store),
		tokenRepo,
		memory.NewAuditLogRepository(store),
		nil,
	)
	h := NewDeviceHandler(identitySvc, memory.NewDeviceRepository(store), 0)

	// Mint a JWT that the auth middleware will accept and decode
	// into the request context.
	secret := []byte("test-secret-actor-attribution")
	userID := uuid.New()
	claims := jwt.MapClaims{
		"iss": "sng-control",
		"aud": "sng-control",
		"sub": userID.String(),
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	authCfg := &config.Auth{
		JWTSecret:   string(secret),
		JWTIssuer:   "sng-control",
		JWTAudience: "sng-control",
	}

	// Run the request through middleware.Auth -> handler so we
	// exercise the exact production path that hydrates UserID in
	// the context.
	authed := middleware.Auth(authCfg, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.SetPathValue("tenant_id", tn.ID.String())
		h.createClaimToken(w, r)
	}))
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/tenants/"+tn.ID.String()+"/claim-tokens", nil)
	req.Header.Set("Authorization", "Bearer "+signed)
	rec := httptest.NewRecorder()
	authed.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body = %s", rec.Code, rec.Body.String())
	}

	// Decode the plaintext, hash it, and look the row up in the
	// repo to confirm CreatedBy was persisted as the authenticated
	// user — proving the handler forwarded actorFromCtx(r) instead
	// of nil.
	var resp ClaimTokenCreateResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(resp.Token)
	if err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	hash := sha256.Sum256(raw)
	stored, err := tokenRepo.GetByHash(context.Background(), tn.ID, hash[:])
	if err != nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if stored.CreatedBy == nil {
		t.Fatal("ClaimToken.CreatedBy is nil; handler did not forward the authenticated actor (regression of PR6 round-4 finding)")
	}
	if *stored.CreatedBy != userID {
		t.Errorf("ClaimToken.CreatedBy = %v, want %v (handler stamped the wrong actor)",
			*stored.CreatedBy, userID)
	}
}
