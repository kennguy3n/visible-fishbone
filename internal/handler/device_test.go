package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

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
