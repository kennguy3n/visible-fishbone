package handler

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/middleware"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/identity"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// newPassthroughDeviceCA builds an in-memory device CA whose key is
// sealed under the passthrough wrapper, for enrollment-handler tests.
func newPassthroughDeviceCA(t *testing.T, s *memory.Store) *identity.CertAuthority {
	t.Helper()
	ca, err := identity.NewCertAuthority(memory.NewDeviceCARepository(s), policy.PassthroughWrapper{}, nil)
	if err != nil {
		t.Fatalf("NewCertAuthority: %v", err)
	}
	return ca
}

// newEnrollHandlerWithGuard wires a DeviceHandler with a real
// enrollment service (in-memory repos) and an IP-keyed brute-force
// guard, mirroring the production wiring in cmd/sng-control.
func newEnrollHandlerWithGuard(t *testing.T, maxFailures int, cooldown time.Duration) (*DeviceHandler, *middleware.AttemptLimiter) {
	t.Helper()
	s := memory.NewStore()
	svc := identity.New(
		memory.NewDeviceRepository(s),
		memory.NewClaimTokenRepository(s),
		memory.NewAuditLogRepository(s),
		nil,
	)
	h := NewDeviceHandler(svc, memory.NewDeviceRepository(s), 0)
	h.SetEnrollmentService(identity.NewEnrollmentService(
		memory.NewDeviceEnrollmentRepository(s),
		memory.NewClaimTokenRepository(s),
		memory.NewAuditLogRepository(s),
		newPassthroughDeviceCA(t, s),
		nil,
	))
	guard, err := middleware.NewAttemptLimiter(middleware.AttemptLimiterConfig{
		MaxFailures:     maxFailures,
		Cooldown:        cooldown,
		CleanupInterval: time.Hour,
		IdleTTL:         10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("NewAttemptLimiter: %v", err)
	}
	h.SetBruteForceGuard(guard, nil)
	return h, guard
}

// enrollReq builds a POST /api/v1/enroll request with a well-formed
// body (valid UUIDs + 32-byte Ed25519 key) but a bogus claim token,
// so RedeemClaimToken fails — the genuine "failed enrollment" signal.
func enrollReq(t *testing.T, remoteAddr string) *http.Request {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	body, _ := json.Marshal(EnrollDeviceRequest{
		ClaimToken: base64.RawURLEncoding.EncodeToString([]byte("nonexistent-token")),
		TenantID:   uuid.New().String(),
		DeviceID:   uuid.New().String(),
		PublicKey:  base64.StdEncoding.EncodeToString(pub),
	})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
	r.RemoteAddr = remoteAddr
	return r
}

func TestEnrollBruteForce_LocksOutAfterThreshold(t *testing.T) {
	t.Parallel()
	h, guard := newEnrollHandlerWithGuard(t, 10, 5*time.Minute)
	defer guard.Close()

	// Ten failed redemptions are rejected normally (4xx, not locked).
	for i := 0; i < 10; i++ {
		rec := httptest.NewRecorder()
		h.enrollDevice(rec, enrollReq(t, "203.0.113.80:5555"))
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d locked out too early", i+1)
		}
	}
	// The 11th from the same IP is now in cooldown.
	rec := httptest.NewRecorder()
	h.enrollDevice(rec, enrollReq(t, "203.0.113.80:5555"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("post-threshold: status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 response missing Retry-After header")
	}
}

func TestEnrollBruteForce_OtherIPUnaffected(t *testing.T) {
	t.Parallel()
	h, guard := newEnrollHandlerWithGuard(t, 3, 5*time.Minute)
	defer guard.Close()

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.enrollDevice(rec, enrollReq(t, "203.0.113.81:6666"))
		_ = rec
	}
	rec := httptest.NewRecorder()
	h.enrollDevice(rec, enrollReq(t, "203.0.113.81:6666"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attacker not locked out: status = %d", rec.Code)
	}

	// A different source IP is still served normally.
	rec = httptest.NewRecorder()
	h.enrollDevice(rec, enrollReq(t, "203.0.113.82:7777"))
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("unrelated IP wrongly locked out (status %d)", rec.Code)
	}
}

func TestEnrollBruteForce_MalformedRequestNotCounted(t *testing.T) {
	t.Parallel()
	h, guard := newEnrollHandlerWithGuard(t, 3, 5*time.Minute)
	defer guard.Close()

	// Malformed requests (missing fields) are client errors that must
	// NOT count toward the lockout — otherwise a client could lock out
	// its own IP (or a shared NAT IP) with junk.
	for i := 0; i < 10; i++ {
		body, _ := json.Marshal(EnrollDeviceRequest{TenantID: uuid.New().String()})
		r := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(body))
		r.RemoteAddr = "203.0.113.83:8888"
		rec := httptest.NewRecorder()
		h.enrollDevice(rec, r)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("malformed request %d wrongly counted toward lockout", i+1)
		}
	}
	// The guard should report this IP as never blocked.
	if _, blocked := guard.Blocked("203.0.113.83"); blocked {
		t.Fatal("IP locked out by malformed (uncounted) requests")
	}
}

// TestEnrollFailure_LogsClientIP_WhenGuardDisabled covers the
// observability path when BruteForce.Enabled is false: the guard is nil
// but failures are still audited, and source_ip must be the real client
// derived with the same trusted-proxy logic the guard would use — not
// the load balancer's address. Mirrors the auth-side WithTrustedProxies
// behaviour so logs are identical whether or not lockout is enabled.
func TestEnrollFailure_LogsClientIP_WhenGuardDisabled(t *testing.T) {
	t.Parallel()
	s := memory.NewStore()
	svc := identity.New(
		memory.NewDeviceRepository(s),
		memory.NewClaimTokenRepository(s),
		memory.NewAuditLogRepository(s),
		nil,
	)
	h := NewDeviceHandler(svc, memory.NewDeviceRepository(s), 0)
	h.SetEnrollmentService(identity.NewEnrollmentService(
		memory.NewDeviceEnrollmentRepository(s),
		memory.NewClaimTokenRepository(s),
		memory.NewAuditLogRepository(s),
		newPassthroughDeviceCA(t, s),
		nil,
	))
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	// Guard disabled (nil) but logging on — the production guard-off case.
	h.SetBruteForceGuard(nil, logger)
	// Trust the proxy CIDR so XFF is honoured; proves the deriver
	// resolves the real client rather than the proxy hop.
	deriver, err := middleware.NewClientIPDeriver("10.0.0.0/8")
	if err != nil {
		t.Fatalf("NewClientIPDeriver: %v", err)
	}
	h.SetClientIPDeriver(deriver)

	req := enrollReq(t, "10.1.2.3:4444") // trusted proxy address
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	rec := httptest.NewRecorder()
	h.enrollDevice(rec, req)

	if rec.Code == http.StatusCreated || rec.Code == http.StatusOK {
		t.Fatalf("expected enrollment failure, got %d", rec.Code)
	}
	if got := buf.String(); !strings.Contains(got, `"source_ip":"203.0.113.9"`) {
		t.Fatalf("failure log should carry the real client source_ip 203.0.113.9; got: %s", got)
	}
}
