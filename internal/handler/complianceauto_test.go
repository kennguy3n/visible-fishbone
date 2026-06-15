package handler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/config"
	"github.com/kennguy3n/visible-fishbone/internal/handler"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/complianceauto"
)

// fakeComplianceAutoSource is a deterministic PlatformSource for the
// handler tests: a single tenant whose snapshot passes every control.
type fakeComplianceAutoSource struct {
	id uuid.UUID
}

func (f fakeComplianceAutoSource) Tenants(context.Context) ([]uuid.UUID, error) {
	return []uuid.UUID{f.id}, nil
}

func (f fakeComplianceAutoSource) Snapshot(_ context.Context, id uuid.UUID) (complianceauto.Snapshot, error) {
	at := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	return complianceauto.Snapshot{
		TenantID:              id,
		ObservedAt:            at,
		HasPolicyGraph:        true,
		PolicyDefaultDeny:     true,
		RLSEnforced:           true,
		EncryptionAtRest:      true,
		TLSEnforced:           true,
		IDPConfigured:         1,
		IDPEnabled:            1,
		HasActiveSigningKey:   true,
		SigningKeyActivatedAt: at.Add(-24 * time.Hour),
		Region:                "us-east-1",
		HasAuditActivity:      true,
		LastAuditAt:           at,
		RetentionDays:         30,
	}, nil
}

func newComplianceAutoTestRouter(t *testing.T) (http.Handler, uuid.UUID, string) {
	t.Helper()
	tenantID := uuid.New()
	engine := complianceauto.NewEngine(
		fakeComplianceAutoSource{id: tenantID},
		memory.NewComplianceAutoRepository(),
		complianceauto.Config{},
	)

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
		Config:         cfg,
		ComplianceAuto: handler.NewComplianceAutoHandler(engine),
	})

	token := tokenForTenant(t, jwtSecret, tenantID)
	return router, tenantID, token
}

func tokenForTenant(t *testing.T, secret string, tenantID uuid.UUID) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss":       "sng-control",
		"aud":       "sng-control",
		"sub":       uuid.NewString(),
		"tenant_id": tenantID.String(),
		"iat":       time.Now().Unix(),
		"exp":       time.Now().Add(5 * time.Minute).Unix(),
	})
	signed, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	return signed
}

func TestComplianceAutoHandler_CollectThenPosture(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newComplianceAutoTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/compliance-auto"

	// Collect seeds the posture.
	rec := doJSON(t, router, http.MethodPost, base+"/collect", token, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("collect: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	// Posture reflects collected state.
	rec = doJSON(t, router, http.MethodGet, base+"/posture", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("posture: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var posture struct {
		Frameworks []struct {
			Framework    string `json:"framework"`
			Total        int    `json:"total"`
			Pass         int    `json:"pass"`
			ScorePercent int    `json:"score_percent"`
		} `json:"frameworks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &posture); err != nil {
		t.Fatalf("decode posture: %v", err)
	}
	if len(posture.Frameworks) == 0 {
		t.Fatal("posture returned no frameworks after collect")
	}
	for _, fw := range posture.Frameworks {
		if fw.Total == 0 {
			t.Errorf("framework %s has no controls", fw.Framework)
		}
		if fw.ScorePercent != 100 {
			t.Errorf("framework %s score = %d, want 100 on healthy snapshot", fw.Framework, fw.ScorePercent)
		}
	}
}

func TestComplianceAutoHandler_PostureFrameworkFilter(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newComplianceAutoTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/compliance-auto"
	doJSON(t, router, http.MethodPost, base+"/collect", token, nil)

	rec := doJSON(t, router, http.MethodGet, base+"/posture?framework=SOC2", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("filtered posture: status = %d, body = %s", rec.Code, rec.Body.String())
	}

	rec = doJSON(t, router, http.MethodGet, base+"/posture?framework=NOPE", token, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown framework: status = %d, want 400", rec.Code)
	}
}

func TestComplianceAutoHandler_EvidencePackJSONAndCSV(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newComplianceAutoTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/compliance-auto"
	doJSON(t, router, http.MethodPost, base+"/collect", token, nil)

	// JSON pack (default format).
	rec := doJSON(t, router, http.MethodGet, base+"/evidence-pack?framework=SOC2", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("json pack: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("json pack content-type = %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, ".json") {
		t.Fatalf("json pack content-disposition = %q", cd)
	}
	pack, err := complianceauto.ParsePackJSON(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("parse pack: %v", err)
	}
	if pack.Framework != complianceauto.FrameworkSOC2 || len(pack.Controls) == 0 {
		t.Fatalf("unexpected pack: %+v", pack.Summary)
	}

	// CSV pack.
	rec = doJSON(t, router, http.MethodGet, base+"/evidence-pack?framework=SOC2&format=csv", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("csv pack: status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/csv" {
		t.Fatalf("csv pack content-type = %q", ct)
	}
	if !strings.HasPrefix(rec.Body.String(), "framework,control_id") {
		t.Fatalf("csv pack missing header: %q", rec.Body.String()[:min(40, rec.Body.Len())])
	}
}

func TestComplianceAutoHandler_EvidencePackErrors(t *testing.T) {
	t.Parallel()
	router, tenantID, token := newComplianceAutoTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/compliance-auto"

	// Missing framework query → 400.
	rec := doJSON(t, router, http.MethodGet, base+"/evidence-pack", token, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing framework: status = %d, want 400", rec.Code)
	}

	// Unknown framework → 400.
	rec = doJSON(t, router, http.MethodGet, base+"/evidence-pack?framework=NOPE", token, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown framework: status = %d, want 400", rec.Code)
	}

	// Valid framework but nothing collected yet → 404.
	rec = doJSON(t, router, http.MethodGet, base+"/evidence-pack?framework=SOC2", token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no evidence: status = %d, want 404", rec.Code)
	}
}

func TestComplianceAutoHandler_TenantMismatchForbidden(t *testing.T) {
	t.Parallel()
	router, _, _ := newComplianceAutoTestRouter(t)
	// A token for a different tenant must not reach another tenant's path.
	otherToken := tokenForTenant(t, "test-jwt-secret-key", uuid.New())
	path := "/api/v1/tenants/" + uuid.NewString() + "/compliance-auto/posture"

	rec := doJSON(t, router, http.MethodGet, path, otherToken, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("tenant mismatch: status = %d, want 403", rec.Code)
	}
}
