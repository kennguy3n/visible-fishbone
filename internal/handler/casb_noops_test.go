package handler_test

import (
	"context"
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
	"github.com/kennguy3n/visible-fishbone/internal/service/casb"
)

// newCASBNoOpsTestRouter builds a CASB router with the NoOps reader
// wired, returning the seedable discovered-app repo + NoOps store so a
// test can stage an inventory and its verdicts. When wireReader is
// false the reader is left unset, exercising the degraded surface.
func newCASBNoOpsTestRouter(t *testing.T, wireReader bool) (
	http.Handler, uuid.UUID, string,
	*memory.CASBDiscoveredAppRepository, *memory.CASBNoOpsStore,
) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	userID := uuid.New()

	appRepo := memory.NewCASBDiscoveredAppRepository(store)
	svc := casb.New(
		memory.NewCASBConnectorRepository(store),
		appRepo,
		memory.NewCASBPostureCheckRepository(store),
		memory.NewAuditLogRepository(store),
		casb.PluginRegistry{},
		nil,
	)
	noops := memory.NewCASBNoOpsStore()

	h := handler.NewCASBHandler(svc)
	if wireReader {
		h.SetNoOpsReader(noops)
	}

	jwtSecret := "test-jwt-secret-key"
	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret:    jwtSecret,
			JWTIssuer:    "sng-control",
			JWTAudience:  "sng-control",
			APIKeyHeader: "X-SNG-API-Key",
		},
	}
	router := handler.NewRouter(handler.RouterDeps{Config: cfg, CASB: h})

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
	return router, tenantID, signed, appRepo, noops
}

func seedDiscoveredApp(t *testing.T, repo *memory.CASBDiscoveredAppRepository, tenantID uuid.UUID, name, vendor, category string, risk int) {
	t.Helper()
	now := time.Now().UTC()
	if _, err := repo.Upsert(context.Background(), tenantID, repository.CASBDiscoveredApp{
		TenantID:  tenantID,
		Name:      name,
		Vendor:    vendor,
		Category:  category,
		RiskScore: &risk,
		FirstSeen: now,
		LastSeen:  now,
	}); err != nil {
		t.Fatalf("seed app %q: %v", name, err)
	}
}

func TestCASBHandler_ListApps_AttachesVerdict(t *testing.T) {
	t.Parallel()
	router, tenantID, token, appRepo, noops := newCASBNoOpsTestRouter(t, true)
	ctx := context.Background()

	// One classified+actioned app and one bare app (discovered but not
	// yet swept) to prove the verdict is per-app and omitted when absent.
	seedDiscoveredApp(t, appRepo, tenantID, "OpenAI ChatGPT", "OpenAI", "genai", 72)
	seedDiscoveredApp(t, appRepo, tenantID, "Unclassified App", "Acme", "other", 10)

	classifiedAt := time.Date(2026, 6, 10, 9, 0, 0, 0, time.UTC)
	if _, err := noops.UpsertClassification(ctx, tenantID, repository.AppClassification{
		AppName:      "OpenAI ChatGPT",
		Category:     "genai",
		RiskScore:    72,
		Sanction:     repository.SanctionUnsanctioned,
		Confidence:   88,
		Source:       repository.ClassificationSourceHeuristic,
		Rationale:    "GenAI category, no connector, broad data egress",
		ClassifiedAt: classifiedAt,
	}); err != nil {
		t.Fatalf("seed classification: %v", err)
	}
	if _, err := noops.AppendAction(ctx, tenantID, repository.CASBAppAction{
		AppName:      "OpenAI ChatGPT",
		Category:     "genai",
		Enforcement:  repository.ActionProtect,
		TrafficClass: repository.ActionProtect.TrafficClass(),
		Mode:         repository.ActionModeRecommend,
		RiskScore:    72,
		Confidence:   88,
		Sanction:     repository.SanctionUnsanctioned,
		Applied:      false,
		Reason:       "recommend SWG inspection",
		CreatedAt:    classifiedAt,
	}); err != nil {
		t.Fatalf("seed action: %v", err)
	}

	rec := doJSON(t, router, http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/casb/apps", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET apps status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []struct {
			Name    string `json:"name"`
			Verdict *struct {
				Sanction   string `json:"sanction"`
				RiskScore  int    `json:"risk_score"`
				Confidence int    `json:"confidence"`
				Source     string `json:"source"`
				Rationale  string `json:"rationale"`
				Action     *struct {
					Enforcement  string `json:"enforcement"`
					Mode         string `json:"mode"`
					TrafficClass string `json:"traffic_class"`
					Applied      bool   `json:"applied"`
				} `json:"action"`
			} `json:"verdict"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var classified, bare bool
	for _, it := range resp.Items {
		switch it.Name {
		case "OpenAI ChatGPT":
			classified = true
			if it.Verdict == nil {
				t.Fatalf("classified app missing verdict")
			}
			if it.Verdict.Sanction != "unsanctioned" {
				t.Errorf("sanction = %q, want unsanctioned", it.Verdict.Sanction)
			}
			if it.Verdict.Confidence != 88 {
				t.Errorf("confidence = %d, want 88", it.Verdict.Confidence)
			}
			if it.Verdict.Source != "heuristic" {
				t.Errorf("source = %q, want heuristic", it.Verdict.Source)
			}
			if it.Verdict.Action == nil {
				t.Fatalf("verdict missing action")
			}
			if it.Verdict.Action.Enforcement != "protect" {
				t.Errorf("enforcement = %q, want protect", it.Verdict.Action.Enforcement)
			}
			if it.Verdict.Action.Mode != "recommend" {
				t.Errorf("mode = %q, want recommend", it.Verdict.Action.Mode)
			}
			if it.Verdict.Action.Applied {
				t.Errorf("applied = true, want false (recommend-only)")
			}
		case "Unclassified App":
			bare = true
			if it.Verdict != nil {
				t.Errorf("unclassified app should have no verdict, got %+v", it.Verdict)
			}
		}
	}
	if !classified || !bare {
		t.Fatalf("missing apps in response: classified=%v bare=%v", classified, bare)
	}
}

func TestCASBHandler_ListNoOpsActions(t *testing.T) {
	t.Parallel()
	router, tenantID, token, _, noops := newCASBNoOpsTestRouter(t, true)
	ctx := context.Background()

	if _, err := noops.AppendAction(ctx, tenantID, repository.CASBAppAction{
		AppName:      "OpenAI ChatGPT",
		Category:     "genai",
		Enforcement:  repository.ActionProtect,
		TrafficClass: repository.ActionProtect.TrafficClass(),
		Mode:         repository.ActionModeRecommend,
		RiskScore:    72,
		Confidence:   88,
		Sanction:     repository.SanctionUnsanctioned,
		Reason:       "recommend SWG inspection",
		CreatedAt:    time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed action: %v", err)
	}

	rec := doJSON(t, router, http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/casb/noops/actions", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET actions status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []struct {
			AppName     string `json:"app_name"`
			Enforcement string `json:"enforcement"`
			Mode        string `json:"mode"`
			Sanction    string `json:"sanction"`
		} `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("actions count = %d, want 1", len(resp.Items))
	}
	if resp.Items[0].AppName != "OpenAI ChatGPT" || resp.Items[0].Enforcement != "protect" {
		t.Errorf("unexpected action row: %+v", resp.Items[0])
	}
}

func TestCASBHandler_NoOpsReaderUnset_OmitsVerdictAndRoute(t *testing.T) {
	t.Parallel()
	router, tenantID, token, appRepo, _ := newCASBNoOpsTestRouter(t, false)
	seedDiscoveredApp(t, appRepo, tenantID, "OpenAI ChatGPT", "OpenAI", "genai", 72)

	// Apps still list, but with no verdict block.
	rec := doJSON(t, router, http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/casb/apps", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET apps status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("apps count = %d, want 1", len(resp.Items))
	}
	if _, ok := resp.Items[0]["verdict"]; ok {
		t.Errorf("verdict present without a NoOps reader wired")
	}

	// The action timeline route is not mounted at all.
	rec = doJSON(t, router, http.MethodGet, "/api/v1/tenants/"+tenantID.String()+"/casb/noops/actions", token, nil)
	if rec.Code != http.StatusNotFound {
		t.Errorf("actions route status = %d, want 404 when reader unset", rec.Code)
	}
}
