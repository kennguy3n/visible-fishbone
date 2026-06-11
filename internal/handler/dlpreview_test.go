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
	"github.com/kennguy3n/visible-fishbone/internal/service/dlpreview"
)

// fixedReviewClock is the deterministic timestamp the review-queue test
// service stamps onto enqueued events and the digest window.
var fixedReviewClock = time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

// newDLPReviewTestRouter builds a router with only the DLP review-queue
// handler wired over an in-memory repo, plus a JWT for the seeded
// tenant/user. It returns the router, the tenant id, the user id (which
// is the actor stamped on decisions), the backing service (so the test
// can seed events the way the DLP engine would), and a signed token.
func newDLPReviewTestRouter(t *testing.T) (http.Handler, uuid.UUID, uuid.UUID, *dlpreview.Service, string) {
	t.Helper()
	store := memory.NewStore()
	tenantID := uuid.New()
	if _, err := memory.NewTenantRepository(store).Create(t.Context(),
		repository.Tenant{
			ID: tenantID, Name: "T", Slug: "t-dlpreview",
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	userID := uuid.New()

	svc, err := dlpreview.New(
		memory.NewDLPReviewRepository(),
		dlpreview.WithClock(func() time.Time { return fixedReviewClock }),
	)
	if err != nil {
		t.Fatalf("new dlpreview service: %v", err)
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
	router := handler.NewRouter(handler.RouterDeps{
		Config:    cfg,
		DLPReview: handler.NewDLPReviewHandler(svc),
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
	return router, tenantID, userID, svc, signed
}

func seedReviewEvent(t *testing.T, svc *dlpreview.Service, tenantID uuid.UUID, app string, sev dlpreview.Severity, conf float64) dlpreview.ReviewEvent {
	t.Helper()
	ev, err := svc.Enqueue(t.Context(), tenantID, dlpreview.EnqueueInput{
		DestinationApp: app,
		Severity:       sev,
		Confidence:     conf,
		Findings: []dlpreview.FindingAggregate{{
			Kind: dlpreview.FindingPII, Label: "ssn_us", Count: 2,
			MaxConfidence: 0.9, Severity: dlpreview.SeverityHigh,
		}},
	})
	if err != nil {
		t.Fatalf("seed review event: %v", err)
	}
	return ev
}

func TestDLPReviewHandler_ListGetAndStateFilter(t *testing.T) {
	t.Parallel()
	router, tenantID, _, svc, token := newDLPReviewTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/review-queue"

	ev := seedReviewEvent(t, svc, tenantID, "chatgpt", dlpreview.SeverityHigh, 0.9)
	seedReviewEvent(t, svc, tenantID, "suspected_ai_app", dlpreview.SeverityMedium, 0.6)

	// LIST all
	rec := doJSON(t, router, http.MethodGet, base, token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var listed struct {
		Items []map[string]any `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("unmarshal list: %v", err)
	}
	if len(listed.Items) != 2 {
		t.Fatalf("list: want 2 items, got %d", len(listed.Items))
	}

	// LIST with a state filter that matches nothing yet.
	rec = doJSON(t, router, http.MethodGet, base+"?state=approved", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("list approved: want 200, got %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("unmarshal list approved: %v", err)
	}
	if len(listed.Items) != 0 {
		t.Fatalf("list approved: want 0 items, got %d", len(listed.Items))
	}

	// LIST with an invalid state → 400.
	rec = doJSON(t, router, http.MethodGet, base+"?state=bogus", token, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("list bogus state: want 400, got %d", rec.Code)
	}

	// GET one.
	rec = doJSON(t, router, http.MethodGet, base+"/"+ev.ID.String(), token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal get: %v", err)
	}
	if got["destination_app"] != "chatgpt" || got["state"] != "pending" {
		t.Fatalf("get: unexpected body %v", got)
	}

	// GET a missing id → 404.
	rec = doJSON(t, router, http.MethodGet, base+"/"+uuid.New().String(), token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get missing: want 404, got %d", rec.Code)
	}
}

func TestDLPReviewHandler_SurfacesTriageContext(t *testing.T) {
	t.Parallel()
	router, tenantID, _, svc, token := newDLPReviewTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/review-queue"

	device := uuid.New()
	occurred := time.Date(2025, 1, 1, 11, 30, 0, 0, time.UTC)
	ev, err := svc.Enqueue(t.Context(), tenantID, dlpreview.EnqueueInput{
		DestinationApp: "chatgpt",
		Severity:       dlpreview.SeverityHigh,
		Confidence:     0.9,
		DeviceID:       device,
		OccurredAt:     occurred,
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	rec := doJSON(t, router, http.MethodGet, base+"/"+ev.ID.String(), token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["device_id"] != device.String() {
		t.Fatalf("device_id = %v, want %s", got["device_id"], device)
	}
	if got["occurred_at"] != occurred.Format(time.RFC3339) {
		t.Fatalf("occurred_at = %v, want %s", got["occurred_at"], occurred.Format(time.RFC3339))
	}

	// An event without triage context omits the keys entirely.
	bare := seedReviewEvent(t, svc, tenantID, "notion", dlpreview.SeverityLow, 0.2)
	rec = doJSON(t, router, http.MethodGet, base+"/"+bare.ID.String(), token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("get bare: want 200, got %d", rec.Code)
	}
	var bareBody map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &bareBody); err != nil {
		t.Fatalf("unmarshal bare: %v", err)
	}
	if _, ok := bareBody["device_id"]; ok {
		t.Fatal("device_id must be omitted when unset")
	}
	if _, ok := bareBody["occurred_at"]; ok {
		t.Fatal("occurred_at must be omitted when unset")
	}
}

func TestDLPReviewHandler_DecisionsAndDoubleDecide(t *testing.T) {
	t.Parallel()
	router, tenantID, userID, svc, token := newDLPReviewTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/review-queue"

	approveEv := seedReviewEvent(t, svc, tenantID, "chatgpt", dlpreview.SeverityHigh, 0.9)
	blockEv := seedReviewEvent(t, svc, tenantID, "suspected_ai_app", dlpreview.SeverityCritical, 0.95)
	dismissEv := seedReviewEvent(t, svc, tenantID, "notion", dlpreview.SeverityLow, 0.3)

	cases := []struct {
		action string
		id     uuid.UUID
		want   string
	}{
		{"approve", approveEv.ID, "approved"},
		{"block", blockEv.ID, "blocked"},
		{"dismiss", dismissEv.ID, "dismissed"},
	}
	for _, c := range cases {
		rec := doJSON(t, router, http.MethodPost, base+"/"+c.id.String()+"/"+c.action, token, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: want 200, got %d — %s", c.action, rec.Code, rec.Body.String())
		}
		var decided map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &decided); err != nil {
			t.Fatalf("%s unmarshal: %v", c.action, err)
		}
		if decided["state"] != c.want {
			t.Fatalf("%s: want state %q, got %q", c.action, c.want, decided["state"])
		}
		if decided["decided_by"] != userID.String() {
			t.Fatalf("%s: want decided_by %q, got %v", c.action, userID, decided["decided_by"])
		}
	}

	// A second decision on an already-terminal event is a conflict.
	rec := doJSON(t, router, http.MethodPost, base+"/"+approveEv.ID.String()+"/block", token, nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("re-decide: want 409, got %d — %s", rec.Code, rec.Body.String())
	}

	// Deciding a missing event → 404.
	rec = doJSON(t, router, http.MethodPost, base+"/"+uuid.New().String()+"/approve", token, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("decide missing: want 404, got %d", rec.Code)
	}
}

func TestDLPReviewHandler_Digest(t *testing.T) {
	t.Parallel()
	router, tenantID, _, svc, token := newDLPReviewTestRouter(t)
	base := "/api/v1/tenants/" + tenantID.String() + "/dlp/review-queue"

	seedReviewEvent(t, svc, tenantID, "chatgpt", dlpreview.SeverityHigh, 0.9)
	seedReviewEvent(t, svc, tenantID, "suspected_ai_app", dlpreview.SeverityMedium, 0.6)

	// Default window.
	rec := doJSON(t, router, http.MethodGet, base+"/digest", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("digest: want 200, got %d — %s", rec.Code, rec.Body.String())
	}
	var d struct {
		Total        int            `json:"total"`
		Pending      int            `json:"pending"`
		ByState      map[string]int `json:"by_state"`
		PendingByApp map[string]int `json:"pending_by_app"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &d); err != nil {
		t.Fatalf("unmarshal digest: %v", err)
	}
	if d.Total != 2 || d.Pending != 2 {
		t.Fatalf("digest: want total=2 pending=2, got total=%d pending=%d", d.Total, d.Pending)
	}
	if d.PendingByApp["chatgpt"] != 1 {
		t.Fatalf("digest: want pending_by_app[chatgpt]=1, got %d", d.PendingByApp["chatgpt"])
	}

	// An explicit, valid window is accepted.
	rec = doJSON(t, router, http.MethodGet, base+"/digest?window=168h", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("digest window: want 200, got %d", rec.Code)
	}

	// A malformed window → 400.
	rec = doJSON(t, router, http.MethodGet, base+"/digest?window=nope", token, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("digest bad window: want 400, got %d", rec.Code)
	}

	// The literal `digest` segment must not be swallowed by the {id}
	// route (which would 400 on a non-UUID path value).
	rec = doJSON(t, router, http.MethodGet, base+"/digest", token, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("digest routing: want 200, got %d", rec.Code)
	}
}
