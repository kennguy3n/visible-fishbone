package rbi

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
)

func seedTenant(t *testing.T, store *memory.Store) uuid.UUID {
	t.Helper()
	tid := uuid.New()
	slug := tid.String()[:8]
	if _, err := memory.NewTenantRepository(store).Create(context.Background(),
		repository.Tenant{
			ID: tid, Name: slug, Slug: slug,
			Status: repository.TenantStatusActive, Tier: repository.TenantTierStarter,
		}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return tid
}

func newTestSvc(t *testing.T, proxyURL string, policy PolicyConfig) (*Service, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tid := seedTenant(t, store)
	repo := memory.NewRBISessionRepository(store)
	return NewService(repo,
		WithProxy(ProxyConfig{BaseURL: proxyURL}),
		WithPolicy(policy),
		WithSessionTTL(10*time.Minute),
	), tid
}

func TestCreateSession_NotConfigured(t *testing.T) {
	svc, tid := newTestSvc(t, "", PolicyConfig{})
	_, err := svc.CreateSession(context.Background(), tid, CreateSessionInput{TargetURL: "https://x.com"}, nil)
	if err != ErrNotConfigured {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

func TestCreateSession_Configured(t *testing.T) {
	svc, tid := newTestSvc(t, "https://rbi.example.com", PolicyConfig{})
	sess, err := svc.CreateSession(context.Background(), tid, CreateSessionInput{
		TargetURL: "https://gambling.example",
		UserID:    uuid.New(),
	}, nil)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if sess.Status != "active" {
		t.Fatalf("expected active, got %s", sess.Status)
	}
	if sess.ProxyURL == "" {
		t.Fatal("expected non-empty proxy URL")
	}
	// Round-trip via Get.
	got, err := svc.GetSession(context.Background(), tid, sess.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.TargetURL != "https://gambling.example" {
		t.Fatalf("unexpected target url: %s", got.TargetURL)
	}
}

func TestCreateSession_EmptyURL(t *testing.T) {
	svc, tid := newTestSvc(t, "https://rbi.example.com", PolicyConfig{})
	_, err := svc.CreateSession(context.Background(), tid, CreateSessionInput{TargetURL: ""}, nil)
	if err == nil {
		t.Fatal("expected error for empty target url")
	}
}

func TestCloseSession(t *testing.T) {
	svc, tid := newTestSvc(t, "https://rbi.example.com", PolicyConfig{})
	sess, err := svc.CreateSession(context.Background(), tid, CreateSessionInput{TargetURL: "https://x.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.CloseSession(context.Background(), tid, sess.ID, nil); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	got, err := svc.GetSession(context.Background(), tid, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "closed" {
		t.Fatalf("expected closed, got %s", got.Status)
	}
	// Double close → not found (no longer active).
	if err := svc.CloseSession(context.Background(), tid, sess.ID, nil); err == nil {
		t.Fatal("expected error closing an already-closed session")
	}
}

func TestListSessions(t *testing.T) {
	svc, tid := newTestSvc(t, "https://rbi.example.com", PolicyConfig{})
	for i := 0; i < 3; i++ {
		if _, err := svc.CreateSession(context.Background(), tid, CreateSessionInput{TargetURL: "https://x.com"}, nil); err != nil {
			t.Fatal(err)
		}
	}
	list, err := svc.ListSessions(context.Background(), tid, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 sessions, got %d", len(list))
	}
}

func TestTenantIsolation(t *testing.T) {
	store := memory.NewStore()
	t1 := seedTenant(t, store)
	t2 := seedTenant(t, store)
	repo := memory.NewRBISessionRepository(store)
	svc := NewService(repo, WithProxy(ProxyConfig{BaseURL: "https://rbi.example.com"}))

	sess, err := svc.CreateSession(context.Background(), t1, CreateSessionInput{TargetURL: "https://x.com"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// t2 must not see t1's session.
	if _, err := svc.GetSession(context.Background(), t2, sess.ID); err == nil {
		t.Fatal("expected tenant isolation: t2 should not see t1's session")
	}
}

func TestEvaluateURL(t *testing.T) {
	cases := []struct {
		name     string
		policy   PolicyConfig
		category string
		risk     int
		want     bool
		reason   TriggerReason
	}{
		{
			name:   "disabled by default",
			policy: PolicyConfig{},
			want:   false,
		},
		{
			name:     "category match",
			policy:   PolicyConfig{Categories: []string{"gambling", "phishing"}},
			category: "Gambling",
			want:     true,
			reason:   TriggerCategoryMatch,
		},
		{
			name:   "risk score threshold",
			policy: PolicyConfig{RiskScoreThreshold: 70},
			risk:   85,
			want:   true,
			reason: TriggerRiskScore,
		},
		{
			name:   "risk score below threshold",
			policy: PolicyConfig{RiskScoreThreshold: 70},
			risk:   50,
			want:   false,
		},
		{
			name:     "uncategorised isolation",
			policy:   PolicyConfig{IsolateUncategorised: true},
			category: "",
			want:     true,
			reason:   TriggerUncategorised,
		},
		{
			name:     "categorised when uncategorised-only policy",
			policy:   PolicyConfig{IsolateUncategorised: true},
			category: "news",
			want:     false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := tc.policy.Evaluate(tc.category, tc.risk)
			if got != tc.want {
				t.Fatalf("Evaluate(%q,%d) = %v, want %v", tc.category, tc.risk, got, tc.want)
			}
			if got && reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}

func TestProxySessionURL(t *testing.T) {
	pc := ProxyConfig{BaseURL: "https://rbi.example.com"}
	url := pc.SessionURL("abc-123")
	want := "https://rbi.example.com/rbi/session/abc-123"
	if url != want {
		t.Fatalf("SessionURL = %q, want %q", url, want)
	}
}
