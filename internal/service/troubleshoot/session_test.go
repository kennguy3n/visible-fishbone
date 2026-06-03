package troubleshoot_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/troubleshoot"
)

func newTestSessionService(t *testing.T) (*troubleshoot.SessionService, uuid.UUID) {
	t.Helper()
	store := memory.NewStore()
	tenantID := seedTenant(t, store)
	kbRepo := memory.NewKBEntryRepository(store)
	sessRepo := memory.NewTroubleshootSessionRepository(store)
	kbSvc := troubleshoot.NewKBService(kbRepo)
	assistant := troubleshoot.NewAssistant(nil, kbSvc, nil)
	svc := troubleshoot.NewSessionService(sessRepo, assistant, nil)
	return svc, tenantID
}

func TestSessionService_StartSession(t *testing.T) {
	svc, tenantID := newTestSessionService(t)
	operatorID := uuid.New()

	sess, err := svc.StartSession(context.Background(), tenantID, operatorID, "VPN is down")
	if err != nil {
		t.Fatal(err)
	}
	if sess.ID == uuid.Nil {
		t.Fatal("expected non-nil session ID")
	}
	if sess.Issue != "VPN is down" {
		t.Fatalf("expected issue 'VPN is down', got %q", sess.Issue)
	}
	if sess.Status != troubleshoot.SessionActive {
		t.Fatalf("expected status active, got %s", sess.Status)
	}
	if len(sess.Messages) < 2 {
		t.Fatalf("expected at least 2 messages (operator + assistant), got %d", len(sess.Messages))
	}
}

func TestSessionService_SendMessage(t *testing.T) {
	svc, tenantID := newTestSessionService(t)
	operatorID := uuid.New()

	sess, err := svc.StartSession(context.Background(), tenantID, operatorID, "Firewall issue")
	if err != nil {
		t.Fatal(err)
	}

	updated, err := svc.SendMessage(context.Background(), tenantID, sess.ID, "Which rules should I check?")
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Messages) < 4 {
		t.Fatalf("expected at least 4 messages, got %d", len(updated.Messages))
	}
}

func TestSessionService_GetSession(t *testing.T) {
	svc, tenantID := newTestSessionService(t)
	operatorID := uuid.New()

	sess, err := svc.StartSession(context.Background(), tenantID, operatorID, "Test issue")
	if err != nil {
		t.Fatal(err)
	}

	got, err := svc.GetSession(context.Background(), tenantID, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != sess.ID {
		t.Fatalf("expected ID %s, got %s", sess.ID, got.ID)
	}
}

func TestSessionService_ResolveSession(t *testing.T) {
	svc, tenantID := newTestSessionService(t)
	operatorID := uuid.New()

	sess, err := svc.StartSession(context.Background(), tenantID, operatorID, "Test issue")
	if err != nil {
		t.Fatal(err)
	}

	resolved, err := svc.ResolveSession(context.Background(), tenantID, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Status != troubleshoot.SessionResolved {
		t.Fatalf("expected resolved status, got %s", resolved.Status)
	}
}

func TestSessionService_SendMessage_ResolvedSession(t *testing.T) {
	svc, tenantID := newTestSessionService(t)
	operatorID := uuid.New()

	sess, err := svc.StartSession(context.Background(), tenantID, operatorID, "Test")
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.ResolveSession(context.Background(), tenantID, sess.ID)
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.SendMessage(context.Background(), tenantID, sess.ID, "More questions")
	if err == nil {
		t.Fatal("expected error sending message to resolved session")
	}
	if !errors.Is(err, repository.ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}

func TestSessionService_EmptyIssue(t *testing.T) {
	svc, tenantID := newTestSessionService(t)
	_, err := svc.StartSession(context.Background(), tenantID, uuid.New(), "")
	if err == nil {
		t.Fatal("expected error for empty issue")
	}
}
