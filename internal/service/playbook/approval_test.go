package playbook_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/repository/memory"
	"github.com/kennguy3n/visible-fishbone/internal/service/playbook"
)

func newApprovalService() (*playbook.ApprovalService, *memory.Store) {
	store := memory.NewStore()
	approvalRepo := memory.NewPlaybookApprovalRepository(store)
	execRepo := memory.NewPlaybookExecutionRepository(store)
	svc := playbook.NewApprovalService(approvalRepo, execRepo, nil)
	return svc, store
}

func createTestExecution(t *testing.T, store *memory.Store, tenantID uuid.UUID) repository.PlaybookExecution {
	t.Helper()
	execRepo := memory.NewPlaybookExecutionRepository(store)
	exec, err := execRepo.Create(context.Background(), tenantID, repository.PlaybookExecution{
		TenantID:     tenantID,
		PlaybookID:   uuid.New(),
		Status:       "pending",
		TriggerEvent: []byte(`{}`),
		StartedAt:    time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return exec
}

func TestApproval_RequestAndApprove(t *testing.T) {
	svc, store := newApprovalService()
	ctx := context.Background()
	tenantID := uuid.New()
	exec := createTestExecution(t, store, tenantID)

	approval, err := svc.RequestApproval(ctx, tenantID, exec.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if approval.Status != string(playbook.ApprovalPending) {
		t.Errorf("expected pending, got %s", approval.Status)
	}

	approverID := uuid.New()
	approved, err := svc.Approve(ctx, tenantID, approval.ID, &approverID)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != string(playbook.ApprovalApproved) {
		t.Errorf("expected approved, got %s", approved.Status)
	}
}

func TestApproval_RequestAndReject(t *testing.T) {
	svc, store := newApprovalService()
	ctx := context.Background()
	tenantID := uuid.New()
	exec := createTestExecution(t, store, tenantID)

	approval, err := svc.RequestApproval(ctx, tenantID, exec.ID, 0)
	if err != nil {
		t.Fatal(err)
	}

	approverID := uuid.New()
	rejected, err := svc.Reject(ctx, tenantID, approval.ID, &approverID)
	if err != nil {
		t.Fatal(err)
	}
	if rejected.Status != string(playbook.ApprovalRejected) {
		t.Errorf("expected rejected, got %s", rejected.Status)
	}
}

func TestApproval_DoubleApprove(t *testing.T) {
	svc, store := newApprovalService()
	ctx := context.Background()
	tenantID := uuid.New()
	exec := createTestExecution(t, store, tenantID)

	approval, _ := svc.RequestApproval(ctx, tenantID, exec.ID, 0)
	approverID := uuid.New()
	_, _ = svc.Approve(ctx, tenantID, approval.ID, &approverID)

	_, err := svc.Approve(ctx, tenantID, approval.ID, &approverID)
	if err == nil {
		t.Error("expected error on double approve")
	}
}

func TestApproval_ListPending(t *testing.T) {
	svc, store := newApprovalService()
	ctx := context.Background()
	tenantID := uuid.New()
	exec1 := createTestExecution(t, store, tenantID)
	exec2 := createTestExecution(t, store, tenantID)

	_, _ = svc.RequestApproval(ctx, tenantID, exec1.ID, 0)
	_, _ = svc.RequestApproval(ctx, tenantID, exec2.ID, 0)

	pending, err := svc.ListPending(ctx, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 2 {
		t.Errorf("expected 2 pending, got %d", len(pending))
	}
}

func TestApproval_ExpireOld(t *testing.T) {
	svc, store := newApprovalService()
	ctx := context.Background()
	tenantID := uuid.New()

	approvalRepo := memory.NewPlaybookApprovalRepository(store)
	_, err := approvalRepo.Create(ctx, tenantID, repository.PlaybookApproval{
		TenantID:    tenantID,
		ExecutionID: uuid.New(),
		Status:      "pending",
		ExpiresAt:   time.Now().UTC().Add(-1 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}

	count, err := svc.ExpireOld(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("expected 1 expired, got %d", count)
	}
}
