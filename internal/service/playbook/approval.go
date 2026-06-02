package playbook

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// DefaultApprovalTTL is the default time-to-live for pending approvals.
const DefaultApprovalTTL = 24 * time.Hour

// ApprovalService manages the approval workflow for playbook executions.
type ApprovalService struct {
	approvalRepo  repository.PlaybookApprovalRepository
	executionRepo repository.PlaybookExecutionRepository
	logger        *slog.Logger
}

// NewApprovalService constructs an ApprovalService.
func NewApprovalService(
	approvalRepo repository.PlaybookApprovalRepository,
	executionRepo repository.PlaybookExecutionRepository,
	logger *slog.Logger,
) *ApprovalService {
	if logger == nil {
		logger = slog.Default()
	}
	return &ApprovalService{
		approvalRepo:  approvalRepo,
		executionRepo: executionRepo,
		logger:        logger,
	}
}

// RequestApproval creates a pending approval for an execution.
func (s *ApprovalService) RequestApproval(
	ctx context.Context,
	tenantID uuid.UUID,
	executionID uuid.UUID,
	ttl time.Duration,
) (repository.PlaybookApproval, error) {
	if ttl <= 0 {
		ttl = DefaultApprovalTTL
	}

	approval := repository.PlaybookApproval{
		TenantID:    tenantID,
		ExecutionID: executionID,
		Status:      string(ApprovalPending),
		ExpiresAt:   time.Now().UTC().Add(ttl),
	}

	created, err := s.approvalRepo.Create(ctx, tenantID, approval)
	if err != nil {
		return repository.PlaybookApproval{}, err
	}

	if err := s.executionRepo.UpdateStatus(ctx, tenantID, executionID, string(StatusAwaitingApproval)); err != nil {
		s.logger.Warn("failed to mark execution awaiting approval", "execution_id", executionID, "tenant_id", tenantID, "error", err)
	}

	return created, nil
}

// Approve approves a pending execution.
func (s *ApprovalService) Approve(
	ctx context.Context,
	tenantID uuid.UUID,
	approvalID uuid.UUID,
	approverID *uuid.UUID,
) (repository.PlaybookApproval, error) {
	approval, err := s.approvalRepo.Get(ctx, tenantID, approvalID)
	if err != nil {
		return repository.PlaybookApproval{}, err
	}

	if approval.Status != string(ApprovalPending) {
		return repository.PlaybookApproval{}, fmt.Errorf("approval is not pending (current: %s): %w", approval.Status, repository.ErrInvalidArgument)
	}

	if time.Now().UTC().After(approval.ExpiresAt) {
		if err := s.approvalRepo.UpdateStatus(ctx, tenantID, approvalID, string(ApprovalExpired), nil); err != nil {
			s.logger.Warn("failed to mark approval expired", "approval_id", approvalID, "tenant_id", tenantID, "error", err)
		}
		return repository.PlaybookApproval{}, fmt.Errorf("approval has expired: %w", repository.ErrInvalidArgument)
	}

	if err := s.approvalRepo.UpdateStatus(ctx, tenantID, approvalID, string(ApprovalApproved), approverID); err != nil {
		return repository.PlaybookApproval{}, err
	}

	if err := s.executionRepo.UpdateStatus(ctx, tenantID, approval.ExecutionID, string(StatusRunning)); err != nil {
		s.logger.Warn("failed to mark execution running", "execution_id", approval.ExecutionID, "tenant_id", tenantID, "error", err)
	}

	s.logger.Info("playbook execution approved",
		"approval_id", approvalID,
		"execution_id", approval.ExecutionID,
		"tenant_id", tenantID,
	)

	return s.approvalRepo.Get(ctx, tenantID, approvalID)
}

// Reject rejects a pending execution.
func (s *ApprovalService) Reject(
	ctx context.Context,
	tenantID uuid.UUID,
	approvalID uuid.UUID,
	approverID *uuid.UUID,
) (repository.PlaybookApproval, error) {
	approval, err := s.approvalRepo.Get(ctx, tenantID, approvalID)
	if err != nil {
		return repository.PlaybookApproval{}, err
	}

	if approval.Status != string(ApprovalPending) {
		return repository.PlaybookApproval{}, fmt.Errorf("approval is not pending (current: %s): %w", approval.Status, repository.ErrInvalidArgument)
	}

	if err := s.approvalRepo.UpdateStatus(ctx, tenantID, approvalID, string(ApprovalRejected), approverID); err != nil {
		return repository.PlaybookApproval{}, err
	}

	if err := s.executionRepo.UpdateStatus(ctx, tenantID, approval.ExecutionID, string(StatusFailed)); err != nil {
		s.logger.Warn("failed to mark execution failed", "execution_id", approval.ExecutionID, "tenant_id", tenantID, "error", err)
	}

	s.logger.Info("playbook execution rejected",
		"approval_id", approvalID,
		"execution_id", approval.ExecutionID,
		"tenant_id", tenantID,
	)

	return s.approvalRepo.Get(ctx, tenantID, approvalID)
}

// ListPending returns all pending approvals for a tenant.
func (s *ApprovalService) ListPending(ctx context.Context, tenantID uuid.UUID) ([]repository.PlaybookApproval, error) {
	return s.approvalRepo.ListPending(ctx, tenantID)
}

// ExpireOld transitions expired pending approvals to expired status.
func (s *ApprovalService) ExpireOld(ctx context.Context) (int, error) {
	count, err := s.approvalRepo.ExpireOld(ctx, time.Now().UTC())
	if err != nil {
		return 0, err
	}
	if count > 0 {
		s.logger.Info("expired pending approvals", "count", count)
	}
	return count, nil
}
