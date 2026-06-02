package playbook

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// StepType enumerates the types of playbook steps.
type StepType string

const (
	StepIsolate      StepType = "isolate"
	StepBlockIP      StepType = "block_ip"
	StepQuarantine   StepType = "quarantine"
	StepNotify       StepType = "notify"
	StepCreateTicket StepType = "create_ticket"
	StepPolicyUpdate StepType = "policy_update"
	StepRevokeAccess StepType = "revoke_access"
)

// ValidStepTypes is the set of recognised step types.
var ValidStepTypes = map[StepType]bool{
	StepIsolate:      true,
	StepBlockIP:      true,
	StepQuarantine:   true,
	StepNotify:       true,
	StepCreateTicket: true,
	StepPolicyUpdate: true,
	StepRevokeAccess: true,
}

// ExecutionStatus enumerates execution lifecycle states.
type ExecutionStatus string

const (
	StatusPending          ExecutionStatus = "pending"
	StatusRunning          ExecutionStatus = "running"
	StatusCompleted        ExecutionStatus = "completed"
	StatusFailed           ExecutionStatus = "failed"
	StatusRolledBack       ExecutionStatus = "rolled_back"
	StatusAwaitingApproval ExecutionStatus = "awaiting_approval"
)

// ApprovalStatus enumerates approval lifecycle states.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
	ApprovalExpired  ApprovalStatus = "expired"
)

// PlaybookStep defines one step in a playbook.
type PlaybookStep struct {
	Order          int             `json:"order"`
	Type           StepType        `json:"type"`
	Config         json.RawMessage `json:"config"`
	TimeoutSeconds int             `json:"timeout_seconds"`
}

// Playbook is the domain object for a playbook definition.
type Playbook struct {
	ID               uuid.UUID      `json:"id"`
	TenantID         uuid.UUID      `json:"tenant_id"`
	Name             string         `json:"name"`
	Description      string         `json:"description"`
	TriggerCondition string         `json:"trigger_condition"`
	Steps            []PlaybookStep `json:"steps"`
	Enabled          bool           `json:"enabled"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
}

// PlaybookExecution tracks one invocation of a playbook.
type PlaybookExecution struct {
	ID           uuid.UUID       `json:"id"`
	TenantID     uuid.UUID       `json:"tenant_id"`
	PlaybookID   uuid.UUID       `json:"playbook_id"`
	Status       ExecutionStatus `json:"status"`
	TriggerEvent json.RawMessage `json:"trigger_event"`
	StartedAt    time.Time       `json:"started_at"`
	CompletedAt  *time.Time      `json:"completed_at,omitempty"`
	StepResults  []StepResult    `json:"step_results,omitempty"`
}

// StepResult records the outcome of one step execution.
type StepResult struct {
	StepOrder   int             `json:"step_order"`
	Status      string          `json:"status"`
	Output      json.RawMessage `json:"output,omitempty"`
	Error       string          `json:"error,omitempty"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
}

// PlaybookApproval tracks the approval workflow for an execution.
type PlaybookApproval struct {
	ID          uuid.UUID      `json:"id"`
	TenantID    uuid.UUID      `json:"tenant_id"`
	ExecutionID uuid.UUID      `json:"execution_id"`
	ApproverID  *uuid.UUID     `json:"approver_id,omitempty"`
	Status      ApprovalStatus `json:"status"`
	ExpiresAt   time.Time      `json:"expires_at"`
	DecidedAt   *time.Time     `json:"decided_at,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}
