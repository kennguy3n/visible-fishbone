package playbook

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Publisher is the NATS publish interface used by the engine.
type Publisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// StepExecutor defines the interface for step execution.
type StepExecutor interface {
	Execute(ctx context.Context, tenantID uuid.UUID, config json.RawMessage) (json.RawMessage, error)
}

// ExecutorRegistry provides executors by step type.
type ExecutorRegistry interface {
	Get(t StepType) (StepExecutor, error)
}

// Engine is the core playbook execution engine.
type Engine struct {
	playbookRepo  repository.PlaybookRepository
	executionRepo repository.PlaybookExecutionRepository
	pub           Publisher
	executors     ExecutorRegistry
	logger        *slog.Logger

	mu       sync.Mutex
	running  map[string]bool // key: tenantID+playbookID
}

// NewEngine constructs a playbook engine.
func NewEngine(
	repo repository.PlaybookRepository,
	execRepo repository.PlaybookExecutionRepository,
	pub Publisher,
	logger *slog.Logger,
) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		playbookRepo:  repo,
		executionRepo: execRepo,
		pub:           pub,
		logger:        logger,
		running:       make(map[string]bool),
	}
}

// SetExecutors injects the executor registry.
func (e *Engine) SetExecutors(reg ExecutorRegistry) {
	e.executors = reg
}

func concurrencyKey(tenantID, playbookID uuid.UUID) string {
	return tenantID.String() + ":" + playbookID.String()
}

// Execute runs a playbook execution with concurrency control.
func (e *Engine) Execute(
	ctx context.Context,
	tenantID uuid.UUID,
	playbookID uuid.UUID,
	triggerEvent json.RawMessage,
) (repository.PlaybookExecution, error) {
	key := concurrencyKey(tenantID, playbookID)

	e.mu.Lock()
	if e.running[key] {
		e.mu.Unlock()
		return repository.PlaybookExecution{}, fmt.Errorf("playbook %s already executing for tenant %s", playbookID, tenantID)
	}
	e.running[key] = true
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.running, key)
		e.mu.Unlock()
	}()

	pb, err := e.playbookRepo.Get(ctx, tenantID, playbookID)
	if err != nil {
		return repository.PlaybookExecution{}, err
	}

	if triggerEvent == nil {
		triggerEvent = json.RawMessage(`{}`)
	}

	exec := repository.PlaybookExecution{
		TenantID:     tenantID,
		PlaybookID:   pb.ID,
		Status:       string(StatusRunning),
		TriggerEvent: triggerEvent,
		StartedAt:    time.Now().UTC(),
	}
	exec, err = e.executionRepo.Create(ctx, tenantID, exec)
	if err != nil {
		return repository.PlaybookExecution{}, err
	}

	var steps []PlaybookStep
	if err := json.Unmarshal(pb.Steps, &steps); err != nil {
		_ = e.executionRepo.UpdateStatus(ctx, tenantID, exec.ID, string(StatusFailed))
		return exec, fmt.Errorf("invalid playbook steps: %w", err)
	}

	finalStatus := string(StatusCompleted)
	for _, step := range steps {
		stepResult := e.executeStep(ctx, tenantID, exec.ID, step)
		_ = e.executionRepo.AddStepResult(ctx, tenantID, exec.ID, stepResult)

		if stepResult.Status == "failed" {
			finalStatus = string(StatusFailed)
			e.logger.Warn("step failed, aborting playbook",
				"playbook_id", playbookID,
				"step_order", step.Order,
				"error", stepResult.Error,
			)
			break
		}
	}

	_ = e.executionRepo.UpdateStatus(ctx, tenantID, exec.ID, finalStatus)
	exec.Status = finalStatus
	now := time.Now().UTC()
	exec.CompletedAt = &now

	return exec, nil
}

func (e *Engine) executeStep(
	ctx context.Context,
	tenantID uuid.UUID,
	executionID uuid.UUID,
	step PlaybookStep,
) repository.StepResult {
	now := time.Now().UTC()
	result := repository.StepResult{
		ExecutionID: executionID,
		TenantID:    tenantID,
		StepOrder:   step.Order,
		Status:      "running",
		Output:      json.RawMessage(`{}`),
		StartedAt:   &now,
	}

	if e.executors == nil {
		result.Status = "failed"
		result.Error = "no executor registry configured"
		end := time.Now().UTC()
		result.CompletedAt = &end
		return result
	}

	executor, err := e.executors.Get(step.Type)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		end := time.Now().UTC()
		result.CompletedAt = &end
		return result
	}

	timeout := time.Duration(step.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	stepCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	output, err := executor.Execute(stepCtx, tenantID, step.Config)
	end := time.Now().UTC()
	result.CompletedAt = &end

	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		return result
	}

	result.Status = "completed"
	result.Output = output
	return result
}

// DryRun simulates a playbook execution without persisting results.
func (e *Engine) DryRun(
	ctx context.Context,
	tenantID uuid.UUID,
	playbookID uuid.UUID,
) ([]StepResult, error) {
	pb, err := e.playbookRepo.Get(ctx, tenantID, playbookID)
	if err != nil {
		return nil, err
	}

	var steps []PlaybookStep
	if err := json.Unmarshal(pb.Steps, &steps); err != nil {
		return nil, fmt.Errorf("invalid playbook steps: %w", err)
	}

	results := make([]StepResult, len(steps))
	for i, step := range steps {
		results[i] = StepResult{
			StepOrder: step.Order,
			Status:    "simulated",
		}
		if e.executors != nil {
			if _, err := e.executors.Get(step.Type); err != nil {
				results[i].Status = "error"
				results[i].Error = err.Error()
			}
		}
	}
	return results, nil
}

// EvaluateTrigger checks if an alert matches a playbook's trigger condition.
func EvaluateTrigger(triggerCondition string, alertKind string) bool {
	if triggerCondition == "" {
		return false
	}
	return triggerCondition == alertKind || triggerCondition == "*"
}

// CreatePlaybook creates a new playbook.
func (e *Engine) CreatePlaybook(
	ctx context.Context,
	tenantID uuid.UUID,
	p repository.Playbook,
) (repository.Playbook, error) {
	return e.playbookRepo.Create(ctx, tenantID, p)
}

// GetPlaybook retrieves a playbook by ID.
func (e *Engine) GetPlaybook(ctx context.Context, tenantID, id uuid.UUID) (repository.Playbook, error) {
	return e.playbookRepo.Get(ctx, tenantID, id)
}

// ListPlaybooks returns paginated playbooks.
func (e *Engine) ListPlaybooks(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.Playbook], error) {
	return e.playbookRepo.List(ctx, tenantID, page)
}

// UpdatePlaybook applies a patch to a playbook.
func (e *Engine) UpdatePlaybook(ctx context.Context, tenantID, id uuid.UUID, patch repository.PlaybookPatch) (repository.Playbook, error) {
	return e.playbookRepo.Update(ctx, tenantID, id, patch)
}

// DeletePlaybook removes a playbook.
func (e *Engine) DeletePlaybook(ctx context.Context, tenantID, id uuid.UUID) error {
	return e.playbookRepo.Delete(ctx, tenantID, id)
}

// GetExecution retrieves an execution by ID.
func (e *Engine) GetExecution(ctx context.Context, tenantID, id uuid.UUID) (repository.PlaybookExecution, error) {
	return e.executionRepo.Get(ctx, tenantID, id)
}

// ListExecutions returns paginated executions.
func (e *Engine) ListExecutions(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.PlaybookExecution], error) {
	return e.executionRepo.List(ctx, tenantID, page)
}
