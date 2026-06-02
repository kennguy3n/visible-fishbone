package executors

import (
	"context"
	"fmt"

	"github.com/kennguy3n/visible-fishbone/internal/service/playbook"
)

// Publisher is the NATS publish interface used by executors.
type Publisher interface {
	Publish(ctx context.Context, subject string, data []byte) error
}

// Registry holds executors keyed by step type.
type Registry struct {
	executors map[playbook.StepType]playbook.StepExecutor
}

// NewRegistry constructs an executor registry with all built-in executors.
func NewRegistry(pub Publisher) *Registry {
	r := &Registry{
		executors: map[playbook.StepType]playbook.StepExecutor{},
	}
	r.executors[playbook.StepIsolate] = &IsolateExecutor{pub: pub}
	r.executors[playbook.StepBlockIP] = &BlockIPExecutor{pub: pub}
	r.executors[playbook.StepQuarantine] = &QuarantineExecutor{pub: pub}
	r.executors[playbook.StepNotify] = &NotifyExecutor{pub: pub}
	r.executors[playbook.StepCreateTicket] = &TicketExecutor{pub: pub}
	r.executors[playbook.StepPolicyUpdate] = &PolicyUpdateExecutor{pub: pub}
	r.executors[playbook.StepRevokeAccess] = &RevokeAccessExecutor{pub: pub}
	return r
}

// Get returns the executor for a step type.
func (r *Registry) Get(t playbook.StepType) (playbook.StepExecutor, error) {
	e, ok := r.executors[t]
	if !ok {
		return nil, fmt.Errorf("no executor for step type: %s", t)
	}
	return e, nil
}
