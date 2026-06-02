package executors

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// PolicyUpdateConfig is the configuration for a scoped policy change.
type PolicyUpdateConfig struct {
	PolicyID uuid.UUID `json:"policy_id"`
	Action   string    `json:"action"`
	Scope    string    `json:"scope"`
	Reason   string    `json:"reason"`
}

// PolicyUpdateExecutor applies a scoped policy change.
type PolicyUpdateExecutor struct {
	pub Publisher
}

func (e *PolicyUpdateExecutor) Execute(ctx context.Context, tenantID uuid.UUID, config json.RawMessage) (json.RawMessage, error) {
	var cfg PolicyUpdateConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("policy_update: invalid config: %w", err)
	}
	if cfg.Action == "" {
		return nil, fmt.Errorf("policy_update: action is required")
	}

	msg, _ := json.Marshal(map[string]string{
		"action":    "policy_update",
		"policy_id": cfg.PolicyID.String(),
		"update":    cfg.Action,
		"scope":     cfg.Scope,
		"tenant_id": tenantID.String(),
		"reason":    cfg.Reason,
	})

	subject := fmt.Sprintf("sng.%s.policy.update", tenantID)
	if e.pub != nil {
		if err := e.pub.Publish(ctx, subject, msg); err != nil {
			return nil, fmt.Errorf("policy_update: publish failed: %w", err)
		}
	}

	return json.Marshal(map[string]string{
		"status": "updated",
		"action": cfg.Action,
	})
}
