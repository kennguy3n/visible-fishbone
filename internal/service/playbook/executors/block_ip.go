package executors

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// BlockIPConfig is the configuration for an IP block step.
type BlockIPConfig struct {
	IPAddress  string `json:"ip_address"`
	Duration   string `json:"duration"`
	Reason     string `json:"reason"`
}

// BlockIPExecutor inserts a temporary IP block via NATS.
type BlockIPExecutor struct {
	pub Publisher
}

func (e *BlockIPExecutor) Execute(ctx context.Context, tenantID uuid.UUID, config json.RawMessage) (json.RawMessage, error) {
	var cfg BlockIPConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("block_ip: invalid config: %w", err)
	}
	if cfg.IPAddress == "" {
		return nil, fmt.Errorf("block_ip: ip_address is required")
	}

	msg, _ := json.Marshal(map[string]string{
		"action":     "block_ip",
		"ip_address": cfg.IPAddress,
		"tenant_id":  tenantID.String(),
		"duration":   cfg.Duration,
		"reason":     cfg.Reason,
	})

	subject := fmt.Sprintf("sng.%s.policy.block_ip", tenantID)
	if e.pub != nil {
		if err := e.pub.Publish(ctx, subject, msg); err != nil {
			return nil, fmt.Errorf("block_ip: publish failed: %w", err)
		}
	}

	return json.Marshal(map[string]string{
		"status":     "blocked",
		"ip_address": cfg.IPAddress,
	})
}
