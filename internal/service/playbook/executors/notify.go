package executors

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// NotifyConfig is the configuration for a notification step.
type NotifyConfig struct {
	Channel string `json:"channel"`
	Message string `json:"message"`
	Target  string `json:"target"`
}

// NotifyExecutor sends a notification via webhook/email.
type NotifyExecutor struct {
	pub Publisher
}

func (e *NotifyExecutor) Execute(ctx context.Context, tenantID uuid.UUID, config json.RawMessage) (json.RawMessage, error) {
	var cfg NotifyConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("notify: invalid config: %w", err)
	}
	if cfg.Message == "" {
		return nil, fmt.Errorf("notify: message is required")
	}
	if cfg.Channel == "" {
		cfg.Channel = "webhook"
	}

	msg, _ := json.Marshal(map[string]string{
		"action":    "notify",
		"channel":   cfg.Channel,
		"message":   cfg.Message,
		"target":    cfg.Target,
		"tenant_id": tenantID.String(),
	})

	subject := fmt.Sprintf("sng.%s.notify", tenantID)
	if e.pub != nil {
		if err := e.pub.Publish(ctx, subject, msg); err != nil {
			return nil, fmt.Errorf("notify: publish failed: %w", err)
		}
	}

	return json.Marshal(map[string]string{
		"status":  "notified",
		"channel": cfg.Channel,
	})
}
