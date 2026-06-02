package executors

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// IsolateConfig is the configuration for a device isolation step.
type IsolateConfig struct {
	DeviceID uuid.UUID `json:"device_id"`
	Reason   string    `json:"reason"`
}

// IsolateExecutor publishes a device-isolation command via NATS.
type IsolateExecutor struct {
	pub Publisher
}

func (e *IsolateExecutor) Execute(ctx context.Context, tenantID uuid.UUID, config json.RawMessage) (json.RawMessage, error) {
	var cfg IsolateConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("isolate: invalid config: %w", err)
	}
	if cfg.DeviceID == uuid.Nil {
		return nil, fmt.Errorf("isolate: device_id is required")
	}

	msg, _ := json.Marshal(map[string]string{
		"action":    "isolate",
		"device_id": cfg.DeviceID.String(),
		"tenant_id": tenantID.String(),
		"reason":    cfg.Reason,
	})

	subject := fmt.Sprintf("sng.%s.device.isolate", tenantID)
	if e.pub != nil {
		if err := e.pub.Publish(ctx, subject, msg); err != nil {
			return nil, fmt.Errorf("isolate: publish failed: %w", err)
		}
	}

	return json.Marshal(map[string]string{
		"status":    "isolated",
		"device_id": cfg.DeviceID.String(),
	})
}
