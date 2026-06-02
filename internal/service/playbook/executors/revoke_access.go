package executors

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// RevokeAccessConfig is the configuration for revoking ZTNA access.
type RevokeAccessConfig struct {
	UserID   uuid.UUID `json:"user_id"`
	DeviceID uuid.UUID `json:"device_id"`
	Reason   string    `json:"reason"`
}

// RevokeAccessExecutor revokes a ZTNA access grant.
type RevokeAccessExecutor struct {
	pub Publisher
}

func (e *RevokeAccessExecutor) Execute(ctx context.Context, tenantID uuid.UUID, config json.RawMessage) (json.RawMessage, error) {
	var cfg RevokeAccessConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("revoke_access: invalid config: %w", err)
	}

	msg, _ := json.Marshal(map[string]string{
		"action":    "revoke_access",
		"user_id":   cfg.UserID.String(),
		"device_id": cfg.DeviceID.String(),
		"tenant_id": tenantID.String(),
		"reason":    cfg.Reason,
	})

	subject := fmt.Sprintf("sng.%s.ztna.revoke", tenantID)
	if e.pub != nil {
		if err := e.pub.Publish(ctx, subject, msg); err != nil {
			return nil, fmt.Errorf("revoke_access: publish failed: %w", err)
		}
	}

	return json.Marshal(map[string]string{
		"status":    "revoked",
		"user_id":   cfg.UserID.String(),
		"device_id": cfg.DeviceID.String(),
	})
}
