package executors

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// QuarantineConfig is the configuration for a file quarantine step.
type QuarantineConfig struct {
	FileID   string `json:"file_id"`
	FilePath string `json:"file_path"`
	Reason   string `json:"reason"`
}

// QuarantineExecutor moves a file to quarantine via CASB connector.
type QuarantineExecutor struct {
	pub Publisher
}

func (e *QuarantineExecutor) Execute(ctx context.Context, tenantID uuid.UUID, config json.RawMessage) (json.RawMessage, error) {
	var cfg QuarantineConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("quarantine: invalid config: %w", err)
	}
	if cfg.FileID == "" && cfg.FilePath == "" {
		return nil, fmt.Errorf("quarantine: file_id or file_path is required")
	}

	msg, _ := json.Marshal(map[string]string{
		"action":    "quarantine",
		"file_id":   cfg.FileID,
		"file_path": cfg.FilePath,
		"tenant_id": tenantID.String(),
		"reason":    cfg.Reason,
	})

	subject := fmt.Sprintf("sng.%s.casb.quarantine", tenantID)
	if e.pub != nil {
		if err := e.pub.Publish(ctx, subject, msg); err != nil {
			return nil, fmt.Errorf("quarantine: publish failed: %w", err)
		}
	}

	return json.Marshal(map[string]string{
		"status":  "quarantined",
		"file_id": cfg.FileID,
	})
}
