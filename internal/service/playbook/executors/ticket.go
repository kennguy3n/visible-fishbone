package executors

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// TicketConfig is the configuration for a ticket creation step.
type TicketConfig struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"`
	Assignee    string `json:"assignee"`
}

// TicketExecutor creates an incident ticket via integration service.
type TicketExecutor struct {
	pub Publisher
}

func (e *TicketExecutor) Execute(ctx context.Context, tenantID uuid.UUID, config json.RawMessage) (json.RawMessage, error) {
	var cfg TicketConfig
	if err := json.Unmarshal(config, &cfg); err != nil {
		return nil, fmt.Errorf("ticket: invalid config: %w", err)
	}
	if cfg.Title == "" {
		return nil, fmt.Errorf("ticket: title is required")
	}
	if cfg.Priority == "" {
		cfg.Priority = "medium"
	}

	msg, _ := json.Marshal(map[string]string{
		"action":      "create_ticket",
		"title":       cfg.Title,
		"description": cfg.Description,
		"priority":    cfg.Priority,
		"assignee":    cfg.Assignee,
		"tenant_id":   tenantID.String(),
	})

	subject := fmt.Sprintf("sng.%s.integration.ticket", tenantID)
	if e.pub != nil {
		if err := e.pub.Publish(ctx, subject, msg); err != nil {
			return nil, fmt.Errorf("ticket: publish failed: %w", err)
		}
	}

	ticketID := uuid.New().String()
	return json.Marshal(map[string]string{
		"status":    "created",
		"ticket_id": ticketID,
	})
}
