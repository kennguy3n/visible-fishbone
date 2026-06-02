package casb

import (
	"time"

	"github.com/google/uuid"
)

// PostureCheck is a single configuration assessment result.
type PostureCheck struct {
	CheckName string `json:"check_name"`
	Status    string `json:"status"`
	Details   string `json:"details"`
}

// PostureReport aggregates posture checks for a SaaS app.
type PostureReport struct {
	AppID      uuid.UUID      `json:"app_id"`
	Checks     []PostureCheck `json:"checks"`
	Score      int            `json:"score"`
	AssessedAt time.Time      `json:"assessed_at"`
}

// SaaSUser represents a user discovered within a SaaS connector.
type SaaSUser struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Active      bool   `json:"active"`
	Admin       bool   `json:"admin"`
}

// ActivityEvent represents an activity/audit event from a SaaS provider.
type ActivityEvent struct {
	ID        string    `json:"id"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	IP        string    `json:"ip"`
	Timestamp time.Time `json:"timestamp"`
	Details   string    `json:"details"`
}
