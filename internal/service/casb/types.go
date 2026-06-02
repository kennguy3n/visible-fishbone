package casb

import "time"

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
