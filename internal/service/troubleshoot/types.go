package troubleshoot

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// KBCategory enumerates the knowledge base categories.
type KBCategory string

const (
	KBCategoryConnectivity KBCategory = "connectivity"
	KBCategoryPolicy       KBCategory = "policy"
	KBCategoryIdentity     KBCategory = "identity"
	KBCategoryPerformance  KBCategory = "performance"
	KBCategoryIntegration  KBCategory = "integration"
)

// KBEntry is a knowledge base article.
type KBEntry struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  *uuid.UUID `json:"tenant_id,omitempty"`
	Category  KBCategory `json:"category"`
	Title     string     `json:"title"`
	Content   string     `json:"content"`
	Tags      []string   `json:"tags"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// DiagnosticStatus enumerates the outcome of a diagnostic check.
type DiagnosticStatus string

const (
	DiagnosticPass DiagnosticStatus = "pass"
	DiagnosticFail DiagnosticStatus = "fail"
	DiagnosticWarn DiagnosticStatus = "warn"
)

// DiagnosticResult captures the outcome of a single diagnostic check.
type DiagnosticResult struct {
	CheckName  string           `json:"check_name"`
	Status     DiagnosticStatus `json:"status"`
	Message    string           `json:"message"`
	Details    json.RawMessage  `json:"details,omitempty"`
	ExecutedAt time.Time        `json:"executed_at"`
}

// SessionStatus enumerates session lifecycle states.
type SessionStatus string

const (
	SessionActive    SessionStatus = "active"
	SessionResolved  SessionStatus = "resolved"
	SessionEscalated SessionStatus = "escalated"
)

// SessionMessage is a single message in a troubleshooting session.
type SessionMessage struct {
	Role        string    `json:"role"` // "operator" or "assistant"
	Content     string    `json:"content"`
	Timestamp   time.Time `json:"timestamp"`
	AIGenerated bool      `json:"ai_generated"`
}

// TroubleshootSession is a conversational troubleshooting session.
type TroubleshootSession struct {
	ID                uuid.UUID          `json:"id"`
	TenantID          uuid.UUID          `json:"tenant_id"`
	OperatorID        uuid.UUID          `json:"operator_id"`
	Issue             string             `json:"issue"`
	Status            SessionStatus      `json:"status"`
	Messages          []SessionMessage   `json:"messages"`
	DiagnosticResults []DiagnosticResult `json:"diagnostic_results"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
}

// AssistantResponse is the output from the troubleshooting assistant.
type AssistantResponse struct {
	Content           string             `json:"content"`
	ReferencedKB      []KBEntry          `json:"referenced_kb,omitempty"`
	DiagnosticResults []DiagnosticResult `json:"diagnostic_results,omitempty"`
	AIGenerated       bool               `json:"ai_generated"`
}
