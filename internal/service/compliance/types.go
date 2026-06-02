package compliance

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ComplianceFramework enumerates supported regulatory frameworks.
type ComplianceFramework string

const (
	FrameworkPCIDSS   ComplianceFramework = "PCI_DSS"
	FrameworkHIPAA    ComplianceFramework = "HIPAA"
	FrameworkSOC2     ComplianceFramework = "SOC2"
	FrameworkISO27001 ComplianceFramework = "ISO_27001"
)

// ValidFrameworks is the set of recognised framework identifiers.
var ValidFrameworks = map[ComplianceFramework]bool{
	FrameworkPCIDSS:   true,
	FrameworkHIPAA:    true,
	FrameworkSOC2:     true,
	FrameworkISO27001: true,
}

// ControlStatusValue enumerates control assessment outcomes.
type ControlStatusValue string

const (
	ControlMet     ControlStatusValue = "met"
	ControlPartial ControlStatusValue = "partial"
	ControlUnmet   ControlStatusValue = "unmet"
)

// ControlStatus captures the assessment of one regulatory control.
type ControlStatus struct {
	ControlID   string             `json:"control_id"`
	Description string             `json:"description"`
	Status      ControlStatusValue `json:"status"`
	Evidence    []string           `json:"evidence"`
}

// ComplianceScore is the computed score for a framework assessment.
type ComplianceScore struct {
	Framework ComplianceFramework `json:"framework"`
	Score     float64             `json:"score"`
	MaxScore  float64             `json:"max_score"`
	Controls  []ControlStatus     `json:"controls"`
}

// ComplianceReport is the domain object for a generated report.
type ComplianceReport struct {
	ID           uuid.UUID           `json:"id"`
	TenantID     uuid.UUID           `json:"tenant_id"`
	Framework    ComplianceFramework `json:"framework"`
	Score        float64             `json:"score"`
	MaxScore     float64             `json:"max_score"`
	Controls     []ControlStatus     `json:"controls"`
	EvidencePack json.RawMessage     `json:"evidence_pack"`
	GeneratedAt  time.Time           `json:"generated_at"`
	CreatedAt    time.Time           `json:"created_at"`
}

// EvidencePack wraps exportable evidence for a compliance report.
type EvidencePack struct {
	Framework   ComplianceFramework `json:"framework"`
	TenantID    uuid.UUID           `json:"tenant_id"`
	GeneratedAt time.Time           `json:"generated_at"`
	Controls    []ControlStatus     `json:"controls"`
	Policies    []PolicyEvidence    `json:"policies"`
}

// PolicyEvidence captures enforcement evidence for a policy type.
type PolicyEvidence struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Enforced bool   `json:"enforced"`
}
