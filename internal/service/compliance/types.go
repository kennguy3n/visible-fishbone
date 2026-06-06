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

	// Regional frameworks (Session 2C). Each reuses the same
	// evidence-collection + report-generation pipeline as the four
	// global frameworks above; only the control catalog and the
	// policy→control mapping differ.

	// FrameworkPDPA is the Personal Data Protection Act family shared
	// across Singapore (PDPA 2012), Thailand (PDPA B.E. 2562), and
	// Malaysia (PDPA 2010): the obligations are near-identical, so one
	// control catalog covers SG/TH/MY.
	FrameworkPDPA ComplianceFramework = "PDPA"
	// FrameworkNESA is the UAE Information Assurance regime — the NESA
	// (now SIA) IA Standards as administered alongside the TDRA.
	FrameworkNESA ComplianceFramework = "NESA_TDRA"
	// FrameworkNDSG is Switzerland's revised Federal Act on Data
	// Protection (nFADP / nDSG), enforced by the FDPIC.
	FrameworkNDSG ComplianceFramework = "FDPIC_NDSG"
	// FrameworkBDSG is Germany's GDPR + Bundesdatenschutzgesetz (BDSG)
	// pairing — the EU GDPR articles plus the German federal additions.
	FrameworkBDSG ComplianceFramework = "BDSG_GDPR"
	// FrameworkCSACE is the Singapore Cyber Security Agency (CSA)
	// Cyber Essentials mark for SMEs.
	FrameworkCSACE ComplianceFramework = "CSA_CE"
)

// ValidFrameworks is the set of recognised framework identifiers.
// The DB CHECK constraint on compliance_reports.framework
// (migration 045) is kept in lock-step with this map.
var ValidFrameworks = map[ComplianceFramework]bool{
	FrameworkPCIDSS:   true,
	FrameworkHIPAA:    true,
	FrameworkSOC2:     true,
	FrameworkISO27001: true,
	FrameworkPDPA:     true,
	FrameworkNESA:     true,
	FrameworkNDSG:     true,
	FrameworkBDSG:     true,
	FrameworkCSACE:    true,
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
