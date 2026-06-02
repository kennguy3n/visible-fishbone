package compliance

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// ReportService generates and manages compliance reports.
type ReportService struct {
	repo   repository.ComplianceReportRepository
	logger *slog.Logger
}

// NewReportService constructs a ReportService.
func NewReportService(repo repository.ComplianceReportRepository, logger *slog.Logger) *ReportService {
	if logger == nil {
		logger = slog.Default()
	}
	return &ReportService{repo: repo, logger: logger}
}

// frameworkControlMap defines the controls assessed per framework.
var frameworkControlMap = map[ComplianceFramework][]ControlStatus{
	FrameworkPCIDSS: {
		{ControlID: "PCI-1.1", Description: "Install and maintain network security controls", Status: ControlUnmet},
		{ControlID: "PCI-1.2", Description: "Apply secure configurations to all system components", Status: ControlUnmet},
		{ControlID: "PCI-2.1", Description: "Protect stored account data", Status: ControlUnmet},
		{ControlID: "PCI-3.1", Description: "Protect cardholder data with strong cryptography", Status: ControlUnmet},
		{ControlID: "PCI-4.1", Description: "Restrict access to system components", Status: ControlUnmet},
		{ControlID: "PCI-5.1", Description: "Log and monitor all access to cardholder data", Status: ControlUnmet},
		{ControlID: "PCI-6.1", Description: "Develop and maintain secure systems", Status: ControlUnmet},
		{ControlID: "PCI-7.1", Description: "Identify and authenticate access to system components", Status: ControlUnmet},
		{ControlID: "PCI-8.1", Description: "Regularly test security systems", Status: ControlUnmet},
		{ControlID: "PCI-9.1", Description: "Maintain an information security policy", Status: ControlUnmet},
	},
	FrameworkHIPAA: {
		{ControlID: "HIPAA-164.312(a)", Description: "Access control - unique user identification", Status: ControlUnmet},
		{ControlID: "HIPAA-164.312(b)", Description: "Audit controls - activity logging", Status: ControlUnmet},
		{ControlID: "HIPAA-164.312(c)", Description: "Integrity controls - data integrity mechanisms", Status: ControlUnmet},
		{ControlID: "HIPAA-164.312(d)", Description: "Person or entity authentication", Status: ControlUnmet},
		{ControlID: "HIPAA-164.312(e)", Description: "Transmission security - encryption", Status: ControlUnmet},
		{ControlID: "HIPAA-164.308(a)(1)", Description: "Security management process - risk analysis", Status: ControlUnmet},
		{ControlID: "HIPAA-164.308(a)(5)", Description: "Security awareness and training", Status: ControlUnmet},
		{ControlID: "HIPAA-164.310(a)", Description: "Facility access controls", Status: ControlUnmet},
	},
	FrameworkSOC2: {
		{ControlID: "SOC2-CC6.1", Description: "Logical and physical access controls", Status: ControlUnmet},
		{ControlID: "SOC2-CC6.2", Description: "System access registration and authorization", Status: ControlUnmet},
		{ControlID: "SOC2-CC6.3", Description: "Role-based access and least privilege", Status: ControlUnmet},
		{ControlID: "SOC2-CC7.1", Description: "Detection of unauthorized changes", Status: ControlUnmet},
		{ControlID: "SOC2-CC7.2", Description: "Monitoring of system components", Status: ControlUnmet},
		{ControlID: "SOC2-CC8.1", Description: "Change management controls", Status: ControlUnmet},
		{ControlID: "SOC2-CC9.1", Description: "Risk mitigation activities", Status: ControlUnmet},
		{ControlID: "SOC2-A1.1", Description: "Availability - system recovery", Status: ControlUnmet},
	},
	FrameworkISO27001: {
		{ControlID: "ISO-A.5", Description: "Information security policies", Status: ControlUnmet},
		{ControlID: "ISO-A.6", Description: "Organization of information security", Status: ControlUnmet},
		{ControlID: "ISO-A.8", Description: "Asset management", Status: ControlUnmet},
		{ControlID: "ISO-A.9", Description: "Access control", Status: ControlUnmet},
		{ControlID: "ISO-A.10", Description: "Cryptography", Status: ControlUnmet},
		{ControlID: "ISO-A.12", Description: "Operations security", Status: ControlUnmet},
		{ControlID: "ISO-A.13", Description: "Communications security", Status: ControlUnmet},
		{ControlID: "ISO-A.16", Description: "Information security incident management", Status: ControlUnmet},
		{ControlID: "ISO-A.18", Description: "Compliance with legal and contractual requirements", Status: ControlUnmet},
	},
}

// policyControlMapping maps policy types to the controls they satisfy.
var policyControlMapping = map[string]map[ComplianceFramework][]string{
	"dlp": {
		FrameworkPCIDSS:   {"PCI-2.1", "PCI-3.1"},
		FrameworkHIPAA:    {"HIPAA-164.312(c)", "HIPAA-164.312(e)"},
		FrameworkSOC2:     {"SOC2-CC6.1"},
		FrameworkISO27001: {"ISO-A.10", "ISO-A.13"},
	},
	"browser": {
		FrameworkPCIDSS:   {"PCI-1.1", "PCI-4.1"},
		FrameworkHIPAA:    {"HIPAA-164.312(a)"},
		FrameworkSOC2:     {"SOC2-CC6.2", "SOC2-CC6.3"},
		FrameworkISO27001: {"ISO-A.9", "ISO-A.12"},
	},
	"casb": {
		FrameworkPCIDSS:   {"PCI-5.1", "PCI-8.1"},
		FrameworkHIPAA:    {"HIPAA-164.312(b)", "HIPAA-164.308(a)(1)"},
		FrameworkSOC2:     {"SOC2-CC7.1", "SOC2-CC7.2"},
		FrameworkISO27001: {"ISO-A.6", "ISO-A.16"},
	},
	"policy": {
		FrameworkPCIDSS:   {"PCI-1.2", "PCI-9.1"},
		FrameworkHIPAA:    {"HIPAA-164.312(d)", "HIPAA-164.308(a)(5)"},
		FrameworkSOC2:     {"SOC2-CC8.1", "SOC2-CC9.1"},
		FrameworkISO27001: {"ISO-A.5", "ISO-A.8"},
	},
	"access_control": {
		FrameworkPCIDSS:   {"PCI-6.1", "PCI-7.1"},
		FrameworkHIPAA:    {"HIPAA-164.310(a)"},
		FrameworkSOC2:     {"SOC2-A1.1"},
		FrameworkISO27001: {"ISO-A.18"},
	},
}

// EnforcedPolicies describes which policy types are active for scoring.
type EnforcedPolicies struct {
	DLP           bool
	Browser       bool
	CASB          bool
	Policy        bool
	AccessControl bool
}

// Generate creates a compliance report for a framework with the given
// enforced policies. It maps policies to controls, computes a score,
// and persists the report.
func (s *ReportService) Generate(
	ctx context.Context,
	tenantID uuid.UUID,
	framework ComplianceFramework,
	policies EnforcedPolicies,
) (ComplianceReport, error) {
	if !ValidFrameworks[framework] {
		return ComplianceReport{}, repository.ErrInvalidArgument
	}

	score := s.computeScore(framework, policies)

	now := time.Now().UTC()
	evidencePack := s.buildEvidencePack(tenantID, framework, score, policies, now)
	evidenceBytes, err := json.Marshal(evidencePack)
	if err != nil {
		return ComplianceReport{}, err
	}

	controlBytes, err := json.Marshal(score.Controls)
	if err != nil {
		return ComplianceReport{}, err
	}

	repoReport := repository.ComplianceReport{
		TenantID:     tenantID,
		Framework:    string(framework),
		Score:        score.Score,
		MaxScore:     score.MaxScore,
		Controls:     controlBytes,
		EvidencePack: evidenceBytes,
		GeneratedAt:  now,
	}

	saved, err := s.repo.Create(ctx, tenantID, repoReport)
	if err != nil {
		return ComplianceReport{}, err
	}

	return s.fromRepoReport(saved), nil
}

// computeScore evaluates controls based on enforced policies.
func (s *ReportService) computeScore(framework ComplianceFramework, policies EnforcedPolicies) ComplianceScore {
	controls := cloneControls(frameworkControlMap[framework])
	metControls := map[string]bool{}

	policyTypes := map[string]bool{
		"dlp":            policies.DLP,
		"browser":        policies.Browser,
		"casb":           policies.CASB,
		"policy":         policies.Policy,
		"access_control": policies.AccessControl,
	}

	for policyType, enforced := range policyTypes {
		if !enforced {
			continue
		}
		mapping, ok := policyControlMapping[policyType]
		if !ok {
			continue
		}
		controlIDs, ok := mapping[framework]
		if !ok {
			continue
		}
		for _, cid := range controlIDs {
			metControls[cid] = true
		}
	}

	maxScore := float64(len(controls))
	score := 0.0
	for i := range controls {
		if metControls[controls[i].ControlID] {
			controls[i].Status = ControlMet
			controls[i].Evidence = []string{"Enforced via SNG policy engine"}
			score++
		}
	}

	return ComplianceScore{
		Framework: framework,
		Score:     score,
		MaxScore:  maxScore,
		Controls:  controls,
	}
}

// buildEvidencePack creates an exportable evidence structure.
func (s *ReportService) buildEvidencePack(
	tenantID uuid.UUID,
	framework ComplianceFramework,
	score ComplianceScore,
	policies EnforcedPolicies,
	generatedAt time.Time,
) EvidencePack {
	policyEvidence := []PolicyEvidence{
		{Type: "dlp", Name: "Data Loss Prevention", Enforced: policies.DLP},
		{Type: "browser", Name: "Browser Protection", Enforced: policies.Browser},
		{Type: "casb", Name: "CASB Discovery", Enforced: policies.CASB},
		{Type: "policy", Name: "Network Policy", Enforced: policies.Policy},
		{Type: "access_control", Name: "Access Control", Enforced: policies.AccessControl},
	}

	return EvidencePack{
		Framework:   framework,
		TenantID:    tenantID,
		GeneratedAt: generatedAt,
		Controls:    score.Controls,
		Policies:    policyEvidence,
	}
}

// Get retrieves a compliance report by ID.
func (s *ReportService) Get(ctx context.Context, tenantID, id uuid.UUID) (ComplianceReport, error) {
	r, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return ComplianceReport{}, err
	}
	return s.fromRepoReport(r), nil
}

// List returns paginated compliance reports for a tenant.
func (s *ReportService) List(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[ComplianceReport], error) {
	result, err := s.repo.List(ctx, tenantID, page)
	if err != nil {
		return repository.PageResult[ComplianceReport]{}, err
	}
	items := make([]ComplianceReport, len(result.Items))
	for i, r := range result.Items {
		items[i] = s.fromRepoReport(r)
	}
	return repository.PageResult[ComplianceReport]{Items: items, NextCursor: result.NextCursor}, nil
}

// GetEvidence returns the evidence pack for a report.
func (s *ReportService) GetEvidence(ctx context.Context, tenantID, id uuid.UUID) (json.RawMessage, error) {
	r, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	return r.EvidencePack, nil
}

func (s *ReportService) fromRepoReport(r repository.ComplianceReport) ComplianceReport {
	var controls []ControlStatus
	if len(r.Controls) > 0 {
		if err := json.Unmarshal(r.Controls, &controls); err != nil {
			s.logger.Warn("failed to unmarshal compliance controls", "report_id", r.ID, "error", err)
		}
	}
	return ComplianceReport{
		ID:           r.ID,
		TenantID:     r.TenantID,
		Framework:    ComplianceFramework(r.Framework),
		Score:        r.Score,
		MaxScore:     r.MaxScore,
		Controls:     controls,
		EvidencePack: r.EvidencePack,
		GeneratedAt:  r.GeneratedAt,
		CreatedAt:    r.CreatedAt,
	}
}

func cloneControls(src []ControlStatus) []ControlStatus {
	out := make([]ControlStatus, len(src))
	for i, c := range src {
		out[i] = ControlStatus{
			ControlID:   c.ControlID,
			Description: c.Description,
			Status:      c.Status,
			Evidence:    append([]string{}, c.Evidence...),
		}
	}
	return out
}
