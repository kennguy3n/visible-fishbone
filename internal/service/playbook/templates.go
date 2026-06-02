package playbook

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
)

// Template is a pre-built playbook template that can be cloned per tenant.
type Template struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Description      string         `json:"description"`
	TriggerCondition string         `json:"trigger_condition"`
	Steps            []PlaybookStep `json:"steps"`
}

// BuiltinTemplates defines the pre-built playbook templates.
var BuiltinTemplates = []Template{
	{
		ID:               "compromised_device",
		Name:             "Compromised Device Response",
		Description:      "Isolate device, revoke certificates, notify SOC, and create incident ticket",
		TriggerCondition: "device.compromised",
		Steps: []PlaybookStep{
			{Order: 1, Type: StepIsolate, Config: json.RawMessage(`{"reason":"compromised device detected"}`), TimeoutSeconds: 30},
			{Order: 2, Type: StepRevokeAccess, Config: json.RawMessage(`{"reason":"compromised device - revoke all access"}`), TimeoutSeconds: 30},
			{Order: 3, Type: StepNotify, Config: json.RawMessage(`{"channel":"webhook","message":"Compromised device detected and isolated","target":"soc"}`), TimeoutSeconds: 15},
			{Order: 4, Type: StepCreateTicket, Config: json.RawMessage(`{"title":"Compromised Device Incident","description":"Device has been isolated and certificates revoked","priority":"critical"}`), TimeoutSeconds: 30},
		},
	},
	{
		ID:               "brute_force",
		Name:             "Brute Force Response",
		Description:      "Block source IP, notify security team, and create incident ticket",
		TriggerCondition: "auth.brute_force",
		Steps: []PlaybookStep{
			{Order: 1, Type: StepBlockIP, Config: json.RawMessage(`{"duration":"24h","reason":"brute force detected"}`), TimeoutSeconds: 15},
			{Order: 2, Type: StepNotify, Config: json.RawMessage(`{"channel":"webhook","message":"Brute force attack detected and source IP blocked","target":"security"}`), TimeoutSeconds: 15},
			{Order: 3, Type: StepCreateTicket, Config: json.RawMessage(`{"title":"Brute Force Attack","description":"Source IP has been blocked for 24h","priority":"high"}`), TimeoutSeconds: 30},
		},
	},
	{
		ID:               "dlp_violation",
		Name:             "DLP Violation Response",
		Description:      "Quarantine file, notify DLP team, and create incident ticket",
		TriggerCondition: "dlp.violation",
		Steps: []PlaybookStep{
			{Order: 1, Type: StepQuarantine, Config: json.RawMessage(`{"reason":"DLP policy violation"}`), TimeoutSeconds: 30},
			{Order: 2, Type: StepNotify, Config: json.RawMessage(`{"channel":"webhook","message":"DLP violation detected - file quarantined","target":"dlp-team"}`), TimeoutSeconds: 15},
			{Order: 3, Type: StepCreateTicket, Config: json.RawMessage(`{"title":"DLP Violation","description":"Sensitive data detected and quarantined","priority":"high"}`), TimeoutSeconds: 30},
		},
	},
	{
		ID:               "anomalous_dns",
		Name:             "Anomalous DNS Response",
		Description:      "Block domain, isolate device, and notify security",
		TriggerCondition: "dns.anomaly",
		Steps: []PlaybookStep{
			{Order: 1, Type: StepBlockIP, Config: json.RawMessage(`{"duration":"48h","reason":"anomalous DNS activity"}`), TimeoutSeconds: 15},
			{Order: 2, Type: StepIsolate, Config: json.RawMessage(`{"reason":"anomalous DNS - potential C2"}`), TimeoutSeconds: 30},
			{Order: 3, Type: StepNotify, Config: json.RawMessage(`{"channel":"webhook","message":"Anomalous DNS detected - device isolated and domain blocked","target":"security"}`), TimeoutSeconds: 15},
		},
	},
	{
		ID:               "failed_posture",
		Name:             "Failed Posture Check Response",
		Description:      "Restrict access, notify device owner, and create remediation ticket",
		TriggerCondition: "posture.failed",
		Steps: []PlaybookStep{
			{Order: 1, Type: StepPolicyUpdate, Config: json.RawMessage(`{"action":"restrict","scope":"device","reason":"failed posture check"}`), TimeoutSeconds: 30},
			{Order: 2, Type: StepNotify, Config: json.RawMessage(`{"channel":"email","message":"Your device failed a security posture check. Access has been restricted until remediation.","target":"device-owner"}`), TimeoutSeconds: 15},
			{Order: 3, Type: StepCreateTicket, Config: json.RawMessage(`{"title":"Failed Posture Check","description":"Device access restricted pending remediation","priority":"medium"}`), TimeoutSeconds: 30},
		},
	},
}

// GetTemplates returns all available playbook templates.
func GetTemplates() []Template {
	out := make([]Template, len(BuiltinTemplates))
	copy(out, BuiltinTemplates)
	return out
}

// GetTemplate returns a specific template by ID.
func GetTemplate(id string) (Template, bool) {
	for _, t := range BuiltinTemplates {
		if t.ID == id {
			return t, true
		}
	}
	return Template{}, false
}

// CloneTemplate creates a tenant-specific playbook from a template.
func CloneTemplate(tenantID uuid.UUID, tmpl Template) repository.Playbook {
	steps, _ := json.Marshal(tmpl.Steps)
	now := time.Now().UTC()
	return repository.Playbook{
		ID:               uuid.New(),
		TenantID:         tenantID,
		Name:             tmpl.Name,
		Description:      tmpl.Description,
		TriggerCondition: tmpl.TriggerCondition,
		Steps:            steps,
		Enabled:          true,
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}
