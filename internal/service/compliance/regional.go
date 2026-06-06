package compliance

// Regional framework control catalogs (Session 2C).
//
// These extend the global frameworkControlMap / policyControlMapping
// defined in report.go rather than forking the report pipeline: a
// regional report is generated, scored, and evidence-packed by exactly
// the same ReportService.Generate path. Only the control catalog and
// the policy→control mapping differ per regulation.
//
// Control IDs reference the actual regulatory instruments so the
// generated evidence packs are auditor-meaningful:
//   - PDPA   : Singapore PDPA 2012 obligations (shared with TH/MY PDPA).
//   - NESA   : UAE Information Assurance Standard controls (T*/M*).
//   - nDSG   : Swiss revised FADP (nFADP) articles, FDPIC-enforced.
//   - GDPR   : EU GDPR articles + German BDSG sections.
//   - CSA CE : Singapore CSA Cyber Essentials measures.
//
// The five SNG policy primitives (dlp, browser, casb, policy,
// access_control) are mapped to the controls they provide evidence
// for. A control with no mapped, enforced policy stays "unmet", which
// is the correct fail-closed default for an unproven control.
var regionalControlCatalog = map[ComplianceFramework][]ControlStatus{
	FrameworkPDPA: {
		{ControlID: "PDPA-Protection", Description: "Protection Obligation — reasonable security arrangements to protect personal data", Status: ControlUnmet},
		{ControlID: "PDPA-Transfer", Description: "Transfer Limitation Obligation — comparable protection for cross-border transfers", Status: ControlUnmet},
		{ControlID: "PDPA-Retention", Description: "Retention Limitation Obligation — cease retention when purpose served", Status: ControlUnmet},
		{ControlID: "PDPA-Access", Description: "Access and Correction Obligation — provide access to and correction of personal data", Status: ControlUnmet},
		{ControlID: "PDPA-Consent", Description: "Consent Obligation — collect, use, disclose only with valid consent", Status: ControlUnmet},
		{ControlID: "PDPA-Purpose", Description: "Purpose Limitation Obligation — purposes a reasonable person considers appropriate", Status: ControlUnmet},
		{ControlID: "PDPA-Accountability", Description: "Accountability Obligation — designate a DPO and document policies", Status: ControlUnmet},
		{ControlID: "PDPA-Breach", Description: "Data Breach Notification Obligation — assess and notify the PDPC/affected individuals", Status: ControlUnmet},
	},
	FrameworkNESA: {
		{ControlID: "NESA-T1.2.1", Description: "Asset Management — inventory and ownership of information assets", Status: ControlUnmet},
		{ControlID: "NESA-T2.3.1", Description: "Access Control — logical access management and least privilege", Status: ControlUnmet},
		{ControlID: "NESA-T3.4.1", Description: "Cryptography — protection of data in transit and at rest", Status: ControlUnmet},
		{ControlID: "NESA-T5.5.1", Description: "Communications Security — network segmentation and protection", Status: ControlUnmet},
		{ControlID: "NESA-T7.6.1", Description: "Security Monitoring — logging and continuous monitoring", Status: ControlUnmet},
		{ControlID: "NESA-M1.1.1", Description: "Risk Management — risk assessment and treatment", Status: ControlUnmet},
		{ControlID: "NESA-M5.2.1", Description: "Incident Management — detection, response and reporting", Status: ControlUnmet},
		{ControlID: "NESA-T4.7.1", Description: "Data Residency — keep regulated data within UAE jurisdiction", Status: ControlUnmet},
	},
	FrameworkNDSG: {
		{ControlID: "nDSG-Art7", Description: "Privacy by Design and by Default (Art. 7 nFADP)", Status: ControlUnmet},
		{ControlID: "nDSG-Art8", Description: "Data Security — appropriate technical and organisational measures (Art. 8)", Status: ControlUnmet},
		{ControlID: "nDSG-Art6", Description: "Lawfulness, good faith and proportionality of processing (Art. 6)", Status: ControlUnmet},
		{ControlID: "nDSG-Art16", Description: "Cross-border disclosure to states with adequate protection (Art. 16)", Status: ControlUnmet},
		{ControlID: "nDSG-Art19", Description: "Duty to inform on collection of personal data (Art. 19)", Status: ControlUnmet},
		{ControlID: "nDSG-Art25", Description: "Right of access by the data subject (Art. 25)", Status: ControlUnmet},
		{ControlID: "nDSG-Art24", Description: "Notification of data security breaches to the FDPIC (Art. 24)", Status: ControlUnmet},
		{ControlID: "nDSG-Art12", Description: "Records of processing activities (Art. 12)", Status: ControlUnmet},
	},
	FrameworkBDSG: {
		{ControlID: "GDPR-Art5", Description: "Principles relating to processing of personal data (Art. 5)", Status: ControlUnmet},
		{ControlID: "GDPR-Art25", Description: "Data protection by design and by default (Art. 25)", Status: ControlUnmet},
		{ControlID: "GDPR-Art32", Description: "Security of processing (Art. 32)", Status: ControlUnmet},
		{ControlID: "GDPR-Art30", Description: "Records of processing activities (Art. 30)", Status: ControlUnmet},
		{ControlID: "GDPR-Art33", Description: "Notification of a personal data breach to the supervisory authority (Art. 33)", Status: ControlUnmet},
		{ControlID: "GDPR-Art15", Description: "Right of access by the data subject (Art. 15)", Status: ControlUnmet},
		{ControlID: "GDPR-Art44", Description: "General principle for transfers of personal data (Art. 44)", Status: ControlUnmet},
		{ControlID: "BDSG-§26", Description: "Processing of employee personal data (BDSG §26)", Status: ControlUnmet},
		{ControlID: "BDSG-§38", Description: "Designation of a data protection officer (BDSG §38)", Status: ControlUnmet},
	},
	FrameworkCSACE: {
		{ControlID: "CE-Assets-People", Description: "Assets: People — security awareness for employees", Status: ControlUnmet},
		{ControlID: "CE-Assets-HW-SW", Description: "Assets: Hardware and software — maintain an asset inventory", Status: ControlUnmet},
		{ControlID: "CE-Assets-Data", Description: "Assets: Data — know and protect the data the organisation has", Status: ControlUnmet},
		{ControlID: "CE-Secure-Config", Description: "Secure/Protect: Secure configuration of hardware and software", Status: ControlUnmet},
		{ControlID: "CE-Access-Control", Description: "Secure/Protect: Access control — manage user accounts and privileges", Status: ControlUnmet},
		{ControlID: "CE-Malware", Description: "Secure/Protect: Antivirus / anti-malware protection", Status: ControlUnmet},
		{ControlID: "CE-Update", Description: "Update: Software updates and patch management", Status: ControlUnmet},
		{ControlID: "CE-Respond", Description: "Respond: Incident response readiness", Status: ControlUnmet},
	},
}

// regionalPolicyMapping maps each SNG policy primitive to the regional
// controls for which its enforcement is evidence. Mirrors the shape of
// policyControlMapping in report.go.
var regionalPolicyMapping = map[string]map[ComplianceFramework][]string{
	"dlp": {
		FrameworkPDPA:  {"PDPA-Protection", "PDPA-Transfer"},
		FrameworkNESA:  {"NESA-T3.4.1", "NESA-T4.7.1"},
		FrameworkNDSG:  {"nDSG-Art8", "nDSG-Art16"},
		FrameworkBDSG:  {"GDPR-Art32", "GDPR-Art44"},
		FrameworkCSACE: {"CE-Assets-Data"},
	},
	"browser": {
		FrameworkPDPA:  {"PDPA-Purpose"},
		FrameworkNESA:  {"NESA-T1.2.1"},
		FrameworkNDSG:  {"nDSG-Art7"},
		FrameworkBDSG:  {"GDPR-Art25"},
		FrameworkCSACE: {"CE-Secure-Config", "CE-Malware"},
	},
	"casb": {
		FrameworkPDPA:  {"PDPA-Breach"},
		FrameworkNESA:  {"NESA-T7.6.1", "NESA-M5.2.1"},
		FrameworkNDSG:  {"nDSG-Art24"},
		FrameworkBDSG:  {"GDPR-Art33"},
		FrameworkCSACE: {"CE-Respond"},
	},
	"policy": {
		FrameworkPDPA:  {"PDPA-Accountability", "PDPA-Retention"},
		FrameworkNESA:  {"NESA-M1.1.1"},
		FrameworkNDSG:  {"nDSG-Art6", "nDSG-Art12"},
		FrameworkBDSG:  {"GDPR-Art5", "GDPR-Art30", "BDSG-§38"},
		FrameworkCSACE: {"CE-Assets-HW-SW", "CE-Update"},
	},
	"access_control": {
		FrameworkPDPA:  {"PDPA-Consent", "PDPA-Access"},
		FrameworkNESA:  {"NESA-T2.3.1", "NESA-T5.5.1"},
		FrameworkNDSG:  {"nDSG-Art19", "nDSG-Art25"},
		FrameworkBDSG:  {"GDPR-Art15", "BDSG-§26"},
		FrameworkCSACE: {"CE-Assets-People", "CE-Access-Control"},
	},
}

// init merges the regional catalogs into the global maps used by
// ReportService so regional frameworks flow through the unchanged
// Generate/score/evidence pipeline. Run-once at package load; the
// global maps are already initialized (package-level var literals run
// before init).
func init() {
	for fw, controls := range regionalControlCatalog {
		frameworkControlMap[fw] = controls
	}
	for policyType, byFramework := range regionalPolicyMapping {
		dst, ok := policyControlMapping[policyType]
		if !ok {
			dst = map[ComplianceFramework][]string{}
			policyControlMapping[policyType] = dst
		}
		for fw, ids := range byFramework {
			dst[fw] = ids
		}
	}
}
