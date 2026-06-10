// Command seed populates a local ShieldNet Gateway control plane with a
// realistic multi-tenant + MSP dataset for the executive blog scenarios.
//
// It drives the *real* operator API (the same endpoints the admin console
// calls), so every row it creates flows through policy compilation, RLS,
// and the audit log exactly as a real operator action would. Detection
// efficacy / throughput numbers are produced separately by the Rust
// harnesses in bench/ and bench/efficacy/ — this tool only seeds the
// console-visible business data (tenants, sites, devices, policies, etc.).
//
// Auth: mints a short-lived global platform-admin JWT (HS256) signed with
// AUTH_JWT_SECRET. A token with no tenant_id claim is treated as global by
// the control plane's tenant middleware, so it can act on any tenant.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	apiBase  = flag.String("api", "http://127.0.0.1:8080", "control-plane base URL")
	operator = flag.String("operator", "190fc952-71ff-4ad5-a0fa-68b78ec39fca", "operator user UUID (sub claim)")
	verbose  = flag.Bool("v", false, "verbose request logging")
)

var token string

func main() {
	flag.Parse()
	secret := os.Getenv("AUTH_JWT_SECRET")
	if secret == "" {
		fatal("AUTH_JWT_SECRET is unset")
	}
	token = mintGlobalAdminJWT(secret, *operator)

	// Provision the platform RBAC grant and canonical fixture identities
	// the API-driven seed cannot create for itself (see bootstrap.go), so
	// a fresh, freshly-migrated database reproduces the same dataset.
	if err := bootstrapFixtures(context.Background(), *operator); err != nil {
		fatal("bootstrap: " + err.Error())
	}

	existing := loadTenantsBySlug()

	summary := map[string]any{}
	var tenantSummaries []map[string]any

	msp := ensureMSP("Northwind Managed Security", "northwind-msp")
	summary["msp"] = msp

	for _, t := range scenarioTenants() {
		tid := existing[t.slug]
		if tid == "" {
			tid = createTenant(t)
		} else {
			logf("tenant %s already exists (%s) — reusing", t.slug, tid)
		}
		if tid == "" {
			continue
		}
		if msp != "" {
			assignTenantToMSP(msp, tid, t.relationship)
		}
		ts := seedTenant(tid, t)
		ts["id"] = tid
		ts["name"] = t.name
		ts["slug"] = t.slug
		tenantSummaries = append(tenantSummaries, ts)
	}
	summary["tenants"] = tenantSummaries

	out, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(out))
	_ = os.WriteFile("blog/artifacts/seed-summary.json", out, 0o600)
}

// --- scenario data model ---------------------------------------------------

type tenantSpec struct {
	name         string
	slug         string
	region       string
	tier         string
	relationship string // owner | co_manager
	sites        []siteSpec
	devices      []deviceSpec
	dlpTemplates []string // template ids to apply (pci-dss, hipaa, ...)
	browser      []browserSpec
	casb         []casbSpec
	health       int
	components   map[string]int
	integrations []integrationSpec
	playbooks    []playbookSpec
}

type siteSpec struct {
	name, template string
}
type deviceSpec struct {
	name, platform string
	posture        map[string]any
}
type browserSpec struct {
	name, category, action, scope string
}
type casbSpec struct {
	typ, name string
}
type integrationSpec struct {
	typ, name string
}
type playbookSpec struct {
	name        string
	description string
	trigger     string
	steps       []map[string]any
	enabled     bool
}

func scenarioTenants() []tenantSpec {
	return []tenantSpec{
		{
			name: "Acme Retail Group", slug: "acme-retail", region: "us-east",
			tier: "enterprise", relationship: "owner",
			sites: []siteSpec{
				{"Acme HQ — Dallas", "hub"},
				{"Distribution Center — Memphis", "hub"},
				{"Store #118 — Austin", "branch"},
				{"Store #204 — Houston", "branch"},
				{"Store #311 — San Antonio", "branch"},
				{"E-commerce Cloud VPC", "cloud_only"},
			},
			devices: []deviceSpec{
				{"acme-pos-118-01", "linux", map[string]any{"disk_encrypted": true, "firewall_enabled": true}},
				{"acme-pos-204-01", "linux", map[string]any{"disk_encrypted": true, "firewall_enabled": true}},
				{"acme-mgr-laptop-01", "windows", map[string]any{"disk_encrypted": true}},
				{"acme-mgr-laptop-02", "macos", map[string]any{"disk_encrypted": true}},
			},
			dlpTemplates: []string{"pci-dss"},
			browser: []browserSpec{
				{"Block gambling at stores", "gambling", "block", "site"},
				{"Isolate uncategorized sites", "uncategorized", "rbi", "group"},
			},
			casb:   []casbSpec{{"m365", "Acme Microsoft 365"}, {"slack", "Acme Slack"}},
			health: 88, components: map[string]int{"policy": 92, "posture": 85, "patch": 84, "identity": 90},
			integrations: []integrationSpec{{"siem_webhook", "Acme Splunk HEC"}},
			playbooks: []playbookSpec{
				{
					name:        "Contain malware-flagged POS endpoint",
					description: "Isolate a point-of-sale device when the edge raises a critical malware verdict, then notify the SOC and open a ticket.",
					trigger:     "alert.severity == 'critical' && alert.category == 'malware'",
					steps: []map[string]any{
						{"action": "isolate_device", "target": "alert.device_id"},
						{"action": "notify", "channel": "soc", "severity": "critical"},
						{"action": "open_ticket", "system": "splunk", "priority": "P1"},
					},
					enabled: true,
				},
				{
					name:        "Quarantine PCI cardholder-data exfil",
					description: "Block an outbound transfer that trips the PCI-DSS DLP classifier and require an analyst sign-off before release.",
					trigger:     "dlp.violation && dlp.template == 'pci-dss'",
					steps: []map[string]any{
						{"action": "block_transfer"},
						{"action": "require_approval", "role": "security_admin"},
						{"action": "notify", "channel": "soc"},
					},
					enabled: true,
				},
			},
		},
		{
			name: "Globex Health Systems", slug: "globex-health", region: "us-west",
			tier: "enterprise", relationship: "owner",
			sites: []siteSpec{
				{"Globex Main Hospital — Seattle", "hub"},
				{"Outpatient Clinic — Bellevue", "branch"},
				{"Outpatient Clinic — Tacoma", "branch"},
				{"Imaging Center — Everett", "branch"},
				{"EHR Cloud (HIPAA)", "cloud_only"},
			},
			devices: []deviceSpec{
				{"globex-clin-ws-01", "windows", map[string]any{"disk_encrypted": true, "screen_lock": true}},
				{"globex-clin-ws-02", "windows", map[string]any{"disk_encrypted": true, "screen_lock": true}},
				{"globex-radiology-01", "linux", map[string]any{"disk_encrypted": true, "firewall_enabled": true}},
				{"globex-nurse-ipad-01", "ios", map[string]any{"disk_encrypted": true, "mdm_enrolled": true}},
			},
			dlpTemplates: []string{"hipaa", "pci-dss"},
			browser: []browserSpec{
				{"Isolate webmail (PHI exfil)", "webmail", "rbi", "group"},
				{"Block file-sharing", "file_sharing", "block", "group"},
			},
			casb:   []casbSpec{{"google", "Globex Google Workspace"}, {"m365", "Globex Microsoft 365"}},
			health: 81, components: map[string]int{"policy": 88, "posture": 78, "patch": 72, "identity": 86},
			integrations: []integrationSpec{{"servicenow", "Globex ServiceNow ITSM"}},
			playbooks: []playbookSpec{
				{
					name:        "Isolate PHI exfil over webmail",
					description: "Route the session to remote browser isolation when the PHI classifier fires on a webmail upload, then alert the privacy officer.",
					trigger:     "dlp.violation && dlp.classifier == 'phi' && app.category == 'webmail'",
					steps: []map[string]any{
						{"action": "isolate_browser", "mode": "rbi"},
						{"action": "notify", "channel": "privacy_officer", "severity": "high"},
						{"action": "open_ticket", "system": "servicenow", "priority": "P2"},
					},
					enabled: true,
				},
				{
					name:        "Revoke access on impossible travel",
					description: "Step up to re-authentication and revoke the active ZTNA session when an impossible-travel anomaly is detected for a clinician identity.",
					trigger:     "alert.type == 'impossible_travel'",
					steps: []map[string]any{
						{"action": "revoke_session", "target": "alert.user_id"},
						{"action": "require_approval", "role": "security_admin"},
						{"action": "notify", "channel": "soc"},
					},
					enabled: false,
				},
			},
		},
		{
			name: "Initech Financial", slug: "initech-financial", region: "eu-central",
			tier: "professional", relationship: "co_manager",
			sites: []siteSpec{
				{"Initech HQ — Frankfurt", "hub"},
				{"Trading Floor — London", "branch"},
				{"Back Office — Dublin", "home_office"},
			},
			devices: []deviceSpec{
				{"initech-trader-01", "windows", map[string]any{"disk_encrypted": true}},
				{"initech-trader-02", "windows", map[string]any{"disk_encrypted": true}},
				{"initech-analyst-mbp", "macos", map[string]any{"disk_encrypted": true}},
			},
			dlpTemplates: []string{"pci-dss"},
			browser: []browserSpec{
				{"Isolate all external browsing", "uncategorized", "rbi", "group"},
				{"Block social media (insider risk)", "social_media", "block", "group"},
			},
			casb:   []casbSpec{{"salesforce", "Initech Salesforce"}, {"m365", "Initech Microsoft 365"}},
			health: 76, components: map[string]int{"policy": 80, "posture": 74, "patch": 70, "identity": 82},
			integrations: []integrationSpec{{"jira", "Initech Jira SecOps"}},
			playbooks: []playbookSpec{
				{
					name:        "Throttle anomalous URL-category surge",
					description: "Open a SecOps ticket and notify the cost owner when a tenant's URL-category lookup run rate exceeds 2x its trailing baseline.",
					trigger:     "anomaly.meter == 'url_cat_lookups' && anomaly.ratio > 2.0",
					steps: []map[string]any{
						{"action": "notify", "channel": "finops", "severity": "warning"},
						{"action": "open_ticket", "system": "jira", "priority": "P3"},
					},
					enabled: true,
				},
			},
		},
		{
			name: "Umbrella Logistics", slug: "umbrella-logistics", region: "ap-southeast",
			tier: "starter", relationship: "owner",
			sites: []siteSpec{
				{"Umbrella HQ — Singapore", "hub"},
				{"Warehouse — Jakarta", "branch"},
			},
			devices: []deviceSpec{
				{"umbrella-ops-01", "windows", map[string]any{"disk_encrypted": true}},
				{"umbrella-wh-android-01", "android", map[string]any{"mdm_enrolled": true}},
			},
			dlpTemplates: []string{},
			browser:      []browserSpec{{"Block malware/phishing", "malware", "block", "site"}},
			casb:         []casbSpec{{"google", "Umbrella Google Workspace"}},
			health:       69, components: map[string]int{"policy": 64, "posture": 70, "patch": 66, "identity": 75},
			integrations: []integrationSpec{{"syslog", "Umbrella rsyslog"}},
		},
	}
}

// --- seeding steps ---------------------------------------------------------

func seedTenant(tid string, t tenantSpec) map[string]any {
	res := map[string]any{}

	var siteIDs []string
	for _, s := range t.sites {
		if id := createSite(tid, s); id != "" {
			siteIDs = append(siteIDs, id)
		}
	}
	res["sites"] = len(siteIDs)

	enrolled := 0
	for _, d := range t.devices {
		if enrollDevice(tid, d) {
			enrolled++
		}
	}
	res["devices"] = enrolled

	dlp := 0
	for _, tmpl := range t.dlpTemplates {
		if applyDLPTemplate(tid, tmpl) {
			dlp++
		}
	}
	res["dlp_policies"] = dlp

	br := 0
	for _, b := range t.browser {
		if createBrowserPolicy(tid, b) {
			br++
		}
	}
	res["browser_policies"] = br

	casb := 0
	for _, c := range t.casb {
		if createCASBConnector(tid, c) {
			casb++
		}
	}
	res["casb_connectors"] = casb

	intg := 0
	for _, ig := range t.integrations {
		if createIntegration(tid, ig) {
			intg++
		}
	}
	res["integrations"] = intg

	res["policy_rules"] = seedPolicyGraph(tid)
	res["casb_inline_rules"] = seedInlineCASBRules(tid)
	res["compliance_reports"] = seedComplianceReport(tid)

	pb := 0
	for _, p := range t.playbooks {
		if createPlaybook(tid, p) {
			pb++
		}
	}
	res["playbooks"] = pb

	if recordOpsHealth(tid, t.health, t.components) {
		res["ops_health"] = t.health
	}

	createAPIKey(tid, "edge-bootstrap", "svc:edge")
	createWebhook(tid, "https://hooks.example.com/sng/"+t.slug, []string{"alert.created", "dlp.violation", "device.enrolled"})

	// Overwrite the per-run create tallies with authoritative server-side
	// counts so the summary reflects the true present state (idempotent
	// reruns create nothing new but the dataset is still fully populated).
	res["sites"] = listCount(tid, "sites")
	res["devices"] = listCount(tid, "devices")
	res["dlp_policies"] = listCount(tid, "dlp/policies")
	res["browser_policies"] = listCount(tid, "browser-policies")
	res["casb_connectors"] = listCount(tid, "casb/connectors")
	res["integrations"] = listCount(tid, "integrations")
	res["playbooks"] = listCount(tid, "playbooks")

	return res
}

// createPlaybook publishes one automated-response playbook. It is
// idempotent across reruns: playbook names are unique per tenant, so a
// name that already exists is skipped rather than duplicated.
func createPlaybook(tid string, p playbookSpec) bool {
	if namedItemExists(tid, "playbooks", "name", p.name) {
		return false
	}
	steps, _ := json.Marshal(p.steps)
	body := map[string]any{
		"name":              p.name,
		"description":       p.description,
		"trigger_condition": p.trigger,
		"steps":             json.RawMessage(steps),
		"enabled":           p.enabled,
	}
	return doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/playbooks", tid), body, nil)
}

func createTenant(t tenantSpec) string {
	body := map[string]any{"name": t.name, "slug": t.slug, "region": t.region, "tier": t.tier}
	var out struct {
		ID string `json:"id"`
	}
	if doJSON("POST", "/api/v1/tenants", body, &out) {
		logf("created tenant %s -> %s", t.slug, out.ID)
		return out.ID
	}
	return ""
}

func ensureMSP(name, slug string) string {
	// list existing
	var list struct {
		Items []struct {
			ID, Slug string
		} `json:"items"`
	}
	if doJSON("GET", "/api/v1/msps", nil, &list) {
		for _, m := range list.Items {
			if m.Slug == slug {
				logf("MSP %s already exists (%s)", slug, m.ID)
				return m.ID
			}
		}
	}
	body := map[string]any{"name": name, "slug": slug, "status": "active"}
	var out struct {
		ID string `json:"id"`
	}
	if doJSON("POST", "/api/v1/msps", body, &out) {
		logf("created MSP %s -> %s", slug, out.ID)
		return out.ID
	}
	return ""
}

func assignTenantToMSP(msp, tid, rel string) {
	if rel == "" {
		rel = "owner"
	}
	body := map[string]any{"relationship": rel}
	if doJSON("POST", fmt.Sprintf("/api/v1/msps/%s/tenants/%s", msp, tid), body, nil) {
		logf("assigned tenant %s to MSP %s (%s)", tid, msp, rel)
	}
}

func createSite(tid string, s siteSpec) string {
	body := map[string]any{"name": s.name, "template": s.template}
	var out struct {
		ID string `json:"id"`
	}
	if doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/sites", tid), body, &out) {
		return out.ID
	}
	return ""
}

func enrollDevice(tid string, d deviceSpec) bool {
	// Idempotency: device uniqueness is keyed on the ed25519 public key,
	// but each run generates a fresh keypair, so enrolling the same logical
	// device again would create a duplicate row. Guard on the operator-facing
	// device name instead and skip if it is already enrolled.
	if deviceExists(tid, d.name) {
		if *verbose {
			logf("EXISTS device %s/%s", tid, d.name)
		}
		return false
	}
	// 1. mint a claim token
	var ct struct {
		Token string `json:"token"`
	}
	if !doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/claim-tokens", tid), map[string]any{"ttl_seconds": 3600}, &ct) {
		return false
	}
	// 2. generate an ed25519 keypair; the agent keeps the private key.
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return false
	}
	body := map[string]any{
		"claim_token":        ct.Token,
		"name":               d.name,
		"platform":           d.platform,
		"public_key_ed25519": base64.StdEncoding.EncodeToString(pub),
		"posture":            d.posture,
	}
	return doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/devices/enroll", tid), body, nil)
}

func deviceExists(tid, name string) bool {
	var list struct {
		Items []struct {
			Name string `json:"name"`
		} `json:"items"`
	}
	if doJSON("GET", fmt.Sprintf("/api/v1/tenants/%s/devices", tid), nil, &list) {
		for _, it := range list.Items {
			if it.Name == name {
				return true
			}
		}
	}
	return false
}

func applyDLPTemplate(tid, tmpl string) bool {
	// ApplyTemplate creates a fresh DLP policy named after the template's
	// display name on every call (no server-side dedup), so re-running the
	// seed would stack duplicate policies. Resolve the template's display
	// name and skip if a policy with that name is already present.
	if name := dlpTemplateName(tid, tmpl); name != "" && namedItemExists(tid, "dlp/policies", "name", name) {
		if *verbose {
			logf("EXISTS dlp policy %q (template %s)", name, tmpl)
		}
		return false
	}
	return doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/dlp/templates/%s/apply", tid, tmpl), map[string]any{}, nil)
}

// dlpTemplateName resolves a DLP template ID to the policy display name the
// control plane assigns when the template is applied.
func dlpTemplateName(tid, templateID string) string {
	var list struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	if doJSON("GET", fmt.Sprintf("/api/v1/tenants/%s/dlp/templates", tid), nil, &list) {
		for _, it := range list.Items {
			if it.ID == templateID {
				return it.Name
			}
		}
	}
	return ""
}

func createBrowserPolicy(tid string, b browserSpec) bool {
	enabled := true
	body := map[string]any{
		"name":   b.name,
		"action": b.action,
		"scope":  b.scope,
		"rules": []map[string]any{
			{"type": "url_category", "condition": b.category, "action": b.action},
		},
		"enabled": &enabled,
	}
	return doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/browser-policies", tid), body, nil)
}

func createCASBConnector(tid string, c casbSpec) bool {
	body := map[string]any{"type": c.typ, "name": c.name, "config": map[string]any{}}
	return doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/casb/connectors", tid), body, nil)
}

func createIntegration(tid string, ig integrationSpec) bool {
	body := map[string]any{"type": ig.typ, "name": ig.name, "config": map[string]any{}}
	return doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/integrations", tid), body, nil)
}

func recordOpsHealth(tid string, score int, components map[string]int) bool {
	body := map[string]any{"health_score": score, "component_scores": components}
	return doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/ops/health", tid), body, nil)
}

// inlineCASBRule is one seeded inline-CASB rule. app_id must be one of
// the service's knownApps (m365, google_workspace, slack, salesforce,
// or "any"); action ∈ {upload,download,share,delete}; verdict ∈
// {allow,block,log}.
type inlineCASBRule struct {
	appID      string
	action     string
	verdict    string
	priority   int32
	conditions map[string]any
}

// seedInlineCASBRules publishes a small inline-CASB ruleset (real
// SaaS-tenant DLP-at-the-edge controls) for the tenant. Idempotent: a
// rerun that finds rules already present creates none. Returns the
// authoritative server-side count.
func seedInlineCASBRules(tid string) int {
	rules := []inlineCASBRule{
		{"m365", "share", "block", 10, map[string]any{"label_match": "confidential"}},
		{"m365", "upload", "log", 20, map[string]any{"size_threshold": 10_000_000}},
		{"salesforce", "download", "block", 30, map[string]any{"file_type": "csv"}},
		{"google_workspace", "share", "log", 40, map[string]any{}},
	}
	if listCount(tid, "casb/inline-rules") == 0 {
		for _, r := range rules {
			enabled := true
			body := map[string]any{
				"app_id":     r.appID,
				"action":     r.action,
				"verdict":    r.verdict,
				"priority":   r.priority,
				"enabled":    &enabled,
				"conditions": r.conditions,
			}
			doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/casb/inline-rules", tid), body, nil)
		}
	}
	return listCount(tid, "casb/inline-rules")
}

// seedComplianceReport generates one SOC2 compliance report spanning
// every control surface (DLP, browser, CASB, policy, access control) so
// the S7 "prove the posture to the board" scenario has a real,
// evidence-linked report to show. Idempotent: skips when a report
// already exists. Returns the authoritative server-side count.
func seedComplianceReport(tid string) int {
	var existing struct {
		Items []json.RawMessage `json:"items"`
	}
	doJSON("GET", fmt.Sprintf("/api/v1/tenants/%s/compliance/reports", tid), nil, &existing)
	if len(existing.Items) == 0 {
		body := map[string]any{
			"framework":      "SOC2",
			"dlp":            true,
			"browser":        true,
			"casb":           true,
			"policy":         true,
			"access_control": true,
		}
		doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/compliance/reports/generate", tid), body, nil)
		doJSON("GET", fmt.Sprintf("/api/v1/tenants/%s/compliance/reports", tid), nil, &existing)
	}
	return len(existing.Items)
}

// scenarioPolicyGraph is the unified policy graph published for every
// tenant. It is the centrepiece of the "one typed policy graph lights
// up NGFW + SWG + DNS + ZTNA + SD-WAN + DLP + inline-CASB" scenario:
// a single document the compiler fans out into per-target bundles.
//
// It carries three things:
//   - `rules`: the ordered, typed enforcement rules the compiler and
//     the Simple-mode "who → can do what → to where" list consume.
//     Two rules are `suggest_only` — proposed-but-not-enforcing
//     ("dormant") deltas, so coverage is intentionally < 100%.
//   - `subjects`/`predicates`: named vertices the rules reference.
//   - `nodes`/`edges`: a presentation projection the React-Flow graph
//     view renders. The Go validator ignores these extra top-level
//     fields and PutGraph preserves them verbatim.
func scenarioPolicyGraph() map[string]any {
	return map[string]any{
		"default_action": "deny",
		"subjects": []map[string]any{
			{"name": "corp-users", "kind": "user"},
			{"name": "managed-devices", "kind": "device"},
			{"name": "private-apps", "kind": "app"},
			{"name": "branch-sites", "kind": "site"},
			{"name": "guest-net", "kind": "network"},
		},
		"predicates": []map[string]any{
			{"name": "cat-malware"},
			{"name": "cat-gambling"},
			{"name": "geo-sanctioned"},
			{"name": "business-hours"},
			{"name": "saas-m365"},
		},
		"rules": []map[string]any{
			{"id": "ngfw-allow-corp-apps", "domain": "ngfw", "verb": "allow",
				"subject_refs": []string{"corp-users", "private-apps"}, "predicate_refs": []string{"business-hours"},
				"description": "Corp users reach private apps during business hours"},
			{"id": "ngfw-deny-guest-apps", "domain": "ngfw", "verb": "deny",
				"subject_refs": []string{"guest-net", "private-apps"},
				"description":  "Guest network is denied all private-app access"},
			{"id": "swg-decrypt-corp", "domain": "swg", "verb": "decrypt",
				"subject_refs": []string{"corp-users"},
				"description":  "TLS-inspect corp web traffic"},
			{"id": "swg-deny-gambling", "domain": "swg", "verb": "deny",
				"predicate_refs": []string{"cat-gambling"},
				"description":    "Block the gambling URL category"},
			{"id": "dns-deny-malware", "domain": "dns", "verb": "deny",
				"predicate_refs": []string{"cat-malware"},
				"description":    "Sinkhole known-malware domains via DNS"},
			{"id": "ztna-allow-posture", "domain": "ztna", "verb": "allow",
				"subject_refs": []string{"corp-users", "managed-devices", "private-apps"},
				"description":  "ZTNA: posture-checked corp devices reach private apps"},
			{"id": "ztna-deny-geo", "domain": "ztna", "verb": "deny",
				"predicate_refs": []string{"geo-sanctioned"},
				"description":    "Deny access from sanctioned geographies"},
			{"id": "sdwan-steer-saas", "domain": "sdwan", "verb": "steer",
				"predicate_refs": []string{"saas-m365"},
				"description":    "Steer M365 SaaS onto the interactive class"},
			{"id": "dlp-inspect-uploads", "domain": "dlp", "verb": "inspect",
				"subject_refs": []string{"managed-devices"},
				"description":  "Inspect uploads from managed devices for regulated data"},
			{"id": "casb-inspect-m365", "domain": "inline_casb", "verb": "inspect",
				"predicate_refs": []string{"saas-m365"},
				"description":    "Inline-CASB inspection of M365 share/upload actions"},
			// Two dormant (suggest_only) deltas — proposed but not yet
			// enforcing, so the coverage meter reads < 100%.
			{"id": "ngfw-suggest-tls10", "domain": "ngfw", "verb": "suggest_only",
				"subject_refs": []string{"corp-users"},
				"description":  "Proposed: block legacy TLS 1.0 egress"},
			{"id": "dns-suggest-nrd", "domain": "dns", "verb": "suggest_only",
				"description": "Proposed: block newly-registered domains (<30d)"},
		},
		// Presentation projection for the React-Flow graph view.
		"nodes": []map[string]any{
			{"id": "corp-users", "label": "Corp users"},
			{"id": "managed-devices", "label": "Managed devices"},
			{"id": "guest-net", "label": "Guest network"},
			{"id": "private-apps", "label": "Private apps"},
			{"id": "saas-m365", "label": "M365 SaaS"},
			{"id": "ngfw", "label": "NGFW"},
			{"id": "swg", "label": "Secure Web Gateway"},
			{"id": "dns", "label": "DNS security"},
			{"id": "ztna", "label": "ZTNA broker"},
			{"id": "sdwan", "label": "SD-WAN steering"},
			{"id": "dlp", "label": "DLP"},
			{"id": "inline_casb", "label": "Inline CASB"},
		},
		"edges": []map[string]any{
			{"source": "corp-users", "target": "ngfw"},
			{"source": "corp-users", "target": "swg"},
			{"source": "corp-users", "target": "dns"},
			{"source": "corp-users", "target": "ztna"},
			{"source": "managed-devices", "target": "ztna"},
			{"source": "managed-devices", "target": "dlp"},
			{"source": "guest-net", "target": "ngfw"},
			{"source": "ztna", "target": "private-apps"},
			{"source": "saas-m365", "target": "inline_casb"},
			{"source": "saas-m365", "target": "sdwan"},
		},
	}
}

// seedPolicyGraph publishes the scenario policy graph and compiles it
// into signed per-target bundles. Idempotent: if the tenant already
// has a published graph with the expected rule count, it neither
// re-publishes (which would bump the version every run) nor recompiles.
// Returns the number of rules in the tenant's current published graph.
func seedPolicyGraph(tid string) int {
	desired := scenarioPolicyGraph()
	wantRules := len(desired["rules"].([]map[string]any))
	if have := policyGraphRuleCount(tid); have == wantRules {
		if *verbose {
			logf("EXISTS policy graph (%d rules) for %s", have, tid)
		}
		return have
	}
	if !doJSON("PUT", fmt.Sprintf("/api/v1/tenants/%s/policy", tid), desired, nil) {
		return policyGraphRuleCount(tid)
	}
	// Compile the freshly published graph into signed bundles so the
	// policy is live end-to-end (S2 evidence: real compiler output).
	doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/policy/compile", tid), map[string]any{}, nil)
	return policyGraphRuleCount(tid)
}

// policyGraphRuleCount returns the number of rules in the tenant's
// current published policy graph (0 if none / unparseable).
func policyGraphRuleCount(tid string) int {
	var pg struct {
		Graph struct {
			Rules []map[string]any `json:"rules"`
		} `json:"graph"`
	}
	// A tenant that has never published a graph legitimately 404s here;
	// that is the "no policy yet" answer to an existence probe, not a
	// failure, so use the 404-tolerant GET to keep the run output clean
	// (a real route regression on this path still surfaces as FAIL).
	if getOptional(fmt.Sprintf("/api/v1/tenants/%s/policy", tid), &pg) {
		return len(pg.Graph.Rules)
	}
	return 0
}

// getOptional performs a GET that treats 404 as a clean "absent" answer
// (returns false without logging), used for existence probes where the
// resource may not have been created yet. Any other non-2xx is still
// logged as FAIL so genuine route regressions remain visible.
func getOptional(path string, out any) bool {
	req, err := http.NewRequestWithContext(context.Background(), "GET", *apiBase+path, nil)
	if err != nil {
		logf("ERR build GET %s: %v", path, err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logf("ERR GET %s: %v", path, err)
		return false
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out != nil && len(raw) > 0 {
			// A 2xx with a malformed body is a genuine regression, not
			// the benign "absent" case 404 represents — surface it as
			// FAIL rather than silently decoding into a zero-value
			// struct (which would understate the policy-graph rule
			// count without any signal).
			if err := json.Unmarshal(raw, out); err != nil {
				logf("FAIL GET %s: HTTP %d with invalid JSON: %v", path, resp.StatusCode, err)
				return false
			}
		}
		return true
	}
	if resp.StatusCode == http.StatusNotFound {
		return false
	}
	logf("FAIL %d GET %s: %s", resp.StatusCode, path, strings.TrimSpace(string(raw)))
	return false
}

func createAPIKey(tid, name, subject string) {
	// API keys are unique only by hash (random per mint), so guard on the
	// operator-facing name to keep the seed idempotent.
	if namedItemExists(tid, "api-keys", "name", name) {
		return
	}
	body := map[string]any{"name": name, "subject": subject}
	doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/api-keys", tid), body, nil)
}

func createWebhook(tid, url string, events []string) {
	// Webhook endpoints have no uniqueness constraint; guard on the URL so
	// reruns do not register duplicate subscriptions.
	if namedItemExists(tid, "webhooks", "url", url) {
		return
	}
	body := map[string]any{"url": url, "events": events}
	doJSON("POST", fmt.Sprintf("/api/v1/tenants/%s/webhooks", tid), body, nil)
}

// namedItemExists reports whether a tenant-scoped collection already has an
// item whose `field` equals `val`. Used to make creates that lack a natural
// uniqueness constraint idempotent across reruns.
func namedItemExists(tid, sub, field, val string) bool {
	var list struct {
		Items []map[string]any `json:"items"`
	}
	if doJSON("GET", fmt.Sprintf("/api/v1/tenants/%s/%s", tid, sub), nil, &list) {
		for _, it := range list.Items {
			if s, ok := it[field].(string); ok && s == val {
				return true
			}
		}
	}
	return false
}

func loadTenantsBySlug() map[string]string {
	out := map[string]string{}
	var list struct {
		Items []struct{ ID, Slug string } `json:"items"`
	}
	if doJSON("GET", "/api/v1/tenants", nil, &list) {
		for _, t := range list.Items {
			out[t.Slug] = t.ID
		}
	}
	return out
}

// --- HTTP + JWT plumbing ---------------------------------------------------

func doJSON(method, path string, body any, out any) bool {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, *apiBase+path, rdr)
	if err != nil {
		logf("ERR build %s %s: %v", method, path, err)
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logf("ERR %s %s: %v", method, path, err)
		return false
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out != nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, out)
		}
		if *verbose {
			logf("OK  %d %s %s", resp.StatusCode, method, path)
		}
		return true
	}
	// 409 means the resource already exists in the desired state — the
	// seed is idempotent and re-runnable, so this is expected on reruns,
	// not a failure. Summary counts are taken from server-side GETs.
	if resp.StatusCode == http.StatusConflict {
		if *verbose {
			logf("EXISTS %s %s", method, path)
		}
		return false
	}
	logf("FAIL %d %s %s: %s", resp.StatusCode, method, path, strings.TrimSpace(string(raw)))
	return false
}

// listCount returns the number of items the control plane reports for a
// tenant-scoped collection. The summary uses these server-side counts as
// ground truth so re-running the seed reports the true present state rather
// than only what this run happened to create.
func listCount(tid, sub string) int {
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if doJSON("GET", fmt.Sprintf("/api/v1/tenants/%s/%s", tid, sub), nil, &list) {
		return len(list.Items)
	}
	return 0
}

func mintGlobalAdminJWT(secret, sub string) string {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	hdr := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now().Unix()
	claims := map[string]any{
		"iss":   "sng-control",
		"aud":   "sng-control",
		"sub":   sub,
		"email": "operator@shieldnet.dev",
		"name":  "Platform Operator",
		"roles": []string{"platform_admin"},
		"iat":   now,
		"nbf":   now,
		"exp":   now + 6*3600,
	}
	cb, _ := json.Marshal(claims)
	seg := hdr + "." + b64(cb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(seg))
	return seg + "." + b64(mac.Sum(nil))
}

func logf(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...) }
func fatal(msg string)                { fmt.Fprintln(os.Stderr, "fatal: "+msg); os.Exit(1) }
