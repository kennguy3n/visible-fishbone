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
	_ = os.WriteFile("blog/artifacts/seed-summary.json", out, 0o644)
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

	return res
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
	req, err := http.NewRequest(method, *apiBase+path, rdr)
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
