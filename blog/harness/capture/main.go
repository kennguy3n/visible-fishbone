// Command capture saves real ShieldNet Gateway control-plane API
// responses to blog/artifacts/payloads/ for use as evidence in the
// blog series. It mints the same short-lived global platform-admin JWT
// the seed harness uses (HS256 over AUTH_JWT_SECRET, no tenant_id claim
// => treated as global admin), GETs a fixed set of scenario-relevant
// endpoints against a running control plane, and writes each response
// as pretty-printed JSON.
//
// Every file under payloads/ is therefore a verbatim capture of a live
// request against the seeded stack — not hand-authored. Re-running this
// against the same seeded data reproduces the same files.
//
// Usage:
//
//	AUTH_JWT_SECRET=... go run . [-base http://localhost:8080] [-out ../../artifacts/payloads]
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Acme Retail Group — the richest seeded tenant; used for the
// per-scenario walk-throughs in the series.
const acme = "92112770-7c0a-410b-b0f4-09dde70e063a"

// Umbrella Logistics — APAC residency tenant; carries a single
// pdpa-singapore DLP policy (the Singapore-residency example).
const umbrella = "0c8d2d9d-896d-45b1-8001-6a6776f832b9"

// Nordic EduCloud — the deliberately-sparse starter tenant (0 DLP
// policies); used to capture an honest, intentional empty-state payload.
const nordic = "8c93e8b9-5710-4f3a-9981-6d2c558bb78f"

// Initech Financial — the professional-tier tenant carrying a seeded
// url_cat surge; used to capture the one credible cost anomaly in the
// dataset (its current-month run rate runs well above its own history).
const initech = "b6520bda-e7bb-4af9-9c53-7b0051eae65b"

// Globex Health Systems — the HIPAA tenant; used to capture a playbook
// set with a mix of enabled and disabled automated-response runbooks.
const globex = "3bd7bb7b-d48a-4569-8f97-46be31ae8e5a"

// Multi-country / multi-industry tenants — each resolves to a distinct
// compliance regime via the smart-default policy-template engine, so
// their applied baselines are the evidence for the jurisdiction story:
//
//	britannia (GB) -> uk-dpa, maple (CA) -> ca-pipeda,
//	outback   (AU) -> au-privacy, lumiere (FR) -> eu-gdpr.
const (
	britannia = "2d0935d3-8c57-4f66-a5a9-0de368f16a7c"
	maple     = "cef9c934-507c-4adc-985b-48f3cbe274b0"
	outback   = "37619610-53b4-4eab-87f9-45ba902d30c2"
	lumiere   = "890486df-98bd-482b-85a8-af361706676f"
)

// postSpec captures a live POST response. Bodies are fixed so reruns
// against the same seeded stack reproduce the same files.
type postSpec struct {
	name string
	path string
	body map[string]any
}

type spec struct {
	name string // output filename (without .json) and scenario tag
	path string // request path
}

func main() {
	base := flag.String("base", "http://localhost:8080", "control-plane base URL")
	out := flag.String("out", "../../artifacts/payloads", "output directory")
	operator := flag.String("operator", "190fc952-71ff-4ad5-a0fa-68b78ec39fca", "operator user UUID (sub claim)")
	flag.Parse()

	secret := os.Getenv("AUTH_JWT_SECRET")
	if secret == "" {
		fatal("AUTH_JWT_SECRET is required (same secret the control plane verifies)")
	}
	token := mintGlobalAdminJWT(secret, *operator)

	if err := os.MkdirAll(*out, 0o750); err != nil {
		fatal("mkdir out: " + err.Error())
	}

	ctx := context.Background()

	specs := []spec{
		// S1 — multi-tenant / MSP onboarding + audit
		{"s1-msps", "/api/v1/msps"},
		{"s1-tenants", "/api/v1/tenants"},
		{"s1-acme-audit-log", "/api/v1/tenants/" + acme + "/audit-log"},
		// S2 — one typed policy graph (the centerpiece)
		{"s2-acme-policy-graph", "/api/v1/tenants/" + acme + "/policy"},
		{"s2-acme-sites", "/api/v1/tenants/" + acme + "/sites"},
		{"s2-acme-devices", "/api/v1/tenants/" + acme + "/devices"},
		// S3 — detection / alerts
		{"s3-acme-alerts", "/api/v1/tenants/" + acme + "/alerts"},
		// S5 — DLP / CASB / browser isolation
		{"s5-acme-dlp-policies", "/api/v1/tenants/" + acme + "/dlp/policies"},
		{"s5-acme-casb-connectors", "/api/v1/tenants/" + acme + "/casb/connectors"},
		{"s5-acme-casb-inline-rules", "/api/v1/tenants/" + acme + "/casb/inline-rules"},
		{"s5-acme-browser-policies", "/api/v1/tenants/" + acme + "/browser-policies"},
		{"s5-nordic-dlp-policies-emptystate", "/api/v1/tenants/" + nordic + "/dlp/policies"},
		{"s5-umbrella-dlp-policies", "/api/v1/tenants/" + umbrella + "/dlp/policies"},
		// S6 — AI posture report (the live policy-coverage fix, #119)
		{"s6-acme-posture-report", "/api/v1/tenants/" + acme + "/ai/reports/posture"},
		{"s6-acme-playbooks", "/api/v1/tenants/" + acme + "/playbooks"},
		{"s6-globex-playbooks", "/api/v1/tenants/" + globex + "/playbooks"},
		// Smart-default policy templates — global catalog + per-tenant
		// applied baselines across five compliance regimes. These are the
		// multi-country / multi-industry evidence: one (industry, country)
		// selection compiles to a jurisdiction-correct baseline graph.
		{"policy-templates-catalog", "/api/v1/policy-templates"},
		{"pt-applied-acme-us-baseline", "/api/v1/tenants/" + acme + "/policy-templates/applied"},
		{"pt-applied-initech-eu-gdpr", "/api/v1/tenants/" + initech + "/policy-templates/applied"},
		{"pt-applied-britannia-uk-dpa", "/api/v1/tenants/" + britannia + "/policy-templates/applied"},
		{"pt-applied-maple-ca-pipeda", "/api/v1/tenants/" + maple + "/policy-templates/applied"},
		{"pt-applied-outback-au-privacy", "/api/v1/tenants/" + outback + "/policy-templates/applied"},
		{"pt-applied-lumiere-eu-gdpr", "/api/v1/tenants/" + lumiere + "/policy-templates/applied"},
		// S7 — cost / metering / compliance / integrations
		{"s7-acme-usage", "/api/v1/tenants/" + acme + "/usage"},
		{"s7-acme-usage-history", "/api/v1/tenants/" + acme + "/usage/history"},
		{"s7-acme-cost-anomalies", "/api/v1/tenants/" + acme + "/cost-anomalies"},
		{"s7-initech-cost-anomalies", "/api/v1/tenants/" + initech + "/cost-anomalies"},
		{"s7-umbrella-usage", "/api/v1/tenants/" + umbrella + "/usage"},
		{"s7-admin-cost-report", "/api/v1/admin/cost-report"},
		{"s7-acme-compliance-reports", "/api/v1/tenants/" + acme + "/compliance/reports"},
		{"s7-acme-integrations", "/api/v1/tenants/" + acme + "/integrations"},
	}

	client := &http.Client{Timeout: 15 * time.Second}
	ok, fail := 0, 0
	for _, s := range specs {
		status, body, err := get(ctx, client, *base, s.path, token)
		if err != nil {
			logf("FAIL %-40s %v", s.name, err)
			fail++
			continue
		}
		if status < 200 || status >= 300 {
			logf("FAIL %-40s HTTP %d: %s", s.name, status, truncate(body, 200))
			fail++
			continue
		}
		pretty, perr := prettyJSON(body)
		if perr != nil {
			logf("FAIL %-40s non-JSON response: %v", s.name, perr)
			fail++
			continue
		}
		dst := filepath.Join(*out, s.name+".json")
		if err := os.WriteFile(dst, pretty, 0o600); err != nil {
			logf("FAIL %-40s write: %v", s.name, err)
			fail++
			continue
		}
		logf("OK   %-40s HTTP %d  %d bytes -> %s", s.name, status, len(pretty), dst)
		ok++
	}
	// POST captures — request + response pairs for the AI NL policy
	// query (S6). The request body is saved alongside the response so
	// the blog can show both sides of a real, deterministic verdict.
	posts := []postSpec{
		{
			"s6-acme-nl-policy-query",
			"/api/v1/tenants/" + acme + "/ai/query",
			map[string]any{"question": "Can user finance access app private-apps from a managed device?"},
		},
		// Smart-default preview: the (industry, country) -> regime + graph
		// resolution, captured as request/response pairs so the blog can
		// show both sides of the deterministic baseline render.
		{
			"pt-preview-finance-de",
			"/api/v1/tenants/" + initech + "/policy-templates/preview",
			map[string]any{"industry": "finance", "country": "DE"},
		},
		{
			"pt-preview-healthcare-ca",
			"/api/v1/tenants/" + maple + "/policy-templates/preview",
			map[string]any{"industry": "healthcare", "country": "CA"},
		},
	}
	for _, p := range posts {
		reqBytes, _ := json.MarshalIndent(p.body, "", "  ")
		if err := os.WriteFile(filepath.Join(*out, p.name+"-request.json"), append(reqBytes, '\n'), 0o600); err != nil {
			logf("FAIL %-40s write request: %v", p.name, err)
			fail++
			continue
		}
		status, body, err := post(ctx, client, *base, p.path, token, p.body)
		if err != nil {
			logf("FAIL %-40s %v", p.name, err)
			fail++
			continue
		}
		if status < 200 || status >= 300 {
			logf("FAIL %-40s HTTP %d: %s", p.name, status, truncate(body, 200))
			fail++
			continue
		}
		pretty, perr := prettyJSON(body)
		if perr != nil {
			logf("FAIL %-40s non-JSON response: %v", p.name, perr)
			fail++
			continue
		}
		dst := filepath.Join(*out, p.name+"-response.json")
		if err := os.WriteFile(dst, pretty, 0o600); err != nil {
			logf("FAIL %-40s write: %v", p.name, err)
			fail++
			continue
		}
		logf("OK   %-40s HTTP %d  %d bytes -> %s", p.name, status, len(pretty), dst)
		ok++
	}

	logf("\ncaptured %d ok, %d failed", ok, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func post(ctx context.Context, c *http.Client, base, path, token string, body map[string]any) (int, []byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", base+path, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	return resp.StatusCode, rb, err
}

func get(ctx context.Context, c *http.Client, base, path, token string) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", base+path, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp.StatusCode, body, err
}

func prettyJSON(b []byte) ([]byte, error) {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
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
