// Command newcaps drives the live ShieldNet Gateway control plane to
// produce real, verbatim API evidence for the capabilities that have no
// dedicated console page yet — application identification (App-ID),
// lightweight digital-experience monitoring (DEM), managed
// threat-content, continuous compliance evidence, and the
// traffic-derived policy recommendation engine.
//
// It mints the same short-lived global platform-admin JWT the seed and
// capture harnesses use (HS256 over AUTH_JWT_SECRET, no tenant_id claim
// => global admin), performs the minimal real work each backend needs to
// have something to show (ingests a batch of synthetic DEM probe results,
// triggers an on-demand compliance sweep), then GETs the resulting
// posture/scores/catalog and writes every response verbatim as
// pretty-printed JSON under blog/artifacts/payloads/.
//
// Every file it writes is therefore a live capture against the seeded
// stack, not hand-authored. Run order: bring up the stack + migrate,
// run blog/harness/seed, then run this.
//
// Usage:
//
//	AUTH_JWT_SECRET=... go run . [-base http://127.0.0.1:8080] [-out ../../artifacts/payloads]
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

	"github.com/kennguy3n/visible-fishbone/blog/harness/fleet"
)

var (
	acme    = fleet.Acme().ID
	globex  = fleet.Globex().ID
	maple   = fleet.Maple().ID
	initech = fleet.Initech().ID
)

var (
	base     = flag.String("base", "http://127.0.0.1:8080", "control-plane base URL")
	out      = flag.String("out", "../../artifacts/payloads", "output directory")
	operator = flag.String("operator", "190fc952-71ff-4ad5-a0fa-68b78ec39fca", "operator user UUID (sub claim)")
	token    string
)

func main() {
	flag.Parse()
	secret := os.Getenv("AUTH_JWT_SECRET")
	if secret == "" {
		fatal("AUTH_JWT_SECRET is unset")
	}
	token = mintGlobalAdminJWT(secret, *operator)
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal("mkdir out: %v", err)
	}

	// 1. DEM — ingest a batch of synthetic probe results for Acme, then
	//    capture the freshly recomputed scores, the default targets, and
	//    any degradation alert. The batch is deterministic: five healthy
	//    SaaS targets and one deliberately degraded one (zoom) that falls
	//    below the absolute score floor and raises an experience alert.
	demBatch := buildDEMBatch()
	postCapture("dem-acme-ingest-result", "/api/v1/tenants/"+acme+"/dem/results", demBatch)
	get("dem-acme-scores", "/api/v1/tenants/"+acme+"/dem/scores")
	get("dem-acme-targets", "/api/v1/tenants/"+acme+"/dem/targets")
	get("dem-acme-alerts", "/api/v1/tenants/"+acme+"/dem/alerts")

	// 2. Continuous compliance — run an on-demand sweep for three tenants
	//    with different regimes, then export framework-mapped evidence
	//    packs (JSON for both frameworks, plus a CSV to show the audit
	//    export encoding).
	postCapture("complianceauto-acme-collect", "/api/v1/tenants/"+acme+"/compliance-auto/collect", nil)
	postCapture("complianceauto-globex-collect", "/api/v1/tenants/"+globex+"/compliance-auto/collect", nil)
	postCapture("complianceauto-maple-collect", "/api/v1/tenants/"+maple+"/compliance-auto/collect", nil)
	get("complianceauto-acme-posture", "/api/v1/tenants/"+acme+"/compliance-auto/posture")
	get("complianceauto-acme-evidence-pack-soc2", "/api/v1/tenants/"+acme+"/compliance-auto/evidence-pack?framework=SOC2")
	get("complianceauto-acme-evidence-pack-iso27001", "/api/v1/tenants/"+acme+"/compliance-auto/evidence-pack?framework=ISO_27001")
	getRaw("complianceauto-acme-evidence-pack-soc2", "csv", "/api/v1/tenants/"+acme+"/compliance-auto/evidence-pack?framework=SOC2&format=csv")

	// 3. App-ID — the published catalog summary, the full admin version
	//    history, and the signed bundle the edge pulls.
	get("appid-acme-catalog-current", "/api/v1/tenants/"+acme+"/appid/catalog/current")
	get("appid-admin-catalog-versions", "/api/v1/admin/appid/catalog/versions")
	get("appid-acme-catalog-bundle", "/api/v1/tenants/"+acme+"/appid/catalog/bundle")

	// 4. Managed threat-content — the per-tenant posture: signed bundle
	//    metadata plus per-source health.
	get("threatcontent-acme-posture", "/api/v1/tenants/"+acme+"/threat-content/posture")

	// 5. Policy recommendation engine — synthesis requires the telemetry
	//    hot tier. On a deployment without it the contract returns a
	//    well-formed 503; we capture that verbatim too, because the
	//    honest story is "the engine is wired and gated on its inputs,"
	//    not a fabricated recommendation.
	postCapture("policyrec-acme-generate", "/api/v1/tenants/"+acme+"/policy/recommendations", nil)
	get("policyrec-acme-list", "/api/v1/tenants/"+acme+"/policy/recommendations")

	_ = initech // reserved for future per-regime captures
	fmt.Println("newcaps: done")
}

// buildDEMBatch returns a deterministic batch of synthetic probe results:
// five healthy SaaS targets (high availability, sub-100ms TTFB => near-
// perfect score) and one degraded target (zoom: half the probes time out
// and the successful ones are slow => availability and latency both poor,
// score below the 70 floor => degradation alert).
func buildDEMBatch() map[string]any {
	nowMs := time.Now().UnixMilli()
	healthy := []struct{ key, name string }{
		{"github", "GitHub"},
		{"google_workspace", "Google Workspace"},
		{"m365", "Microsoft 365"},
		{"salesforce", "Salesforce"},
		{"slack", "Slack"},
	}
	var results []map[string]any
	for _, t := range healthy {
		for i := 0; i < 12; i++ {
			results = append(results, map[string]any{
				"target_key": t.key, "target_name": t.name, "probe_kind": "https",
				"success": true,
				"dns_ms":  3.0 + float64(i%3), "tcp_ms": 8.0 + float64(i%4),
				"tls_ms": 12.0, "ttfb_ms": 28.0 + float64(i%5), "total_ms": 41.0 + float64(i%5),
				"http_status":    200,
				"observed_at_ms": nowMs - int64((12-i)*1000),
			})
		}
	}
	// Degraded: zoom. Half time out, the rest are slow (multi-second TTFB).
	for i := 0; i < 12; i++ {
		r := map[string]any{
			"target_key": "zoom", "target_name": "Zoom", "probe_kind": "https",
			"observed_at_ms": nowMs - int64((12-i)*1000),
		}
		if i%2 == 0 {
			r["success"] = false
			r["error_kind"] = "timeout"
		} else {
			r["success"] = true
			r["dns_ms"] = 40.0
			r["tcp_ms"] = 220.0
			r["tls_ms"] = 380.0
			r["ttfb_ms"] = 2600.0
			r["total_ms"] = 3100.0
			r["http_status"] = 200
		}
		results = append(results, r)
	}
	return map[string]any{"results": results}
}

// --- HTTP plumbing (mirrors blog/harness/capture) ---

func get(name, path string) { getRaw(name, "json", path) }

func getRaw(name, ext, path string) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, *base+path, nil)
	if err != nil {
		fatal("build GET %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	write(name, ext, resp.StatusCode, body)
}

func postCapture(name, path string, payload any) {
	var rdr io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			fatal("marshal %s: %v", name, err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, *base+path, rdr)
	if err != nil {
		fatal("build POST %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	write(name+"-response", "json", resp.StatusCode, body)
}

func write(name, ext string, status int, body []byte) {
	dst := filepath.Join(*out, name+"."+ext)
	var content []byte
	if ext == "json" {
		var pretty bytes.Buffer
		if json.Indent(&pretty, body, "", "  ") == nil {
			content = pretty.Bytes()
		} else {
			content = body
		}
	} else {
		content = body
	}
	if err := os.WriteFile(dst, content, 0o644); err != nil {
		fatal("write %s: %v", dst, err)
	}
	fmt.Printf("[%d] %-44s -> %s\n", status, name, dst)
}

func mintGlobalAdminJWT(secret, sub string) string {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	hdr := b64([]byte(`{"alg":"HS256","typ":"JWT"}`))
	now := time.Now().Unix()
	claims := map[string]any{
		"iss": "sng-control", "aud": "sng-control", "sub": sub,
		"email": "operator@shieldnet.dev", "name": "Platform Operator",
		"roles": []string{"platform_admin"},
		"iat":   now, "nbf": now, "exp": now + 6*3600,
	}
	cb, _ := json.Marshal(claims)
	seg := hdr + "." + b64(cb)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(seg))
	return seg + "." + b64(mac.Sum(nil))
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "newcaps: "+format+"\n", args...)
	os.Exit(1)
}
