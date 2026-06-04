package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// APILatencyConfig parameterises the live API workload. The workload
// drives an already-running control plane reachable at BaseURL — it
// does NOT spin up Postgres or the binary itself. The integration test
// (build tag `integration`) provisions a real control plane via
// testcontainers and hands its URL + auth here; an operator can
// instead point --url at a running instance.
type APILatencyConfig struct {
	// BaseURL is the control-plane root, e.g. "http://127.0.0.1:8080".
	BaseURL string
	// JWTSecret / JWTIssuer / JWTAudience mint operator JWTs the Auth
	// middleware accepts (HS256). Required unless APIKey is set.
	JWTSecret   string
	JWTIssuer   string
	JWTAudience string
	// APIKey, when set, is sent in APIKeyHeader instead of a JWT.
	APIKey       string
	APIKeyHeader string
	// TenantCounts is the set of pre-seed tenant tiers to measure.
	TenantCounts []int
	// Concurrency is the number of concurrent virtual clients per tier.
	Concurrency int
	// Duration is the measurement window per tier.
	Duration time.Duration
	// Client is the HTTP client used for every request.
	Client *http.Client
}

// seededTenant records the IDs created while seeding so the workload
// can target real resources (and exercise RLS-scoped lookups).
type seededTenant struct {
	ID      string
	SiteIDs []string
}

// apiClient is the workload's thin HTTP wrapper. It owns auth header
// injection and latency capture so the workload loop stays readable.
type apiClient struct {
	base   string
	cfg    *APILatencyConfig
	client *http.Client
}

func newAPIClient(cfg *APILatencyConfig) *apiClient {
	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &apiClient{base: strings.TrimRight(cfg.BaseURL, "/"), cfg: cfg, client: client}
}

// authHeader sets the credential for a request scoped to tenantID
// (empty tenantID mints a non-tenant-scoped operator token, used for
// tenant creation). Returns an error if no credential is configured.
func (c *apiClient) authHeader(req *http.Request, tenantID string) error {
	if c.cfg.APIKey != "" {
		header := c.cfg.APIKeyHeader
		if header == "" {
			header = "X-SNG-API-Key"
		}
		req.Header.Set(header, c.cfg.APIKey)
		return nil
	}
	if c.cfg.JWTSecret == "" {
		return fmt.Errorf("no credential configured: set JWTSecret or APIKey")
	}
	token, err := mintToken(c.cfg, tenantID)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// do executes one request and returns the status code and wall-clock
// latency. The response body is always drained + closed so connections
// are reused (and to satisfy bodyclose).
func (c *apiClient) do(ctx context.Context, method, path, tenantID string, body any) (int, time.Duration, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, 0, fmt.Errorf("marshal body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, 0, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := c.authHeader(req, tenantID); err != nil {
		return 0, 0, err
	}

	start := time.Now()
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, time.Since(start), err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, time.Since(start), nil
}

// doDecode is like do but decodes a 2xx JSON body into out.
func (c *apiClient) doDecode(ctx context.Context, method, path, tenantID string, body, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("marshal body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := c.authHeader(req, tenantID); err != nil {
		return 0, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("read body: %w", err)
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 && out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s %s: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// mintToken builds an HS256 operator JWT the Auth middleware accepts.
// A non-empty tenantID adds the tenant_id claim so tenant-scoped reads
// pass RLS; an empty tenantID mints a platform-operator token for
// tenant creation.
func mintToken(cfg *APILatencyConfig, tenantID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub": "bench-operator",
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
	}
	if cfg.JWTIssuer != "" {
		claims["iss"] = cfg.JWTIssuer
	}
	if cfg.JWTAudience != "" {
		claims["aud"] = cfg.JWTAudience
	}
	if tenantID != "" {
		claims["tenant_id"] = tenantID
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(cfg.JWTSecret))
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return signed, nil
}

// seedTenants provisions n tenants, each with 3 sites and a policy
// graph, so the read/write/heavy workload targets real, RLS-scoped
// data. Device enrollment is a multi-step CSR flow out of scope for a
// load seed; GET /devices still exercises the (empty) tenant-scoped
// list path.
func (c *apiClient) seedTenants(ctx context.Context, n int) ([]seededTenant, error) {
	tenants := make([]seededTenant, 0, n)
	siteTemplates := []string{"branch", "hub", "cloud_only"}
	graph, err := GenerateGraphJSON(50)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		var created struct {
			ID string `json:"id"`
		}
		status, err := c.doDecode(ctx, http.MethodPost, "/api/v1/tenants", "", map[string]any{
			"name": fmt.Sprintf("bench-tenant-%05d", i),
			"tier": "professional",
		}, &created)
		if err != nil {
			return nil, fmt.Errorf("create tenant %d: %w", i, err)
		}
		if status != http.StatusCreated || created.ID == "" {
			return nil, fmt.Errorf("create tenant %d: unexpected status %d", i, status)
		}

		st := seededTenant{ID: created.ID}
		for s := 0; s < 3; s++ {
			var site struct {
				ID string `json:"id"`
			}
			path := "/api/v1/tenants/" + created.ID + "/sites"
			scode, serr := c.doDecode(ctx, http.MethodPost, path, created.ID, map[string]any{
				"name":     fmt.Sprintf("site-%d", s),
				"template": siteTemplates[s%len(siteTemplates)],
			}, &site)
			if serr != nil {
				return nil, fmt.Errorf("create site for tenant %d: %w", i, serr)
			}
			if scode == http.StatusCreated && site.ID != "" {
				st.SiteIDs = append(st.SiteIDs, site.ID)
			}
		}

		// Seed a policy graph so GET /policy, compile, and simulate
		// all have something to operate on.
		gcode, _, gerr := c.do(ctx, http.MethodPut, "/api/v1/tenants/"+created.ID+"/policy", created.ID, json.RawMessage(graph))
		if gerr != nil {
			return nil, fmt.Errorf("seed policy graph for tenant %d: %w", i, gerr)
		}
		if gcode != http.StatusCreated && gcode != http.StatusOK {
			return nil, fmt.Errorf("seed policy graph for tenant %d: status %d", i, gcode)
		}
		tenants = append(tenants, st)
	}
	return tenants, nil
}

// workloadOp is one weighted request template in the mix.
type workloadOp struct {
	key    string // recorder key: "METHOD route-template"
	method string
	// path builds the concrete path for a chosen tenant.
	path func(t seededTenant) string
	// body builds the request body (nil for reads).
	body func(t seededTenant) any
}

// buildWorkloadOps returns the weighted operation list: 60% reads,
// 30% writes, 10% heavy. Weighting is by repetition count in the
// returned slice so a uniform pick reproduces the mix.
func buildWorkloadOps() []workloadOp {
	graph, _ := GenerateGraphJSON(50)
	reads := []workloadOp{
		{key: "GET /tenants/{id}", method: http.MethodGet,
			path: func(t seededTenant) string { return "/api/v1/tenants/" + t.ID }},
		{key: "GET /tenants/{id}/sites", method: http.MethodGet,
			path: func(t seededTenant) string { return "/api/v1/tenants/" + t.ID + "/sites" }},
		{key: "GET /tenants/{id}/devices", method: http.MethodGet,
			path: func(t seededTenant) string { return "/api/v1/tenants/" + t.ID + "/devices" }},
		{key: "GET /tenants/{id}/policy", method: http.MethodGet,
			path: func(t seededTenant) string { return "/api/v1/tenants/" + t.ID + "/policy" }},
	}
	writes := []workloadOp{
		{key: "PATCH /tenants/{id}", method: http.MethodPatch,
			path: func(t seededTenant) string { return "/api/v1/tenants/" + t.ID },
			body: func(_ seededTenant) any { return map[string]any{"region": "us-east-1"} }},
		{key: "POST /tenants/{id}/sites", method: http.MethodPost,
			path: func(t seededTenant) string { return "/api/v1/tenants/" + t.ID + "/sites" },
			body: func(_ seededTenant) any {
				return map[string]any{"name": fmt.Sprintf("wl-site-%d", rand.Intn(1_000_000)), "template": "branch"} //nolint:gosec // non-crypto load id
			}},
		{key: "POST /tenants/{id}/claim-tokens", method: http.MethodPost,
			path: func(t seededTenant) string { return "/api/v1/tenants/" + t.ID + "/claim-tokens" },
			body: func(_ seededTenant) any { return map[string]any{"ttl_seconds": 3600} }},
	}
	heavy := []workloadOp{
		{key: "POST /tenants/{id}/policy/compile", method: http.MethodPost,
			path: func(t seededTenant) string { return "/api/v1/tenants/" + t.ID + "/policy/compile" }},
		{key: "POST /tenants/{id}/policy/simulations", method: http.MethodPost,
			path: func(t seededTenant) string { return "/api/v1/tenants/" + t.ID + "/policy/simulations" },
			body: func(_ seededTenant) any { return map[string]any{"proposed": json.RawMessage(graph)} }},
	}

	ops := make([]workloadOp, 0, 100)
	appendN := func(src []workloadOp, total int) {
		for i := 0; i < total; i++ {
			ops = append(ops, src[i%len(src)])
		}
	}
	appendN(reads, 60)
	appendN(writes, 30)
	appendN(heavy, 10)
	return ops
}

// isError reports whether an HTTP status counts as a failed request
// for the error-rate metric (any non-2xx).
func isError(status int) bool {
	return status < 200 || status >= 300
}

// runTier runs the weighted workload against the seeded tenants for the
// configured duration and folds the result into an APILatencyTier.
func (c *apiClient) runTier(ctx context.Context, tenantCount int, tenants []seededTenant) APILatencyTier {
	ops := buildWorkloadOps()
	recorders := make(map[string]*latencyRecorder)
	var recMu sync.Mutex
	recorderFor := func(op workloadOp) *latencyRecorder {
		recMu.Lock()
		defer recMu.Unlock()
		rec, ok := recorders[op.key]
		if !ok {
			rec = newLatencyRecorder(op.method, op.key)
			recorders[op.key] = rec
		}
		return rec
	}

	runCtx, cancel := context.WithTimeout(ctx, c.cfg.Duration)
	defer cancel()

	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < c.cfg.Concurrency; w++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(seed) + start.UnixNano())) //nolint:gosec // non-crypto workload sequencing
			for runCtx.Err() == nil {
				op := ops[rng.Intn(len(ops))]
				t := tenants[rng.Intn(len(tenants))]
				var body any
				if op.body != nil {
					body = op.body(t)
				}
				status, latency, err := c.do(runCtx, op.method, op.path(t), t.ID, body)
				if runCtx.Err() != nil {
					return
				}
				recorderFor(op).record(latency, err != nil || isError(status))
			}
		}(w)
	}
	wg.Wait()
	elapsed := time.Since(start)

	recs := make([]*latencyRecorder, 0, len(recorders))
	for _, rec := range recorders {
		recs = append(recs, rec)
	}
	return aggregateTier(tenantCount, int(c.cfg.Duration.Seconds()), c.cfg.Concurrency, elapsed, recs)
}

// RunAPILatencyBench seeds each tenant tier and runs the workload
// against a live control plane at cfg.BaseURL.
func RunAPILatencyBench(ctx context.Context, cfg *APILatencyConfig) (*APILatencySection, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("api-latency requires --url (or run --dry-run)")
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 32
	}
	if cfg.Duration <= 0 {
		cfg.Duration = 60 * time.Second
	}
	client := newAPIClient(cfg)
	section := &APILatencySection{}
	for _, count := range cfg.TenantCounts {
		tenants, err := client.seedTenants(ctx, count)
		if err != nil {
			return nil, fmt.Errorf("seed %d tenants: %w", count, err)
		}
		if len(tenants) == 0 {
			return nil, fmt.Errorf("seeded 0 tenants for tier %d", count)
		}
		tier := client.runTier(ctx, count, tenants)
		section.Tiers = append(section.Tiers, tier)
	}
	return section, nil
}
