package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HybridAnalysisConfig configures the Hybrid Analysis (Falcon
// Sandbox) v2 hash-search adapter. Like VirusTotal, this is a
// hash-lookup reputation provider: Submit searches HA's existing
// reports for the file's SHA-256 and resolves synchronously without
// uploading the file.
type HybridAnalysisConfig struct {
	// APIKey is the HA API key, sent in the "api-key" header. Empty
	// disables the provider.
	APIKey string
	// BaseURL overrides the API root (tests point it at a stub).
	// Defaults to https://www.hybrid-analysis.com.
	BaseURL string
	// MinRequestInterval paces requests to respect the free-tier
	// quota. Defaults to 6s (~10 req/min). A non-positive value
	// disables pacing.
	MinRequestInterval time.Duration
	// MaliciousThreshold is the HA threat_score (0-100) at or above
	// which the verdict is ClassMalicious when HA does not return an
	// explicit verdict string. Defaults to 70.
	MaliciousThreshold int
	// SuspiciousThreshold is the threat_score at or above which the
	// verdict is at least ClassSuspicious. Defaults to 30.
	SuspiciousThreshold int
}

// HybridAnalysis is the HA Falcon Sandbox hash-reputation provider.
type HybridAnalysis struct {
	cfg     HybridAnalysisConfig
	client  HTTPDoer
	limiter *rateLimiter
}

// NewHybridAnalysis builds the provider, defaulting client, pacing,
// and thresholds.
func NewHybridAnalysis(cfg HybridAnalysisConfig, client HTTPDoer) *HybridAnalysis {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://www.hybrid-analysis.com"
	}
	if cfg.MinRequestInterval == 0 {
		cfg.MinRequestInterval = 6 * time.Second
	}
	if cfg.MaliciousThreshold <= 0 {
		cfg.MaliciousThreshold = 70
	}
	if cfg.SuspiciousThreshold <= 0 {
		cfg.SuspiciousThreshold = 30
	}
	return &HybridAnalysis{
		cfg:     cfg,
		client:  client,
		limiter: newRateLimiter(cfg.MinRequestInterval),
	}
}

func (h *HybridAnalysis) ID() string { return "hybrid_analysis" }

func (h *HybridAnalysis) configured() bool { return strings.TrimSpace(h.cfg.APIKey) != "" }

// Submit resolves the file's reputation by hash search. HA is
// synchronous here, so this returns StatusComplete with the verdict
// in Result.
func (h *HybridAnalysis) Submit(ctx context.Context, f File) (SubmitResult, error) {
	if !h.configured() {
		return SubmitResult{}, ErrProviderUnavailable
	}
	res, err := h.lookup(ctx, f.SHA256)
	if err != nil {
		return SubmitResult{}, err
	}
	return SubmitResult{SandboxID: f.SHA256, Status: StatusComplete, Result: res}, nil
}

// Poll re-runs the idempotent hash search.
func (h *HybridAnalysis) Poll(ctx context.Context, sandboxID string) (PollResult, error) {
	if !h.configured() {
		return PollResult{}, ErrProviderUnavailable
	}
	return h.lookup(ctx, sandboxID)
}

// haReport is one entry of the HA /search/hash array response.
type haReport struct {
	Verdict     string `json:"verdict"`
	ThreatScore *int   `json:"threat_score"`
	ThreatLevel *int   `json:"threat_level"`
	VxFamily    string `json:"vx_family"`
}

func (h *HybridAnalysis) lookup(ctx context.Context, sha string) (PollResult, error) {
	if err := h.limiter.acquire(ctx); err != nil {
		return PollResult{}, fmt.Errorf("hybrid_analysis: rate limit wait: %w", err)
	}
	endpoint := strings.TrimRight(h.cfg.BaseURL, "/") + "/api/v2/search/hash"
	form := url.Values{}
	form.Set("hash", strings.ToLower(strings.TrimSpace(sha)))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return PollResult{}, fmt.Errorf("hybrid_analysis: build request: %w", err)
	}
	req.Header.Set("api-key", h.cfg.APIKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// HA requires a User-Agent of "Falcon Sandbox" on API requests.
	req.Header.Set("User-Agent", "Falcon Sandbox")

	resp, err := h.client.Do(req)
	if err != nil {
		return PollResult{}, fmt.Errorf("hybrid_analysis: request: %w", err)
	}
	defer drain(resp)

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return PollResult{}, fmt.Errorf("hybrid_analysis: rate limited (HTTP 429)")
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return PollResult{}, fmt.Errorf("hybrid_analysis: auth rejected (HTTP %d)", resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return PollResult{}, fmt.Errorf("hybrid_analysis: unexpected status %d", resp.StatusCode)
	}

	var reports []haReport
	if err := json.NewDecoder(resp.Body).Decode(&reports); err != nil {
		return PollResult{}, fmt.Errorf("hybrid_analysis: decode response: %w", err)
	}
	if len(reports) == 0 {
		// No report for this hash — absence of intel, not a verdict.
		return PollResult{
			Status:         StatusComplete,
			Classification: ClassUnknown,
			Provider:       h.ID(),
			Summary:        "hybrid_analysis: no report for hash",
			AnalyzedAt:     time.Now().UTC(),
		}, nil
	}

	// Multiple reports (different environments) can exist for one
	// hash; take the strictest across them.
	best := ClassUnknown
	bestScore := -1
	family := ""
	for i := range reports {
		c, score := h.classifyReport(reports[i])
		if severityRank(c) > severityRank(best) {
			best = c
		}
		if score > bestScore {
			bestScore = score
		}
		if family == "" && reports[i].VxFamily != "" {
			family = reports[i].VxFamily
		}
	}

	confidence := 0.0
	if bestScore >= 0 {
		confidence = NormalizeConfidence(float64(bestScore) / 100.0)
	}
	summary := fmt.Sprintf("hybrid_analysis: %d report(s), threat_score %d", len(reports), bestScore)
	if family != "" {
		summary = fmt.Sprintf("hybrid_analysis: %s (threat_score %d)", family, bestScore)
	}

	return PollResult{
		Status:         StatusComplete,
		Classification: best,
		Confidence:     confidence,
		Summary:        summary,
		Provider:       h.ID(),
		AnalyzedAt:     time.Now().UTC(),
	}, nil
}

// classifyReport maps one HA report onto a Classification and its
// threat_score. The explicit verdict string is authoritative when
// present; otherwise the numeric threat_score is bucketed against
// the configured thresholds.
func (h *HybridAnalysis) classifyReport(r haReport) (Classification, int) {
	score := -1
	if r.ThreatScore != nil {
		score = *r.ThreatScore
	}
	switch strings.ToLower(strings.TrimSpace(r.Verdict)) {
	case "malicious":
		return ClassMalicious, score
	case "suspicious":
		return ClassSuspicious, score
	case "whitelisted", "no specific threat", "no verdict", "clean":
		return ClassClean, score
	}
	// No usable verdict string — fall back to the numeric score.
	switch {
	case score >= h.cfg.MaliciousThreshold:
		return ClassMalicious, score
	case score >= h.cfg.SuspiciousThreshold:
		return ClassSuspicious, score
	case score >= 0:
		return ClassClean, score
	default:
		return ClassUnknown, score
	}
}
