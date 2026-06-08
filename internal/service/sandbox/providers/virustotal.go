package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// VirusTotalConfig configures the VirusTotal v3 file-reputation
// adapter. VirusTotal is a *hash-lookup* provider, not a detonation
// backend: Submit looks the file's SHA-256 up against VT's existing
// multi-engine analysis and resolves synchronously. The file bytes
// are never uploaded (privacy + the free tier forbids it), so an
// unknown hash resolves to ClassUnknown rather than triggering an
// upload.
type VirusTotalConfig struct {
	// APIKey is the VT API key. Empty disables the provider
	// (Submit/Poll return ErrProviderUnavailable), so wiring it
	// unconfigured is safe.
	APIKey string
	// BaseURL overrides the API root (tests point it at a stub).
	// Defaults to https://www.virustotal.com.
	BaseURL string
	// MinRequestInterval paces requests to respect the free-tier
	// quota (4 requests/min ≈ one per 15s). Defaults to 15s. Set to
	// a small value (or rely on the limiter being disabled) on a
	// paid tier. A non-positive value disables pacing.
	MinRequestInterval time.Duration
	// MaliciousThreshold is the number of VT engines that must flag
	// the file "malicious" for the verdict to be ClassMalicious.
	// Defaults to 3 — a single noisy engine should not condemn a
	// file, but a handful agreeing is decisive.
	MaliciousThreshold int
	// SuspiciousThreshold is the combined malicious+suspicious
	// detection count at or above which the verdict is at least
	// ClassSuspicious. Defaults to 1.
	SuspiciousThreshold int
}

// VirusTotal is the VT v3 hash-reputation provider.
type VirusTotal struct {
	cfg     VirusTotalConfig
	client  HTTPDoer
	limiter *rateLimiter
}

// NewVirusTotal builds the provider, defaulting the HTTP client,
// pacing interval, and thresholds. A nil client falls back to a
// http.Client with a conservative timeout.
func NewVirusTotal(cfg VirusTotalConfig, client HTTPDoer) *VirusTotal {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://www.virustotal.com"
	}
	if cfg.MinRequestInterval == 0 {
		cfg.MinRequestInterval = 15 * time.Second
	}
	if cfg.MaliciousThreshold <= 0 {
		cfg.MaliciousThreshold = 3
	}
	if cfg.SuspiciousThreshold <= 0 {
		cfg.SuspiciousThreshold = 1
	}
	return &VirusTotal{
		cfg:     cfg,
		client:  client,
		limiter: newRateLimiter(cfg.MinRequestInterval),
	}
}

func (v *VirusTotal) ID() string { return "virustotal" }

func (v *VirusTotal) configured() bool { return strings.TrimSpace(v.cfg.APIKey) != "" }

// Submit resolves the file's reputation by hash. VT is synchronous,
// so this returns StatusComplete with the verdict in Result; the
// service persists it without polling.
func (v *VirusTotal) Submit(ctx context.Context, f File) (SubmitResult, error) {
	if !v.configured() {
		return SubmitResult{}, ErrProviderUnavailable
	}
	res, err := v.lookup(ctx, f.SHA256)
	if err != nil {
		return SubmitResult{}, err
	}
	return SubmitResult{SandboxID: f.SHA256, Status: StatusComplete, Result: res}, nil
}

// Poll re-runs the (idempotent) hash lookup. The service only polls
// rows it persisted as pending; VT never returns pending, so this is
// reached only if an operator re-polls a sample, in which case a
// fresh lookup is the correct behaviour.
func (v *VirusTotal) Poll(ctx context.Context, sandboxID string) (PollResult, error) {
	if !v.configured() {
		return PollResult{}, ErrProviderUnavailable
	}
	return v.lookup(ctx, sandboxID)
}

// vtFileResponse is the slice of the VT v3 /files/{id} response we
// consume: the engine tally under data.attributes.last_analysis_stats.
type vtFileResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Harmless   int `json:"harmless"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			Reputation         int    `json:"reputation"`
			MeaningfulName     string `json:"meaningful_name"`
			PopularThreatLabel struct {
				SuggestedLabel string `json:"suggested_threat_label"`
			} `json:"popular_threat_classification"`
		} `json:"attributes"`
	} `json:"data"`
}

func (v *VirusTotal) lookup(ctx context.Context, sha string) (PollResult, error) {
	if err := v.limiter.acquire(ctx); err != nil {
		return PollResult{}, fmt.Errorf("virustotal: rate limit wait: %w", err)
	}
	url := strings.TrimRight(v.cfg.BaseURL, "/") + "/api/v3/files/" + strings.ToLower(strings.TrimSpace(sha))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return PollResult{}, fmt.Errorf("virustotal: build request: %w", err)
	}
	req.Header.Set("x-apikey", v.cfg.APIKey)
	req.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(req)
	if err != nil {
		return PollResult{}, fmt.Errorf("virustotal: request: %w", err)
	}
	defer drain(resp)

	switch {
	case resp.StatusCode == http.StatusNotFound:
		// VT has never seen this hash — not a verdict, just absence
		// of intel. Resolve as unknown so the service does not cache
		// it as a disposition.
		return PollResult{
			Status:         StatusComplete,
			Classification: ClassUnknown,
			Provider:       v.ID(),
			Summary:        "virustotal: hash not found",
			AnalyzedAt:     time.Now().UTC(),
		}, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		return PollResult{}, fmt.Errorf("virustotal: rate limited (HTTP 429)")
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return PollResult{}, fmt.Errorf("virustotal: auth rejected (HTTP %d)", resp.StatusCode)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return PollResult{}, fmt.Errorf("virustotal: unexpected status %d", resp.StatusCode)
	}

	var decoded vtFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return PollResult{}, fmt.Errorf("virustotal: decode response: %w", err)
	}

	stats := decoded.Data.Attributes.LastAnalysisStats
	detections := stats.Malicious + stats.Suspicious
	total := detections + stats.Undetected + stats.Harmless + stats.Timeout

	class := v.classify(stats.Malicious, detections)
	confidence := 0.0
	if total > 0 {
		confidence = NormalizeConfidence(float64(detections) / float64(total))
	}
	if class == ClassClean {
		// Confidence in a clean verdict scales with engine coverage.
		if total > 0 {
			confidence = NormalizeConfidence(float64(stats.Harmless+stats.Undetected) / float64(total))
		} else {
			confidence = 0
		}
	}

	label := decoded.Data.Attributes.PopularThreatLabel.SuggestedLabel
	summary := fmt.Sprintf("virustotal: %d/%d engines flagged", detections, total)
	if label != "" {
		summary = fmt.Sprintf("virustotal: %d/%d engines flagged (%s)", detections, total, label)
	}

	return PollResult{
		Status:         StatusComplete,
		Classification: class,
		Confidence:     confidence,
		Summary:        summary,
		Provider:       v.ID(),
		AnalyzedAt:     time.Now().UTC(),
	}, nil
}

func (v *VirusTotal) classify(malicious, detections int) Classification {
	switch {
	case malicious >= v.cfg.MaliciousThreshold:
		return ClassMalicious
	case detections >= v.cfg.SuspiciousThreshold:
		return ClassSuspicious
	default:
		return ClassClean
	}
}
