package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// CuckooConfig configures the Cuckoo Sandbox adapter against the
// Cuckoo REST API (https://cuckoo.readthedocs.io/, /tasks/create/file
// + /tasks/view/{id}). BaseURL empty disables the provider.
type CuckooConfig struct {
	// BaseURL is the Cuckoo REST API root, e.g.
	// "http://cuckoo.internal:8090". Empty disables the provider.
	BaseURL string
	// APIToken, when set, is sent as "Authorization: Bearer <token>"
	// (Cuckoo's api_token auth).
	APIToken string
	// MalscoreThreshold is the Cuckoo malscore (0..10) at or above
	// which a report is treated as malicious. Defaults to 5.0 when
	// zero. Scores between SuspiciousThreshold and this map to
	// suspicious.
	MalscoreThreshold float64
	// SuspiciousThreshold is the malscore at or above which a report
	// is at least suspicious. Defaults to 2.0 when zero.
	SuspiciousThreshold float64
}

// Cuckoo is the Cuckoo Sandbox provider.
type Cuckoo struct {
	cfg    CuckooConfig
	client HTTPDoer
}

// NewCuckoo builds the provider, defaulting the client and the
// score thresholds.
func NewCuckoo(cfg CuckooConfig, client HTTPDoer) *Cuckoo {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.MalscoreThreshold == 0 {
		cfg.MalscoreThreshold = 5.0
	}
	if cfg.SuspiciousThreshold == 0 {
		cfg.SuspiciousThreshold = 2.0
	}
	return &Cuckoo{cfg: cfg, client: client}
}

func (c *Cuckoo) ID() string { return "cuckoo" }

func (c *Cuckoo) configured() bool { return strings.TrimSpace(c.cfg.BaseURL) != "" }

func (c *Cuckoo) auth(req *http.Request) {
	if c.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	}
}

func (c *Cuckoo) url(path string) string {
	return strings.TrimRight(c.cfg.BaseURL, "/") + path
}

func (c *Cuckoo) Submit(ctx context.Context, f File) (SubmitResult, error) {
	if !c.configured() {
		return SubmitResult{}, ErrProviderUnavailable
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", fileName(f.Filename, f.SHA256))
	if err != nil {
		return SubmitResult{}, fmt.Errorf("cuckoo: form file: %w", err)
	}
	if _, err := part.Write(f.Content); err != nil {
		return SubmitResult{}, fmt.Errorf("cuckoo: write content: %w", err)
	}
	if err := mw.Close(); err != nil {
		return SubmitResult{}, fmt.Errorf("cuckoo: close writer: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/tasks/create/file"), &body)
	if err != nil {
		return SubmitResult{}, fmt.Errorf("cuckoo: build request: %w", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return SubmitResult{}, fmt.Errorf("cuckoo: submit: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SubmitResult{}, fmt.Errorf("cuckoo: submit status %d", resp.StatusCode)
	}
	var decoded struct {
		TaskID int64 `json:"task_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return SubmitResult{}, fmt.Errorf("cuckoo: decode submit: %w", err)
	}
	if decoded.TaskID == 0 {
		return SubmitResult{}, fmt.Errorf("cuckoo: submit returned no task_id")
	}
	return SubmitResult{SandboxID: fmt.Sprintf("%d", decoded.TaskID), Status: StatusPending}, nil
}

func (c *Cuckoo) Poll(ctx context.Context, sandboxID string) (PollResult, error) {
	if !c.configured() {
		return PollResult{}, ErrProviderUnavailable
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/tasks/view/"+sandboxID), nil)
	if err != nil {
		return PollResult{}, fmt.Errorf("cuckoo: build poll request: %w", err)
	}
	c.auth(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return PollResult{}, fmt.Errorf("cuckoo: poll: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return PollResult{}, fmt.Errorf("cuckoo: poll status %d", resp.StatusCode)
	}
	var decoded struct {
		Task struct {
			Status string `json:"status"`
		} `json:"task"`
		// Malscore is present once the report stage completes.
		Malscore *float64 `json:"malscore"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return PollResult{}, fmt.Errorf("cuckoo: decode poll: %w", err)
	}
	// Cuckoo task states: pending, running, completed, reported,
	// failed_analysis/failed_processing. Only "reported" carries a
	// final malscore.
	switch strings.ToLower(decoded.Task.Status) {
	case "reported":
		score := 0.0
		if decoded.Malscore != nil {
			score = *decoded.Malscore
		}
		return PollResult{
			Status:         StatusComplete,
			Classification: c.classify(score),
			Confidence:     NormalizeConfidence(score / 10.0),
			Summary:        fmt.Sprintf("cuckoo malscore %.1f/10", score),
			AnalyzedAt:     time.Now().UTC(),
		}, nil
	case "failed_analysis", "failed_processing":
		return PollResult{Status: StatusError}, nil
	default:
		return PollResult{Status: StatusPending}, nil
	}
}

func (c *Cuckoo) classify(malscore float64) Classification {
	switch {
	case malscore >= c.cfg.MalscoreThreshold:
		return ClassMalicious
	case malscore >= c.cfg.SuspiciousThreshold:
		return ClassSuspicious
	default:
		return ClassClean
	}
}
