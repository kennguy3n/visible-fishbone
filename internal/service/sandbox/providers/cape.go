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

// CAPEConfig configures the CAPEv2 adapter against the CAPEv2 REST
// API (apiv2): POST /apiv2/tasks/create/file/, GET
// /apiv2/tasks/status/{id}/, GET /apiv2/tasks/get/report/{id}/.
// BaseURL empty disables the provider.
type CAPEConfig struct {
	// BaseURL is the CAPEv2 root, e.g. "https://cape.internal".
	// Empty disables the provider.
	BaseURL string
	// APIToken, when set, is sent as "Authorization: Token <token>"
	// (CAPEv2's DRF token auth).
	APIToken string
	// MalscoreThreshold is the CAPE malscore (0..10) at or above
	// which a report is malicious. Defaults to 5.0.
	MalscoreThreshold float64
	// SuspiciousThreshold is the malscore at or above which a report
	// is at least suspicious. Defaults to 2.0.
	SuspiciousThreshold float64
}

// CAPE is the CAPEv2 sandbox provider.
type CAPE struct {
	cfg    CAPEConfig
	client HTTPDoer
}

// NewCAPE builds the provider, defaulting the client and thresholds.
func NewCAPE(cfg CAPEConfig, client HTTPDoer) *CAPE {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.MalscoreThreshold == 0 {
		cfg.MalscoreThreshold = 5.0
	}
	if cfg.SuspiciousThreshold == 0 {
		cfg.SuspiciousThreshold = 2.0
	}
	return &CAPE{cfg: cfg, client: client}
}

func (c *CAPE) ID() string { return "cape" }

func (c *CAPE) configured() bool { return strings.TrimSpace(c.cfg.BaseURL) != "" }

func (c *CAPE) auth(req *http.Request) {
	if c.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Token "+c.cfg.APIToken)
	}
}

func (c *CAPE) url(path string) string {
	return strings.TrimRight(c.cfg.BaseURL, "/") + path
}

func (c *CAPE) Submit(ctx context.Context, f File) (SubmitResult, error) {
	if !c.configured() {
		return SubmitResult{}, ErrProviderUnavailable
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", fileName(f.Filename, f.SHA256))
	if err != nil {
		return SubmitResult{}, fmt.Errorf("cape: form file: %w", err)
	}
	if _, err := part.Write(f.Content); err != nil {
		return SubmitResult{}, fmt.Errorf("cape: write content: %w", err)
	}
	if err := mw.Close(); err != nil {
		return SubmitResult{}, fmt.Errorf("cape: close writer: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/apiv2/tasks/create/file/"), &body)
	if err != nil {
		return SubmitResult{}, fmt.Errorf("cape: build request: %w", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	c.auth(req)

	resp, err := c.client.Do(req)
	if err != nil {
		return SubmitResult{}, fmt.Errorf("cape: submit: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SubmitResult{}, fmt.Errorf("cape: submit status %d", resp.StatusCode)
	}
	// CAPEv2 returns {"error": false, "data": {"task_ids": [N]}} or
	// the older {"task_id": N}. Accept both.
	var decoded struct {
		Data struct {
			TaskIDs []int64 `json:"task_ids"`
		} `json:"data"`
		TaskID int64 `json:"task_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return SubmitResult{}, fmt.Errorf("cape: decode submit: %w", err)
	}
	id := decoded.TaskID
	if id == 0 && len(decoded.Data.TaskIDs) > 0 {
		id = decoded.Data.TaskIDs[0]
	}
	if id == 0 {
		return SubmitResult{}, fmt.Errorf("cape: submit returned no task id")
	}
	return SubmitResult{SandboxID: fmt.Sprintf("%d", id), Status: StatusPending}, nil
}

func (c *CAPE) Poll(ctx context.Context, sandboxID string) (PollResult, error) {
	if !c.configured() {
		return PollResult{}, ErrProviderUnavailable
	}
	// First check status; only fetch the (large) report when done.
	statusReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/apiv2/tasks/status/"+sandboxID+"/"), nil)
	if err != nil {
		return PollResult{}, fmt.Errorf("cape: build status request: %w", err)
	}
	c.auth(statusReq)
	statusResp, err := c.client.Do(statusReq)
	if err != nil {
		return PollResult{}, fmt.Errorf("cape: status: %w", err)
	}
	defer drain(statusResp)
	if statusResp.StatusCode < 200 || statusResp.StatusCode >= 300 {
		return PollResult{}, fmt.Errorf("cape: status %d", statusResp.StatusCode)
	}
	var st struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(statusResp.Body).Decode(&st); err != nil {
		return PollResult{}, fmt.Errorf("cape: decode status: %w", err)
	}
	switch strings.ToLower(st.Data) {
	case "reported":
		return c.fetchReport(ctx, sandboxID)
	case "failed_analysis", "failed_processing":
		return PollResult{Status: StatusError}, nil
	default:
		return PollResult{Status: StatusPending}, nil
	}
}

func (c *CAPE) fetchReport(ctx context.Context, sandboxID string) (PollResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/apiv2/tasks/get/report/"+sandboxID+"/"), nil)
	if err != nil {
		return PollResult{}, fmt.Errorf("cape: build report request: %w", err)
	}
	c.auth(req)
	resp, err := c.client.Do(req)
	if err != nil {
		return PollResult{}, fmt.Errorf("cape: report: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return PollResult{}, fmt.Errorf("cape: report status %d", resp.StatusCode)
	}
	var rep struct {
		Malscore *float64 `json:"malscore"`
		Info     struct {
			Score *float64 `json:"score"`
		} `json:"info"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return PollResult{}, fmt.Errorf("cape: decode report: %w", err)
	}
	score := 0.0
	switch {
	case rep.Malscore != nil:
		score = *rep.Malscore
	case rep.Info.Score != nil:
		score = *rep.Info.Score
	}
	return PollResult{
		Status:         StatusComplete,
		Classification: c.classify(score),
		Confidence:     NormalizeConfidence(score / 10.0),
		Summary:        fmt.Sprintf("cape malscore %.1f/10", score),
		AnalyzedAt:     time.Now().UTC(),
	}, nil
}

func (c *CAPE) classify(malscore float64) Classification {
	switch {
	case malscore >= c.cfg.MalscoreThreshold:
		return ClassMalicious
	case malscore >= c.cfg.SuspiciousThreshold:
		return ClassSuspicious
	default:
		return ClassClean
	}
}
