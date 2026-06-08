package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

// GenericConfig configures the bring-your-own-sandbox webhook
// provider. An operator points it at any HTTP service that speaks
// the small JSON contract below, so SNG can integrate a sandbox we
// don't ship a first-class adapter for.
//
// Submit: multipart POST to SubmitURL with field "file"; the
// service responds 2xx with {"id": "<analysis id>"}.
//
// Poll: GET StatusURL with the id appended (StatusURL must end in a
// trailing slash or include the id placeholder "{id}"); the service
// responds {"status": "...", "classification": "...",
// "score": <0..1>, "summary": "..."}.
type GenericConfig struct {
	// SubmitURL is the multipart submission endpoint. Empty disables
	// the provider (Submit/Poll return ErrProviderUnavailable).
	SubmitURL string
	// StatusURL is the polling endpoint. If it contains "{id}" the
	// id is substituted there; otherwise the id is appended.
	StatusURL string
	// AuthHeader / AuthValue, when both set, are sent on every
	// request (e.g. "Authorization", "Bearer <token>").
	AuthHeader string
	AuthValue  string
}

// Generic is the BYO webhook sandbox provider.
type Generic struct {
	cfg    GenericConfig
	client HTTPDoer
}

// NewGeneric builds the provider. A nil client falls back to a
// http.Client with a conservative timeout. An empty SubmitURL
// yields a provider that reports itself unavailable, so wiring it
// unconfigured is safe.
func NewGeneric(cfg GenericConfig, client HTTPDoer) *Generic {
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Generic{cfg: cfg, client: client}
}

func (g *Generic) ID() string { return "generic" }

func (g *Generic) configured() bool {
	return strings.TrimSpace(g.cfg.SubmitURL) != "" && strings.TrimSpace(g.cfg.StatusURL) != ""
}

func (g *Generic) auth(req *http.Request) {
	if g.cfg.AuthHeader != "" && g.cfg.AuthValue != "" {
		req.Header.Set(g.cfg.AuthHeader, g.cfg.AuthValue)
	}
}

func (g *Generic) Submit(ctx context.Context, f File) (SubmitResult, error) {
	if !g.configured() {
		return SubmitResult{}, ErrProviderUnavailable
	}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	part, err := mw.CreateFormFile("file", fileName(f.Filename, f.SHA256))
	if err != nil {
		return SubmitResult{}, fmt.Errorf("generic: form file: %w", err)
	}
	if _, err := part.Write(f.Content); err != nil {
		return SubmitResult{}, fmt.Errorf("generic: write content: %w", err)
	}
	if err := mw.WriteField("sha256", f.SHA256); err != nil {
		return SubmitResult{}, fmt.Errorf("generic: write sha256: %w", err)
	}
	// Forward the magic-byte-detected file type so the BYO sandbox
	// can route the sample to the right analysis environment.
	if err := mw.WriteField("filetype", string(f.DetectedType())); err != nil {
		return SubmitResult{}, fmt.Errorf("generic: write filetype: %w", err)
	}
	if err := mw.Close(); err != nil {
		return SubmitResult{}, fmt.Errorf("generic: close writer: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.SubmitURL, &body)
	if err != nil {
		return SubmitResult{}, fmt.Errorf("generic: build request: %w", err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	g.auth(req)

	resp, err := g.client.Do(req)
	if err != nil {
		return SubmitResult{}, fmt.Errorf("generic: submit: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return SubmitResult{}, fmt.Errorf("generic: submit status %d", resp.StatusCode)
	}
	var decoded struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return SubmitResult{}, fmt.Errorf("generic: decode submit: %w", err)
	}
	if decoded.ID == "" {
		return SubmitResult{}, fmt.Errorf("generic: submit returned empty id")
	}
	return SubmitResult{SandboxID: decoded.ID, Status: StatusPending}, nil
}

func (g *Generic) Poll(ctx context.Context, sandboxID string) (PollResult, error) {
	if !g.configured() {
		return PollResult{}, ErrProviderUnavailable
	}
	url := g.cfg.StatusURL
	if strings.Contains(url, "{id}") {
		url = strings.ReplaceAll(url, "{id}", sandboxID)
	} else {
		if !strings.HasSuffix(url, "/") {
			url += "/"
		}
		url += sandboxID
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return PollResult{}, fmt.Errorf("generic: build poll request: %w", err)
	}
	g.auth(req)

	resp, err := g.client.Do(req)
	if err != nil {
		return PollResult{}, fmt.Errorf("generic: poll: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return PollResult{}, fmt.Errorf("generic: poll status %d", resp.StatusCode)
	}
	var decoded struct {
		Status         string  `json:"status"`
		Classification string  `json:"classification"`
		Score          float64 `json:"score"`
		Summary        string  `json:"summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return PollResult{}, fmt.Errorf("generic: decode poll: %w", err)
	}
	status := parseStatus(decoded.Status)
	out := PollResult{
		Status:     status,
		Confidence: NormalizeConfidence(decoded.Score),
		Summary:    decoded.Summary,
	}
	if status == StatusComplete {
		out.Classification = parseClassification(decoded.Classification)
		out.AnalyzedAt = time.Now().UTC()
	}
	return out, nil
}

// parseStatus maps the webhook's free-form status string onto the
// provider Status enum, defaulting to pending so an unknown value
// keeps the caller polling rather than wrongly resolving.
func parseStatus(s string) Status {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "complete", "completed", "done", "finished", "reported":
		return StatusComplete
	case "error", "failed", "failure":
		return StatusError
	default:
		return StatusPending
	}
}

// parseClassification maps the webhook's verdict string onto the
// Classification enum, defaulting to suspicious for an unrecognised
// value so an unexpected disposition fails toward caution rather
// than being silently treated as clean.
func parseClassification(s string) Classification {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "clean", "benign", "ok":
		return ClassClean
	case "malicious", "malware", "bad":
		return ClassMalicious
	case "timeout":
		return ClassTimeout
	case "suspicious", "":
		return ClassSuspicious
	default:
		return ClassSuspicious
	}
}

// fileName picks a stable upload name: the original filename if
// present, else the digest (so the sandbox report is still keyed to
// something meaningful).
func fileName(name, sha string) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	return sha
}

// drain reads and closes the response body so the underlying
// connection can be reused by keep-alive.
func drain(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
}
