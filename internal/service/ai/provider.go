package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// maxResponseBytes caps the bytes accepted from an upstream LLM
// response. Defence-in-depth: even though the endpoint is
// operator-configured, a misconfigured or hostile proxy must not
// be able to exhaust the process heap with a single reply.
const maxResponseBytes = 1 << 20 // 1 MiB

// LLMProvider is the pluggable LLM caller. Production wires up
// HTTPProvider (OpenAI-compatible); tests wire up a deterministic
// stub.
type LLMProvider interface {
	Complete(ctx context.Context, req LLMRequest) (LLMResponse, error)
}

// LLMRequest is the input shape passed to an LLMProvider.
type LLMRequest struct {
	Prompt         string
	TemperatureX10 int // temperature * 10, integer to keep the type plain
	MaxTokens      int
}

// LLMResponse is the parsed output from an LLMProvider.
type LLMResponse struct {
	Text       string
	ModelID    string
	TokenCount int
}

// HTTPProvider is a minimal OpenAI-compatible client for the
// /v1/chat/completions endpoint. Mirrors the pattern from
// sn360-security-platform/services/soc-triage/internal/summarizer/llm.go.
type HTTPProvider struct {
	Endpoint string
	APIKey   string
	Model    string
	Timeout  time.Duration
	HTTP     *http.Client

	onceClient sync.Once
	client     *http.Client
}

func (p *HTTPProvider) httpClient() *http.Client {
	p.onceClient.Do(func() {
		if p.HTTP != nil {
			p.client = p.HTTP
			return
		}
		t := p.Timeout
		if t <= 0 {
			t = 8 * time.Second
		}
		p.client = &http.Client{Timeout: t}
	})
	return p.client
}

// Complete sends one chat-completion request and decodes the first
// choice's content. Returns a non-nil error on any transport
// failure, non-200 status, or empty response so callers can fall
// back to the deterministic template.
func (p *HTTPProvider) Complete(ctx context.Context, req LLMRequest) (LLMResponse, error) {
	if p == nil || p.Endpoint == "" {
		return LLMResponse{}, errors.New("ai: LLM not configured")
	}
	httpClient := p.httpClient()
	temperature := float64(req.TemperatureX10) / 10.0
	model := p.Model
	if model == "" {
		model = "gpt-4o-mini"
	}
	body := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": "You are a senior security analyst. Be concise, factual, and never invent data. Only reference evidence provided in the prompt."},
			{"role": "user", "content": req.Prompt},
		},
		"temperature": temperature,
		"max_tokens":  req.MaxTokens,
		"n":           1,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return LLMResponse{}, fmt.Errorf("marshal: %w", err)
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return LLMResponse{}, fmt.Errorf("new request: %w", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		hreq.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
	resp, err := httpClient.Do(hreq)
	if err != nil {
		return LLMResponse{}, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxResponseBytes)+1))
	if err != nil {
		return LLMResponse{}, fmt.Errorf("read body: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return LLMResponse{}, fmt.Errorf("oversize response: > %d bytes", maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return LLMResponse{}, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(raw), 200))
	}
	var parsed struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Usage struct {
			TotalTokens int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return LLMResponse{}, fmt.Errorf("decode: %w", err)
	}
	if len(parsed.Choices) == 0 || parsed.Choices[0].Message.Content == "" {
		return LLMResponse{}, errors.New("empty response")
	}
	return LLMResponse{
		Text:       parsed.Choices[0].Message.Content,
		ModelID:    parsed.Model,
		TokenCount: parsed.Usage.TotalTokens,
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
