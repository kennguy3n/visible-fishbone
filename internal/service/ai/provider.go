package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// maxResponseBytes caps the bytes accepted from an upstream LLM
// response. Defence-in-depth: even though the endpoint is
// operator-configured, a misconfigured or hostile proxy must not
// be able to exhaust the process heap with a single reply.
const maxResponseBytes = 1 << 20 // 1 MiB

// DefaultModel is the served model name used when AI_LLM_MODEL is
// unset but an endpoint is configured. ShieldNet self-hosts
// Ternary-Bonsai-8B — a quantized 8B model that runs on commodity
// hardware via llama.cpp / Ollama / vLLM. The source bundle is
// https://huggingface.co/prism-ml/Ternary-Bonsai-8B-gguf; the value
// here is the served model name (the tag you pull into Ollama or pass
// to llama-server), not the HuggingFace repo path.
const DefaultModel = "Ternary-Bonsai-8B"

// defaultTimeout is the per-call HTTP timeout. Local quantized
// inference is meaningfully slower than a hosted API call (a 512-token
// reply is ~2–5s on a 4-core CPU), so the default is higher than a
// typical cloud-API client would use.
const defaultTimeout = 15 * time.Second

// defaultMaxResponseTokens caps the completion length when a caller
// does not specify one. 512 keeps 8B-class models in their
// high-quality regime; callers that genuinely need a longer structured
// output (e.g. the policy-graph JSON in SuggestPolicy) set MaxTokens
// explicitly and are intentionally NOT clamped here.
const defaultMaxResponseTokens = 512

// Retry defaults for transient local-model failures. Local inference
// servers (Ollama/llama.cpp) can briefly 503 while loading a model or
// while a previous request drains, so a single short retry materially
// improves reliability without masking real outages.
const (
	defaultMaxRetries = 1
	defaultRetryDelay = 2 * time.Second
	// maxBackoffShift caps the exponential-backoff left-shift so a large
	// MaxRetries cannot overflow the int64 time.Duration. 2s << 16 ≈ 36h,
	// already past any realistic request deadline.
	maxBackoffShift = 16
)

// Recognised model families. The family selects a built-in system
// prompt tuned for the model's strengths when SystemPromptPrefix is not
// set. A smaller local model (Ternary-Bonsai) benefits from terser,
// more structured framing than a hosted GPT-class model.
const (
	ModelFamilyTernaryBonsai = "ternary-bonsai"
	ModelFamilyOpenAICompat  = "openai-compat"
)

// systemPromptGeneral is the general-purpose system prompt used for
// hosted / larger OpenAI-compatible models.
const systemPromptGeneral = "You are a senior security analyst. Be concise, factual, and never invent data. Only reference evidence provided in the prompt."

// systemPromptTernaryBonsai is tuned for the self-hosted 8B model:
// shorter, with an explicit instruction to emit JSON when asked, since
// smaller models need more direct formatting guidance.
const systemPromptTernaryBonsai = "You are a security analyst. Respond in JSON when asked. Be concise and factual. Only reference provided evidence."

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

	// SystemPromptPrefix, when non-empty, replaces the built-in system
	// prompt entirely. Lets operators tune prompt framing per model
	// without recompiling.
	SystemPromptPrefix string

	// ModelFamily selects a built-in system prompt tuned for the
	// model when SystemPromptPrefix is empty. Recognised values are
	// ModelFamilyTernaryBonsai and ModelFamilyOpenAICompat; an empty
	// value or "auto" infers the family from the model name.
	ModelFamily string

	// MaxRetries is the number of ADDITIONAL attempts after the first
	// on a transient failure (transport error, HTTP 429, or 5xx). Zero
	// uses defaultMaxRetries; a negative value disables retries.
	MaxRetries int

	// RetryDelay is the base backoff between attempts and doubles each
	// retry (exponential backoff). Zero/negative uses defaultRetryDelay.
	RetryDelay time.Duration

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
			t = defaultTimeout
		}
		p.client = &http.Client{Timeout: t}
	})
	return p.client
}

// family resolves the effective model family, inferring it from the
// model name when ModelFamily is empty or "auto".
func (p *HTTPProvider) family() string {
	mf := strings.ToLower(strings.TrimSpace(p.ModelFamily))
	if mf != "" && mf != "auto" {
		return mf
	}
	m := strings.ToLower(p.Model)
	if strings.Contains(m, "bonsai") || strings.Contains(m, "ternary") {
		return ModelFamilyTernaryBonsai
	}
	return ModelFamilyOpenAICompat
}

// effectiveSystemPrompt returns the system message for a request: the
// operator override when set, otherwise the family-tuned default.
func (p *HTTPProvider) effectiveSystemPrompt() string {
	if p.SystemPromptPrefix != "" {
		return p.SystemPromptPrefix
	}
	if p.family() == ModelFamilyTernaryBonsai {
		return systemPromptTernaryBonsai
	}
	return systemPromptGeneral
}

// buildPayload marshals one chat-completion request body. When the
// caller leaves MaxTokens unset it is defaulted to
// defaultMaxResponseTokens; an explicit value is forwarded unchanged.
func (p *HTTPProvider) buildPayload(req LLMRequest) ([]byte, error) {
	temperature := float64(req.TemperatureX10) / 10.0
	model := p.Model
	if model == "" {
		model = DefaultModel
	}
	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = defaultMaxResponseTokens
	}
	body := map[string]any{
		"model": model,
		"messages": []map[string]string{
			{"role": "system", "content": p.effectiveSystemPrompt()},
			{"role": "user", "content": req.Prompt},
		},
		"temperature": temperature,
		"max_tokens":  maxTokens,
		"n":           1,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	return payload, nil
}

// Complete sends one chat-completion request and decodes the first
// choice's content, retrying transient failures with exponential
// backoff. Returns a non-nil error on any persistent transport
// failure, non-200 status, or empty response so callers can fall back
// to the deterministic template.
func (p *HTTPProvider) Complete(ctx context.Context, req LLMRequest) (LLMResponse, error) {
	if p == nil || p.Endpoint == "" {
		return LLMResponse{}, errors.New("ai: LLM not configured")
	}
	payload, err := p.buildPayload(req)
	if err != nil {
		return LLMResponse{}, err
	}

	maxRetries := p.MaxRetries
	if maxRetries == 0 {
		maxRetries = defaultMaxRetries
	}
	if maxRetries < 0 {
		maxRetries = 0
	}
	delay := p.RetryDelay
	if delay <= 0 {
		delay = defaultRetryDelay
	}

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff; abort early if the caller's context
			// is already done so we never sleep past a deadline. Use an
			// explicit timer so it can be stopped on the cancel path
			// rather than leaking until expiry (time.After cannot).
			//
			// Cap the shift so a large MaxRetries can't overflow the
			// int64 Duration (which would wrap negative and fire the
			// timer immediately). At shift 16 the delay is already
			// ~2s<<16 ≈ 36h — far beyond any sane request deadline — so
			// clamping here changes nothing for realistic configs.
			shift := attempt - 1
			if shift > maxBackoffShift {
				shift = maxBackoffShift
			}
			wait := delay << shift
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return LLMResponse{}, ctx.Err()
			case <-timer.C:
			}
		}
		resp, retryable, callErr := p.doRequest(ctx, payload)
		if callErr == nil {
			return resp, nil
		}
		lastErr = callErr
		if !retryable {
			return LLMResponse{}, callErr
		}
	}
	return LLMResponse{}, fmt.Errorf("ai: llm call failed after %d attempt(s): %w", maxRetries+1, lastErr)
}

// doRequest performs a single chat-completion attempt. The boolean
// return reports whether the failure is transient and worth retrying
// (transport error with a live context, HTTP 429, or 5xx).
func (p *HTTPProvider) doRequest(ctx context.Context, payload []byte) (LLMResponse, bool, error) {
	httpClient := p.httpClient()
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint, bytes.NewReader(payload))
	if err != nil {
		return LLMResponse{}, false, fmt.Errorf("new request: %w", err)
	}
	hreq.Header.Set("Content-Type", "application/json")
	if p.APIKey != "" {
		hreq.Header.Set("Authorization", "Bearer "+p.APIKey)
	}
	resp, err := httpClient.Do(hreq)
	if err != nil {
		// A transport failure is transient and worth retrying unless
		// the caller's context was cancelled / timed out, in which
		// case retrying is pointless.
		if ctx.Err() != nil {
			return LLMResponse{}, false, fmt.Errorf("http: %w", err)
		}
		return LLMResponse{}, true, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, int64(maxResponseBytes)+1))
	if err != nil {
		return LLMResponse{}, true, fmt.Errorf("read body: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return LLMResponse{}, false, fmt.Errorf("oversize response: > %d bytes", maxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		// 429 (rate limited / model busy) and 5xx (server-side) are
		// transient; 4xx other than 429 indicates a bad request that
		// will fail identically on retry.
		retryable := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return LLMResponse{}, retryable, fmt.Errorf("status %d: %s", resp.StatusCode, truncate(string(raw), 200))
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
		return LLMResponse{}, false, fmt.Errorf("decode: %w", err)
	}
	if len(parsed.Choices) == 0 || parsed.Choices[0].Message.Content == "" {
		return LLMResponse{}, false, errors.New("empty response")
	}
	return LLMResponse{
		Text:       parsed.Choices[0].Message.Content,
		ModelID:    parsed.Model,
		TokenCount: parsed.Usage.TotalTokens,
	}, false, nil
}

func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + "…"
}
