package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// decodeChatRequest reads and decodes the OpenAI-compatible request
// body the provider sent so tests can assert on model/messages/tokens.
type chatRequest struct {
	Model    string `json:"model"`
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	MaxTokens   int     `json:"max_tokens"`
	Temperature float64 `json:"temperature"`
}

func decodeChatRequest(t *testing.T, r *http.Request) chatRequest {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	var cr chatRequest
	if err := json.Unmarshal(raw, &cr); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return cr
}

// okBody is a minimal valid chat-completions response.
func okBody(model, content string) string {
	return `{"model":"` + model + `","choices":[{"message":{"content":"` + content + `"}}],"usage":{"total_tokens":42}}`
}

func TestComplete_DefaultModelWhenUnset(t *testing.T) {
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotModel = decodeChatRequest(t, r).Model
		_, _ = io.WriteString(w, okBody(gotModel, "ok"))
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client()}
	resp, err := p.Complete(context.Background(), LLMRequest{Prompt: "hello", MaxTokens: 100})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotModel != DefaultModel {
		t.Fatalf("model: got %q want %q", gotModel, DefaultModel)
	}
	if DefaultModel != "Ternary-Bonsai-8B" {
		t.Fatalf("DefaultModel: got %q want Ternary-Bonsai-8B", DefaultModel)
	}
	if resp.TokenCount != 42 {
		t.Fatalf("token count: got %d want 42", resp.TokenCount)
	}
}

func TestComplete_ExplicitModelForwarded(t *testing.T) {
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotModel = decodeChatRequest(t, r).Model
		_, _ = io.WriteString(w, okBody(gotModel, "ok"))
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, Model: "custom-model", HTTP: srv.Client()}
	if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x", MaxTokens: 10}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotModel != "custom-model" {
		t.Fatalf("model: got %q want custom-model", gotModel)
	}
}

func TestComplete_MaxTokensDefaultWhenUnset(t *testing.T) {
	var gotMax int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMax = decodeChatRequest(t, r).MaxTokens
		_, _ = io.WriteString(w, okBody("m", "ok"))
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client()}
	// MaxTokens unset (0) -> defaultMaxResponseTokens.
	if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotMax != defaultMaxResponseTokens {
		t.Fatalf("max_tokens default: got %d want %d", gotMax, defaultMaxResponseTokens)
	}
}

func TestComplete_ExplicitMaxTokensNotClamped(t *testing.T) {
	var gotMax int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMax = decodeChatRequest(t, r).MaxTokens
		_, _ = io.WriteString(w, okBody("m", "ok"))
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client()}
	// A caller that needs a long structured output (e.g. policy JSON)
	// passes 2000 explicitly; it must be forwarded unchanged, not
	// clamped down to the 512 default.
	if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x", MaxTokens: 2000}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotMax != 2000 {
		t.Fatalf("max_tokens: got %d want 2000 (must not be clamped)", gotMax)
	}
}

func TestComplete_SystemPromptSelection(t *testing.T) {
	cases := []struct {
		name        string
		prefix      string
		family      string
		model       string
		wantSystem  string
		wantInfered string
	}{
		{name: "default general", wantSystem: systemPromptGeneral},
		{name: "explicit prefix wins", prefix: "CUSTOM PROMPT", family: ModelFamilyTernaryBonsai, wantSystem: "CUSTOM PROMPT"},
		{name: "ternary family", family: ModelFamilyTernaryBonsai, wantSystem: systemPromptTernaryBonsai},
		{name: "openai family", family: ModelFamilyOpenAICompat, wantSystem: systemPromptGeneral},
		{name: "auto infers bonsai from model", family: "auto", model: "Ternary-Bonsai-8B", wantSystem: systemPromptTernaryBonsai},
		{name: "empty infers bonsai from model", model: "ternary-bonsai-8b.Q4_K_M", wantSystem: systemPromptTernaryBonsai},
		{name: "auto non-bonsai model -> general", family: "auto", model: "llama3", wantSystem: systemPromptGeneral},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotSystem string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				cr := decodeChatRequest(t, r)
				for _, m := range cr.Messages {
					if m.Role == "system" {
						gotSystem = m.Content
					}
				}
				_, _ = io.WriteString(w, okBody("m", "ok"))
			}))
			defer srv.Close()

			p := &HTTPProvider{
				Endpoint:           srv.URL,
				HTTP:               srv.Client(),
				SystemPromptPrefix: tc.prefix,
				ModelFamily:        tc.family,
				Model:              tc.model,
			}
			if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x", MaxTokens: 10}); err != nil {
				t.Fatalf("Complete: %v", err)
			}
			if gotSystem != tc.wantSystem {
				t.Fatalf("system prompt: got %q want %q", gotSystem, tc.wantSystem)
			}
		})
	}
}

func TestComplete_RetriesOn5xxThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			http.Error(w, "model loading", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, okBody("m", "ok"))
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client(), RetryDelay: time.Millisecond}
	resp, err := p.Complete(context.Background(), LLMRequest{Prompt: "x", MaxTokens: 10})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Text != "ok" {
		t.Fatalf("text: got %q want ok", resp.Text)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("calls: got %d want 2 (1 retry)", got)
	}
}

func TestComplete_RetriesOn429(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			http.Error(w, "busy", http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, okBody("m", "ok"))
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client(), RetryDelay: time.Millisecond}
	if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x", MaxTokens: 10}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("calls: got %d want 2", got)
	}
}

func TestComplete_NoRetryOn4xx(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client(), RetryDelay: time.Millisecond}
	if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x", MaxTokens: 10}); err == nil {
		t.Fatal("expected error on 400, got nil")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("calls: got %d want 1 (no retry on 4xx)", got)
	}
}

func TestComplete_RetriesExhaustedReturnsError(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client(), MaxRetries: 2, RetryDelay: time.Millisecond}
	if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x", MaxTokens: 10}); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("calls: got %d want 3 (1 + 2 retries)", got)
	}
}

func TestComplete_RetriesDisabled(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client(), MaxRetries: -1}
	if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x", MaxTokens: 10}); err == nil {
		t.Fatal("expected error")
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("calls: got %d want 1 (retries disabled)", got)
	}
}

func TestComplete_NotConfigured(t *testing.T) {
	p := &HTTPProvider{}
	if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x"}); err == nil {
		t.Fatal("expected error when endpoint empty")
	}
}

func TestComplete_EmptyChoicesIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"model":"m","choices":[],"usage":{"total_tokens":0}}`)
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client()}
	if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x", MaxTokens: 10}); err == nil {
		t.Fatal("expected error on empty choices")
	}
}

func TestComplete_OversizeResponseRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"`))
		_, _ = w.Write([]byte(strings.Repeat("A", maxResponseBytes+10)))
	}))
	defer srv.Close()

	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client()}
	if _, err := p.Complete(context.Background(), LLMRequest{Prompt: "x", MaxTokens: 10}); err == nil {
		t.Fatal("expected oversize-response error")
	}
}

func TestComplete_ContextCancelStopsRetry(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel before the backoff wait elapses so the retry loop aborts.
	p := &HTTPProvider{Endpoint: srv.URL, HTTP: srv.Client(), MaxRetries: 3, RetryDelay: time.Hour}
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	if _, err := p.Complete(ctx, LLMRequest{Prompt: "x", MaxTokens: 10}); err == nil {
		t.Fatal("expected error from cancelled context")
	}
	// First attempt fires (1), then the loop waits on the 1h backoff and
	// is interrupted by cancel — so no further upstream calls.
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("calls: got %d want 1", got)
	}
}
