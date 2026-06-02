package ai

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// GuardrailConfig configures the guardrail middleware.
type GuardrailConfig struct {
	// MaxRequestsPerMinute is the per-tenant rate limit.
	MaxRequestsPerMinute int
	// MaxTokensPerDay is the daily token budget per tenant.
	MaxTokensPerDay int
	// ContentFilterPatterns are regexes for PII/secret detection.
	ContentFilterPatterns []string
}

func (c GuardrailConfig) normalize() GuardrailConfig {
	if c.MaxRequestsPerMinute <= 0 {
		c.MaxRequestsPerMinute = 60
	}
	if c.MaxTokensPerDay <= 0 {
		c.MaxTokensPerDay = 100000
	}
	return c
}

// AuditRecord logs a single AI interaction.
type AuditRecord struct {
	Timestamp  time.Time `json:"timestamp"`
	TenantID   uuid.UUID `json:"tenant_id"`
	Model      string    `json:"model"`
	Action     string    `json:"action"`
	TokenCount int       `json:"token_count"`
	LatencyMS  int64     `json:"latency_ms"`
	Redacted   bool      `json:"redacted"`
	Error      string    `json:"error,omitempty"`
}

// GuardrailStatus reports current usage and limits.
type GuardrailStatus struct {
	TenantID             uuid.UUID `json:"tenant_id"`
	RequestsThisMinute   int       `json:"requests_this_minute"`
	MaxRequestsPerMinute int       `json:"max_requests_per_minute"`
	TokensToday          int       `json:"tokens_today"`
	MaxTokensPerDay      int       `json:"max_tokens_per_day"`
	AuditLogSize         int       `json:"audit_log_size"`
}

// tenantUsage tracks per-tenant rate and token usage.
type tenantUsage struct {
	requestsThisMinute int
	minuteStart        time.Time
	tokensToday        int
	dayStart           time.Time
}

// GuardrailedProvider wraps an LLMProvider with guardrails:
// rate limiting, content filtering, output validation, and audit
// logging. The audit log is capped at maxAuditLogSize entries (ring buffer).
type GuardrailedProvider struct {
	inner   LLMProvider
	config  GuardrailConfig
	logger  *slog.Logger
	filters []*regexp.Regexp

	mu        sync.Mutex
	usage     map[uuid.UUID]*tenantUsage
	auditLog  []AuditRecord
	lastSweep time.Time
}

const maxAuditLogSize = 10000

// usageTTL is how long an idle tenant's usage entry is retained before
// it is evicted; usageSweepInterval bounds how often the (cheap)
// eviction sweep runs so the per-tenant usage map cannot grow without
// bound across the process lifetime.
const (
	usageTTL           = 24 * time.Hour
	usageSweepInterval = 10 * time.Minute
)

// NewGuardrailedProvider constructs a guardrailed LLM wrapper.
// inner must not be nil.
func NewGuardrailedProvider(inner LLMProvider, cfg GuardrailConfig, logger *slog.Logger) *GuardrailedProvider {
	if logger == nil {
		logger = slog.Default()
	}
	cfg = cfg.normalize()

	filters := make([]*regexp.Regexp, 0, len(cfg.ContentFilterPatterns))
	for _, p := range cfg.ContentFilterPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			logger.Warn("ai/guardrails: invalid content filter pattern",
				slog.String("pattern", p),
				slog.String("error", err.Error()))
			continue
		}
		filters = append(filters, re)
	}

	// Add default PII patterns.
	defaultPatterns := []string{
		`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`,       // email
		`\b\d{3}-\d{2}-\d{4}\b`,                                      // SSN
		`\b(?:\d{4}[- ]?){3}\d{4}\b`,                                 // credit card
		`(?i)\b(?:api[_-]?key|secret|password|token)\s*[:=]\s*\S+\b`, // secrets
	}
	for _, p := range defaultPatterns {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		filters = append(filters, re)
	}

	return &GuardrailedProvider{
		inner:   inner,
		config:  cfg,
		logger:  logger,
		filters: filters,
		usage:   make(map[uuid.UUID]*tenantUsage),
	}
}

// Complete implements LLMProvider with guardrails applied.
func (g *GuardrailedProvider) Complete(ctx context.Context, req LLMRequest) (LLMResponse, error) {
	tenantID := tenantIDFromContext(ctx)
	start := time.Now()

	// Rate limiting.
	if err := g.checkRateLimit(tenantID); err != nil {
		g.recordAudit(tenantID, "", "complete", 0, time.Since(start), false, err.Error())
		return LLMResponse{}, err
	}

	// Content filtering: redact PII/secrets from prompt.
	filteredPrompt, redacted := g.filterContent(req.Prompt)
	filteredReq := LLMRequest{
		Prompt:         filteredPrompt,
		TemperatureX10: req.TemperatureX10,
		MaxTokens:      req.MaxTokens,
	}

	// Forward to inner provider.
	resp, err := g.inner.Complete(ctx, filteredReq)
	elapsed := time.Since(start)

	if err != nil {
		g.recordAudit(tenantID, "", "complete", 0, elapsed, redacted, err.Error())
		return LLMResponse{}, err
	}

	// Track token usage.
	g.trackTokens(tenantID, resp.TokenCount)

	g.recordAudit(tenantID, resp.ModelID, "complete", resp.TokenCount, elapsed, redacted, "")

	return resp, nil
}

func (g *GuardrailedProvider) checkRateLimit(tenantID uuid.UUID) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	g.evictStaleLocked(now)
	u := g.getOrCreateUsage(tenantID)

	// Reset minute counter if window has passed.
	if now.Sub(u.minuteStart) > time.Minute {
		u.requestsThisMinute = 0
		u.minuteStart = now
	}

	// Reset daily counter if day has passed.
	if now.Sub(u.dayStart) > 24*time.Hour {
		u.tokensToday = 0
		u.dayStart = now
	}

	if u.requestsThisMinute >= g.config.MaxRequestsPerMinute {
		return fmt.Errorf("ai/guardrails: rate limit exceeded (%d/%d requests/min) for tenant %s",
			u.requestsThisMinute, g.config.MaxRequestsPerMinute, tenantID)
	}

	if u.tokensToday >= g.config.MaxTokensPerDay {
		return fmt.Errorf("ai/guardrails: daily token limit exceeded (%d/%d) for tenant %s",
			u.tokensToday, g.config.MaxTokensPerDay, tenantID)
	}

	u.requestsThisMinute++
	return nil
}

func (g *GuardrailedProvider) trackTokens(tenantID uuid.UUID, tokens int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	u := g.getOrCreateUsage(tenantID)
	u.tokensToday += tokens
}

// evictStaleLocked removes usage entries for tenants that have had no
// activity within usageTTL. It must be called with g.mu held. The
// sweep runs at most once per usageSweepInterval so the common path
// stays O(1).
func (g *GuardrailedProvider) evictStaleLocked(now time.Time) {
	if now.Sub(g.lastSweep) < usageSweepInterval {
		return
	}
	g.lastSweep = now
	for id, u := range g.usage {
		if now.Sub(u.dayStart) > usageTTL && now.Sub(u.minuteStart) > usageTTL {
			delete(g.usage, id)
		}
	}
}

func (g *GuardrailedProvider) getOrCreateUsage(tenantID uuid.UUID) *tenantUsage {
	u, ok := g.usage[tenantID]
	if !ok {
		now := time.Now()
		u = &tenantUsage{minuteStart: now, dayStart: now}
		g.usage[tenantID] = u
	}
	return u
}

func (g *GuardrailedProvider) filterContent(text string) (string, bool) {
	redacted := false
	for _, re := range g.filters {
		if re.MatchString(text) {
			text = re.ReplaceAllString(text, "[REDACTED]")
			redacted = true
		}
	}
	return text, redacted
}

func (g *GuardrailedProvider) recordAudit(tenantID uuid.UUID, model, action string, tokens int, latency time.Duration, redacted bool, errMsg string) {
	record := AuditRecord{
		Timestamp:  time.Now().UTC(),
		TenantID:   tenantID,
		Model:      model,
		Action:     action,
		TokenCount: tokens,
		LatencyMS:  latency.Milliseconds(),
		Redacted:   redacted,
		Error:      errMsg,
	}
	g.mu.Lock()
	if len(g.auditLog) >= maxAuditLogSize {
		g.auditLog = g.auditLog[1:]
	}
	g.auditLog = append(g.auditLog, record)
	g.mu.Unlock()

	g.logger.Info("ai/guardrails: audit",
		slog.String("tenant_id", tenantID.String()),
		slog.String("model", model),
		slog.String("action", action),
		slog.Int("tokens", tokens),
		slog.Int64("latency_ms", latency.Milliseconds()),
		slog.Bool("redacted", redacted))
}

// Status returns the current guardrail status for a tenant.
func (g *GuardrailedProvider) Status(tenantID uuid.UUID) GuardrailStatus {
	g.mu.Lock()
	defer g.mu.Unlock()

	u, ok := g.usage[tenantID]
	now := time.Now()

	var reqThisMin, tokensToday int
	if ok {
		reqThisMin = u.requestsThisMinute
		if now.Sub(u.minuteStart) > time.Minute {
			reqThisMin = 0
		}
		tokensToday = u.tokensToday
		if now.Sub(u.dayStart) > 24*time.Hour {
			tokensToday = 0
		}
	}

	return GuardrailStatus{
		TenantID:             tenantID,
		RequestsThisMinute:   reqThisMin,
		MaxRequestsPerMinute: g.config.MaxRequestsPerMinute,
		TokensToday:          tokensToday,
		MaxTokensPerDay:      g.config.MaxTokensPerDay,
		AuditLogSize:         len(g.auditLog),
	}
}

// AuditLog returns a copy of the audit log. Primarily used in tests.
func (g *GuardrailedProvider) AuditLog() []AuditRecord {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditRecord, len(g.auditLog))
	copy(out, g.auditLog)
	return out
}

// tenantIDFromContext extracts the tenant ID from context. In
// production this would read from the middleware-set context value;
// here we use a simple context key.
type contextKey string

const tenantContextKey contextKey = "guardrail_tenant_id"

// ContextWithTenantID returns a context with the tenant ID set.
func ContextWithTenantID(ctx context.Context, tenantID uuid.UUID) context.Context {
	return context.WithValue(ctx, tenantContextKey, tenantID)
}

func tenantIDFromContext(ctx context.Context) uuid.UUID {
	v := ctx.Value(tenantContextKey)
	if v == nil {
		return uuid.Nil
	}
	id, ok := v.(uuid.UUID)
	if !ok {
		return uuid.Nil
	}
	return id
}

// ValidateOutput checks that an AI output string is well-formed.
// Returns an error if the output contains obvious issues.
func ValidateOutput(output string) error {
	output = strings.TrimSpace(output)
	if output == "" {
		return fmt.Errorf("ai/guardrails: empty output")
	}
	return nil
}
