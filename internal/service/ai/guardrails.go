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

// AuditSink is a narrow, optional durable sink for guardrail audit
// records. The in-memory ring buffer (exposed via Status/AuditLog) is
// always maintained for the live status endpoint and tests; when a
// sink is configured, every AI interaction is ALSO persisted durably
// (e.g. to the append-only audit-log service) so records survive
// process restarts and are queryable for compliance.
//
// The interface is declared here, rather than importing the audit
// service, so the ai package takes no dependency on it (avoiding an
// import cycle) and tests can stub it. A thin adapter in
// cmd/sng-control maps AuditRecord onto the audit service's Append.
type AuditSink interface {
	RecordAIAudit(ctx context.Context, rec AuditRecord) error
}

// BudgetGate is the slice of the cost-metering BudgetEnforcer the
// guardrails need: a pre-flight check that a tenant still has budget
// for an estimated number of LLM tokens. It returns a non-nil error
// (wrapping the budget-exceeded sentinel) only when the hard limit
// would be breached; a soft-limit crossing is allowed and handled
// (alerted) inside the enforcer.
//
// Declared here, rather than importing the metering package, so the ai
// package takes no dependency on it (mirroring AuditSink) and tests can
// stub it. A thin adapter in cmd/sng-control maps this onto
// metering.BudgetEnforcer.CheckBudget("llm_tokens_used", ...).
type BudgetGate interface {
	CheckLLMTokenBudget(ctx context.Context, tenantID uuid.UUID, estimatedTokens int64) error
}

// UsageRecorder meters the actual LLM consumption of a completed call
// (token count and a single call) so the cost-metering service can
// accumulate it. Failures are logged, never surfaced to the caller —
// metering must not break the live LLM path. A thin adapter in
// cmd/sng-control maps this onto metering.MeteringService.Record.
type UsageRecorder interface {
	RecordLLMUsage(ctx context.Context, tenantID uuid.UUID, tokens, calls int64) error
}

// GuardrailedProvider wraps an LLMProvider with guardrails:
// rate limiting, content filtering, output validation, and audit
// logging. The audit log is capped at maxAuditLogSize entries (ring buffer).
type GuardrailedProvider struct {
	inner        LLMProvider
	config       GuardrailConfig
	logger       *slog.Logger
	filters      []*regexp.Regexp
	auditSink    AuditSink
	budgetGate   BudgetGate
	costRecorder UsageRecorder

	mu        sync.Mutex
	usage     map[uuid.UUID]*tenantUsage
	auditLog  []AuditRecord
	lastSweep time.Time
}

// GuardrailOption customizes a GuardrailedProvider.
type GuardrailOption func(*GuardrailedProvider)

// WithAuditSink configures a durable sink that receives a copy of
// every guardrail audit record in addition to the in-memory ring
// buffer. When nil (the default) audit records are kept in memory
// only.
func WithAuditSink(sink AuditSink) GuardrailOption {
	return func(g *GuardrailedProvider) { g.auditSink = sink }
}

// WithBudgetGate wires the cost-metering budget pre-check into the LLM
// path. When set, every Complete call is gated on the tenant's LLM
// token budget before any tokens are spent. When nil (the default) the
// guardrails behave exactly as before.
func WithBudgetGate(gate BudgetGate) GuardrailOption {
	return func(g *GuardrailedProvider) { g.budgetGate = gate }
}

// WithUsageRecorder wires the cost-metering usage recorder so the
// actual token / call consumption of each successful completion is
// metered. When nil (the default) no metering is recorded.
func WithUsageRecorder(rec UsageRecorder) GuardrailOption {
	return func(g *GuardrailedProvider) { g.costRecorder = rec }
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
// inner must not be nil. Optional behaviour (e.g. a durable audit
// sink) is supplied via GuardrailOption.
func NewGuardrailedProvider(inner LLMProvider, cfg GuardrailConfig, logger *slog.Logger, opts ...GuardrailOption) *GuardrailedProvider {
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

	g := &GuardrailedProvider{
		inner:   inner,
		config:  cfg,
		logger:  logger,
		filters: filters,
		usage:   make(map[uuid.UUID]*tenantUsage),
	}
	for _, opt := range opts {
		opt(g)
	}
	return g
}

// Complete implements LLMProvider with guardrails applied.
func (g *GuardrailedProvider) Complete(ctx context.Context, req LLMRequest) (LLMResponse, error) {
	tenantID := tenantIDFromContext(ctx)
	start := time.Now()

	// Rate limiting.
	if err := g.checkRateLimit(tenantID); err != nil {
		g.recordAudit(ctx, tenantID, "", "complete", 0, time.Since(start), false, err.Error())
		return LLMResponse{}, err
	}

	// Cost-budget pre-check. Refuse to spend LLM tokens a tenant has no
	// budget for: on a hard-limit breach we return a template-only
	// fallback (no LLM call) with a user-visible note instead of an
	// error, so the AI feature degrades gracefully while security
	// enforcement is unaffected.
	estTokens := estimateLLMTokens(req)
	if g.budgetGate != nil {
		if err := g.budgetGate.CheckLLMTokenBudget(ctx, tenantID, estTokens); err != nil {
			g.recordAudit(ctx, tenantID, budgetFallbackModelID, "budget_blocked", 0, time.Since(start), false, err.Error())
			g.logger.WarnContext(ctx, "ai/guardrails: llm call blocked by cost budget",
				slog.String("tenant_id", tenantID.String()),
				slog.Int64("estimated_tokens", estTokens),
				slog.String("error", err.Error()))
			return budgetFallbackResponse(), nil
		}
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
		g.recordAudit(ctx, tenantID, "", "complete", 0, elapsed, redacted, err.Error())
		return LLMResponse{}, err
	}

	// Track token usage.
	g.trackTokens(tenantID, resp.TokenCount)

	// Meter the actual consumption for cost accounting (best-effort).
	g.recordLLMUsage(ctx, tenantID, int64(resp.TokenCount))

	g.recordAudit(ctx, tenantID, resp.ModelID, "complete", resp.TokenCount, elapsed, redacted, "")

	return resp, nil
}

// budgetFallbackModelID marks a response synthesised locally because
// the tenant's LLM budget was exhausted (no upstream model was called).
const budgetFallbackModelID = "budget-fallback"

// budgetFallbackNote is the user-visible message returned in place of
// an LLM completion when a tenant's hard LLM budget is exceeded.
const budgetFallbackNote = "AI assistance is temporarily unavailable for your account because your AI usage budget has been reached. Security enforcement is unaffected. Contact your administrator to raise the limit."

// budgetFallbackResponse builds the template-only fallback returned
// when a tenant's hard LLM budget is exceeded.
func budgetFallbackResponse() LLMResponse {
	return LLMResponse{Text: budgetFallbackNote, ModelID: budgetFallbackModelID, TokenCount: 0}
}

// estimateLLMTokens estimates the worst-case tokens a request will
// consume for the pre-flight budget check: a rough prompt estimate
// (~4 chars/token) plus the requested completion ceiling (MaxTokens),
// falling back to a conservative default completion size when MaxTokens
// is unset. Deliberately an upper bound so the budget gate errs toward
// protecting spend.
func estimateLLMTokens(req LLMRequest) int64 {
	promptTokens := int64(len(req.Prompt)/4) + 1
	completion := int64(req.MaxTokens)
	if completion <= 0 {
		completion = 256
	}
	return promptTokens + completion
}

// recordLLMUsage meters one completed LLM call (tokens + a single
// call) when a recorder is configured. Best-effort: a metering failure
// is logged, never returned, so cost accounting cannot break the live
// LLM path.
func (g *GuardrailedProvider) recordLLMUsage(ctx context.Context, tenantID uuid.UUID, tokens int64) {
	if g.costRecorder == nil {
		return
	}
	if err := g.costRecorder.RecordLLMUsage(ctx, tenantID, tokens, 1); err != nil {
		g.logger.WarnContext(ctx, "ai/guardrails: cost metering record failed",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
	}
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

func (g *GuardrailedProvider) recordAudit(ctx context.Context, tenantID uuid.UUID, model, action string, tokens int, latency time.Duration, redacted bool, errMsg string) {
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
	// Bounded ring buffer. Once at capacity, drop the oldest record by
	// shifting in place (copy) and reusing the same backing array,
	// rather than re-slicing with g.auditLog[1:] which would advance
	// the slice header off the front of the array and leak the head
	// region until the next append-driven reallocation.
	if len(g.auditLog) >= maxAuditLogSize {
		copy(g.auditLog, g.auditLog[1:])
		g.auditLog[len(g.auditLog)-1] = record
	} else {
		g.auditLog = append(g.auditLog, record)
	}
	g.mu.Unlock()

	g.logger.Info("ai/guardrails: audit",
		slog.String("tenant_id", tenantID.String()),
		slog.String("model", model),
		slog.String("action", action),
		slog.Int("tokens", tokens),
		slog.Int64("latency_ms", latency.Milliseconds()),
		slog.Bool("redacted", redacted))

	// Durably persist the record when a sink is configured so AI
	// interactions survive restarts and are queryable for compliance.
	// Persistence failures must not break the live LLM path: the call
	// already succeeded (or failed) on its own merits, so we log and
	// continue rather than surfacing the sink error to the caller.
	if g.auditSink != nil {
		if err := g.auditSink.RecordAIAudit(ctx, record); err != nil {
			g.logger.Warn("ai/guardrails: durable audit sink failed",
				slog.String("tenant_id", tenantID.String()),
				slog.String("error", err.Error()))
		}
	}
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
