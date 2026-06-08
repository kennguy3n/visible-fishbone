package ai

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// EvidenceReader queries ClickHouse for recent alerts, baselines,
// and policy verdicts. Declared as an interface so the summarizer
// can be unit-tested without a ClickHouse instance.
type EvidenceReader interface {
	QueryEvidence(ctx context.Context, tenantID uuid.UUID, tr TimeRange) (TemplateData, error)
}

// Summarizer wraps an LLMProvider and an EvidenceReader to produce
// incident summaries. When the LLM is nil or fails, the
// deterministic template output is returned verbatim.
type Summarizer struct {
	llm        LLMProvider
	evidence   EvidenceReader
	logger     *slog.Logger
	maxLatency time.Duration
}

// SummarizerOption configures NewSummarizer.
type SummarizerOption func(*Summarizer)

// WithSummarizerLogger installs a non-default logger.
func WithSummarizerLogger(l *slog.Logger) SummarizerOption {
	return func(s *Summarizer) {
		if l != nil {
			s.logger = l
		}
	}
}

// WithMaxLatency sets the total time budget for a single
// summarization (template + LLM combined).
func WithMaxLatency(d time.Duration) SummarizerOption {
	return func(s *Summarizer) {
		if d > 0 {
			s.maxLatency = d
		}
	}
}

// NewSummarizer constructs a Summarizer. llm may be nil
// (template-only mode). evidence may be nil — Generate will
// produce a template summary with empty evidence data until a
// real EvidenceReader is wired.
func NewSummarizer(llm LLMProvider, evidence EvidenceReader, opts ...SummarizerOption) *Summarizer {
	s := &Summarizer{
		llm:        llm,
		evidence:   evidence,
		logger:     slog.Default(),
		maxLatency: 10 * time.Second,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Generate produces a summary for the given tenant and time range.
//
//  1. Query ClickHouse for recent evidence.
//  2. Build a deterministic template summary (always works).
//  3. If LLM is configured, polish within a time budget.
//  4. On any LLM failure, return template output verbatim.
//  5. Flag ai_generated accordingly.
func (s *Summarizer) Generate(ctx context.Context, tenantID uuid.UUID, tr TimeRange) (Summary, error) {
	start := time.Now()

	var data TemplateData
	if s.evidence != nil {
		var err error
		data, err = s.evidence.QueryEvidence(ctx, tenantID, tr)
		if err != nil {
			return Summary{}, fmt.Errorf("ai/summarizer: query evidence: %w", err)
		}
	}

	data.TenantID = tenantID.String()
	data.TimeRangeLabel = fmt.Sprintf("%s to %s",
		tr.Start.Format(time.RFC3339), tr.End.Format(time.RFC3339))

	// Step 2: deterministic template (always works).
	tmpl := RenderTemplate(data)
	tmpl.LatencyMS = time.Since(start).Milliseconds()

	// Step 3: if LLM configured, polish within budget.
	if s.llm == nil {
		return tmpl, nil
	}

	remaining := s.maxLatency - time.Since(start)
	if remaining <= 0 {
		s.logger.Warn("ai/summarizer: time budget exhausted before LLM call; returning template",
			slog.String("tenant_id", tenantID.String()))
		return tmpl, nil
	}

	llmCtx, cancel := context.WithTimeout(ctx, remaining)
	defer cancel()

	resp, err := s.llm.Complete(llmCtx, LLMRequest{
		Prompt:         buildSummarizerPrompt(tmpl.Text),
		TemperatureX10: 3,
		MaxTokens:      800,
	})
	if err != nil {
		s.logger.Warn("ai/summarizer: LLM failed; returning template output",
			slog.String("tenant_id", tenantID.String()),
			slog.String("error", err.Error()))
		return tmpl, nil
	}

	polished := Summary{
		Text:               resp.Text,
		KeyFindings:        tmpl.KeyFindings,
		RecommendedActions: tmpl.RecommendedActions,
		EvidenceRefs:       tmpl.EvidenceRefs,
		AIGenerated:        true,
		ModelID:            resp.ModelID,
		LatencyMS:          time.Since(start).Milliseconds(),
	}
	return polished, nil
}

func buildSummarizerPrompt(templateText string) string {
	return "You are a ShieldNet Gateway security analyst. " +
		"Polish the following template summary into a concise, professional narrative. " +
		"Do not invent data — only rephrase the evidence provided. " +
		"Preserve all key findings and recommended actions. " +
		"Respond with plain prose only — no headings or bullet points.\n\n" +
		"Template summary:\n" + templateText
}
