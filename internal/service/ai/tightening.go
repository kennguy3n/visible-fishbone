package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// maxCachedReports bounds the per-tenant report cache so it cannot
// grow without limit in a long-running multi-tenant process. When the
// cap is reached the oldest cached tenant is evicted (FIFO); an
// evicted tenant simply re-runs analysis (the GET endpoint returns
// 404 until it does), so eviction is never a correctness problem.
const maxCachedReports = 1024

// TighteningService identifies rules that can be tightened:
// unused rules, shadowed rules, and overly-permissive rules.
type TighteningService struct {
	llm    LLMProvider
	logger *slog.Logger

	// lastReports caches the most recent analysis report per tenant
	// so the GET report endpoint can return the result of the most
	// recent POST analyze run instead of an empty placeholder. It is
	// bounded by maxCachedReports with FIFO eviction tracked by
	// reportOrder. This is a best-effort, single-instance cache: in a
	// horizontally-scaled deployment a GET may land on an instance
	// that did not run the analysis and will 404, prompting a re-run.
	mu          sync.RWMutex
	lastReports map[uuid.UUID]TighteningReport
	reportOrder []uuid.UUID
}

// NewTighteningService constructs a TighteningService.
func NewTighteningService(llm LLMProvider, logger *slog.Logger) *TighteningService {
	if logger == nil {
		logger = slog.Default()
	}
	return &TighteningService{
		llm:         llm,
		logger:      logger,
		lastReports: make(map[uuid.UUID]TighteningReport),
	}
}

// AnalyzeInput parameterises a tightening analysis run.
type AnalyzeInput struct {
	TenantID   uuid.UUID
	Rules      []json.RawMessage
	HitCounts  map[string]int64
	WindowDays int
}

// Analyze runs a full tightening analysis and returns a report.
func (s *TighteningService) Analyze(ctx context.Context, input AnalyzeInput) (TighteningReport, error) {
	if err := ctx.Err(); err != nil {
		return TighteningReport{}, err
	}
	if input.WindowDays <= 0 {
		input.WindowDays = 30
	}

	recs := []TighteningRecommendation{}

	for _, ruleRaw := range input.Rules {
		var rule struct {
			ID          string          `json:"id"`
			Verb        string          `json:"verb"`
			Domain      string          `json:"domain"`
			SubjectRefs []string        `json:"subject_refs,omitempty"`
			Subjects    json.RawMessage `json:"subjects,omitempty"`
		}
		if err := json.Unmarshal(ruleRaw, &rule); err != nil {
			continue
		}
		if rule.ID == "" {
			continue
		}

		hits := input.HitCounts[rule.ID]

		if hits == 0 && rule.Verb == "allow" {
			recs = append(recs, buildUnusedRecommendation(rule.ID, input.WindowDays, ruleRaw))
			continue
		}

		if rule.Verb == "allow" && isBroadRule(ruleRaw) {
			recs = append(recs, buildOverlyPermissiveRecommendation(rule.ID, ruleRaw))
		}
	}

	shadowedRecs := s.detectShadowedRules(input.Rules)
	recs = append(recs, shadowedRecs...)

	report := TighteningReport{
		TenantID:        input.TenantID,
		Recommendations: recs,
		AnalysisWindow:  input.WindowDays,
		RulesAnalyzed:   len(input.Rules),
		GeneratedAt:     time.Now().UTC(),
	}

	s.mu.Lock()
	if _, exists := s.lastReports[input.TenantID]; !exists {
		if len(s.reportOrder) >= maxCachedReports {
			oldest := s.reportOrder[0]
			delete(s.lastReports, oldest)
			// Shift the remaining IDs down in place rather than
			// resliding with [1:]. Reslicing would advance the slice
			// header past the head element on every eviction, so the
			// backing array (and the evicted UUID it still references)
			// could only be reclaimed when append happened to
			// reallocate. Compacting in place keeps a single stable
			// backing array bounded by maxCachedReports.
			copy(s.reportOrder, s.reportOrder[1:])
			s.reportOrder = s.reportOrder[:len(s.reportOrder)-1]
		}
		s.reportOrder = append(s.reportOrder, input.TenantID)
	}
	s.lastReports[input.TenantID] = report
	s.mu.Unlock()

	return report, nil
}

// LastReport returns the most recent analysis report for a tenant
// and whether one exists. It lets the GET report endpoint serve the
// result of the last Analyze run.
func (s *TighteningService) LastReport(tenantID uuid.UUID) (TighteningReport, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	report, ok := s.lastReports[tenantID]
	return report, ok
}

func (s *TighteningService) detectShadowedRules(rules []json.RawMessage) []TighteningRecommendation {
	type parsedRule struct {
		ID          string   `json:"id"`
		Verb        string   `json:"verb"`
		Domain      string   `json:"domain"`
		SubjectRefs []string `json:"subject_refs,omitempty"`
	}

	var parsed []parsedRule
	for _, raw := range rules {
		var r parsedRule
		if err := json.Unmarshal(raw, &r); err != nil {
			continue
		}
		parsed = append(parsed, r)
	}

	var recs []TighteningRecommendation

	for i := 1; i < len(parsed); i++ {
		rule := parsed[i]
		for j := 0; j < i; j++ {
			higher := parsed[j]
			if higher.Domain == rule.Domain &&
				higher.Verb == rule.Verb &&
				len(higher.SubjectRefs) == 0 &&
				len(rule.SubjectRefs) > 0 {
				recs = append(recs, TighteningRecommendation{
					RuleID:   rule.ID,
					Category: SuggestionCategoryShadowed,
					Change: SuggestedChange{
						Action: "remove",
						Justification: fmt.Sprintf(
							"Rule %s is shadowed by higher-priority rule %s which matches all traffic in domain %s.",
							rule.ID, higher.ID, rule.Domain),
					},
					Confidence: 0.8,
					Reasoning: fmt.Sprintf(
						"Higher-priority rule %s with no subject restrictions catches all traffic before rule %s can match.",
						higher.ID, rule.ID),
				})
				break
			}
		}
	}

	return recs
}

func buildUnusedRecommendation(ruleID string, windowDays int, ruleRaw json.RawMessage) TighteningRecommendation {
	return TighteningRecommendation{
		RuleID:   ruleID,
		Category: SuggestionCategoryUnused,
		Change: SuggestedChange{
			Action:        "remove",
			BeforeRule:    ruleRaw,
			Justification: fmt.Sprintf("Rule has not matched any traffic in %d days.", windowDays),
		},
		Confidence: unusedRuleConfidence(windowDays),
		Reasoning:  fmt.Sprintf("No traffic matched this rule in the analysis window of %d days.", windowDays),
	}
}

func buildOverlyPermissiveRecommendation(ruleID string, ruleRaw json.RawMessage) TighteningRecommendation {
	return TighteningRecommendation{
		RuleID:   ruleID,
		Category: SuggestionCategoryOverlyPermissive,
		Change: SuggestedChange{
			Action:        "modify",
			BeforeRule:    ruleRaw,
			Justification: "Allow-any pattern should be restricted to specific sources.",
		},
		Confidence: 0.6,
		Reasoning:  "Allow-any patterns increase attack surface. Restricting to known traffic patterns improves security posture.",
	}
}
