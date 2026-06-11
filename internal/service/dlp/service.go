package dlp

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/dlp/engine"
)

// Service is the DLP classification service. It orchestrates
// policy CRUD, the classification pipeline (regex, MIP labels,
// fingerprints), and the pre-baked policy template catalog.
type Service struct {
	policies     repository.DLPPolicyRepository
	fingerprints repository.DLPFingerprintRepository
	matches      repository.DLPMatchRepository
	models       repository.DLPModelRepository
	blockedApps  BlockedAppsSource
	regex        *engine.RegexEngine
	mip          *engine.MIPReader
	fp           *engine.FingerprintEngine
	logger       *slog.Logger
}

// BlockedAppsSource yields the destination app ids an operator has
// confirmed should be blocked for a tenant (via a `block` decision in
// the HITL review queue). [Service.CompileEndpointBundle] embeds these
// into the endpoint AI-app detector policy so the edge escalates
// sensitive uploads to those apps from coach to block. The HITL review
// queue (internal/service/dlpreview) and its repository both satisfy
// this single-method contract.
type BlockedAppsSource interface {
	BlockedApps(ctx context.Context, tenantID uuid.UUID) ([]string, error)
}

// Option configures optional [Service] dependencies.
type Option func(*Service)

// WithBlockedApps wires the source of operator-confirmed blocked
// destination apps. When unset, compiled bundles carry no per-app block
// overrides (the coach-first default), so the feature degrades safely
// to monitoring-only.
func WithBlockedApps(src BlockedAppsSource) Option {
	return func(s *Service) { s.blockedApps = src }
}

// New constructs a DLP service. A nil models repository disables ML
// model management: model CRUD/assignment calls return
// ErrModelsUnavailable and endpoint bundles compile without a model
// descriptor (the agent runs regex-only NER, the documented
// fail-safe).
func New(
	policies repository.DLPPolicyRepository,
	fingerprints repository.DLPFingerprintRepository,
	matches repository.DLPMatchRepository,
	models repository.DLPModelRepository,
	logger *slog.Logger,
	opts ...Option,
) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Service{
		policies:     policies,
		fingerprints: fingerprints,
		matches:      matches,
		models:       models,
		regex:        engine.NewRegexEngine(),
		mip:          engine.NewMIPReader(),
		fp:           engine.NewFingerprintEngine(fingerprints),
		logger:       logger,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Classify runs content through every enabled policy for the tenant
// and returns the aggregate result. The highest-severity action wins.
func (s *Service) Classify(ctx context.Context, tenantID uuid.UUID, input ClassificationInput) (ClassificationResult, error) {
	policies, err := s.policies.ListEnabled(ctx, tenantID)
	if err != nil {
		return ClassificationResult{}, err
	}
	var result ClassificationResult
	for _, p := range policies {
		hits := s.evaluatePolicy(ctx, tenantID, p, input)
		if len(hits) > 0 {
			result.Matches = append(result.Matches, hits...)
			result.PolicyIDs = append(result.PolicyIDs, p.ID)
			result.Action = higherAction(result.Action, p.Action)
		}
	}
	if len(result.Matches) > 0 {
		result.Confidence = avgConfidence(result.Matches)
	}

	// Persist audit trail for each matched policy.
	for _, pid := range result.PolicyIDs {
		details, _ := json.Marshal(map[string]any{
			"source":     input.Metadata.Filename,
			"action":     result.Action,
			"confidence": result.Confidence,
		})
		if _, err := s.matches.Create(ctx, tenantID, repository.DLPMatch{
			PolicyID:  pid,
			Source:    input.Metadata.Source,
			MatchedAt: time.Now(),
			Details:   details,
		}); err != nil {
			s.logger.WarnContext(ctx, "dlp: failed to record audit match", "policy_id", pid, "err", err)
		}
	}

	return result, nil
}

// ListPolicies returns paginated DLP policies for the tenant.
func (s *Service) ListPolicies(ctx context.Context, tenantID uuid.UUID, page repository.Page) (repository.PageResult[repository.DLPPolicy], error) {
	return s.policies.List(ctx, tenantID, page)
}

// GetPolicy returns a single DLP policy.
func (s *Service) GetPolicy(ctx context.Context, tenantID, id uuid.UUID) (repository.DLPPolicy, error) {
	return s.policies.Get(ctx, tenantID, id)
}

// CreatePolicy creates a new DLP policy.
func (s *Service) CreatePolicy(ctx context.Context, tenantID uuid.UUID, p repository.DLPPolicy) (repository.DLPPolicy, error) {
	if p.Name == "" {
		return repository.DLPPolicy{}, repository.ErrInvalidArgument
	}
	if len(p.Rules) == 0 {
		return repository.DLPPolicy{}, repository.ErrInvalidArgument
	}
	if !validAction(p.Action) {
		return repository.DLPPolicy{}, repository.ErrInvalidArgument
	}
	for _, r := range p.Rules {
		if !validRuleType(r.Type) {
			return repository.DLPPolicy{}, repository.ErrInvalidArgument
		}
	}
	return s.policies.Create(ctx, tenantID, p)
}

// UpdatePolicy applies a sparse patch to an existing policy.
func (s *Service) UpdatePolicy(ctx context.Context, tenantID, id uuid.UUID, patch repository.DLPPolicyPatch) (repository.DLPPolicy, error) {
	if patch.Action != nil && !validAction(*patch.Action) {
		return repository.DLPPolicy{}, repository.ErrInvalidArgument
	}
	if patch.Rules != nil {
		for _, r := range *patch.Rules {
			if !validRuleType(r.Type) {
				return repository.DLPPolicy{}, repository.ErrInvalidArgument
			}
		}
	}
	return s.policies.Update(ctx, tenantID, id, patch)
}

// DeletePolicy removes a DLP policy.
func (s *Service) DeletePolicy(ctx context.Context, tenantID, id uuid.UUID) error {
	return s.policies.Delete(ctx, tenantID, id)
}

// TestPolicy dry-runs a specific policy against sample content.
func (s *Service) TestPolicy(ctx context.Context, tenantID, policyID uuid.UUID, sampleContent []byte) (TestResult, error) {
	p, err := s.policies.Get(ctx, tenantID, policyID)
	if err != nil {
		return TestResult{}, err
	}
	input := ClassificationInput{
		ContentType: "text/plain",
		Content:     sampleContent,
	}
	hits := s.evaluatePolicy(ctx, tenantID, p, input)
	return TestResult{
		Matches: hits,
		Action:  p.Action,
		Matched: len(hits) > 0,
	}, nil
}

// evaluatePolicy runs a single policy's rules against content.
// Fingerprint matching is hoisted: if any rule has type fingerprint
// a single query loads all matches and appends them once.
func (s *Service) evaluatePolicy(ctx context.Context, tenantID uuid.UUID, p repository.DLPPolicy, input ClassificationInput) []Match {
	var hits []Match
	var hasFingerprint bool

	for _, rule := range p.Rules {
		switch rule.Type {
		case repository.DLPRuleTypeRegex, repository.DLPRuleTypeKeyword:
			em := s.regex.Match(input.Content, []repository.DLPRule{rule})
			for _, m := range em {
				hits = append(hits, Match{
					RuleType:   m.RuleType,
					Pattern:    m.Pattern,
					Offset:     m.Offset,
					Length:     m.Length,
					Snippet:    m.Snippet,
					Confidence: m.Confidence,
				})
			}
		case repository.DLPRuleTypeMIPLabel:
			labels, err := s.mip.ReadMIPLabels(input.Content, input.ContentType)
			if err != nil {
				s.logger.WarnContext(ctx, "mip label read failed", "err", err)
				continue
			}
			for _, l := range labels {
				if l.LabelID == rule.Pattern || (rule.SensitivityLevel != "" && l.Sensitivity == rule.SensitivityLevel) {
					hits = append(hits, Match{
						RuleType:   repository.DLPRuleTypeMIPLabel,
						Pattern:    rule.Pattern,
						Snippet:    l.LabelID,
						Confidence: 1.0,
					})
				}
			}
		case repository.DLPRuleTypeFingerprint:
			hasFingerprint = true
		case repository.DLPRuleTypeMLNER:
			// ML NER inference runs on-device (sng-dlp's ONNX
			// classifier), not in the inline control-plane Classify
			// path — there is no server-side model. The rule is still
			// valid and is projected into the endpoint bundle by
			// compileEndpointRules; here it is a no-op.
		}
	}

	if hasFingerprint {
		fpMatches, err := s.fp.MatchFingerprints(ctx, tenantID, input.Content)
		if err != nil {
			s.logger.WarnContext(ctx, "fingerprint match failed", "err", err)
		}
		for _, fm := range fpMatches {
			hits = append(hits, Match{
				RuleType:   repository.DLPRuleTypeFingerprint,
				Pattern:    fm.Name,
				Confidence: fm.Similarity,
			})
		}
	}

	return hits
}

// actionPriority returns a numeric priority so we can pick the
// strictest action across multiple matching policies.
func actionPriority(a repository.DLPAction) int {
	switch a {
	case repository.DLPActionLog:
		return 1
	case repository.DLPActionRedact:
		return 2
	case repository.DLPActionEncrypt:
		return 3
	case repository.DLPActionBlock:
		return 4
	default:
		return 0
	}
}

func higherAction(a, b repository.DLPAction) repository.DLPAction {
	if actionPriority(a) >= actionPriority(b) {
		return a
	}
	return b
}

func avgConfidence(matches []Match) float64 {
	if len(matches) == 0 {
		return 0
	}
	var sum float64
	for _, m := range matches {
		sum += m.Confidence
	}
	return sum / float64(len(matches))
}

func validAction(a repository.DLPAction) bool {
	switch a {
	case repository.DLPActionLog, repository.DLPActionBlock,
		repository.DLPActionEncrypt, repository.DLPActionRedact:
		return true
	}
	return false
}

func validRuleType(t repository.DLPRuleType) bool {
	switch t {
	case repository.DLPRuleTypeRegex, repository.DLPRuleTypeMIPLabel,
		repository.DLPRuleTypeFingerprint, repository.DLPRuleTypeKeyword,
		repository.DLPRuleTypeMLNER:
		return true
	}
	return false
}
