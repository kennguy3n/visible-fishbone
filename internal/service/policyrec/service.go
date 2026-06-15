package policyrec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// MaxNewlyDeniedSamples bounds the number of distinct newly-denied
// traffic descriptors stored in a recommendation's evidence so the
// JSONB summary stays small regardless of how much traffic a sweeping
// recommendation would block.
const MaxNewlyDeniedSamples = 50

// DefaultMaxEvents bounds the telemetry a single recommendation run
// pulls. Mirrors policy.DefaultSimulationMaxEvents so a recommendation
// and a manual simulation over the same window see the same budget.
const DefaultMaxEvents = policy.DefaultSimulationMaxEvents

// ErrTelemetryUnavailable is returned by Generate when no telemetry
// source is wired (the ClickHouse hot tier is not configured on this
// deployment). The HTTP layer maps it to 503. Callers should gate on
// Ready() before invoking Generate to surface this proactively.
var ErrTelemetryUnavailable = errors.New("policyrec: telemetry source not configured")

// PolicyGraphProvider is the slice of policy.Service the engine needs:
// read the tenant's live graph (to measure impact against) and stage a
// candidate as a draft (to apply a recommendation). *policy.Service
// satisfies it.
type PolicyGraphProvider interface {
	GetCurrentGraph(ctx context.Context, tenantID uuid.UUID) (repository.PolicyGraph, error)
	PutDraftGraph(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, raw json.RawMessage) (repository.PolicyGraph, error)
}

// Service orchestrates recommendation generation, persistence, and
// application. Construct with New.
//
// The telemetry source is stored behind an atomic.Pointer so it can be
// wired post-construction once the ClickHouse hot tier is alive
// (mirroring PolicySimulationHandler.SetSimulator). The persistence
// paths — Get / List / Apply / Dismiss — depend only on Postgres and
// stay available even before telemetry is wired; only Generate requires
// the source.
type Service struct {
	repo    repository.PolicyRecommendationRepository
	src     atomic.Pointer[policy.TelemetrySource]
	policy  PolicyGraphProvider
	factory policy.EvaluatorFactory
	logger  *slog.Logger
}

// New constructs a recommendation Service. src may be nil when the
// ClickHouse hot tier is not yet available (wire it later with
// SetTelemetrySource). A nil factory defaults to
// policy.GraphEvaluatorFactory{} (the same evaluator the simulator
// uses); a nil logger defaults to slog.Default().
func New(
	repo repository.PolicyRecommendationRepository,
	src policy.TelemetrySource,
	graphs PolicyGraphProvider,
	factory policy.EvaluatorFactory,
	logger *slog.Logger,
) *Service {
	if factory == nil {
		factory = policy.GraphEvaluatorFactory{}
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Service{repo: repo, policy: graphs, factory: factory, logger: logger}
	if src != nil {
		s.src.Store(&src)
	}
	return s
}

// SetTelemetrySource wires (or replaces) the telemetry source after
// construction. Passing nil is a no-op.
func (s *Service) SetTelemetrySource(src policy.TelemetrySource) {
	if s == nil || src == nil {
		return
	}
	s.src.Store(&src)
}

// Ready reports whether a telemetry source is wired — i.e. whether
// Generate can run. Get / List / Apply / Dismiss do not require it.
func (s *Service) Ready() bool {
	return s != nil && s.src.Load() != nil
}

// GenerateRequest parameterises a single recommendation run.
type GenerateRequest struct {
	// Since / Until bound the closed-open telemetry window. Both
	// required and non-zero; Until must be after Since.
	Since time.Time
	Until time.Time
	// MaxEvents caps the envelopes pulled. Zero -> DefaultMaxEvents.
	MaxEvents int
	// Options tunes synthesis (aggregation prefixes, rule caps, noise
	// floor). The zero value is valid.
	Options SynthesisOptions
}

// VerdictTransition is one cell of the prev->next impact matrix.
type VerdictTransition struct {
	PrevVerdict string `json:"prev_verdict"`
	NextVerdict string `json:"next_verdict"`
	Count       int    `json:"count"`
}

// NewlyDeniedSample describes a class of observed permitted traffic the
// candidate policy would newly deny — the operator-facing blast radius.
type NewlyDeniedSample struct {
	EventClass string `json:"event_class"`
	Descriptor string `json:"descriptor"`
	Count      int    `json:"count"`
}

// CoverageReport measures how much observed permitted traffic the
// candidate preserves. It is computed against the same telemetry the
// recommendation was synthesized from.
type CoverageReport struct {
	ObservedPermitted  int                 `json:"observed_permitted"`
	Preserved          int                 `json:"preserved"`
	NewlyDenied        int                 `json:"newly_denied"`
	Coverage           float64             `json:"coverage"`
	NewlyDeniedSamples []NewlyDeniedSample `json:"newly_denied_samples"`
}

// ImpactSummary is the prev-vs-next verdict diff over the observed
// window — the same question policy.Simulator answers, computed here
// over the identical event set the recommendation was built from.
type ImpactSummary struct {
	Total           int                 `json:"total"`
	Changed         int                 `json:"changed"`
	Transitions     []VerdictTransition `json:"transitions"`
	AffectedDevices []uuid.UUID         `json:"affected_devices"`
	AffectedSites   []uuid.UUID         `json:"affected_sites"`
}

// RecommendationSummary is the typed evidence document persisted as the
// recommendation's summary JSONB.
type RecommendationSummary struct {
	WindowStart time.Time        `json:"window_start"`
	WindowEnd   time.Time        `json:"window_end"`
	Options     SynthesisOptions `json:"options"`
	Synthesis   SynthesisStats   `json:"synthesis"`
	Coverage    CoverageReport   `json:"coverage"`
	Impact      ImpactSummary    `json:"impact"`
}

// Generate observes the tenant's telemetry over the requested window,
// synthesizes a least-privilege candidate graph, proves coverage +
// impact against the same observed events, and persists the result as a
// pending recommendation.
func (s *Service) Generate(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, req GenerateRequest) (repository.PolicyRecommendation, error) {
	if tenantID == uuid.Nil {
		return repository.PolicyRecommendation{}, fmt.Errorf("tenant id required: %w", repository.ErrInvalidArgument)
	}
	if req.Since.IsZero() || req.Until.IsZero() || !req.Until.After(req.Since) {
		return repository.PolicyRecommendation{}, fmt.Errorf("invalid window: until must be after since: %w", repository.ErrInvalidArgument)
	}
	maxEvents := req.MaxEvents
	if maxEvents <= 0 {
		maxEvents = DefaultMaxEvents
	}

	srcPtr := s.src.Load()
	if srcPtr == nil {
		return repository.PolicyRecommendation{}, ErrTelemetryUnavailable
	}
	src := *srcPtr

	classes := []schema.EventClass{schema.EventClassFlow, schema.EventClassDNS, schema.EventClassHTTP}
	events, err := src.ListEvents(ctx, tenantID, classes, req.Since, req.Until, maxEvents)
	if err != nil {
		return repository.PolicyRecommendation{}, fmt.Errorf("policyrec: list telemetry: %w", err)
	}

	graph, stats := Synthesize(events, req.Options)
	candidateJSON, err := json.Marshal(graph)
	if err != nil {
		return repository.PolicyRecommendation{}, fmt.Errorf("policyrec: marshal candidate graph: %w", err)
	}
	// Compile gate: the candidate must pass the same schema validation
	// the policy compiler enforces, or we never persist it. This is the
	// "deterministic systems enforce" half of the platform invariant.
	if _, err := policy.ParseGraph(candidateJSON); err != nil {
		return repository.PolicyRecommendation{}, fmt.Errorf("policyrec: candidate graph failed validation: %w", err)
	}

	// Current (live) graph is the prev side of the impact diff. A fresh
	// tenant with no policy yet diffs against an empty default-deny
	// graph, which is exactly the simulator's "no policy" semantics.
	var prevGraph repository.PolicyGraph
	if cur, gerr := s.policy.GetCurrentGraph(ctx, tenantID); gerr == nil {
		prevGraph = cur
	} else if !errors.Is(gerr, repository.ErrNotFound) {
		return repository.PolicyRecommendation{}, fmt.Errorf("policyrec: current graph: %w", gerr)
	}

	prevParsed, err := policy.ParseGraph(prevGraph.Graph)
	if err != nil {
		return repository.PolicyRecommendation{}, fmt.Errorf("policyrec: parse current graph: %w", err)
	}

	coverage, err := s.computeCoverage(ctx, events, graph)
	if err != nil {
		return repository.PolicyRecommendation{}, err
	}
	impact, err := s.computeImpact(ctx, events, prevParsed, graph)
	if err != nil {
		return repository.PolicyRecommendation{}, err
	}

	summary := RecommendationSummary{
		WindowStart: req.Since.UTC(),
		WindowEnd:   req.Until.UTC(),
		Options:     req.Options.normalize(),
		Synthesis:   stats,
		Coverage:    coverage,
		Impact:      impact,
	}
	summaryJSON, err := json.Marshal(summary)
	if err != nil {
		return repository.PolicyRecommendation{}, fmt.Errorf("policyrec: marshal summary: %w", err)
	}

	rec := repository.PolicyRecommendation{
		TenantID:       tenantID,
		Status:         repository.PolicyRecommendationStatusPending,
		WindowStart:    req.Since.UTC(),
		WindowEnd:      req.Until.UTC(),
		CandidateGraph: candidateJSON,
		Summary:        summaryJSON,
		Coverage:       coverage.Coverage,
		RuleCount:      stats.RuleCount,
		ActorID:        actorID,
	}
	saved, err := s.repo.Create(ctx, tenantID, rec)
	if err != nil {
		return repository.PolicyRecommendation{}, fmt.Errorf("policyrec: persist recommendation: %w", err)
	}
	s.logger.Info("policyrec: generated recommendation",
		slog.String("tenant_id", tenantID.String()),
		slog.String("recommendation_id", saved.ID.String()),
		slog.Int("observed", stats.ObservedTotal),
		slog.Int("rules", stats.RuleCount),
		slog.Float64("coverage", coverage.Coverage),
		slog.Int("newly_denied", coverage.NewlyDenied),
	)
	return saved, nil
}

// Apply stages a pending recommendation's candidate graph as a policy
// draft (feeding the existing canary-rollout path) and marks the
// recommendation applied. Returns the refreshed recommendation and the
// draft graph that was created.
func (s *Service) Apply(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, id uuid.UUID) (repository.PolicyRecommendation, repository.PolicyGraph, error) {
	rec, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return repository.PolicyRecommendation{}, repository.PolicyGraph{}, err
	}
	if rec.Status != repository.PolicyRecommendationStatusPending {
		return repository.PolicyRecommendation{}, repository.PolicyGraph{}, fmt.Errorf("recommendation is %s, only pending recommendations can be applied: %w", rec.Status, repository.ErrConflict)
	}
	draft, err := s.policy.PutDraftGraph(ctx, tenantID, actorID, rec.CandidateGraph)
	if err != nil {
		return repository.PolicyRecommendation{}, repository.PolicyGraph{}, fmt.Errorf("policyrec: stage draft: %w", err)
	}
	if err := s.repo.MarkApplied(ctx, tenantID, id, draft.ID, actorID); err != nil {
		return repository.PolicyRecommendation{}, repository.PolicyGraph{}, fmt.Errorf("policyrec: mark applied: %w", err)
	}
	refreshed, err := s.repo.Get(ctx, tenantID, id)
	if err != nil {
		return repository.PolicyRecommendation{}, repository.PolicyGraph{}, err
	}
	s.logger.Info("policyrec: applied recommendation",
		slog.String("tenant_id", tenantID.String()),
		slog.String("recommendation_id", id.String()),
		slog.String("draft_graph_id", draft.ID.String()))
	return refreshed, draft, nil
}

// Dismiss marks a pending recommendation dismissed without applying it.
func (s *Service) Dismiss(ctx context.Context, tenantID uuid.UUID, actorID *uuid.UUID, id uuid.UUID) (repository.PolicyRecommendation, error) {
	if err := s.repo.MarkDismissed(ctx, tenantID, id, actorID); err != nil {
		return repository.PolicyRecommendation{}, err
	}
	return s.repo.Get(ctx, tenantID, id)
}

// Get returns a single recommendation.
func (s *Service) Get(ctx context.Context, tenantID, id uuid.UUID) (repository.PolicyRecommendation, error) {
	return s.repo.Get(ctx, tenantID, id)
}

// List returns recommendations, optionally filtered by status.
func (s *Service) List(ctx context.Context, tenantID uuid.UUID, status *string, page repository.Page) (repository.PageResult[repository.PolicyRecommendation], error) {
	return s.repo.List(ctx, tenantID, status, page)
}

// classEnforcementDomains maps a telemetry event class to the policy
// domains that actually enforce it at the edge — the L3/L4 firewall
// planes for flows, the DNS resolver for queries, the web planes for
// HTTP. Coverage / impact are evaluated against the per-class subset of
// rules so an HTTP host-allow rule cannot spuriously "allow" a raw
// flow (the policy.GraphEvaluator's cross-domain matcher is
// deliberately conservative — it never misses a change — but that
// conservatism over-counts allows for a least-privilege proof, where
// edge-accurate verdicts are what make the safety claim trustworthy).
var classEnforcementDomains = map[schema.EventClass][]policy.Domain{
	schema.EventClassFlow: {policy.DomainNGFW, policy.DomainSDWAN, policy.DomainZTNA},
	schema.EventClassDNS:  {policy.DomainDNS},
	schema.EventClassHTTP: {policy.DomainSWG, policy.DomainInlineCASB, policy.DomainDLP},
}

// classEvaluatorCache lazily builds one evaluator per event class over
// the class-relevant subset of a graph's rules, caching the result.
type classEvaluatorCache struct {
	base    policy.Graph
	factory policy.EvaluatorFactory
	byClass map[schema.EventClass]policy.Evaluator
}

func newClassEvaluatorCache(base policy.Graph, factory policy.EvaluatorFactory) *classEvaluatorCache {
	return &classEvaluatorCache{base: base, factory: factory, byClass: map[schema.EventClass]policy.Evaluator{}}
}

func (c *classEvaluatorCache) evaluator(ctx context.Context, cls schema.EventClass) (policy.Evaluator, error) {
	if e, ok := c.byClass[cls]; ok {
		return e, nil
	}
	allowed := map[policy.Domain]struct{}{}
	for _, d := range classEnforcementDomains[cls] {
		allowed[d] = struct{}{}
	}
	sub := policy.Graph{
		DefaultAction: c.base.DefaultAction,
		Subjects:      c.base.Subjects,
		Predicates:    c.base.Predicates,
	}
	for _, r := range c.base.Rules {
		if _, ok := allowed[r.Domain]; ok {
			sub.Rules = append(sub.Rules, r)
		}
	}
	raw, err := json.Marshal(sub)
	if err != nil {
		return nil, fmt.Errorf("policyrec: marshal %s subgraph: %w", cls, err)
	}
	e, err := c.factory.Build(ctx, repository.PolicyGraph{Graph: raw})
	if err != nil {
		return nil, fmt.Errorf("policyrec: build %s evaluator: %w", cls, err)
	}
	c.byClass[cls] = e
	return e, nil
}

// computeCoverage replays the observed permitted traffic through the
// candidate graph and reports how much it preserves vs newly denies.
func (s *Service) computeCoverage(ctx context.Context, events []schema.Envelope, candidate policy.Graph) (CoverageReport, error) {
	cache := newClassEvaluatorCache(candidate, s.factory)
	report := CoverageReport{Coverage: 1.0}
	deniedCounts := map[string]*NewlyDeniedSample{}
	for i := range events {
		env := events[i]
		observed, ok := observedPermit(env)
		if !ok {
			continue
		}
		eval, err := cache.evaluator(ctx, env.EventClass)
		if err != nil {
			return CoverageReport{}, err
		}
		report.ObservedPermitted++
		verdict, err := eval.Evaluate(ctx, env)
		if err != nil {
			// A malformed envelope the candidate evaluator rejects is
			// not coverage signal; skip it (the same envelope would
			// have failed at the edge too).
			report.ObservedPermitted--
			continue
		}
		if verdictPermits(verdict) {
			report.Preserved++
			continue
		}
		report.NewlyDenied++
		key := string(env.EventClass) + "|" + observed
		if sample, ok := deniedCounts[key]; ok {
			sample.Count++
		} else {
			deniedCounts[key] = &NewlyDeniedSample{EventClass: string(env.EventClass), Descriptor: observed, Count: 1}
		}
	}
	if report.ObservedPermitted > 0 {
		report.Coverage = float64(report.Preserved) / float64(report.ObservedPermitted)
	}
	report.NewlyDeniedSamples = topNewlyDenied(deniedCounts)
	return report, nil
}

// computeImpact diffs prev vs next verdicts over the observed events,
// answering policy.Simulator's prev-vs-next question over the same
// in-memory event set with edge-accurate per-class evaluation.
func (s *Service) computeImpact(ctx context.Context, events []schema.Envelope, prev, next policy.Graph) (ImpactSummary, error) {
	prevCache := newClassEvaluatorCache(prev, s.factory)
	nextCache := newClassEvaluatorCache(next, s.factory)
	type transitionKey struct{ prev, next schema.Verdict }
	transitions := map[transitionKey]int{}
	devices := map[uuid.UUID]struct{}{}
	sites := map[uuid.UUID]struct{}{}
	summary := ImpactSummary{}
	for i := range events {
		env := events[i]
		prevEval, err := prevCache.evaluator(ctx, env.EventClass)
		if err != nil {
			return ImpactSummary{}, err
		}
		nextEval, err := nextCache.evaluator(ctx, env.EventClass)
		if err != nil {
			return ImpactSummary{}, err
		}
		prevV, perr := prevEval.Evaluate(ctx, env)
		nextV, nerr := nextEval.Evaluate(ctx, env)
		if perr != nil || nerr != nil {
			continue
		}
		summary.Total++
		transitions[transitionKey{prevV, nextV}]++
		if prevV != nextV {
			summary.Changed++
			if env.DeviceID != uuid.Nil {
				devices[env.DeviceID] = struct{}{}
			}
			if env.SiteID != nil && *env.SiteID != uuid.Nil {
				sites[*env.SiteID] = struct{}{}
			}
		}
	}
	summary.Transitions = make([]VerdictTransition, 0, len(transitions))
	for k, count := range transitions {
		summary.Transitions = append(summary.Transitions, VerdictTransition{
			PrevVerdict: string(k.prev), NextVerdict: string(k.next), Count: count,
		})
	}
	sort.Slice(summary.Transitions, func(i, j int) bool {
		if summary.Transitions[i].PrevVerdict != summary.Transitions[j].PrevVerdict {
			return summary.Transitions[i].PrevVerdict < summary.Transitions[j].PrevVerdict
		}
		return summary.Transitions[i].NextVerdict < summary.Transitions[j].NextVerdict
	})
	summary.AffectedDevices = sortedUUIDs(devices)
	summary.AffectedSites = sortedUUIDs(sites)
	return summary, nil
}

// observedPermit reports whether an envelope is permitted observed
// traffic in a modelled class and returns a stable human descriptor of
// it for the newly-denied report.
func observedPermit(env schema.Envelope) (string, bool) {
	switch env.EventClass {
	case schema.EventClassFlow:
		var f schema.FlowEvent
		if err := schema.UnpackPayload(env.Payload, &f); err != nil {
			return "", false
		}
		if !permittedVerdict(f.Verdict) {
			return "", false
		}
		if f.DstPort != 0 {
			return fmt.Sprintf("%s/%d -> %s", protoLabel(f.Protocol), f.DstPort, f.DstIP), true
		}
		return fmt.Sprintf("%s -> %s", protoLabel(f.Protocol), f.DstIP), true
	case schema.EventClassDNS:
		var d schema.DNSEvent
		if err := schema.UnpackPayload(env.Payload, &d); err != nil {
			return "", false
		}
		if !permittedVerdict(d.Verdict) {
			return "", false
		}
		return normalizeDomain(d.Query), true
	case schema.EventClassHTTP:
		var h schema.HTTPEvent
		if err := schema.UnpackPayload(env.Payload, &h); err != nil {
			return "", false
		}
		if !permittedVerdict(h.Verdict) {
			return "", false
		}
		return normalizeDomain(h.Host), true
	}
	return "", false
}

// verdictPermits reports whether an evaluator verdict lets traffic flow.
func verdictPermits(v schema.Verdict) bool {
	switch v {
	case schema.VerdictAllow, schema.VerdictInspect, schema.VerdictLog:
		return true
	}
	return false
}

func topNewlyDenied(m map[string]*NewlyDeniedSample) []NewlyDeniedSample {
	out := make([]NewlyDeniedSample, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		if out[i].EventClass != out[j].EventClass {
			return out[i].EventClass < out[j].EventClass
		}
		return out[i].Descriptor < out[j].Descriptor
	})
	if len(out) > MaxNewlyDeniedSamples {
		out = out[:MaxNewlyDeniedSamples]
	}
	return out
}

func sortedUUIDs(set map[uuid.UUID]struct{}) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
