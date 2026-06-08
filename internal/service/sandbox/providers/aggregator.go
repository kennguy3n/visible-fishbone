package providers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// severityRank orders classifications from least to most severe so
// the aggregator can pick the strictest verdict and HA can collapse
// multiple reports. Unknown is below clean: a provider that has no
// intel must never override a provider that positively cleared the
// file.
func severityRank(c Classification) int {
	switch c {
	case ClassMalicious:
		return 4
	case ClassSuspicious:
		return 3
	case ClassTimeout:
		return 2
	case ClassClean:
		return 1
	case ClassUnknown:
		return 0
	default:
		return 0
	}
}

// Aggregator fans a lookup out to several reputation providers
// (e.g. VirusTotal + Hybrid Analysis) and returns the STRICTEST
// verdict among them — the conservative choice for a security
// control: if any reputable source calls a file malicious, SNG
// treats it as malicious.
//
// It is itself a Provider, so it slots into the sandbox Service via
// WithProvider without the service knowing it is talking to several
// backends. It is purpose-built for SYNCHRONOUS hash-lookup
// providers (VT/HA resolve on Submit); a child that returns a
// pending async submission is treated as "no synchronous verdict"
// and skipped for aggregation (its absence cannot relax the verdict,
// only the other providers can decide it).
//
// Availability: children returning ErrProviderUnavailable are
// ignored. If EVERY child is unavailable the Aggregator reports
// ErrProviderUnavailable so the service degrades to "no verdict".
// If at least one child produced a verdict, transient errors from
// other children are tolerated (logged into the summary) rather than
// failing the whole lookup — partial intel still beats none.
type Aggregator struct {
	providers []Provider
	id        string
}

// NewAggregator builds an aggregator over the given providers. Nil
// entries are dropped. The optional id names the aggregate verdict's
// provider field at the service layer when no child is identified;
// it defaults to "aggregator".
func NewAggregator(id string, ps ...Provider) *Aggregator {
	cleaned := make([]Provider, 0, len(ps))
	for _, p := range ps {
		if p != nil {
			cleaned = append(cleaned, p)
		}
	}
	if strings.TrimSpace(id) == "" {
		id = "aggregator"
	}
	return &Aggregator{providers: cleaned, id: id}
}

// ID returns the aggregate provider id.
func (a *Aggregator) ID() string { return a.id }

// Submit queries every child's Submit and returns the strictest
// synchronous verdict as a StatusComplete result.
func (a *Aggregator) Submit(ctx context.Context, f File) (SubmitResult, error) {
	results, err := a.collect(ctx, func(p Provider) (PollResult, string, error) {
		sr, e := p.Submit(ctx, f)
		if e != nil {
			return PollResult{}, p.ID(), e
		}
		// Only synchronous completions carry a usable verdict.
		if sr.Status != StatusComplete {
			return PollResult{Status: sr.Status}, p.ID(), errPending
		}
		res := sr.Result
		if res.Provider == "" {
			res.Provider = p.ID()
		}
		return res, p.ID(), nil
	})
	if err != nil {
		return SubmitResult{}, err
	}
	winner := a.strictest(results)
	return SubmitResult{
		SandboxID: f.SHA256,
		Status:    StatusComplete,
		Result:    winner,
	}, nil
}

// Poll re-runs the aggregate lookup. Children's hash-lookup Poll is
// idempotent, so the sandboxID (the file digest) is forwarded to
// each child.
func (a *Aggregator) Poll(ctx context.Context, sandboxID string) (PollResult, error) {
	results, err := a.collect(ctx, func(p Provider) (PollResult, string, error) {
		res, e := p.Poll(ctx, sandboxID)
		if e != nil {
			return PollResult{}, p.ID(), e
		}
		if res.Status != StatusComplete {
			return PollResult{Status: res.Status}, p.ID(), errPending
		}
		if res.Provider == "" {
			res.Provider = p.ID()
		}
		return res, p.ID(), nil
	})
	if err != nil {
		return PollResult{}, err
	}
	return a.strictest(results), nil
}

// errPending is a sentinel used internally to mark a child that
// returned a non-complete status (async pending). It is never
// surfaced to the caller.
var errPending = errors.New("provider returned pending")

// collect runs op against every child and partitions the outcomes.
// It returns the completed verdicts. The error is non-nil only when
// NO child produced a verdict: ErrProviderUnavailable when every
// child was unavailable/pending, or a joined error when at least one
// child failed for another reason and none succeeded.
func (a *Aggregator) collect(ctx context.Context, op func(Provider) (PollResult, string, error)) ([]PollResult, error) {
	if len(a.providers) == 0 {
		return nil, ErrProviderUnavailable
	}
	var (
		results    []PollResult
		hardErrs   []error
		unavailErr int
		pending    int
	)
	for _, p := range a.providers {
		// Honour cancellation between children.
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		res, _, err := op(p)
		switch {
		case err == nil:
			results = append(results, res)
		case errors.Is(err, ErrProviderUnavailable):
			unavailErr++
		case errors.Is(err, errPending):
			pending++
		default:
			hardErrs = append(hardErrs, err)
		}
	}

	if len(results) > 0 {
		return results, nil
	}
	// No verdicts. Decide the most informative error.
	if len(hardErrs) > 0 {
		return nil, fmt.Errorf("aggregator: all providers failed: %w", errors.Join(hardErrs...))
	}
	// Only unavailable / pending children — degrade to no-verdict.
	_ = unavailErr
	_ = pending
	return nil, ErrProviderUnavailable
}

// strictest returns the most severe verdict among results, merging
// their summaries and carrying the winning child's provider id. The
// confidence is the winner's own confidence.
func (a *Aggregator) strictest(results []PollResult) PollResult {
	best := results[0]
	for _, r := range results[1:] {
		if severityRank(r.Classification) > severityRank(best.Classification) {
			best = r
		}
	}

	// Build a combined, deterministic-ish summary listing every
	// provider's call so an operator sees the full picture, not just
	// the winner.
	parts := make([]string, 0, len(results))
	var analyzedAt time.Time
	for _, r := range results {
		tag := r.Provider
		if tag == "" {
			tag = "provider"
		}
		parts = append(parts, fmt.Sprintf("%s=%s", tag, r.Classification))
		if r.AnalyzedAt.After(analyzedAt) {
			analyzedAt = r.AnalyzedAt
		}
	}
	if analyzedAt.IsZero() {
		analyzedAt = time.Now().UTC()
	}

	summary := best.Summary
	if len(results) > 1 {
		summary = fmt.Sprintf("%s [%s]", best.Summary, strings.Join(parts, ", "))
	}

	return PollResult{
		Status:         StatusComplete,
		Classification: best.Classification,
		Confidence:     best.Confidence,
		Summary:        summary,
		Provider:       best.Provider,
		AnalyzedAt:     analyzedAt,
	}
}
