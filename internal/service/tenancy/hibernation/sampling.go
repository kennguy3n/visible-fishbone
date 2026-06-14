package hibernation

import (
	"context"

	"github.com/google/uuid"
)

// DefaultHibernatedSampleRate is the keep probability the
// [SampleResolver] returns for a hibernated tenant's telemetry. At
// 1-in-10000 a parked tenant that somehow still emits events writes
// almost no ClickHouse rows — the "no traffic → near-zero rows" goal —
// without hard-dropping the stream entirely (a non-zero rate keeps a
// faint heartbeat so a tenant that has genuinely come back is still
// observable before the wake path catches up).
//
// This rate is NOT applied to the inspect_full traffic class: the
// telemetry sampler's mandatory 1:1 floor for security-relevant events
// overrides any per-tenant rate, so a hibernated tenant's TLS-decrypt /
// AV / IPS / DLP record is still captured in full. Hibernation shrinks
// the cost of the high-volume, low-value classes; it never sampling-
// drops the compliance/audit record.
const DefaultHibernatedSampleRate = 0.0001

// rateResolver is the structural subset of
// telemetry.SampleRateResolver the [SampleResolver] composes. It is
// redeclared here (rather than importing the telemetry package) so the
// hibernation package keeps its inward-pointing dependency rule; a
// *telemetry.MapSampleRateResolver satisfies it.
type rateResolver interface {
	ResolveSampleRate(ctx context.Context, tenantID uuid.UUID, trafficClass string) (float64, bool)
}

// SampleResolver is a telemetry sample-rate resolver that overrides a
// hibernated tenant's keep probability to near-zero, deferring to an
// inner resolver for everyone else. It satisfies
// telemetry.SampleRateResolver structurally, so it drops into the
// adaptive sampler's RateResolver slot in place of the bare
// policy-graph resolver.
//
// Security preservation is delegated to the sampler: this resolver
// returns the same near-zero rate for every class (including
// inspect_full), and the sampler's mandatory 1:1 floor for inspect_full
// raises it back to full fidelity. Keeping the floor in one place (the
// sampler) means hibernation cannot accidentally regress it.
type SampleResolver struct {
	reg     *Registry
	inner   rateResolver
	rate    float64
	metrics *Metrics
}

// NewSampleResolver wraps inner (which may be nil — then non-hibernated
// tenants fall through to the sampler's own default policy) with a
// hibernation override driven by reg. A non-positive rate uses
// [DefaultHibernatedSampleRate]. metrics may be nil.
func NewSampleResolver(reg *Registry, inner rateResolver, rate float64, metrics *Metrics) *SampleResolver {
	if rate <= 0 {
		rate = DefaultHibernatedSampleRate
	}
	return &SampleResolver{reg: reg, inner: inner, rate: rate, metrics: metrics}
}

// ResolveSampleRate implements telemetry.SampleRateResolver. For a
// hibernated tenant it returns the near-zero hibernation rate with
// ok=true so the sampler uses it (subject to the inspect_full floor).
// Otherwise it defers to the inner resolver, or returns ok=false when
// there is none so the sampler applies its own default.
func (s *SampleResolver) ResolveSampleRate(ctx context.Context, tenantID uuid.UUID, trafficClass string) (float64, bool) {
	if s.reg.IsHibernated(tenantID) {
		s.metrics.observeSampledEvent(trafficClass)
		return s.rate, true
	}
	if s.inner != nil {
		return s.inner.ResolveSampleRate(ctx, tenantID, trafficClass)
	}
	return 0, false
}
