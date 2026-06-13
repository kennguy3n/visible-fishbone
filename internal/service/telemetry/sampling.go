// Package telemetry — sampling.go implements adaptive, deterministic
// per-tenant telemetry sampling. It sits in the consumer hot path
// between decode and the hot/cold writers and decides, per event,
// whether to keep (write) or drop the event so a high-volume tenant
// cannot swamp ClickHouse with low-information-density events.
//
// Why sampling in addition to the PerTenantLimiter (consumer.go):
//
//   - The PerTenantLimiter is *hard back-pressure*: it Naks
//     over-budget events so JetStream redelivers them later, and
//     eventually routes them to the DLQ once MaxDeliver is hit. That
//     protects the writers but it neither reduces the total work
//     (every event is still processed, just later) nor preserves a
//     statistically faithful picture — the events that lose the
//     redelivery race are dropped arbitrarily.
//   - Sampling is *load shedding with de-bias*: when a tenant's
//     arrival rate exceeds their tier budget, we deterministically
//     keep a representative fraction of events and drop the rest
//     immediately (Ack, never redeliver). The kept events carry the
//     keep probability so analytics can multiply aggregates by
//     1/SampleRate to recover the tenant's true volume. This cuts
//     ClickHouse write volume for the noisy tenant by 30-50%+ while
//     preserving visibility (every dimension is still represented in
//     proportion).
//
// Determinism is the load-bearing property. The keep/drop decision
// for an event is a pure function of (EventID, keep probability):
//
//	keep  <=>  hashFraction(EventID) < keepProb
//
// Two consequences follow, both of which the architecture relies on:
//
//  1. **Redelivery stability.** JetStream is at-least-once; the same
//     EventID can be redelivered. A coin-flip sampler would make
//     inconsistent decisions across redeliveries, corrupting the
//     1/SampleRate de-bias weight and racing the dedup ring. A hash
//     sampler always reaches the same verdict for the same event at
//     a given rate.
//  2. **Monotone (consistent) sampling.** Because the decision is a
//     threshold on a fixed per-event hash fraction, the set kept at
//     rate p1 is a strict subset of the set kept at p2 > p1. Raising
//     or lowering the adaptive rate never reshuffles which events
//     are kept — it only widens or narrows the threshold — so the
//     sampled stream stays coherent as the rate adapts.
//
// The rate adapts per tenant on a fixed window: each window's keep
// probability is computed from the *previous* window's observed
// arrival rate versus the tenant's tier budget (a LimitResolver,
// shared with the PerTenantLimiter so budgets stay consistent).
// Computing the rate from arrivals (not kept events) makes it a
// stable fixed point — a steadily over-budget tenant holds a steady
// keep probability rather than oscillating.
package telemetry

import (
	"context"
	"hash/fnv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/tenancy"
)

// DefaultSamplingWindow is the per-tenant rate-estimation window.
// Each window's keep probability is derived from the arrival rate
// observed over the prior window. Ten seconds smooths sub-second
// bursts (an edge replaying its spool) without lagging a sustained
// volume change by more than one window.
const DefaultSamplingWindow = 10 * time.Second

// DefaultMinSampleRate is the floor on the adaptive keep
// probability. Even a tenant emitting orders of magnitude over their
// budget keeps at least this fraction of events, so the hot store
// never loses total visibility into them — the de-bias weight
// (1/rate) stays finite and the tenant remains queryable. 0.05 keeps
// 1-in-20 at the extreme, enough to retain every active dimension on
// a busy tenant while still shedding 95% of the flood.
const DefaultMinSampleRate = 0.05

// TrustedClassSampleRate is the fixed 1-in-100 keep probability applied
// to the trusted_direct and trusted_media_bypass traffic classes. Both
// carry the strongest trust guarantees in the taxonomy (DNS + cert-pin
// + IP-range binding, no proxy, no TLS decrypt — see
// repository.TrafficClass), so their per-event telemetry is high-volume
// but low-information-density: a 1:100 sample retains a statistically
// faithful picture (de-biased by 1/rate) while shedding 99% of the
// write load these classes would otherwise impose on ClickHouse. The
// trusted_media_bypass class is documented as "telemetry sampled for
// cost control" precisely for this. This is a class-level policy: it is
// applied at a constant rate independent of the tenant's adaptive
// budget, because the rationale (low signal density) is a property of
// the class, not of any tenant's volume.
const TrustedClassSampleRate = 0.01

// InspectFullSampleRate is the fixed full-fidelity (1:1) keep
// probability for the inspect_full traffic class. inspect_full is the
// full secure-web-gateway path — TLS decrypt, AV, IPS, DLP (see
// repository.TrafficClassInspectFull) — so its per-event telemetry is
// the security-and-compliance record of the highest-scrutiny traffic on
// the platform: detections, blocks, DLP hits, and the audit trail an
// SME tenant is legally obligated to retain. Sampling it away to save
// ClickHouse cost would silently drop evidence, so the class is pinned
// at 1:1 as a class-level policy and is deliberately exempt from the
// adaptive per-tenant load shedder: even a tenant flooding inspect_full
// keeps every event (back-pressure for that case is the row limiter,
// which defers rather than drops). 1.0 is the no-sampling rate; it is
// expressed as a fixed class rate (rather than "fall through to
// adaptive") so a misconfigured budget can never cause inspect_full to
// be shed.
const InspectFullSampleRate = 1.0

// fixedClassSampleRate reports the constant, class-determined keep
// probability for traffic classes whose sampling regime is a property
// of the class, not of any tenant's adaptive volume. It returns
// (rate, true) for such a class and (0, false) for every other class,
// which then falls through to the adaptive per-tenant sampler. Keyed on
// the canonical repository.TrafficClass values so it stays in lockstep
// with the taxonomy; an empty or unknown class is never fixed-rate.
//
// These are the BUILT-IN defaults. A per-tenant / per-class override
// supplied through a SampleRateResolver (e.g. distilled from the policy
// graph) takes precedence over them — see AdaptiveSampler.DecideClass.
func fixedClassSampleRate(trafficClass string) (float64, bool) {
	switch repository.TrafficClass(trafficClass) {
	case repository.TrafficClassTrustedDirect, repository.TrafficClassTrustedMediaBypass:
		return TrustedClassSampleRate, true
	case repository.TrafficClassInspectFull:
		return InspectFullSampleRate, true
	default:
		return 0, false
	}
}

// mandatorySampleRateFloor reports the minimum keep probability a class
// may EVER be sampled at, regardless of any operator override. It is the
// compliance backstop for inspect_full: that class is legally-required
// audit evidence (see InspectFullSampleRate), so its 1:1 retention is an
// invariant of the sampling hot path itself, not merely of the policy
// graph validator that rejects a sub-1.0 inspect_full rate on publish.
// Enforcing it here too means an override reaching the sampler by any
// path — a directly constructed SampleRateOverrides, a future bug in
// policy validation, a test fixture — can still never shed inspect_full.
// Returns (floor, true) for a floored class and (0, false) for classes
// an operator may freely tune in either direction (e.g. the trusted
// classes, which an operator may legitimately sample more aggressively).
func mandatorySampleRateFloor(trafficClass string) (float64, bool) {
	if repository.TrafficClass(trafficClass) == repository.TrafficClassInspectFull {
		return InspectFullSampleRate, true
	}
	return 0, false
}

// clampSampleRate bounds a configured keep probability to the valid
// (0,1] range the deterministic sampler operates on. A rate <= 0 is
// nonsensical (it would drop everything and make the 1/rate de-bias
// weight infinite), so it is rejected by reporting ok=false to the
// caller; a rate > 1 is clamped to 1 (keep everything).
func clampSampleRate(r float64) (float64, bool) {
	if r <= 0 {
		return 0, false
	}
	if r > 1 {
		return 1, true
	}
	return r, true
}

// SampleRateResolver supplies an operator-configured keep probability
// for a (tenant, trafficClass) pair, overriding the built-in class
// default and the adaptive per-tenant policy. It is the seam through
// which the policy graph drives sampling: a deployment can dial a
// noisy class down (or a compliance-sensitive class up to 1:1) per
// tenant without a code change.
//
// ResolveSampleRate returns (rate, true) when an override applies and
// (0, false) to defer to the built-in behaviour (fixed class rate, else
// adaptive). The returned rate is a keep probability; the sampler
// clamps it to (0,1], so a resolver need not pre-validate.
//
// HOT-PATH CONTRACT: ResolveSampleRate is called once per event on the
// consumer hot path, so it MUST be cheap, non-blocking, and in-memory —
// never a synchronous DB/RPC call. The shipped MapSampleRateResolver is
// a couple of map reads under a read lock; a resolver wanting live
// per-tenant config must serve it from a cache it refreshes out-of-band
// (e.g. on policy-graph publish), not by doing I/O here.
type SampleRateResolver interface {
	ResolveSampleRate(ctx context.Context, tenantID uuid.UUID, trafficClass string) (rate float64, ok bool)
}

// SampleRateOverrides is an immutable snapshot of operator-configured
// keep probabilities: a per-class default layer (applied to every
// tenant) and a per-tenant layer (which takes precedence). It is the
// value the policy graph compiles its sampling configuration into and
// hands to a MapSampleRateResolver. Treat instances as read-only after
// construction (the resolver swaps whole snapshots rather than mutating
// in place), so they are safe to share across goroutines without a lock.
type SampleRateOverrides struct {
	// ByClass maps a traffic class to the keep probability applied to
	// that class for ALL tenants (unless a per-tenant override exists).
	// A nil/absent entry means "no class-level override".
	ByClass map[string]float64
	// ByTenant maps a tenant to its per-class keep probabilities, which
	// take precedence over ByClass. A nil/absent entry means "no
	// per-tenant override for this tenant".
	ByTenant map[uuid.UUID]map[string]float64
}

// lookup resolves the most specific configured rate for (tenant,class):
// per-tenant per-class first, then the per-class default. Reports
// ok=false when neither layer configures the pair.
func (o *SampleRateOverrides) lookup(tenantID uuid.UUID, trafficClass string) (float64, bool) {
	if o == nil {
		return 0, false
	}
	if byClass, ok := o.ByTenant[tenantID]; ok {
		if r, ok := byClass[trafficClass]; ok {
			return r, true
		}
	}
	if r, ok := o.ByClass[trafficClass]; ok {
		return r, true
	}
	return 0, false
}

// MapSampleRateResolver is a SampleRateResolver backed by an atomically
// swappable SampleRateOverrides snapshot. The hot path (ResolveSampleRate)
// loads the current snapshot pointer with a single atomic load — no lock,
// no allocation — and the control plane installs a new snapshot with
// Replace when the policy graph republishes. A nil *MapSampleRateResolver
// is a valid no-op resolver (never overrides), so wiring it is optional.
type MapSampleRateResolver struct {
	snap atomic.Pointer[SampleRateOverrides]
	// writeMu serialises snapshot producers (Replace, SetTenant) so a
	// read-copy-update in SetTenant cannot lose a concurrent update.
	// Readers (ResolveSampleRate) never take it — they only atomic-load
	// the snapshot pointer.
	writeMu sync.Mutex
}

// NewMapSampleRateResolver builds a resolver seeded with the given
// overrides (nil is allowed and means "no overrides yet").
func NewMapSampleRateResolver(initial *SampleRateOverrides) *MapSampleRateResolver {
	r := &MapSampleRateResolver{}
	r.snap.Store(initial)
	return r
}

// Replace atomically installs a new overrides snapshot. The next
// ResolveSampleRate call sees it; in-flight calls finish against the
// snapshot they loaded. Passing nil clears all overrides.
func (r *MapSampleRateResolver) Replace(overrides *SampleRateOverrides) {
	if r == nil {
		return
	}
	// Held so Replace cannot interleave with a SetTenant read-copy-update
	// and silently undo it (or be undone). Readers are unaffected.
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	r.snap.Store(overrides)
}

// SetTenant atomically updates a single tenant's per-class overrides,
// preserving every other tenant's overrides and the per-class default
// layer. It is the per-tenant entry point the policy-graph sampling
// observer drives on publish/promote: one tenant republishes, only that
// tenant's row changes.
//
// Semantics:
//   - classRates is sanitised through clampSampleRate, so a rate > 1 is
//     pinned to 1 and a non-positive rate drops that class entry.
//   - An empty result (nil/empty input, or every entry rejected) REMOVES
//     the tenant's override row, so the tenant reverts to the per-class
//     defaults / built-in behaviour rather than being pinned at a stale
//     value.
//
// Implemented copy-on-write under writeMu: a fresh snapshot is built and
// atomically swapped in, so concurrent ResolveSampleRate readers always
// observe a complete, consistent snapshot and never a half-applied map.
func (r *MapSampleRateResolver) SetTenant(tenantID uuid.UUID, classRates map[string]float64) {
	if r == nil {
		return
	}
	sane := make(map[string]float64, len(classRates))
	for class, rate := range classRates {
		if c, ok := clampSampleRate(rate); ok {
			sane[class] = c
		}
	}

	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	cur := r.snap.Load()
	next := &SampleRateOverrides{
		ByClass:  copyRateMap(curByClass(cur)),
		ByTenant: copyTenantMap(curByTenant(cur)),
	}
	if next.ByTenant == nil {
		next.ByTenant = make(map[uuid.UUID]map[string]float64, 1)
	}
	if len(sane) == 0 {
		delete(next.ByTenant, tenantID)
	} else {
		next.ByTenant[tenantID] = sane
	}
	r.snap.Store(next)
}

func curByClass(o *SampleRateOverrides) map[string]float64 {
	if o == nil {
		return nil
	}
	return o.ByClass
}

func curByTenant(o *SampleRateOverrides) map[uuid.UUID]map[string]float64 {
	if o == nil {
		return nil
	}
	return o.ByTenant
}

func copyRateMap(m map[string]float64) map[string]float64 {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]float64, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copyTenantMap(m map[uuid.UUID]map[string]float64) map[uuid.UUID]map[string]float64 {
	if len(m) == 0 {
		return nil
	}
	out := make(map[uuid.UUID]map[string]float64, len(m))
	for k, v := range m {
		out[k] = v // inner maps are immutable once stored, so share them
	}
	return out
}

// ResolveSampleRate implements SampleRateResolver with two map reads on
// the current snapshot. Nil receiver returns no override.
func (r *MapSampleRateResolver) ResolveSampleRate(_ context.Context, tenantID uuid.UUID, trafficClass string) (float64, bool) {
	if r == nil {
		return 0, false
	}
	return r.snap.Load().lookup(tenantID, trafficClass)
}

// SamplerConfig configures an AdaptiveSampler.
type SamplerConfig struct {
	// Resolver supplies each tenant's steady-state events-per-second
	// budget (TenantLimit.Rate). Sampling engages only when a
	// tenant's observed arrival rate exceeds this budget. A nil
	// resolver defaults to the package default budget
	// (DefaultTenantRateLimit / DefaultTenantBurstSize), matching the
	// PerTenantLimiter's default.
	Resolver LimitResolver
	// Window is the rate-estimation window. Defaults to
	// DefaultSamplingWindow when zero.
	Window time.Duration
	// MinSampleRate is the floor on the adaptive keep probability.
	// Defaults to DefaultMinSampleRate when zero. Values are clamped
	// to (0,1].
	MinSampleRate float64
	// RateResolver supplies operator-configured per-tenant /
	// per-traffic-class keep-probability overrides (typically distilled
	// from the policy graph). When it returns an override for an event's
	// (tenant, class), that rate wins over both the built-in fixed class
	// rate and the adaptive per-tenant policy. Nil means "no overrides":
	// the sampler keeps its built-in behaviour unchanged.
	RateResolver SampleRateResolver
	// TierPolicy layers the WS-4 activity-tier-aware sampling policy on
	// top of the base keep probability: idle tenants are sampled more
	// aggressively and dormant tenants drop everything but their
	// security / compliance events. Nil means the feature is OFF — the
	// sampler behaves exactly as it did before WS-4 (DecideClass path),
	// so an upgrade never silently changes retention. See
	// tier_sampling.go.
	TierPolicy *TierSamplingPolicy
	// NowFunc returns the current time. Injected so tests can pin the
	// clock; production passes time.Now.
	NowFunc func() time.Time
}

// AdaptiveSampler makes deterministic per-tenant keep/drop decisions.
// Construct via NewAdaptiveSampler. Safe for concurrent use. A nil
// *AdaptiveSampler is a valid no-op (keeps every event at rate 1.0),
// so wiring it onto the Service is optional.
type AdaptiveSampler struct {
	resolver     LimitResolver
	rateResolver SampleRateResolver
	tierPolicy   *TierSamplingPolicy
	window       time.Duration
	minRate      float64
	now          func() time.Time

	mu      sync.RWMutex
	tenants map[uuid.UUID]*samplerState
}

// samplerState is one tenant's rate-estimation window. The keep
// probability is held stable for the lifetime of a window and
// recomputed at the boundary from the just-closed window's arrival
// count, so every event in a window shares one de-bias weight.
type samplerState struct {
	mu          sync.Mutex
	windowStart time.Time
	arrivals    int64
	keepProb    float64
}

// NewAdaptiveSampler constructs a sampler from cfg. A zero-value
// config yields a usable sampler with the package defaults.
func NewAdaptiveSampler(cfg SamplerConfig) *AdaptiveSampler {
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = StaticLimitResolver{Limit: TenantLimit{
			Rate:  DefaultTenantRateLimit,
			Burst: DefaultTenantBurstSize,
		}}
	}
	window := cfg.Window
	if window <= 0 {
		window = DefaultSamplingWindow
	}
	minRate := cfg.MinSampleRate
	if minRate <= 0 {
		minRate = DefaultMinSampleRate
	}
	if minRate > 1 {
		minRate = 1
	}
	now := cfg.NowFunc
	if now == nil {
		now = time.Now
	}
	return &AdaptiveSampler{
		resolver:     resolver,
		rateResolver: cfg.RateResolver,
		tierPolicy:   cfg.TierPolicy,
		window:       window,
		minRate:      minRate,
		now:          now,
		tenants:      make(map[uuid.UUID]*samplerState),
	}
}

// ForPartition returns a sibling sampler that shares this sampler's
// budget resolver, window, and floor but owns an independent
// per-tenant state map. Mirrors PerTenantLimiter.ForPartition: a
// tenant is pinned to exactly one telemetry partition, so the
// per-partition state maps are disjoint and there is no
// cross-partition lock contention, while budgets stay globally
// consistent through the shared resolver. Returns nil on a nil
// receiver so callers can clone an optional sampler without a nil
// check.
func (s *AdaptiveSampler) ForPartition() *AdaptiveSampler {
	if s == nil {
		return nil
	}
	return &AdaptiveSampler{
		resolver:     s.resolver,
		rateResolver: s.rateResolver,
		tierPolicy:   s.tierPolicy,
		window:       s.window,
		minRate:      s.minRate,
		now:          s.now,
		tenants:      make(map[uuid.UUID]*samplerState),
	}
}

// Decide reports whether to keep the event identified by eventID for
// the given tenant, and the keep probability (sampling rate) that was
// applied. A kept event MUST be stamped with the returned rate so
// analytics can de-bias (each kept event represents 1/rate events).
//
// The decision is deterministic: for a fixed tenant keep probability,
// the same eventID always yields the same verdict. A nil sampler
// keeps everything at rate 1.0.
//
// Decide applies only the adaptive per-tenant policy. Callers that
// know the event's traffic class should use DecideClass so the fixed
// class-level rates (see TrustedClassSampleRate) are honoured.
func (s *AdaptiveSampler) Decide(ctx context.Context, tenantID, eventID uuid.UUID) (keep bool, sampleRate float64) {
	return s.DecideClass(ctx, tenantID, eventID, "")
}

// DecideClass is the traffic-class-aware keep/drop decision. It is the
// entry point the consumer hot path uses, because the chosen sampling
// regime depends on the class:
//
//   - trusted_direct / trusted_media_bypass are sampled at the fixed
//     TrustedClassSampleRate (1:100) — a class-level cost-control
//     policy that does NOT depend on, and does not feed, the tenant's
//     adaptive arrival-rate window. The verdict is the same
//     deterministic hash threshold, so it is redelivery-stable and the
//     1/rate de-bias weight is exact.
//   - every other class falls through to the adaptive per-tenant
//     sampler (Decide's historical behaviour), which records the
//     arrival and sheds load only when the tenant exceeds its budget.
//
// A nil sampler keeps everything at rate 1.0 (the optional-dependency
// no-op contract is preserved: when no sampler is wired, no sampling —
// including the fixed class policy — is applied).
func (s *AdaptiveSampler) DecideClass(ctx context.Context, tenantID, eventID uuid.UUID, trafficClass string) (keep bool, sampleRate float64) {
	if s == nil {
		return true, 1.0
	}
	p := s.resolveBaseKeepProb(ctx, tenantID, trafficClass)
	if p >= 1.0 {
		return true, 1.0
	}
	if hashFraction(eventID) < p {
		return true, p
	}
	return false, p
}

// resolveBaseKeepProb returns the keep probability for (tenant, class)
// honouring the same precedence DecideClass relies on — operator
// override, then fixed class rate, then the adaptive per-tenant policy —
// without applying the final hash threshold. It is the shared core of
// DecideClass and the tier-aware DecideEvent so both compose the same
// base probability. The adaptive branch (only reached when no override
// or fixed rate applies) records one arrival as a side effect, exactly
// as DecideClass did before this refactor.
func (s *AdaptiveSampler) resolveBaseKeepProb(ctx context.Context, tenantID uuid.UUID, trafficClass string) float64 {
	if r, ok := s.overrideRate(ctx, tenantID, trafficClass); ok {
		// Operator-configured per-tenant / per-class override wins over
		// the built-in class rate and the adaptive policy; no adaptive
		// state touched.
		return r
	}
	if fixed, ok := fixedClassSampleRate(trafficClass); ok {
		// Fixed class rate: no adaptive state touched (no arrival
		// recorded) — these events bypass the per-tenant window entirely.
		return fixed
	}
	return s.keepProb(ctx, tenantID)
}

// DecideEvent is the activity-tier-aware keep/drop decision and the
// entry point the consumer hot path uses when the WS-4 tier policy is
// wired (SamplerConfig.TierPolicy). It layers the tenant's activity tier
// on top of the base keep probability DecideClass computes:
//
//   - Security-relevant events (securityRelevant == true) and the
//     inspect_full compliance class are pinned at 1.0 in EVERY tier, so
//     a dormant tenant never loses an IPS / ZTNA / DLP signal or a
//     legally-required audit record.
//   - TierActive applies the multiplier 1.0 — identical to DecideClass
//     for non-security classes.
//   - TierIdle scales the base probability by the idle multiplier
//     (reduced sampling), keeping the same deterministic hash threshold
//     so the verdict is redelivery-stable and the 1/rate de-bias weight
//     is exact.
//   - TierDormant scales by the dormant multiplier (0 by default), so
//     every non-security, non-compliance event is dropped outright —
//     "security-events-only".
//
// The returned tier is the tier the decision was made under (for the
// per-tier rows/s metric); tiered reports whether the tier policy was in
// effect (false when no policy is wired, so callers skip the per-tier
// metric and the decision is exactly DecideClass).
//
// A nil sampler keeps everything at rate 1.0. When no tier policy is
// wired, DecideEvent delegates to DecideClass — the feature is fully
// default-OFF.
func (s *AdaptiveSampler) DecideEvent(ctx context.Context, tenantID, eventID uuid.UUID, trafficClass string, securityRelevant bool) (keep bool, sampleRate float64, tier tenancy.Tier, tiered bool) {
	if s == nil {
		return true, 1.0, tenancy.TierActive, false
	}
	if s.tierPolicy == nil {
		k, r := s.DecideClass(ctx, tenantID, eventID, trafficClass)
		return k, r, tenancy.TierActive, false
	}

	tier = s.tierPolicy.tierFor(ctx, tenantID)

	// Floor: events that may never be shed on cost grounds. Security
	// events are pinned at 1.0; inspect_full keeps its compliance floor.
	// The max of the two is the hard lower bound for this event.
	floor := 0.0
	if securityRelevant {
		floor = 1.0
	}
	if f, ok := mandatorySampleRateFloor(trafficClass); ok && f > floor {
		floor = f
	}
	if floor >= 1.0 {
		// Always keep, never sample, no adaptive state touched. NOTE:
		// because this returns before resolveBaseKeepProb, a floored
		// event (security-relevant, or the inspect_full compliance
		// class) records NO arrival — whereas the pre-tier DecideClass
		// path counted a security event with an empty traffic class as
		// one arrival via keepProb. So enabling tier sampling slightly
		// lowers the measured arrival rate for security-heavy tenants,
		// making the adaptive sampler a touch less aggressive on their
		// *non*-security events. This is deliberate and one-sided (it
		// keeps MORE, never less — the fail-safe direction), and such
		// tenants are active-tier anyway, so the practical effect is
		// negligible; flagged here for operators watching keepProb.
		return true, 1.0, tier, true
	}

	mult := s.tierPolicy.multiplier(tier)
	if mult <= 0 {
		// Dormant security-events-only: drop the non-security,
		// non-compliance event without computing (or perturbing) the
		// adaptive base probability — a dormant tenant's shed stream
		// must not feed the rate estimate.
		return false, 0, tier, true
	}

	base := s.resolveBaseKeepProb(ctx, tenantID, trafficClass)
	p := base * mult
	if p < floor {
		p = floor
	}
	if p >= 1.0 {
		return true, 1.0, tier, true
	}
	if hashFraction(eventID) < p {
		return true, p, tier, true
	}
	return false, p, tier, true
}

// TierAware reports whether a WS-4 activity-tier sampling policy is
// wired. Callers on the hot path use it to recover a redelivered event's
// de-bias rate through SampleRateForEvent rather than SampleRateForClass.
func (s *AdaptiveSampler) TierAware() bool {
	return s != nil && s.tierPolicy != nil
}

// SampleRateFor returns the keep probability currently in effect for
// the tenant WITHOUT recording an arrival or rolling the window. It is
// a read-only companion to Decide, used to recover the de-bias rate
// for a redelivered event: the keep/drop verdict was already made on
// the first delivery (and must not be re-made), but the SampleRate
// stamped then lived only on the in-memory envelope and is lost when
// the redelivery is re-decoded from the producer's wire bytes.
//
// It returns the tenant's last-computed keep probability rather than
// rolling to a fresh window, because the value of interest is the rate
// that was in effect when the event was admitted, not a recomputed
// one. Returns 1.0 for a nil sampler or a tenant with no state yet
// (e.g. admitted at the full default rate, so no de-bias is needed).
func (s *AdaptiveSampler) SampleRateFor(tenantID uuid.UUID) float64 {
	if s == nil {
		return 1.0
	}
	s.mu.RLock()
	st, ok := s.tenants[tenantID]
	s.mu.RUnlock()
	if !ok {
		return 1.0
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.windowStart.IsZero() || st.keepProb <= 0 {
		return 1.0
	}
	return st.keepProb
}

// SampleRateForClass is the traffic-class-aware companion to
// SampleRateFor, used to recover a redelivered event's de-bias rate.
// For a fixed-rate class (trusted_direct / trusted_media_bypass) it
// returns the constant class rate directly — the verdict on the first
// delivery used that rate, never the tenant's adaptive probability, so
// recovering it from per-tenant state would stamp the wrong weight.
// Every other class defers to SampleRateFor. Returns 1.0 for a nil
// sampler.
func (s *AdaptiveSampler) SampleRateForClass(tenantID uuid.UUID, trafficClass string) float64 {
	if s == nil {
		return 1.0
	}
	// Mirror DecideClass's precedence so a redelivered event recovers
	// the exact rate its keep/drop verdict was made under: override
	// first, then fixed class rate, then the adaptive per-tenant rate.
	if r, ok := s.overrideRate(context.Background(), tenantID, trafficClass); ok {
		return r
	}
	if fixed, ok := fixedClassSampleRate(trafficClass); ok {
		return fixed
	}
	return s.SampleRateFor(tenantID)
}

// SampleRateForEvent is the activity-tier-aware companion to
// SampleRateForClass, used to recover a redelivered event's de-bias
// rate when the WS-4 tier policy is wired. It mirrors DecideEvent's rate
// arithmetic — security / compliance floor first, then base rate scaled
// by the tenant's tier multiplier — without recording an arrival (a
// redelivery is the same event, not new load).
//
// A would-have-been-dropped event (tier multiplier 0, non-security) can
// never be a redelivery: a sampling drop is Ack'd, never redelivered. So
// the only way control reaches here for such an event is a downstream
// retry of an already-admitted event, which means it was kept on first
// delivery; recovering 1.0 (no de-bias) is the conservative, correct
// weight in that impossible-in-practice case. When no tier policy is
// wired this defers to SampleRateForClass, preserving prior behaviour.
func (s *AdaptiveSampler) SampleRateForEvent(tenantID uuid.UUID, trafficClass string, securityRelevant bool) float64 {
	if s == nil {
		return 1.0
	}
	if s.tierPolicy == nil {
		return s.SampleRateForClass(tenantID, trafficClass)
	}
	tier := s.tierPolicy.tierFor(context.Background(), tenantID)
	floor := 0.0
	if securityRelevant {
		floor = 1.0
	}
	if f, ok := mandatorySampleRateFloor(trafficClass); ok && f > floor {
		floor = f
	}
	if floor >= 1.0 {
		return 1.0
	}
	mult := s.tierPolicy.multiplier(tier)
	if mult <= 0 {
		return 1.0
	}
	p := s.SampleRateForClass(tenantID, trafficClass) * mult
	if p < floor {
		p = floor
	}
	if p > 1 {
		p = 1
	}
	return p
}

// overrideRate consults the configured SampleRateResolver (if any) for a
// per-tenant / per-class keep-probability override, clamping the result
// to the valid (0,1] range. Reports ok=false when no resolver is wired,
// no override applies, or the configured value is non-positive (which
// the clamp rejects rather than silently dropping all events).
//
// A class with a mandatory floor (mandatorySampleRateFloor — currently
// only inspect_full at 1:1) is raised to that floor here, so the
// compliance pin holds no matter what an override asks for. This is the
// single chokepoint both DecideClass and SampleRateForClass consult, so
// flooring once here keeps the keep/drop verdict and the recovered
// de-bias rate in agreement.
func (s *AdaptiveSampler) overrideRate(ctx context.Context, tenantID uuid.UUID, trafficClass string) (float64, bool) {
	if s.rateResolver == nil {
		return 0, false
	}
	r, ok := s.rateResolver.ResolveSampleRate(ctx, tenantID, trafficClass)
	if !ok {
		return 0, false
	}
	clamped, ok := clampSampleRate(r)
	if !ok {
		return 0, false
	}
	if floor, floored := mandatorySampleRateFloor(trafficClass); floored && clamped < floor {
		clamped = floor
	}
	return clamped, true
}

// keepProb returns the keep probability for the tenant's current
// window, rolling the window and recomputing the probability from the
// just-closed window's arrival rate when the window has elapsed. It
// records this call as one arrival.
func (s *AdaptiveSampler) keepProb(ctx context.Context, tenantID uuid.UUID) float64 {
	st := s.stateFor(tenantID)
	st.mu.Lock()
	defer st.mu.Unlock()
	now := s.now()
	if st.windowStart.IsZero() {
		// First event for this tenant: no history, keep everything.
		st.windowStart = now
		st.keepProb = 1.0
	} else if elapsed := now.Sub(st.windowStart); elapsed >= s.window {
		observed := float64(st.arrivals) / elapsed.Seconds()
		st.keepProb = s.computeKeepProb(ctx, tenantID, observed)
		st.windowStart = now
		st.arrivals = 0
	}
	st.arrivals++
	return st.keepProb
}

// computeKeepProb maps an observed arrival rate (events/sec) to a
// keep probability given the tenant's budget. At or under budget
// (or with an unlimited / unconfigured budget) it keeps everything;
// over budget it keeps budget/observed so the kept volume lands at
// roughly the budget, clamped to the [minRate,1] floor so visibility
// is never fully lost.
func (s *AdaptiveSampler) computeKeepProb(ctx context.Context, tenantID uuid.UUID, observed float64) float64 {
	limit := s.resolver.Resolve(ctx, tenantID)
	if limit.Rate == rate.Inf {
		return 1.0
	}
	budget := float64(limit.Rate)
	if budget <= 0 || observed <= budget {
		return 1.0
	}
	p := budget / observed
	if p < s.minRate {
		p = s.minRate
	}
	if p > 1 {
		p = 1
	}
	return p
}

// stateFor returns (creating if necessary) the per-tenant sampler
// state. The hot path (existing tenant) takes the read lock only.
func (s *AdaptiveSampler) stateFor(tenantID uuid.UUID) *samplerState {
	s.mu.RLock()
	st, ok := s.tenants[tenantID]
	s.mu.RUnlock()
	if ok {
		return st
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-check under the write lock in case of a concurrent create.
	if st, ok := s.tenants[tenantID]; ok {
		return st
	}
	st = &samplerState{}
	s.tenants[tenantID] = st
	return st
}

// SamplerSnapshot is a read-only view of one tenant's current keep
// probability, for the /metrics handler and tests.
type SamplerSnapshot struct {
	Tenant   uuid.UUID
	KeepProb float64
}

// Snapshot returns the current per-tenant keep probabilities.
func (s *AdaptiveSampler) Snapshot() map[uuid.UUID]SamplerSnapshot {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[uuid.UUID]SamplerSnapshot, len(s.tenants))
	for id, st := range s.tenants {
		st.mu.Lock()
		out[id] = SamplerSnapshot{Tenant: id, KeepProb: st.keepProb}
		st.mu.Unlock()
	}
	return out
}

// hashFraction maps a UUID to a uniformly-distributed fraction in
// [0,1) using a seedless FNV-1a hash. Seedless (unlike maphash) is
// essential: the fraction must be identical across process restarts
// and across partitions so the keep/drop decision for an event is
// globally reproducible. The top 53 bits are used so the quotient is
// exactly representable as a float64.
func hashFraction(id uuid.UUID) float64 {
	h := fnv.New64a()
	_, _ = h.Write(id[:])
	return float64(h.Sum64()>>11) / float64(uint64(1)<<53)
}
