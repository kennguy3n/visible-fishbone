package ai

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/nats/schema"
)

// RetroHunter sweeps a tenant's historical telemetry for prior
// exposure to an indicator the store only learned was malicious
// after the fact. It is the read-side dual of the enforcement
// compilers: where IOCEnforcementCompiler / IPSRuleCompiler turn a
// known-bad indicator into a FORWARD-looking block, the hunter
// answers the BACKWARD-looking question an analyst asks the moment
// a feed lights up — "we now know X is bad; did anyone here talk to
// it in the last N days, before we were blocking it?".
//
// It deliberately mirrors policy.Simulator's proven shape: a thin
// reader over the ClickHouse hot tier (RetroEventSource.ListEvents),
// a bounded [since, until] window, a per-tenant event cap, and an
// in-memory classification pass. The matching surface:
//
//   - DNS query        -> domain IOC (apex match + subdomain)
//   - HTTP host / SNI   -> domain IOC (apex match + subdomain)
//   - flow dst IP       -> IP IOC (exact) or CIDR IOC (containment)
//
// URL and hash IOCs are not hunted here: a URL lands in the SWG
// request log (an HTTP host match already catches the destination)
// and a hash is a content verdict with no network-telemetry value
// to match against.
type RetroHunter struct {
	src       RetroEventSource
	classes   []schema.EventClass
	maxEvents int
	now       func() time.Time
}

// RetroEventSource is the minimal read surface the hunter needs:
// the same ListEvents the policy simulator consumes, so the
// ClickHouse Reader satisfies it without a new query shape. Kept as
// a local interface (not an import of the clickhouse package) so the
// ai package does not take a dependency on the telemetry hot tier.
type RetroEventSource interface {
	ListEvents(
		ctx context.Context,
		tenantID uuid.UUID,
		classes []schema.EventClass,
		since, until time.Time,
		maxEvents int,
	) ([]schema.Envelope, error)
}

// DefaultRetroEventClasses is the set of telemetry classes the
// hunter scans: the three that carry a network destination an IOC
// can name. Flow carries the dst IP, DNS the queried name, HTTP the
// host/SNI.
var DefaultRetroEventClasses = []schema.EventClass{
	schema.EventClassFlow,
	schema.EventClassDNS,
	schema.EventClassHTTP,
}

// DefaultRetroMaxEvents bounds a single tenant sweep, matching the
// simulator's hot-path event cap so a hunt over a wide window on a
// busy tenant stays a bounded scan rather than an unbounded read.
const DefaultRetroMaxEvents = 100_000

// RetroHunterOption configures NewRetroHunter.
type RetroHunterOption func(*RetroHunter)

// WithRetroEventClasses overrides the telemetry classes scanned.
// Empty entries and duplicates are dropped; an all-empty override
// falls back to DefaultRetroEventClasses.
func WithRetroEventClasses(classes ...schema.EventClass) RetroHunterOption {
	return func(h *RetroHunter) {
		seen := make(map[schema.EventClass]struct{}, len(classes))
		out := make([]schema.EventClass, 0, len(classes))
		for _, c := range classes {
			if !c.IsValid() {
				continue
			}
			if _, dup := seen[c]; dup {
				continue
			}
			seen[c] = struct{}{}
			out = append(out, c)
		}
		if len(out) > 0 {
			h.classes = out
		}
	}
}

// WithRetroMaxEvents overrides the per-tenant event cap. Zero or
// negative falls back to DefaultRetroMaxEvents.
func WithRetroMaxEvents(maxEvents int) RetroHunterOption {
	return func(h *RetroHunter) {
		if maxEvents > 0 {
			h.maxEvents = maxEvents
		}
	}
}

// WithRetroClock overrides the hunter's clock (tests).
func WithRetroClock(now func() time.Time) RetroHunterOption {
	return func(h *RetroHunter) {
		if now != nil {
			h.now = now
		}
	}
}

// NewRetroHunter builds a hunter over the given event source.
func NewRetroHunter(src RetroEventSource, opts ...RetroHunterOption) *RetroHunter {
	h := &RetroHunter{
		src:       src,
		classes:   DefaultRetroEventClasses,
		maxEvents: DefaultRetroMaxEvents,
		now:       time.Now,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// RetroHit is a single historical telemetry event that, in
// hindsight, touched a now-known-bad indicator.
type RetroHit struct {
	// Indicator is the stored IOC value that matched.
	Indicator string
	// IndicatorType is the IOC category that matched.
	IndicatorType IOCType
	// EventClass is the telemetry class the hit came from.
	EventClass schema.EventClass
	// MatchedValue is the telemetry-side value that matched the
	// indicator (the queried name, host, or dst IP) — equal to
	// Indicator for an exact match, the contained IP for a CIDR
	// match, or the subdomain for an apex match.
	MatchedValue string
	// Timestamp is when the historical event occurred.
	Timestamp time.Time
	// DeviceID / SiteID locate the exposed asset.
	DeviceID uuid.UUID
	SiteID   *uuid.UUID
	// Verdict is the verdict the edge recorded at the time (e.g.
	// allow), which is the whole point: a retro-hit on an allowed
	// flow is exposure that predates enforcement.
	Verdict schema.Verdict
	// Confidence / ThreatActor / Campaign carry the matched IOC's
	// attribution so a finding is actionable without a second
	// store lookup.
	Confidence  float64
	ThreatActor string
	Campaign    string
}

// RetroReport is the outcome of a single tenant sweep.
type RetroReport struct {
	TenantID      uuid.UUID
	Since         time.Time
	Until         time.Time
	EventsScanned int
	// Hits are the matched events, ordered by timestamp ascending
	// then indicator, so a report is byte-stable across runs.
	Hits []RetroHit
	// ByType counts hits per matched IOC type.
	ByType map[IOCType]int
	// DistinctDevices is the number of unique devices with at
	// least one hit — the blast radius of the exposure.
	DistinctDevices int
	// DecodeErrors counts envelopes whose payload failed to
	// decode (skipped, not fatal).
	DecodeErrors int
}

// Hunt sweeps [since, until] of tenantID's telemetry for events
// matching any indicator in set, returning a per-tenant report.
// An empty set short-circuits without touching the event source.
func (h *RetroHunter) Hunt(
	ctx context.Context,
	tenantID uuid.UUID,
	set *RetroIndicatorSet,
	since, until time.Time,
) (RetroReport, error) {
	if tenantID == uuid.Nil {
		return RetroReport{}, fmt.Errorf("ai/retrohunt: tenant_id required")
	}
	if !until.After(since) {
		return RetroReport{}, fmt.Errorf("ai/retrohunt: until must be after since")
	}
	report := RetroReport{
		TenantID: tenantID,
		Since:    since.UTC(),
		Until:    until.UTC(),
		ByType:   map[IOCType]int{},
	}
	if set == nil || set.empty() {
		return report, nil
	}

	envelopes, err := h.src.ListEvents(ctx, tenantID, h.classes, since, until, h.maxEvents)
	if err != nil {
		return RetroReport{}, fmt.Errorf("ai/retrohunt: list events: %w", err)
	}
	report.EventsScanned = len(envelopes)

	devices := make(map[uuid.UUID]struct{})
	for i := range envelopes {
		hit, ok, decodeErr := h.matchEnvelope(envelopes[i], set)
		if decodeErr {
			report.DecodeErrors++
			continue
		}
		if !ok {
			continue
		}
		report.Hits = append(report.Hits, hit)
		report.ByType[hit.IndicatorType]++
		devices[hit.DeviceID] = struct{}{}
	}
	report.DistinctDevices = len(devices)

	sort.SliceStable(report.Hits, func(i, j int) bool {
		a, b := report.Hits[i], report.Hits[j]
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.Before(b.Timestamp)
		}
		return a.Indicator < b.Indicator
	})
	return report, nil
}

// matchEnvelope decodes one envelope's payload by class and reports
// whether it touched a known-bad indicator. The third return is
// true when the payload failed to decode (the caller counts it as a
// decode error and skips it).
func (h *RetroHunter) matchEnvelope(env schema.Envelope, set *RetroIndicatorSet) (RetroHit, bool, bool) {
	base := func(value string, ioc IOC, verdict schema.Verdict) RetroHit {
		return RetroHit{
			Indicator:     ioc.Value,
			IndicatorType: ioc.Type,
			EventClass:    env.EventClass,
			MatchedValue:  value,
			Timestamp:     env.Timestamp.UTC(),
			DeviceID:      env.DeviceID,
			SiteID:        env.SiteID,
			Verdict:       verdict,
			Confidence:    ioc.Confidence,
			ThreatActor:   ioc.ThreatActor,
			Campaign:      ioc.Campaign,
		}
	}

	switch env.EventClass {
	case schema.EventClassDNS:
		var ev schema.DNSEvent
		if err := schema.UnpackPayload(env.Payload, &ev); err != nil {
			return RetroHit{}, false, true
		}
		if ioc, ok := set.matchDomain(ev.Query); ok {
			return base(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(ev.Query), ".")), ioc, ev.Verdict), true, false
		}
	case schema.EventClassHTTP:
		var ev schema.HTTPEvent
		if err := schema.UnpackPayload(env.Payload, &ev); err != nil {
			return RetroHit{}, false, true
		}
		// SNI is the most reliable destination identity (it
		// survives an IP-only connect); fall back to Host. The Host
		// header may carry a :port (e.g. "evil.com:8080") whereas
		// stored domains never do (normalizeDomain rejects ':'), so
		// strip the port before matching to avoid a false negative on
		// plain HTTP to a non-standard port with no SNI.
		host := ev.SNI
		if host == "" {
			host = ev.Host
		}
		if hostPart, _, found := strings.Cut(host, ":"); found {
			host = hostPart
		}
		if ioc, ok := set.matchDomain(host); ok {
			return base(strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), ".")), ioc, ev.Verdict), true, false
		}
	case schema.EventClassFlow:
		var ev schema.FlowEvent
		if err := schema.UnpackPayload(env.Payload, &ev); err != nil {
			return RetroHit{}, false, true
		}
		if ioc, ok := set.matchIP(ev.DstIP); ok {
			return base(ev.DstIP, ioc, ev.Verdict), true, false
		}
	}
	return RetroHit{}, false, false
}

// RetroIndicatorSet is the lookup-optimised view of the indicators
// a hunt matches against: a domain map (exact + parent-suffix),
// an IP map (exact), and a slice of parsed CIDR networks. Build it
// once via NewRetroIndicatorSet and reuse across per-tenant hunts.
type RetroIndicatorSet struct {
	domains map[string]IOC
	ips     map[string]IOC
	cidrs   []retroCIDR
}

type retroCIDR struct {
	net *net.IPNet
	ioc IOC
}

// NewRetroIndicatorSet builds a hunt set from the domain, IP and
// CIDR IOCs in snap whose confidence clears minConfidence. JA3, URL
// and hash indicators are ignored (no network-telemetry surface to
// match). Values are already normalised by the store, so they are
// indexed as-is.
func NewRetroIndicatorSet(snap IOCSnapshot, minConfidence float64) *RetroIndicatorSet {
	set := &RetroIndicatorSet{
		domains: make(map[string]IOC, len(snap.Domains)),
		ips:     make(map[string]IOC, len(snap.IPs)),
	}
	for _, ioc := range snap.Domains {
		if ioc.Confidence < minConfidence {
			continue
		}
		set.domains[ioc.Value] = ioc
	}
	for _, ioc := range snap.IPs {
		if ioc.Confidence < minConfidence {
			continue
		}
		set.ips[ioc.Value] = ioc
	}
	for _, ioc := range snap.CIDRs {
		if ioc.Confidence < minConfidence {
			continue
		}
		_, ipNet, err := net.ParseCIDR(ioc.Value)
		if err != nil {
			continue
		}
		set.cidrs = append(set.cidrs, retroCIDR{net: ipNet, ioc: ioc})
	}
	return set
}

// Len reports the number of indicators in the set.
func (s *RetroIndicatorSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.domains) + len(s.ips) + len(s.cidrs)
}

func (s *RetroIndicatorSet) empty() bool { return s.Len() == 0 }

// matchDomain reports whether a queried name matches a domain IOC,
// either exactly or as a subdomain of one (a malicious apex
// "evil.example" matches a lookup of "c2.evil.example"). The query
// is normalised the same way stored domains are (lowercase, no
// trailing dot) so the comparison is byte-for-byte.
func (s *RetroIndicatorSet) matchDomain(query string) (IOC, bool) {
	name := strings.ToLower(strings.TrimSpace(query))
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return IOC{}, false
	}
	if ioc, ok := s.domains[name]; ok {
		return ioc, true
	}
	// Walk parent labels: c2.evil.example -> evil.example -> example.
	for i := 0; i < len(name); i++ {
		if name[i] != '.' {
			continue
		}
		if ioc, ok := s.domains[name[i+1:]]; ok {
			return ioc, true
		}
	}
	return IOC{}, false
}

// matchIP reports whether a destination IP matches an IP IOC
// (exact) or falls inside a CIDR IOC (containment). Exact wins over
// containment when both are present.
func (s *RetroIndicatorSet) matchIP(raw string) (IOC, bool) {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return IOC{}, false
	}
	if ioc, ok := s.ips[ip.String()]; ok {
		return ioc, true
	}
	for _, c := range s.cidrs {
		if c.net.Contains(ip) {
			return c.ioc, true
		}
	}
	return IOC{}, false
}
