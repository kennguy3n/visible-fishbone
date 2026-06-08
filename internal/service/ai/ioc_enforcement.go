package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/kennguy3n/visible-fishbone/internal/service/policy"
)

// IOCEnforcementCompiler turns a point-in-time IOCStore snapshot
// into the enforcement artefacts the signed policy bundle carries:
//
//   - IP indicators   -> NGFW firewall-deny rules (DomainNGFW)
//   - domain IOCs      -> DNS deny / sinkhole rules (DomainDNS)
//   - URL indicators   -> SWG host-deny rules       (DomainSWG)
//   - file-hash IOCs   -> malware verdict entries    (StaticMalwareList)
//
// It implements both policy.IOCCompiler (rule slice) and
// policy.MalwareHashCompiler (malware section) so a single
// instance wires the whole IOC -> bundle path through the existing
// policy.Service.Compile flow — the same seam inline-CASB uses. The
// compiler reads the store through a snapshot func so it is trivial
// to unit-test against a fixed snapshot and so the store's RWMutex
// is held only for the snapshot copy, never across rule encoding.
//
// Threat-feed indicators are global, so CompileIOCRules /
// CompileMalwareHashes ignore the tenant id and return the same set
// for every tenant; the parameter is kept to satisfy the policy
// interfaces and to leave room for a future per-tenant carve-out.
type IOCEnforcementCompiler struct {
	snapshot func() IOCSnapshot
	// minConfidence is the floor an indicator must clear to be
	// compiled into an enforcement rule. It is deliberately
	// separate from the IOCStore's own admission floor: the store
	// may retain lower-confidence indicators for live-traffic
	// alerting (ThreatIntelEngine) while enforcement only blocks
	// on higher-confidence hits to bound false positives.
	minConfidence float64
	// maliciousThreshold is the confidence at/above which a hash
	// IOC compiles to a "malicious" (deny) verdict; between
	// minConfidence and this it compiles to "suspicious" so the
	// SWG can treat it per its risk posture rather than denying
	// outright.
	maliciousThreshold float64
}

// IOCEnforcementOption configures NewIOCEnforcementCompiler.
type IOCEnforcementOption func(*IOCEnforcementCompiler)

// WithEnforcementMinConfidence sets the floor an indicator must
// clear to be compiled into an enforcement rule. Defaults to
// defaultEnforcementMinConfidence.
func WithEnforcementMinConfidence(floor float64) IOCEnforcementOption {
	return func(c *IOCEnforcementCompiler) { c.minConfidence = clampConfidence(floor) }
}

// WithMaliciousThreshold sets the confidence at/above which a hash
// IOC is compiled to a "malicious" verdict (vs. "suspicious").
// Defaults to defaultMaliciousThreshold.
func WithMaliciousThreshold(t float64) IOCEnforcementOption {
	return func(c *IOCEnforcementCompiler) { c.maliciousThreshold = clampConfidence(t) }
}

const (
	defaultEnforcementMinConfidence = 0.5
	defaultMaliciousThreshold       = 0.8
)

// NewIOCEnforcementCompiler builds a compiler over the given store.
func NewIOCEnforcementCompiler(store *IOCStore, opts ...IOCEnforcementOption) *IOCEnforcementCompiler {
	c := &IOCEnforcementCompiler{
		snapshot:           store.Snapshot,
		minConfidence:      defaultEnforcementMinConfidence,
		maliciousThreshold: defaultMaliciousThreshold,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// newIOCEnforcementCompilerFromSnapshot builds a compiler over a
// fixed snapshot func. Used by tests to drive deterministic input
// without standing up a store.
func newIOCEnforcementCompilerFromSnapshot(snap func() IOCSnapshot, opts ...IOCEnforcementOption) *IOCEnforcementCompiler {
	c := &IOCEnforcementCompiler{
		snapshot:           snap,
		minConfidence:      defaultEnforcementMinConfidence,
		maliciousThreshold: defaultMaliciousThreshold,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// CompileIOCRules implements policy.IOCCompiler. It returns the
// IP / domain / URL deny rules for the current snapshot, sorted by
// rule id for byte-deterministic bundle output. Hash IOCs are not
// rules — they ride the malware section (CompileMalwareHashes).
func (c *IOCEnforcementCompiler) CompileIOCRules(_ context.Context, _ uuid.UUID) ([]policy.Rule, error) {
	snap := c.snapshot()
	rules := make([]policy.Rule, 0, len(snap.IPs)+len(snap.Domains)+len(snap.URLs))

	for _, ioc := range snap.IPs {
		if ioc.Confidence < c.minConfidence {
			continue
		}
		pred, err := flowDstIPPredicate(ioc.Value)
		if err != nil {
			return nil, err
		}
		rules = append(rules, policy.Rule{
			ID:          "ti-ngfw-" + ioc.Value,
			Domain:      policy.DomainNGFW,
			Verb:        policy.VerbDeny,
			Predicates:  []policy.Predicate{pred},
			Description: iocRuleDescription("firewall deny", ioc),
		})
	}

	for _, ioc := range snap.Domains {
		if ioc.Confidence < c.minConfidence {
			continue
		}
		pred, err := dnsQueryPredicate(ioc.Value)
		if err != nil {
			return nil, err
		}
		rules = append(rules, policy.Rule{
			ID:          "ti-dns-" + ioc.Value,
			Domain:      policy.DomainDNS,
			Verb:        policy.VerbDeny,
			Predicates:  []policy.Predicate{pred},
			Description: iocRuleDescription("DNS sinkhole", ioc),
		})
	}

	// URL IOCs match on the SWG Host header, so multiple URLs that
	// share a host collapse to a single deny rule. Dedupe by host,
	// keeping the highest-confidence indicator for the rule's
	// description/provenance.
	byHost := make(map[string]IOC)
	for _, ioc := range snap.URLs {
		if ioc.Confidence < c.minConfidence {
			continue
		}
		host := ioc.URLHost()
		if host == "" {
			continue
		}
		if cur, ok := byHost[host]; !ok || ioc.Confidence > cur.Confidence {
			byHost[host] = ioc
		}
	}
	hosts := make([]string, 0, len(byHost))
	for host := range byHost {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		pred, err := httpHostPredicate(host)
		if err != nil {
			return nil, err
		}
		rules = append(rules, policy.Rule{
			ID:          "ti-swg-" + host,
			Domain:      policy.DomainSWG,
			Verb:        policy.VerbDeny,
			Predicates:  []policy.Predicate{pred},
			Description: iocRuleDescription("SWG deny", byHost[host]),
		})
	}

	sort.SliceStable(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}

// CompileMalwareHashes implements policy.MalwareHashCompiler. Hash
// IOCs at/above maliciousThreshold compile to a "malicious"
// verdict; those between minConfidence and the threshold compile
// to "suspicious". Entries below minConfidence are dropped.
func (c *IOCEnforcementCompiler) CompileMalwareHashes(_ context.Context, _ uuid.UUID) ([]policy.MalwareHashEntry, error) {
	snap := c.snapshot()
	out := make([]policy.MalwareHashEntry, 0, len(snap.Hashes))
	for _, ioc := range snap.Hashes {
		if ioc.Confidence < c.minConfidence {
			continue
		}
		verdict := "suspicious"
		if ioc.Confidence >= c.maliciousThreshold {
			verdict = "malicious"
		}
		out = append(out, policy.MalwareHashEntry{Hash: ioc.Value, Verdict: verdict})
	}
	// policy.encodeMalwareHashes sorts before encoding, but sort
	// here too so the compiler's own output is stable for tests.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Hash < out[j].Hash })
	return out, nil
}

// iocRuleDescription builds a human-readable, operator-facing rule
// label that records the enforcement action, the feed source and
// any attribution so a reviewer can trace a bundle rule back to the
// indicator that produced it.
func iocRuleDescription(action string, ioc IOC) string {
	desc := fmt.Sprintf("threat-intel %s: %s", action, ioc.Value)
	if ioc.Source != "" {
		desc += " [" + ioc.Source + "]"
	}
	switch {
	case ioc.ThreatActor != "" && ioc.Campaign != "":
		desc += fmt.Sprintf(" (%s / %s)", ioc.ThreatActor, ioc.Campaign)
	case ioc.ThreatActor != "":
		desc += " (" + ioc.ThreatActor + ")"
	case ioc.Campaign != "":
		desc += " (" + ioc.Campaign + ")"
	}
	return desc
}

// flowDstIPPredicate builds the inline predicate matching a flow's
// destination IP. The match document shape mirrors the policy
// evaluator's predicateMatchDoc (dst_ip) and the Rust
// sng-policy-eval matcher.
func flowDstIPPredicate(ip string) (policy.Predicate, error) {
	return inlinePredicate("ti-dst-ip-"+ip, map[string]string{"dst_ip": ip})
}

// dnsQueryPredicate builds the inline predicate matching a DNS
// query name (query field).
func dnsQueryPredicate(domain string) (policy.Predicate, error) {
	return inlinePredicate("ti-dns-query-"+domain, map[string]string{"query": domain})
}

// httpHostPredicate builds the inline predicate matching an HTTP
// request Host (host field).
func httpHostPredicate(host string) (policy.Predicate, error) {
	return inlinePredicate("ti-http-host-"+host, map[string]string{"host": host})
}

func inlinePredicate(name string, match map[string]string) (policy.Predicate, error) {
	raw, err := json.Marshal(match)
	if err != nil {
		return policy.Predicate{}, fmt.Errorf("encode ioc predicate %q: %w", name, err)
	}
	return policy.Predicate{Name: name, Match: raw}, nil
}

// Ensure the compiler satisfies both policy interfaces at compile
// time so a signature drift in either is caught here, not at the
// wiring site in cmd/sng-control.
var (
	_ policy.IOCCompiler         = (*IOCEnforcementCompiler)(nil)
	_ policy.MalwareHashCompiler = (*IOCEnforcementCompiler)(nil)
)

// DemotionEmitter is the seam the domain-IOC demotion bridge uses
// to push a domain into the appdb demotion engine without the ai
// package importing appdb (avoiding an import cycle and keeping the
// bridge unit-testable). cmd/sng-control adapts
// *appdb.DemotionEngine to this interface.
type DemotionEmitter interface {
	// EmitDomainDemotion demotes a single domain. Implementations
	// map it onto a threat_feed DemotionEvent (DNS sinkhole + app
	// registry demotion). observedAt is the time the indicator was
	// last seen on the feed.
	EmitDomainDemotion(ctx context.Context, domain, reason string, observedAt time.Time) error
}

// DemotionBridge feeds domain IOCs from a store snapshot into the
// demotion engine. It is invoked from the FeedManager OnUpdate hook
// so every feed refresh demotes any newly-seen malicious domain to
// inspect_full (the demotion engine de-duplicates against existing
// overrides, so re-emitting an already-demoted domain is a no-op).
//
// Sync is delta-driven: the bridge remembers the LastSeen it last
// emitted for each domain and skips a domain whose sighting has not
// advanced. Without this, every refresh of every feed (e.g. 7 feeds
// hourly) would re-scan the whole merged snapshot and issue a
// per-domain demotion call — thousands of redundant DB lookups an
// hour against overrides that already exist. A domain is re-emitted
// only when its LastSeen moves forward (the feed re-observed it),
// which re-establishes the override if an operator cleared it in the
// meantime.
type DemotionBridge struct {
	emitter       DemotionEmitter
	minConfidence float64

	mu sync.Mutex
	// emitted maps a domain to the LastSeen of the most recent
	// demotion the bridge issued for it, so a repeated snapshot with
	// an unchanged sighting is a no-op.
	emitted map[string]time.Time
}

// NewDemotionBridge builds a bridge over the given emitter.
func NewDemotionBridge(emitter DemotionEmitter, opts ...IOCEnforcementOption) *DemotionBridge {
	// Reuse IOCEnforcementOption purely for the min-confidence
	// floor so the bridge and the rule compiler share one knob.
	tmp := &IOCEnforcementCompiler{minConfidence: defaultEnforcementMinConfidence}
	for _, opt := range opts {
		opt(tmp)
	}
	return &DemotionBridge{
		emitter:       emitter,
		minConfidence: tmp.minConfidence,
		emitted:       make(map[string]time.Time),
	}
}

// Sync emits a demotion for every domain IOC in the snapshot at or
// above the confidence floor whose sighting is new or has advanced
// since the bridge last emitted it (see DemotionBridge docs for the
// delta rationale). Errors from individual emits are collected and
// returned joined so one bad domain does not abort the batch; a
// domain whose emit fails is NOT recorded as emitted, so the next
// refresh retries it.
func (b *DemotionBridge) Sync(ctx context.Context, snap IOCSnapshot) error {
	if b.emitter == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.emitted == nil {
		b.emitted = make(map[string]time.Time)
	}
	var errs []error
	for _, ioc := range snap.Domains {
		if ioc.Confidence < b.minConfidence {
			continue
		}
		// Skip a domain we have already demoted unless the feed has
		// re-observed it since (LastSeen advanced). A zero LastSeen
		// is treated as "unchanged" once first emitted.
		if prev, ok := b.emitted[ioc.Value]; ok && !ioc.LastSeen.After(prev) {
			continue
		}
		reason := iocRuleDescription("demotion", ioc)
		if err := b.emitter.EmitDomainDemotion(ctx, ioc.Value, reason, ioc.LastSeen); err != nil {
			errs = append(errs, fmt.Errorf("demote %q: %w", ioc.Value, err))
			continue
		}
		b.emitted[ioc.Value] = ioc.LastSeen
	}
	return errors.Join(errs...)
}
