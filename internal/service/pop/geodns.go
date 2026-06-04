// Copyright 2026 ShieldNet Gateway contributors.
// SPDX-License-Identifier: LicenseRef-Proprietary

package pop

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// RoutingPolicy is the DNS steering strategy the zone records encode.
type RoutingPolicy string

// Supported routing policies.
const (
	// RoutingLatency emits one record set per PoP tagged with its
	// region; the DNS provider answers each resolver with the
	// lowest-latency region (Route53 latency records / Cloudflare geo
	// steering). This is the default for "nearest PoP" steering.
	RoutingLatency RoutingPolicy = "latency"
	// RoutingWeighted emits weighted record sets so resolvers are
	// distributed across PoPs proportional to capacity tier. Useful
	// when latency data is unavailable or for deliberate load spread.
	RoutingWeighted RoutingPolicy = "weighted"
	// RoutingSimple emits a flat multi-value answer (every PoP). The
	// client picks; no provider-side steering.
	RoutingSimple RoutingPolicy = "simple"
)

// Valid reports whether p is a supported routing policy.
func (p RoutingPolicy) Valid() bool {
	switch p {
	case RoutingLatency, RoutingWeighted, RoutingSimple:
		return true
	default:
		return false
	}
}

// DNSRecord is one resource record in the steering zone. The shape is
// provider-agnostic; Route53 / Cloudflare adapters translate it into
// their own record-set APIs (SetIdentifier ↦ Route53 set identifier,
// Region ↦ latency-routing region, Weight ↦ weighted-routing weight).
type DNSRecord struct {
	Name          string        // FQDN clients resolve, e.g. edge.sng.example.com
	Type          string        // "A" (IPv4) or "AAAA" (IPv6)
	Value         string        // the PoP's anycast IP
	TTL           time.Duration // record TTL
	SetIdentifier string        // unique per-PoP record-set id
	Region        string        // PoP region (latency routing)
	Weight        int           // relative weight (weighted routing)
	Policy        RoutingPolicy
}

// GeoDNSConfig configures the steering zone.
type GeoDNSConfig struct {
	// Hostname is the steering FQDN clients resolve during enrolment
	// (the PAC file / DNS config points at the resolved PoP).
	Hostname string
	// TTL is applied to every emitted record. Short TTLs let a PoP
	// failure drain quickly; the default is 30s.
	TTL time.Duration
	// Policy selects the steering strategy. Defaults to latency.
	Policy RoutingPolicy
}

// DefaultGeoDNSTTL is the record TTL when none is configured.
const DefaultGeoDNSTTL = 30 * time.Second

// ZoneGenerator turns the live PoP fleet into a desired DNS record
// set for the steering hostname.
type ZoneGenerator struct {
	cfg GeoDNSConfig
}

// NewZoneGenerator validates cfg and returns a generator.
func NewZoneGenerator(cfg GeoDNSConfig) (*ZoneGenerator, error) {
	if strings.TrimSpace(cfg.Hostname) == "" {
		return nil, fmt.Errorf("geodns: hostname is required")
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultGeoDNSTTL
	}
	if cfg.Policy == "" {
		cfg.Policy = RoutingLatency
	}
	if !cfg.Policy.Valid() {
		return nil, fmt.Errorf("geodns: invalid routing policy %q", cfg.Policy)
	}
	return &ZoneGenerator{cfg: cfg}, nil
}

// tierWeight maps a capacity tier to a relative DNS weight roughly
// proportional to the PoP's connection ceiling, so weighted routing
// sends more clients to bigger PoPs.
func tierWeight(t CapacityTier) int {
	switch t {
	case CapacitySmall:
		return 1
	case CapacityMedium:
		return 5
	case CapacityLarge:
		return 20
	default:
		return 1
	}
}

// Records builds the desired record set for the enabled PoPs in pops.
// Disabled PoPs and PoPs with an unparseable anycast IP are skipped
// (the latter is logged by the caller via the returned skip count is
// not surfaced here — RegisterPoP already validates the IP, so a bad
// value only reaches here through direct DB tampering). Records are
// returned sorted by SetIdentifier for deterministic output.
func (g *ZoneGenerator) Records(pops []PoP) []DNSRecord {
	out := make([]DNSRecord, 0, len(pops))
	for _, p := range pops {
		if !p.Enabled {
			continue
		}
		addr, err := netip.ParseAddr(p.AnycastIP)
		if err != nil {
			continue
		}
		rtype := "A"
		if addr.Is6() && !addr.Is4In6() {
			rtype = "AAAA"
		}
		out = append(out, DNSRecord{
			Name:          g.cfg.Hostname,
			Type:          rtype,
			Value:         p.AnycastIP,
			TTL:           g.cfg.TTL,
			SetIdentifier: p.ID.String(),
			Region:        p.Region,
			Weight:        tierWeight(p.CapacityTier),
			Policy:        g.cfg.Policy,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].SetIdentifier < out[j].SetIdentifier })
	return out
}

// DNSProvider applies a desired record set to an external DNS zone.
// Production implementations wrap the Route53 / Cloudflare APIs;
// StaticDNSProvider is the in-memory test double / dry-run sink.
type DNSProvider interface {
	// ApplyZone reconciles the record set for hostname to exactly
	// records (an upsert-and-prune for that hostname's steering set).
	ApplyZone(ctx context.Context, hostname string, records []DNSRecord) error
}

// StaticDNSProvider records the most recent ApplyZone call per
// hostname. Used by tests and as a safe default (dry-run) when no real
// DNS provider is configured.
type StaticDNSProvider struct {
	mu      sync.Mutex
	applied map[string][]DNSRecord
}

// NewStaticDNSProvider returns an empty in-memory provider.
func NewStaticDNSProvider() *StaticDNSProvider {
	return &StaticDNSProvider{applied: map[string][]DNSRecord{}}
}

// ApplyZone stores a copy of records for hostname.
func (p *StaticDNSProvider) ApplyZone(_ context.Context, hostname string, records []DNSRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]DNSRecord, len(records))
	copy(cp, records)
	p.applied[hostname] = cp
	return nil
}

// Applied returns a copy of the last record set applied for hostname.
func (p *StaticDNSProvider) Applied(hostname string) []DNSRecord {
	p.mu.Lock()
	defer p.mu.Unlock()
	src := p.applied[hostname]
	out := make([]DNSRecord, len(src))
	copy(out, src)
	return out
}

// GeoDNSPublisher reconciles the steering zone from the live registry
// on a schedule. It is a singleton task (run on the leader) so the
// fleet's DNS records are written from one place.
type GeoDNSPublisher struct {
	gen      *ZoneGenerator
	provider DNSProvider
	registry *Registry
	logger   *slog.Logger
}

// NewGeoDNSPublisher wires a publisher. provider may be a
// StaticDNSProvider for dry-run; registry supplies the live fleet.
func NewGeoDNSPublisher(gen *ZoneGenerator, provider DNSProvider, registry *Registry, logger *slog.Logger) *GeoDNSPublisher {
	if logger == nil {
		logger = slog.Default()
	}
	return &GeoDNSPublisher{gen: gen, provider: provider, registry: registry, logger: logger}
}

// Publish computes the desired record set from the current registry
// and applies it through the provider.
func (p *GeoDNSPublisher) Publish(ctx context.Context) error {
	records := p.gen.Records(p.registry.Available())
	if err := p.provider.ApplyZone(ctx, p.gen.cfg.Hostname, records); err != nil {
		return fmt.Errorf("geodns publish: %w", err)
	}
	return nil
}

// Run re-publishes the zone every interval until ctx is cancelled,
// publishing once immediately on entry.
func (p *GeoDNSPublisher) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	if err := p.Publish(ctx); err != nil && ctx.Err() == nil {
		p.logger.Warn("geodns: initial publish failed", slog.Any("error", err))
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := p.Publish(ctx); err != nil && ctx.Err() == nil {
				p.logger.Warn("geodns: publish failed", slog.Any("error", err))
			}
		}
	}
}

// StaticRegionLocator is an in-memory RegionLocator for tests and
// small static deployments: it maps IP prefixes to region labels,
// longest-prefix-match wins. Production swaps in a GeoIP-backed
// implementation behind the same interface.
type StaticRegionLocator struct {
	prefixes []regionPrefix
}

type regionPrefix struct {
	prefix netip.Prefix
	region string
}

// NewStaticRegionLocator builds a locator from prefix→region pairs.
// Invalid prefixes are rejected.
func NewStaticRegionLocator(mapping map[string]string) (*StaticRegionLocator, error) {
	loc := &StaticRegionLocator{}
	for cidr, region := range mapping {
		pfx, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("geodns: invalid region prefix %q: %w", cidr, err)
		}
		loc.prefixes = append(loc.prefixes, regionPrefix{prefix: pfx.Masked(), region: region})
	}
	// Longest prefix first so the most specific match wins.
	sort.Slice(loc.prefixes, func(i, j int) bool {
		return loc.prefixes[i].prefix.Bits() > loc.prefixes[j].prefix.Bits()
	})
	return loc, nil
}

// LocateRegion returns the region of the longest matching prefix.
func (l *StaticRegionLocator) LocateRegion(ip netip.Addr) (string, bool) {
	for _, rp := range l.prefixes {
		if rp.prefix.Contains(ip) {
			return rp.region, true
		}
	}
	return "", false
}
