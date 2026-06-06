package ai

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// ThreatRegion identifies a regional IOC source. Session 2C adds
// curated feeds for the three regions ShieldNet Gateway is being
// rolled out into.
type ThreatRegion string

const (
	// ThreatRegionSEA is Southeast Asia (SG/TH/MY/VN/ID/PH).
	ThreatRegionSEA ThreatRegion = "SEA"
	// ThreatRegionGCC is the Gulf Cooperation Council (AE/SA/QA/KW/BH/OM).
	ThreatRegionGCC ThreatRegion = "GCC"
	// ThreatRegionDACH is the German-speaking bloc (DE/AT/CH).
	ThreatRegionDACH ThreatRegion = "DACH"
)

// regionalIOC is one curated indicator with its attribution. The
// indicator is stored already-normalized (see normalizeIndicator).
type regionalIOC struct {
	indicator  string
	threatType string // ip, domain, hash, url
	actor      string
	campaign   string
	confidence float64
}

// RegionalFeed is an in-memory ThreatFeedProvider seeded with a
// curated, region-specific IOC set. It implements the existing
// ThreatFeedProvider contract unchanged, so the ThreatIntelEngine and
// every existing caller treat it like any other feed.
//
// Attribution (actor/campaign names, regions, confidence) is real and
// reflects publicly documented threat groups active against each
// region. The indicator *values* in the shipped seed are deliberately
// drawn from documentation ranges (RFC 5737 TEST-NET addresses and
// example.test domains) rather than live malicious infrastructure — a
// source tree is the wrong place to ship hot IPs, and they would be
// stale within days. Production deployments load current indicators
// from a regional CERT/ISAC source via NewRegionalFeedWithData while
// keeping this attribution catalog; the seed exists so the feed is
// exercisable end-to-end (and unit-testable) without a network
// dependency.
type RegionalFeed struct {
	region      ThreatRegion
	name        string
	byIndicator map[string]regionalIOC
	now         func() time.Time
}

// NewRegionalFeed builds a RegionalFeed for region seeded with the
// built-in curated catalog. An unknown region yields a feed with an
// empty catalog (it still satisfies the interface and simply never
// matches).
func NewRegionalFeed(region ThreatRegion) *RegionalFeed {
	return NewRegionalFeedWithData(region, seedRegionalIOCs(region))
}

// NewRegionalFeedWithData builds a RegionalFeed from an explicit IOC
// set, the seam production uses to inject indicators pulled from a
// regional feed source. Indicators are normalized on the way in so
// lookups are case/whitespace-insensitive.
func NewRegionalFeedWithData(region ThreatRegion, iocs []regionalIOC) *RegionalFeed {
	byIndicator := make(map[string]regionalIOC, len(iocs))
	for _, ioc := range iocs {
		key := normalizeIndicator(ioc.indicator)
		if key == "" {
			continue
		}
		ioc.indicator = key
		byIndicator[key] = ioc
	}
	return &RegionalFeed{
		region:      region,
		name:        "regional:" + string(region),
		byIndicator: byIndicator,
		now:         time.Now,
	}
}

// Region returns the feed's region.
func (f *RegionalFeed) Region() ThreatRegion { return f.region }

// QueryIOCs implements ThreatFeedProvider: it returns a match for each
// queried indicator present in the regional catalog. Indicators are
// matched after normalization, so callers need not pre-canonicalize.
func (f *RegionalFeed) QueryIOCs(_ context.Context, indicators []string) ([]IOCMatch, error) {
	if len(indicators) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(indicators))
	var out []IOCMatch
	for _, raw := range indicators {
		key := normalizeIndicator(raw)
		if key == "" {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		ioc, ok := f.byIndicator[key]
		if !ok {
			continue
		}
		out = append(out, IOCMatch{
			Indicator:   ioc.indicator,
			FeedName:    f.name,
			ThreatType:  ioc.threatType,
			ThreatActor: ioc.actor,
			Campaign:    ioc.campaign,
			Confidence:  ioc.confidence,
			LastSeen:    f.now().UTC(),
		})
	}
	return out, nil
}

// MultiFeed fans a QueryIOCs call out to several ThreatFeedProviders
// and merges their matches. It is itself a ThreatFeedProvider, so the
// ThreatIntelEngine queries SEA+GCC+DACH (and any other feeds)
// through the single existing interface.
//
// Error handling is degrade-open per feed but fail-closed overall:
// matches from feeds that succeed are still returned, and an error is
// surfaced only when EVERY feed failed (so enrichment is never
// silently blinded by one flaky regional source, but a total outage
// is not masked as "no threats").
type MultiFeed struct {
	providers []ThreatFeedProvider
}

// NewMultiFeed groups providers into one. nil providers are dropped.
func NewMultiFeed(providers ...ThreatFeedProvider) *MultiFeed {
	filtered := make([]ThreatFeedProvider, 0, len(providers))
	for _, p := range providers {
		if p != nil {
			filtered = append(filtered, p)
		}
	}
	return &MultiFeed{providers: filtered}
}

// NewRegionalFeeds is the default regional wiring: a MultiFeed over
// the curated SEA, GCC and DACH catalogs.
func NewRegionalFeeds() *MultiFeed {
	return NewMultiFeed(
		NewRegionalFeed(ThreatRegionSEA),
		NewRegionalFeed(ThreatRegionGCC),
		NewRegionalFeed(ThreatRegionDACH),
	)
}

// QueryIOCs implements ThreatFeedProvider. Matches from all feeds are
// concatenated and de-duplicated on (indicator, feed). Results are
// sorted by descending confidence (then indicator) so the engine's
// max-confidence escalation and any UI rendering are deterministic.
func (m *MultiFeed) QueryIOCs(ctx context.Context, indicators []string) ([]IOCMatch, error) {
	if len(m.providers) == 0 || len(indicators) == 0 {
		return nil, nil
	}
	var (
		out  []IOCMatch
		errs []error
		ok   int
		seen = map[string]struct{}{}
	)
	for _, p := range m.providers {
		matches, err := p.QueryIOCs(ctx, indicators)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ok++
		for _, mm := range matches {
			dedupeKey := normalizeIndicator(mm.Indicator) + "\x00" + mm.FeedName
			if _, dup := seen[dedupeKey]; dup {
				continue
			}
			seen[dedupeKey] = struct{}{}
			out = append(out, mm)
		}
	}
	// Every feed failed → surface the failure rather than reporting a
	// clean "no matches".
	if ok == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Indicator < out[j].Indicator
	})
	return out, nil
}

// normalizeIndicator canonicalizes an IOC for case/whitespace-
// insensitive comparison. IPs, domains and hashes are all
// case-insensitive in practice, and a leading/trailing space is a
// common copy-paste artifact.
func normalizeIndicator(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// seedRegionalIOCs returns the built-in curated catalog for a region.
// See the RegionalFeed doc for why indicator values use documentation
// ranges while attribution is real.
func seedRegionalIOCs(region ThreatRegion) []regionalIOC {
	switch region {
	case ThreatRegionSEA:
		return []regionalIOC{
			{indicator: "198.51.100.21", threatType: "ip", actor: "APT32 (OceanLotus)", campaign: "SEA government espionage", confidence: 0.9},
			{indicator: "update.oceanlotus.example.test", threatType: "domain", actor: "APT32 (OceanLotus)", campaign: "SEA government espionage", confidence: 0.85},
			{indicator: "198.51.100.47", threatType: "ip", actor: "Mustang Panda (Bronze President)", campaign: "SEA NGO/government targeting", confidence: 0.88},
			{indicator: "cdn.mustangpanda.example.test", threatType: "domain", actor: "Mustang Panda (Bronze President)", campaign: "PlugX delivery", confidence: 0.8},
			{indicator: "203.0.113.66", threatType: "ip", actor: "Sidewinder (Rattlesnake)", campaign: "South/Southeast Asia spear-phishing", confidence: 0.75},
		}
	case ThreatRegionGCC:
		return []regionalIOC{
			{indicator: "192.0.2.61", threatType: "ip", actor: "APT34 (OilRig)", campaign: "Gulf energy-sector intrusion", confidence: 0.9},
			{indicator: "vpn.oilrig.example.test", threatType: "domain", actor: "APT34 (OilRig)", campaign: "DNS-tunnel C2", confidence: 0.85},
			{indicator: "192.0.2.77", threatType: "ip", actor: "MuddyWater (Static Kitten)", campaign: "Middle East government targeting", confidence: 0.84},
			{indicator: "mail.muddywater.example.test", threatType: "domain", actor: "MuddyWater (Static Kitten)", campaign: "PowerShell backdoor delivery", confidence: 0.8},
			{indicator: "203.0.113.140", threatType: "ip", actor: "APT35 (Charming Kitten)", campaign: "GCC credential phishing", confidence: 0.72},
		}
	case ThreatRegionDACH:
		return []regionalIOC{
			{indicator: "203.0.113.9", threatType: "ip", actor: "Turla (Snake)", campaign: "DACH government/defense espionage", confidence: 0.9},
			{indicator: "sync.turla.example.test", threatType: "domain", actor: "Turla (Snake)", campaign: "Snake implant C2", confidence: 0.85},
			{indicator: "203.0.113.23", threatType: "ip", actor: "APT41 (Winnti)", campaign: "DACH industrial IP theft", confidence: 0.86},
			{indicator: "telemetry.winnti.example.test", threatType: "domain", actor: "APT41 (Winnti)", campaign: "supply-chain implant", confidence: 0.8},
			{indicator: "198.51.100.205", threatType: "ip", actor: "Ghostwriter (UNC1151)", campaign: "DACH disinformation/credential theft", confidence: 0.74},
		}
	default:
		return nil
	}
}
