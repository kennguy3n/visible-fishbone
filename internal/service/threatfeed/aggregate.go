package threatfeed

import (
	"sort"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

// contribution is one source's strongest sighting of an indicator
// within a single refresh. Multiple rows from the SAME feed collapse
// into one contribution (a feed listing a value twice is not
// corroboration), so the noisy-OR combines DISTINCT sources only.
type contribution struct {
	weight    float64
	firstSeen time.Time
	lastSeen  time.Time
	expiresAt time.Time
}

// indicatorGroup accumulates all contributions to one (type, value)
// indicator across feeds.
type indicatorGroup struct {
	typ      ai.IOCType
	value    string
	hashAlgo ai.HashAlgo
	bySource map[string]contribution
}

// aggregate deduplicates raw IOCs across feeds into scored Indicators.
// For each (type, value):
//   - contributions from the same source are merged (strongest weight,
//     widest observation window) so only distinct feeds corroborate;
//   - the score is noisyOr(distinct source weights) * recency(lastSeen);
//   - the TTL boundary is the latest contributor expiry, unless any
//     contributor never-expires (then the indicator never expires);
//   - indicators already expired as of now are dropped.
//
// weightOf resolves a source name to its registry trust weight; an
// unknown source falls back to a low default so an unexpected feed
// label still contributes, but weakly.
func aggregate(iocs []ai.IOC, weightOf func(source string) float64, now time.Time, halfLife time.Duration) []Indicator {
	groups := make(map[string]*indicatorGroup, len(iocs))
	for _, ioc := range iocs {
		if !ioc.Type.Valid() || ioc.Value == "" {
			continue
		}
		key := ioc.Key()
		g := groups[key]
		if g == nil {
			g = &indicatorGroup{
				typ:      ioc.Type,
				value:    ioc.Value,
				hashAlgo: ioc.HashAlgo,
				bySource: make(map[string]contribution, 2),
			}
			groups[key] = g
		}
		if g.hashAlgo == "" {
			g.hashAlgo = ioc.HashAlgo
		}
		src := ioc.Source
		if src == "" {
			src = "unknown"
		}
		w := clamp01(weightOf(src))
		// A feed that supplies a per-indicator confidence scales its own
		// contribution by it; a plain blocklist (confidence 0) relies on
		// its source weight alone.
		if ioc.Confidence > 0 {
			w *= clamp01(ioc.Confidence)
		}
		c := contribution{
			weight:    w,
			firstSeen: ioc.FirstSeen,
			lastSeen:  ioc.LastSeen,
			expiresAt: ioc.ExpiresAt,
		}
		if prev, ok := g.bySource[src]; ok {
			if c.weight > prev.weight {
				prev.weight = c.weight
			}
			prev.firstSeen = earliest(prev.firstSeen, c.firstSeen)
			prev.lastSeen = latest(prev.lastSeen, c.lastSeen)
			prev.expiresAt = latest(prev.expiresAt, c.expiresAt)
			g.bySource[src] = prev
		} else {
			g.bySource[src] = c
		}
	}

	out := make([]Indicator, 0, len(groups))
	for _, g := range groups {
		var (
			weights        = make([]float64, 0, len(g.bySource))
			sources        = make([]string, 0, len(g.bySource))
			firstSeen      time.Time
			lastSeen       time.Time
			expiresAt      time.Time
			anyNeverExpire bool
		)
		for src, c := range g.bySource {
			weights = append(weights, c.weight)
			sources = append(sources, src)
			firstSeen = earliest(firstSeen, c.firstSeen)
			lastSeen = latest(lastSeen, c.lastSeen)
			if c.expiresAt.IsZero() {
				anyNeverExpire = true
			} else {
				expiresAt = latest(expiresAt, c.expiresAt)
			}
		}
		// An indicator lives as long as ANY contributor keeps it alive.
		if anyNeverExpire {
			expiresAt = time.Time{}
		}
		if !expiresAt.IsZero() && !expiresAt.After(now) {
			continue // already expired
		}
		ref := lastSeen
		if ref.IsZero() {
			ref = now
		}
		score := noisyOr(weights) * recencyFactor(now.Sub(ref), halfLife)
		out = append(out, Indicator{
			Type:      string(g.typ),
			Value:     g.value,
			HashAlgo:  string(g.hashAlgo),
			Score:     clamp01(score),
			Sources:   sources,
			FirstSeen: firstSeen,
			LastSeen:  lastSeen,
			ExpiresAt: expiresAt,
		})
	}
	return out
}

// capIndicators bounds the indicator set to at most limit entries,
// keeping the highest-scoring ones (ties broken by type then value for
// determinism). This bounds bundle size and memory regardless of how
// large the upstream feeds grow. A non-positive limit means unbounded.
func capIndicators(in []Indicator, limit int) []Indicator {
	if limit <= 0 || len(in) <= limit {
		return in
	}
	sort.Slice(in, func(i, j int) bool {
		if in[i].Score != in[j].Score {
			return in[i].Score > in[j].Score
		}
		if in[i].Type != in[j].Type {
			return in[i].Type < in[j].Type
		}
		return in[i].Value < in[j].Value
	})
	return in[:limit]
}
