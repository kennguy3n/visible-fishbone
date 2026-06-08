package ai

import (
	"context"
	"sort"
	"sync"
	"time"
)

// IOCStore is the in-memory, deduplicated, TTL-aware indicator
// store at the heart of the feed aggregator. Every feed ingest
// run Upserts its parsed IOCs here; the enforcement compilers
// (ioc_enforcement.go) read a point-in-time Snapshot to build
// firewall / DNS / SWG / malware rules.
//
// De-duplication is by (type, value): when two feeds report the
// same indicator, the store keeps a single merged entry with the
// higher confidence, the more-recent LastSeen, and the later
// ExpiresAt (so a still-active feed keeps an indicator alive even
// if a second feed reported it with a shorter TTL). Attribution
// (actor / campaign) is filled from whichever observation first
// supplied it.
//
// The store implements ThreatFeedProvider, so the aggregated feed
// set drops straight into the existing ThreatIntelEngine for
// live-traffic matching and typed-alert escalation alongside the
// curated RegionalFeed — no separate matching path.
type IOCStore struct {
	mu    sync.RWMutex
	byKey map[string]IOC
	// minConfidence drops indicators below the configured floor
	// at Upsert time so low-signal feed noise never reaches
	// enforcement. Zero admits everything.
	minConfidence float64
	now           func() time.Time
}

// IOCStoreOption configures NewIOCStore.
type IOCStoreOption func(*IOCStore)

// WithMinConfidence sets the minimum confidence an indicator must
// carry to be admitted. Indicators below the floor are dropped at
// Upsert.
func WithMinConfidence(floor float64) IOCStoreOption {
	return func(s *IOCStore) { s.minConfidence = clampConfidence(floor) }
}

// withStoreClock overrides the wall-clock source (tests).
func withStoreClock(now func() time.Time) IOCStoreOption {
	return func(s *IOCStore) {
		if now != nil {
			s.now = now
		}
	}
}

// NewIOCStore constructs an empty store.
func NewIOCStore(opts ...IOCStoreOption) *IOCStore {
	s := &IOCStore{
		byKey: make(map[string]IOC),
		now:   time.Now,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// UpsertResult reports the outcome of an Upsert batch.
type UpsertResult struct {
	// Added is the number of new indicators inserted.
	Added int
	// Updated is the number of existing indicators merged.
	Updated int
	// Skipped is the number dropped for being below the
	// confidence floor or carrying an empty value.
	Skipped int
}

// Upsert merges a batch of indicators into the store. Indicators
// are assumed already-normalized (built via NewIOC); an empty
// Value or a confidence below the floor is skipped. Returns a
// per-batch tally.
func (s *IOCStore) Upsert(iocs ...IOC) UpsertResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	var res UpsertResult
	for _, in := range iocs {
		if in.Value == "" || !in.Type.Valid() {
			res.Skipped++
			continue
		}
		if in.Confidence < s.minConfidence {
			res.Skipped++
			continue
		}
		key := in.Key()
		existing, ok := s.byKey[key]
		if !ok {
			s.byKey[key] = in
			res.Added++
			continue
		}
		s.byKey[key] = mergeIOC(existing, in)
		res.Updated++
	}
	return res
}

// mergeIOC combines two observations of the same indicator. The
// merge is commutative on the fields that matter for enforcement:
// the result carries the higher confidence, the later LastSeen,
// the later ExpiresAt (a zero == permanent ExpiresAt always
// wins, since "never expires" outranks any finite TTL), and the
// earlier FirstSeen. Attribution and source prefer the existing
// non-empty value, falling back to the incoming one.
func mergeIOC(existing, incoming IOC) IOC {
	out := existing
	if incoming.Confidence > out.Confidence {
		out.Confidence = incoming.Confidence
	}
	if incoming.LastSeen.After(out.LastSeen) {
		out.LastSeen = incoming.LastSeen
	}
	if !out.FirstSeen.IsZero() && !incoming.FirstSeen.IsZero() {
		if incoming.FirstSeen.Before(out.FirstSeen) {
			out.FirstSeen = incoming.FirstSeen
		}
	} else if out.FirstSeen.IsZero() {
		out.FirstSeen = incoming.FirstSeen
	}
	// ExpiresAt: zero means permanent and beats any finite TTL;
	// otherwise the later expiry wins so a still-fresh feed keeps
	// the indicator alive.
	switch {
	case out.ExpiresAt.IsZero() || incoming.ExpiresAt.IsZero():
		out.ExpiresAt = time.Time{}
	case incoming.ExpiresAt.After(out.ExpiresAt):
		out.ExpiresAt = incoming.ExpiresAt
	}
	if out.ThreatActor == "" {
		out.ThreatActor = incoming.ThreatActor
	}
	if out.Campaign == "" {
		out.Campaign = incoming.Campaign
	}
	if out.HashAlgo == "" {
		out.HashAlgo = incoming.HashAlgo
	}
	return out
}

// Restore re-warms the store from a persisted snapshot. Loaded
// indicators are filtered for expiry against the store clock (a
// snapshot taken before a long downtime may contain entries whose
// TTL has since elapsed) and folded in via the normal Upsert path,
// so the confidence floor and merge semantics apply exactly as
// they do for a live feed ingest. Returns the per-batch tally.
//
// Intended to run once at boot, before the feed manager starts, so
// enforcement (live-traffic matching, demotion sync) is warm
// immediately rather than empty until the first feed warm-up
// completes.
func (s *IOCStore) Restore(ctx context.Context, p IOCPersister) (UpsertResult, error) {
	if p == nil {
		return UpsertResult{}, nil
	}
	loaded, err := p.LoadIOCs(ctx)
	if err != nil {
		return UpsertResult{}, err
	}
	now := s.now().UTC()
	live := make([]IOC, 0, len(loaded))
	for _, ioc := range loaded {
		if ioc.Expired(now) {
			continue
		}
		live = append(live, ioc)
	}
	return s.Upsert(live...), nil
}

// Persist writes the current active (non-expired) indicator set to
// durable storage via the persister, using whole-set snapshot
// semantics so the persisted table tracks expiry-driven removals.
// Returns the number of indicators written.
func (s *IOCStore) Persist(ctx context.Context, p IOCPersister) (int, error) {
	if p == nil {
		return 0, nil
	}
	snap := s.Snapshot()
	all := make([]IOC, 0, len(snap.Domains)+len(snap.IPs)+len(snap.URLs)+len(snap.Hashes))
	all = append(all, snap.Domains...)
	all = append(all, snap.IPs...)
	all = append(all, snap.URLs...)
	all = append(all, snap.Hashes...)
	if err := p.SaveIOCs(ctx, all); err != nil {
		return 0, err
	}
	return len(all), nil
}

// Sweep removes expired indicators and returns the number
// dropped. Called periodically by the feed manager so the store
// does not accumulate stale entries between feed refreshes.
func (s *IOCStore) Sweep() int {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed int
	for key, ioc := range s.byKey {
		if ioc.Expired(now) {
			delete(s.byKey, key)
			removed++
		}
	}
	return removed
}

// Len returns the number of active (non-expired) indicators.
func (s *IOCStore) Len() int {
	now := s.now().UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()
	var n int
	for _, ioc := range s.byKey {
		if !ioc.Expired(now) {
			n++
		}
	}
	return n
}

// IOCCounts is the active indicator cardinality partitioned by
// enforcement type, plus the total.
type IOCCounts struct {
	Domains int
	IPs     int
	URLs    int
	Hashes  int
	Total   int
}

// SizeByType returns the active (non-expired) indicator counts
// partitioned by type. It is a lighter-weight alternative to
// Snapshot for telemetry: it counts under the read lock without
// materialising or sorting the per-type slices.
func (s *IOCStore) SizeByType() IOCCounts {
	now := s.now().UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()
	var c IOCCounts
	for _, ioc := range s.byKey {
		if ioc.Expired(now) {
			continue
		}
		switch ioc.Type {
		case IOCTypeDomain:
			c.Domains++
		case IOCTypeIP:
			c.IPs++
		case IOCTypeURL:
			c.URLs++
		case IOCTypeHash:
			c.Hashes++
		}
		c.Total++
	}
	return c
}

// Snapshot returns the active indicators grouped by type, each
// group sorted by descending confidence then value so downstream
// rule compilation is byte-deterministic. Expired indicators are
// excluded (but not deleted — that is Sweep's job).
func (s *IOCStore) Snapshot() IOCSnapshot {
	now := s.now().UTC()
	s.mu.RLock()
	active := make([]IOC, 0, len(s.byKey))
	for _, ioc := range s.byKey {
		if !ioc.Expired(now) {
			active = append(active, ioc)
		}
	}
	s.mu.RUnlock()

	snap := IOCSnapshot{}
	for _, ioc := range active {
		switch ioc.Type {
		case IOCTypeDomain:
			snap.Domains = append(snap.Domains, ioc)
		case IOCTypeIP:
			snap.IPs = append(snap.IPs, ioc)
		case IOCTypeURL:
			snap.URLs = append(snap.URLs, ioc)
		case IOCTypeHash:
			snap.Hashes = append(snap.Hashes, ioc)
		}
	}
	sortIOCs(snap.Domains)
	sortIOCs(snap.IPs)
	sortIOCs(snap.URLs)
	sortIOCs(snap.Hashes)
	return snap
}

// IOCSnapshot is a point-in-time view of the active indicator set
// partitioned by enforcement sink.
type IOCSnapshot struct {
	Domains []IOC
	IPs     []IOC
	URLs    []IOC
	Hashes  []IOC
}

func sortIOCs(s []IOC) {
	sort.SliceStable(s, func(i, j int) bool {
		if s[i].Confidence != s[j].Confidence {
			return s[i].Confidence > s[j].Confidence
		}
		return s[i].Value < s[j].Value
	})
}

// QueryIOCs implements ThreatFeedProvider so the aggregated store
// can be queried for live-traffic matching by the
// ThreatIntelEngine exactly like a RegionalFeed. Each queried
// indicator is normalized against the four type-specific
// canonicalizers and looked up; a hit yields an IOCMatch carrying
// the stored attribution and confidence. Expired indicators never
// match.
func (s *IOCStore) QueryIOCs(_ context.Context, indicators []string) ([]IOCMatch, error) {
	if len(indicators) == 0 {
		return nil, nil
	}
	now := s.now().UTC()
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := make(map[string]struct{}, len(indicators))
	var out []IOCMatch
	for _, raw := range indicators {
		for _, key := range candidateKeys(raw) {
			if _, dup := seen[key]; dup {
				continue
			}
			ioc, ok := s.byKey[key]
			if !ok || ioc.Expired(now) {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, IOCMatch{
				Indicator:   ioc.Value,
				FeedName:    ioc.Source,
				ThreatType:  string(ioc.Type),
				ThreatActor: ioc.ThreatActor,
				Campaign:    ioc.Campaign,
				Confidence:  ioc.Confidence,
				LastSeen:    ioc.LastSeen,
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Indicator < out[j].Indicator
	})
	return out, nil
}

// candidateKeys maps a raw queried indicator to every store key it
// could match. A raw value is type-ambiguous (an analyst querying
// "evil.com" doesn't say whether it's a domain or URL host), so we
// canonicalize it under each type that accepts it and look up all
// resulting keys. This keeps QueryIOCs callers from having to
// pre-classify indicators.
func candidateKeys(raw string) []string {
	var keys []string
	if v, ok := normalizeURL(raw); ok {
		keys = append(keys, string(IOCTypeURL)+"\x00"+v)
	}
	if v, ok := normalizeIP(raw); ok {
		keys = append(keys, string(IOCTypeIP)+"\x00"+v)
	}
	if v, algo, ok := normalizeHash(raw); ok {
		_ = algo
		keys = append(keys, string(IOCTypeHash)+"\x00"+v)
	}
	if v, ok := normalizeDomain(raw); ok {
		keys = append(keys, string(IOCTypeDomain)+"\x00"+v)
	}
	return keys
}
