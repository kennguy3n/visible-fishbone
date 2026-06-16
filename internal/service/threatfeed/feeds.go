package threatfeed

import (
	"net/http"
	"time"

	"github.com/kennguy3n/visible-fishbone/internal/repository"
	"github.com/kennguy3n/visible-fishbone/internal/service/ai"
)

// Feed binds a parser to a fetcher plus the registry/scoring metadata
// the engine applies on ingest. One Feed is one curated upstream.
type Feed struct {
	// Name uniquely identifies the feed and is stamped as the IOC
	// Source (the corroboration identity in scoring).
	Name string
	// DisplayName is the human-facing label for the posture surface.
	DisplayName string
	// Kind is the dominant indicator category (advisory only).
	Kind string
	// URL is the upstream endpoint (telemetry / registry).
	URL string
	// Weight is the source trust in (0,1], folded into the score.
	Weight float64
	// DefaultTTL is applied to indicators the feed gives no explicit
	// expiry. Zero leaves them permanent (zero ExpiresAt).
	DefaultTTL time.Duration
	// Parser decodes fetched bytes into normalized IOCs.
	Parser ai.FeedParser
	// Fetcher retrieves the raw bytes (conditional-GET capable).
	Fetcher Fetcher
}

// feedSpec is the static description of a built-in feed, independent of
// the runtime http client. DefaultFeeds turns each spec into a wired
// Feed.
type feedSpec struct {
	name        string
	displayName string
	kind        string
	url         string
	weight      float64
	ttl         time.Duration
	makeParser  func(source string) ai.FeedParser
}

// builtinFeedSpecs is the curated managed-content source set. These are
// well-known, freely-redistributable open feeds covering all four
// indicator types, with corroboration designed in (URLhaus + OpenPhish
// overlap on malicious URLs). Weights reflect each source's precision
// reputation. This is the no-ops default every tenant gets; an operator
// changes nothing.
var builtinFeedSpecs = []feedSpec{
	{
		name:        "abuse.ch:feodo",
		displayName: "Feodo Tracker (abuse.ch) botnet C2 IP blocklist",
		kind:        "ip",
		url:         "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		weight:      0.9,
		ttl:         7 * 24 * time.Hour,
		makeParser:  func(s string) ai.FeedParser { return IPListParser{Source: s} },
	},
	{
		name:        "abuse.ch:urlhaus",
		displayName: "URLhaus (abuse.ch) malware distribution URL feed",
		kind:        "url",
		url:         "https://urlhaus.abuse.ch/downloads/text/",
		weight:      0.85,
		ttl:         5 * 24 * time.Hour,
		makeParser:  func(s string) ai.FeedParser { return URLListParser{Source: s} },
	},
	{
		name:        "abuse.ch:urlhaus-hostfile",
		displayName: "URLhaus (abuse.ch) malware host file",
		kind:        "domain",
		url:         "https://urlhaus.abuse.ch/downloads/hostfile/",
		weight:      0.8,
		ttl:         5 * 24 * time.Hour,
		makeParser:  func(s string) ai.FeedParser { return DomainListParser{Source: s, HostsFile: true} },
	},
	{
		name:        "abuse.ch:malwarebazaar",
		displayName: "MalwareBazaar (abuse.ch) recent SHA-256 sample hashes",
		kind:        "hash",
		url:         "https://bazaar.abuse.ch/export/txt/sha256/recent/",
		weight:      0.8,
		ttl:         14 * 24 * time.Hour,
		makeParser:  func(s string) ai.FeedParser { return HashListParser{Source: s} },
	},
	{
		name:        "openphish",
		displayName: "OpenPhish community phishing URL feed",
		kind:        "url",
		url:         "https://openphish.com/feed.txt",
		weight:      0.7,
		ttl:         3 * 24 * time.Hour,
		makeParser:  func(s string) ai.FeedParser { return URLListParser{Source: s} },
	},
}

// DefaultFeeds returns the built-in curated feed set wired with
// conditional-GET HTTP fetchers sharing the given client and per-feed
// byte cap. A nil client applies a default-timeout client per feed.
func DefaultFeeds(client *http.Client, maxBytes int64) []Feed {
	feeds := make([]Feed, 0, len(builtinFeedSpecs))
	for _, spec := range builtinFeedSpecs {
		feeds = append(feeds, Feed{
			Name:        spec.name,
			DisplayName: spec.displayName,
			Kind:        spec.kind,
			URL:         spec.url,
			Weight:      spec.weight,
			DefaultTTL:  spec.ttl,
			Parser:      spec.makeParser(spec.name),
			Fetcher:     &HTTPFetcher{URL: spec.url, Client: client, MaxBytes: maxBytes},
		})
	}
	return feeds
}

// SourcesFromFeeds projects the feed set onto registry rows for
// UpsertSources, so the operator-visible registry always matches the
// code-defined managed sources.
func SourcesFromFeeds(feeds []Feed) []repository.ThreatFeedSource {
	out := make([]repository.ThreatFeedSource, 0, len(feeds))
	for _, f := range feeds {
		out = append(out, repository.ThreatFeedSource{
			Name:              f.Name,
			DisplayName:       f.DisplayName,
			Kind:              normalizeKind(f.Kind),
			URL:               f.URL,
			Weight:            f.Weight,
			Enabled:           true,
			DefaultTTLSeconds: int64(f.DefaultTTL / time.Second),
		})
	}
	return out
}

// weightMap builds the source-name -> trust-weight lookup the
// aggregator uses to score corroboration.
func weightMap(feeds []Feed) map[string]float64 {
	m := make(map[string]float64, len(feeds))
	for _, f := range feeds {
		m[f.Name] = f.Weight
	}
	return m
}

// normalizeKind maps an empty/unknown kind onto the registry's "mixed"
// default so the CHECK constraint always holds.
func normalizeKind(kind string) string {
	switch kind {
	case "domain", "ip", "url", "hash", "mixed":
		return kind
	default:
		return "mixed"
	}
}
