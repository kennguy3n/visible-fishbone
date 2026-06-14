package ai

import (
	"math"
	"net"
	"net/url"
	"strings"
	"time"
)

// IOCType is the indicator-of-compromise category. The four
// categories map one-to-one onto the four enforcement sinks the
// IOC pipeline drives (see ioc_enforcement.go):
//
//   - IOCTypeDomain -> DNS sinkhole rule + app-registry demotion
//   - IOCTypeIP     -> NGFW firewall-deny rule (single address)
//   - IOCTypeCIDR   -> NGFW firewall-deny rule (address range)
//   - IOCTypeURL    -> SWG deny-list rule
//   - IOCTypeHash   -> malware-verdict provider (StaticMalwareList)
//   - IOCTypeJA3    -> Suricata IPS rule (TLS client fingerprint)
//
// IOCTypeIP and IOCTypeCIDR drive the SAME enforcement sink (an
// NGFW destination-CIDR deny); they are kept distinct so the store
// dedupes a host and a range independently and telemetry can tell
// "block this address" from "block this network". The compiler
// folds a single IP into a /32 (or /128) so both ride one matcher.
//
// The string values match the ThreatType field already used by
// IOCMatch / RegionalFeed ("ip", "domain", "hash", "url") so the
// aggregated store plugs into the existing ThreatFeedProvider
// surface without a translation layer.
type IOCType string

const (
	// IOCTypeDomain is a DNS name (fully-qualified, no scheme).
	IOCTypeDomain IOCType = "domain"
	// IOCTypeIP is an IPv4 or IPv6 address (no CIDR).
	IOCTypeIP IOCType = "ip"
	// IOCTypeCIDR is an IPv4 or IPv6 address range in CIDR notation.
	IOCTypeCIDR IOCType = "cidr"
	// IOCTypeURL is an absolute http/https URL.
	IOCTypeURL IOCType = "url"
	// IOCTypeHash is a file hash (MD5, SHA-1 or SHA-256), hex.
	IOCTypeHash IOCType = "hash"
	// IOCTypeJA3 is a JA3 TLS client fingerprint, the 32-char
	// lowercase-hex MD5 of the TLS ClientHello feature string
	// (the form Suricata's ja3.hash keyword matches). It drives
	// the IPS Suricata-rule sink, not the NGFW/DNS/SWG sinks: a
	// JA3 identifies a malicious CLIENT (malware/C2 tooling) by
	// how it speaks TLS, independent of the destination address
	// or SNI, so it is enforced in the inline IPS engine rather
	// than the L3/L4 firewall.
	IOCTypeJA3 IOCType = "ja3"
)

// Valid reports whether t is one of the known IOC types.
func (t IOCType) Valid() bool {
	switch t {
	case IOCTypeDomain, IOCTypeIP, IOCTypeCIDR, IOCTypeURL, IOCTypeHash, IOCTypeJA3:
		return true
	}
	return false
}

// HashAlgo identifies the digest algorithm of an IOCTypeHash
// indicator, inferred from the hex length. The malware verdict
// provider does not care which algorithm produced a hash (it
// matches the response-body digest the SWG computes), but
// carrying it lets feeds that mix algorithms round-trip the
// distinction for telemetry and de-duplication.
type HashAlgo string

const (
	// HashAlgoMD5 is a 128-bit MD5 digest (32 hex chars).
	HashAlgoMD5 HashAlgo = "md5"
	// HashAlgoSHA1 is a 160-bit SHA-1 digest (40 hex chars).
	HashAlgoSHA1 HashAlgo = "sha1"
	// HashAlgoSHA256 is a 256-bit SHA-256 digest (64 hex chars).
	HashAlgoSHA256 HashAlgo = "sha256"
)

// IOC is a single normalized indicator of compromise carried
// through the aggregation pipeline. Values are stored
// already-normalized (see NewIOC / normalization helpers) so the
// store, de-duplication and enforcement layers can compare them
// byte-for-byte without re-canonicalizing.
type IOC struct {
	// Type is the indicator category.
	Type IOCType
	// Value is the normalized indicator (lowercase domain,
	// canonical IP, normalized URL, lowercase-hex hash).
	Value string
	// HashAlgo is set only when Type == IOCTypeHash.
	HashAlgo HashAlgo
	// Source is the feed that produced this indicator
	// (e.g. "abuse.ch:urlhaus", "otx", "taxii:mitre").
	Source string
	// ThreatActor / Campaign are optional attribution carried
	// from the feed when available.
	ThreatActor string
	Campaign    string
	// Confidence is the feed-supplied confidence in [0,1].
	Confidence float64
	// FirstSeen / LastSeen bound the indicator's observation
	// window. LastSeen drives recency-based de-duplication.
	FirstSeen time.Time
	LastSeen  time.Time
	// ExpiresAt is the TTL boundary. A zero value means the
	// indicator never expires on its own — matching the
	// demotion engine's threat_feed TTL of 0 ("permanent until
	// an operator clears it"). The store drops an IOC once
	// now >= ExpiresAt.
	ExpiresAt time.Time
}

// Expired reports whether the IOC's TTL has elapsed as of now. A
// zero ExpiresAt never expires.
func (i IOC) Expired(now time.Time) bool {
	if i.ExpiresAt.IsZero() {
		return false
	}
	return !i.ExpiresAt.After(now)
}

// Key is the de-duplication identity of an indicator: (type,
// value). Two IOCs with the same Key from different feeds are the
// same indicator and are merged by the store (keeping the higher
// confidence and the more-recent LastSeen / later ExpiresAt).
func (i IOC) Key() string {
	return string(i.Type) + "\x00" + i.Value
}

// URLHost returns the host[:port] component of an IOCTypeURL
// indicator, used to build the SWG host-match predicate (the
// policy evaluator and the SWG match on Host, not the full URL).
// Returns "" for non-URL types or an unparseable URL.
func (i IOC) URLHost() string {
	if i.Type != IOCTypeURL {
		return ""
	}
	u, err := url.Parse(i.Value)
	if err != nil {
		return ""
	}
	return u.Host
}

// normalizeDomain canonicalizes a DNS name: lowercase, trim
// whitespace, strip a trailing root dot and an optional leading
// "*." wildcard label so "*.evil.com." and "EVIL.com" collapse to
// "evil.com". Returns ("", false) for an input that cannot be a
// hostname (empty, contains a scheme, whitespace or a slash).
//
// Enforcement note: the IOC enforcement compiler emits exact-match
// DNS/SWG predicates (the predicate dialect the policy evaluator
// and the bundle carry has no suffix operator — DomainSuffix is a
// graph *subject* matcher, not a predicate one), so a "*.evil.com"
// feed entry compiles to an exact deny on the apex "evil.com", not
// a tree-wide block of arbitrary subdomains. Tree-wide blocking is
// the data plane's suffix-matching layer, configured independently
// of per-indicator feed IOCs; keeping IOCs keyed on a single
// canonical value is what lets the store dedupe a wildcard and a
// bare-apex sighting of the same domain into one indicator.
func normalizeDomain(s string) (string, bool) {
	d := strings.ToLower(strings.TrimSpace(s))
	d = strings.TrimSuffix(d, ".")
	d = strings.TrimPrefix(d, "*.")
	if d == "" {
		return "", false
	}
	// A bare hostname has no scheme, path, whitespace or port.
	if strings.ContainsAny(d, " \t/\\:") {
		return "", false
	}
	if !strings.Contains(d, ".") {
		return "", false
	}
	// Reject IP literals: a dotted-quad like "203.0.113.10" otherwise
	// passes every check above and would be canonicalized as a domain.
	// It is already covered by the IP key, so accepting it here only
	// produces a phantom domain-key lookup in candidateKeys (and lets
	// NewIOC mis-store an IP under a domain key). IPv6 literals are
	// already rejected by the ':' check above.
	if net.ParseIP(d) != nil {
		return "", false
	}
	return d, true
}

// normalizeIP canonicalizes an IP literal via net.ParseIP, which
// collapses equivalent forms (e.g. "::ffff:1.2.3.4", uppercase
// IPv6) to a single representation. CIDR ranges are rejected —
// the firewall-deny path keys on single addresses. Returns ("",
// false) for anything that is not a single valid IP.
func normalizeIP(s string) (string, bool) {
	t := strings.TrimSpace(s)
	ip := net.ParseIP(t)
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}

// normalizeCIDR canonicalizes an IP range in CIDR notation via
// net.ParseCIDR, masking off any host bits so equivalent forms
// collapse to one network key (e.g. "203.0.113.10/24" ->
// "203.0.113.0/24", uppercase IPv6 lowercased). A bare address
// without a prefix length is rejected here — that is a single IP
// and belongs under IOCTypeIP / normalizeIP, keeping the two
// types disjoint so a /32 range and a host address don't both
// claim the same indicator. Returns ("", false) for anything that
// is not a valid CIDR.
func normalizeCIDR(s string) (string, bool) {
	t := strings.TrimSpace(s)
	_, ipNet, err := net.ParseCIDR(t)
	if err != nil {
		return "", false
	}
	// ParseCIDR already zeroes host bits in ipNet; String() emits
	// the canonical masked form.
	return ipNet.String(), true
}

// normalizeURL canonicalizes an absolute http/https URL: trims
// whitespace, lowercases the scheme and host, and requires a
// host. Returns ("", false) for relative URLs, unsupported
// schemes or unparseable input.
func normalizeURL(s string) (string, bool) {
	t := strings.TrimSpace(s)
	if t == "" {
		return "", false
	}
	u, err := url.Parse(t)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if u.Host == "" {
		return "", false
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	return u.String(), true
}

// normalizeHash validates and lowercases a hex file hash,
// inferring the algorithm from its length (MD5=32, SHA-1=40,
// SHA-256=64). Returns ("", "", false) for a non-hex string or an
// unrecognised length.
func normalizeHash(s string) (string, HashAlgo, bool) {
	h := strings.ToLower(strings.TrimSpace(s))
	if !isHex(h) {
		return "", "", false
	}
	switch len(h) {
	case 32:
		return h, HashAlgoMD5, true
	case 40:
		return h, HashAlgoSHA1, true
	case 64:
		return h, HashAlgoSHA256, true
	}
	return "", "", false
}

// normalizeJA3 validates and lowercases a JA3 TLS client
// fingerprint. A JA3 hash is the MD5 of the ClientHello feature
// string, so on the wire it is exactly 32 hex characters — the
// same shape Suricata's ja3.hash keyword matches. Returns ("",
// false) for anything that is not 32 hex chars. JA3 shares the
// MD5 shape with a 32-char file hash, so the two types are only
// distinguished by the feed's explicit label (an unlabelled
// 32-hex value classifies as IOCTypeHash, see classifyIndicator).
func normalizeJA3(s string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(s))
	if len(h) != 32 || !isHex(h) {
		return "", false
	}
	return h, true
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

// NewIOC builds a normalized IOC of the given type from a raw
// indicator value, applying the per-type canonicalization above.
// It returns (IOC{}, false) when the value is not a valid
// indicator of that type, so feed parsers can skip malformed rows
// without aborting a whole batch. Confidence is clamped to [0,1].
func NewIOC(t IOCType, rawValue string, opts IOCMeta) (IOC, bool) {
	ioc := IOC{
		Type:        t,
		Source:      opts.Source,
		ThreatActor: opts.ThreatActor,
		Campaign:    opts.Campaign,
		Confidence:  clampConfidence(opts.Confidence),
		FirstSeen:   opts.FirstSeen,
		LastSeen:    opts.LastSeen,
		ExpiresAt:   opts.ExpiresAt,
	}
	switch t {
	case IOCTypeDomain:
		v, ok := normalizeDomain(rawValue)
		if !ok {
			return IOC{}, false
		}
		ioc.Value = v
	case IOCTypeIP:
		v, ok := normalizeIP(rawValue)
		if !ok {
			return IOC{}, false
		}
		ioc.Value = v
	case IOCTypeCIDR:
		v, ok := normalizeCIDR(rawValue)
		if !ok {
			return IOC{}, false
		}
		ioc.Value = v
	case IOCTypeURL:
		v, ok := normalizeURL(rawValue)
		if !ok {
			return IOC{}, false
		}
		ioc.Value = v
	case IOCTypeHash:
		v, algo, ok := normalizeHash(rawValue)
		if !ok {
			return IOC{}, false
		}
		ioc.Value = v
		ioc.HashAlgo = algo
	case IOCTypeJA3:
		v, ok := normalizeJA3(rawValue)
		if !ok {
			return IOC{}, false
		}
		ioc.Value = v
	default:
		return IOC{}, false
	}
	return ioc, true
}

// IOCMeta carries the optional attribution / scoring / lifetime
// fields shared by NewIOC callers. Splitting it out of NewIOC's
// positional args keeps feed parsers readable as the field set
// grows.
type IOCMeta struct {
	Source      string
	ThreatActor string
	Campaign    string
	Confidence  float64
	FirstSeen   time.Time
	LastSeen    time.Time
	ExpiresAt   time.Time
}

func clampConfidence(c float64) float64 {
	switch {
	// NaN/Inf are non-comparable garbage (a NaN floor would make
	// every `confidence < floor` test false, silently disabling the
	// filter; a NaN confidence would never clear any floor). Collapse
	// them to the conservative bound so the value stays a well-ordered
	// number: NaN -> 0 (treated as "no confidence"/floor disabled, the
	// documented default), +Inf -> 1, -Inf -> 0.
	case math.IsNaN(c), c < 0:
		return 0
	case c > 1:
		return 1
	}
	return c
}

// classifyIndicator infers the IOC type of a bare indicator
// string when a feed does not label it (common in flat CSV feeds
// that ship a single "indicator" column). The order matters: URLs
// are tested before domains (a URL contains a host that would
// also parse as a domain), and IPs before domains. Hashes are
// detected by hex shape. Returns ("", false) when no type fits.
func classifyIndicator(raw string) (IOCType, bool) {
	t := strings.TrimSpace(raw)
	if t == "" {
		return "", false
	}
	if _, ok := normalizeURL(t); ok {
		return IOCTypeURL, true
	}
	if _, ok := normalizeIP(t); ok {
		return IOCTypeIP, true
	}
	if _, ok := normalizeCIDR(t); ok {
		return IOCTypeCIDR, true
	}
	if _, _, ok := normalizeHash(t); ok {
		return IOCTypeHash, true
	}
	if _, ok := normalizeDomain(t); ok {
		return IOCTypeDomain, true
	}
	return "", false
}

// ipKindForValue picks the right NGFW-sink IOC type for a value a
// feed has labelled as an address indicator. Feeds express hosts
// and ranges under the same address-family attribute type (STIX
// ipv4-addr, MISP ip-dst, an OTX IPv4 pulse), so the value's shape
// — a prefix-bearing CIDR vs. a bare address — decides which sink
// type stores it, rather than dropping the range because the
// feed's label said "ip". A non-address value falls back to
// IOCTypeIP, where NewIOC's own normalization rejects it.
func ipKindForValue(value string) IOCType {
	if _, ok := normalizeCIDR(value); ok {
		return IOCTypeCIDR
	}
	return IOCTypeIP
}
