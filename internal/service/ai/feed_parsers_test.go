package ai

import (
	"context"
	"testing"
	"time"
)

// indexByKey groups parsed IOCs by their (type,value) key so a
// test can assert on a specific indicator without depending on the
// parser's emission order.
func indexByKey(iocs []IOC) map[string]IOC {
	m := make(map[string]IOC, len(iocs))
	for _, ioc := range iocs {
		m[ioc.Key()] = ioc
	}
	return m
}

func countByType(iocs []IOC) map[IOCType]int {
	m := map[IOCType]int{}
	for _, ioc := range iocs {
		m[ioc.Type]++
	}
	return m
}

// realistic 32/40/64-hex digests reused across the parser tests.
const (
	sampleMD5    = "0123456789abcdef0123456789abcdef"
	sampleSHA1   = "0123456789abcdef0123456789abcdef01234567"
	sampleSHA256 = "a1b2c3d4e5f6071829304a5b6c7d8e9f00112233445566778899aabbccddeeff"
	// a second, distinct SHA-256 so a test can assert two separate hash
	// IOCs landed independently.
	sampleSHA256b = "ffeeddccbbaa99887766554433221100f9e8d7c6b5a4039281706f5e4d3c2b1a"
)

// --- STIX / TAXII 2.1 ---

func TestSTIXTAXIIParser_RealisticBundle(t *testing.T) {
	t.Parallel()
	// A STIX 2.1 bundle carrying one indicator of each enforceable
	// type, plus two objects the parser must ignore: a `malware`
	// SDO (context, not an indicator) and a snort-dialect indicator
	// (a pattern this parser cannot decompose into network IOCs).
	raw := []byte(`{
      "type": "bundle",
      "id": "bundle--1",
      "objects": [
        {
          "type": "indicator",
          "name": "Cobalt Strike C2 domain",
          "pattern": "[domain-name:value = 'evil.example.com']",
          "pattern_type": "stix",
          "confidence": 90,
          "labels": ["malicious-activity"],
          "created": "2023-01-01T00:00:00Z",
          "modified": "2023-02-01T00:00:00Z",
          "valid_until": "2030-01-01T00:00:00Z"
        },
        {
          "type": "indicator",
          "name": "C2 IP",
          "pattern": "[ipv4-addr:value = '203.0.113.10']",
          "pattern_type": "stix",
          "confidence": 75,
          "labels": ["command-and-control"]
        },
        {
          "type": "indicator",
          "name": "drive-by URL",
          "pattern": "[url:value = 'http://malware.example/path']",
          "confidence": 80
        },
        {
          "type": "indicator",
          "name": "dropper hash",
          "pattern": "[file:hashes.'SHA-256' = '` + sampleSHA256 + `']",
          "confidence": 95
        },
        {
          "type": "indicator",
          "name": "unscored",
          "pattern": "[domain-name:value = 'unscored.example.net']"
        },
        {
          "type": "indicator",
          "name": "snort sig",
          "pattern_type": "snort",
          "pattern": "alert tcp any any -> any any"
        },
        {
          "type": "malware",
          "name": "Emotet",
          "is_family": true
        }
      ]
    }`)

	p := STIXTAXIIParser{Source: "taxii:mitre", DefaultConfidence: 0.6}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	counts := countByType(iocs)
	if counts[IOCTypeDomain] != 2 || counts[IOCTypeIP] != 1 || counts[IOCTypeURL] != 1 || counts[IOCTypeHash] != 1 {
		t.Fatalf("unexpected type counts: %#v (iocs=%d)", counts, len(iocs))
	}
	by := indexByKey(iocs)

	dom := by[string(IOCTypeDomain)+"\x00"+"evil.example.com"]
	if dom.Confidence != 0.9 {
		t.Errorf("domain confidence: got %v want 0.9", dom.Confidence)
	}
	if dom.Source != "taxii:mitre" {
		t.Errorf("source: got %q", dom.Source)
	}
	if dom.Campaign != "Cobalt Strike C2 domain" {
		t.Errorf("campaign: got %q", dom.Campaign)
	}
	if dom.ThreatActor != "malicious-activity" {
		t.Errorf("actor (first label): got %q", dom.ThreatActor)
	}
	if dom.ExpiresAt.IsZero() || dom.ExpiresAt.Year() != 2030 {
		t.Errorf("valid_until -> ExpiresAt not propagated: %v", dom.ExpiresAt)
	}

	if ip := by[string(IOCTypeIP)+"\x00"+"203.0.113.10"]; ip.Confidence != 0.75 {
		t.Errorf("ip confidence: got %v want 0.75", ip.Confidence)
	}
	if h := by[string(IOCTypeHash)+"\x00"+sampleSHA256]; h.Confidence != 0.95 || h.HashAlgo != HashAlgoSHA256 {
		t.Errorf("hash: conf=%v algo=%q", h.Confidence, h.HashAlgo)
	}
	// The unscored indicator falls back to DefaultConfidence.
	if u := by[string(IOCTypeDomain)+"\x00"+"unscored.example.net"]; u.Confidence != 0.6 {
		t.Errorf("unscored default confidence: got %v want 0.6", u.Confidence)
	}
}

func TestSTIXTAXIIParser_TAXIIEnvelopeAndMalformed(t *testing.T) {
	t.Parallel()
	// A TAXII 2.1 collection envelope (objects + pagination) is the
	// same shape the bundle parser reads.
	raw := []byte(`{
      "more": false,
      "objects": [
        {"type":"indicator","pattern":"[ipv4-addr:value = '198.51.100.5']","confidence":70}
      ]
    }`)
	iocs, err := STIXTAXIIParser{}.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(iocs) != 1 || iocs[0].Type != IOCTypeIP || iocs[0].Value != "198.51.100.5" {
		t.Fatalf("taxii envelope: %#v", iocs)
	}
	// A malformed envelope is a hard error (not a per-row skip).
	if _, err := (STIXTAXIIParser{}).Parse([]byte("not json")); err == nil {
		t.Fatal("expected error on malformed envelope")
	}
}

// --- CSV ---

func TestCSVParser_HeaderAddressedColumns(t *testing.T) {
	t.Parallel()
	raw := []byte("# national-CERT export\n" +
		"indicator,type,confidence,actor,campaign\n" +
		"evil1.example.com,domain,90,APT29,SolarWinds\n" +
		"203.0.113.5,ip,0.8,,\n" +
		"http://bad.example/x,url,75,,\n" +
		sampleMD5 + ",hash,95,,\n" +
		",domain,50,,\n" + // empty indicator -> skipped
		"foo.example,bogus,50,,\n" + // invalid type -> skipped
		"ragged.example.com,domain\n") // ragged row, missing cols -> default confidence

	p := CSVParser{
		IndicatorColumn:   "indicator",
		TypeColumn:        "type",
		ConfidenceColumn:  "confidence",
		ActorColumn:       "actor",
		CampaignColumn:    "campaign",
		HasHeader:         true,
		DefaultConfidence: 0.5,
		Source:            "cert-csv",
	}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	counts := countByType(iocs)
	if counts[IOCTypeDomain] != 2 || counts[IOCTypeIP] != 1 || counts[IOCTypeURL] != 1 || counts[IOCTypeHash] != 1 {
		t.Fatalf("unexpected counts %#v (n=%d)", counts, len(iocs))
	}
	by := indexByKey(iocs)
	dom := by[string(IOCTypeDomain)+"\x00"+"evil1.example.com"]
	if dom.Confidence != 0.9 || dom.ThreatActor != "APT29" || dom.Campaign != "SolarWinds" {
		t.Errorf("domain row: %#v", dom)
	}
	if ip := by[string(IOCTypeIP)+"\x00"+"203.0.113.5"]; ip.Confidence != 0.8 {
		t.Errorf("ip 0-1 confidence: got %v", ip.Confidence)
	}
	// Ragged row with a missing confidence cell falls back to default.
	if r := by[string(IOCTypeDomain)+"\x00"+"ragged.example.com"]; r.Confidence != 0.5 {
		t.Errorf("ragged default confidence: got %v want 0.5", r.Confidence)
	}
}

func TestCSVParser_TypeInferenceNoHeader(t *testing.T) {
	t.Parallel()
	// Header-less, single-column "one indicator per line" export —
	// type is inferred from each value's shape.
	raw := []byte("evil.example.org\n203.0.113.9\nhttp://x.example/y\n" + sampleSHA256 + "\n")
	p := CSVParser{IndicatorColumn: "0", DefaultConfidence: 0.7}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	counts := countByType(iocs)
	if counts[IOCTypeDomain] != 1 || counts[IOCTypeIP] != 1 || counts[IOCTypeURL] != 1 || counts[IOCTypeHash] != 1 {
		t.Fatalf("inference counts %#v", counts)
	}
	for _, ioc := range iocs {
		if ioc.Confidence != 0.7 {
			t.Errorf("default confidence not applied: %#v", ioc)
		}
	}
}

func TestCSVParser_MissingIndicatorColumnIsConfigError(t *testing.T) {
	t.Parallel()
	raw := []byte("a,b\n1,2\n")
	_, err := CSVParser{IndicatorColumn: "nope", HasHeader: true}.Parse(raw)
	if err == nil {
		t.Fatal("expected config error for missing indicator column")
	}
}

// --- JSON ---

func TestJSONParser_BareArray(t *testing.T) {
	t.Parallel()
	raw := []byte(`[
      {"indicator":"evil.example.io","type":"domain","confidence":85},
      {"indicator":"203.0.113.7","type":"ip","confidence":0.6},
      {"indicator":"` + sampleSHA1 + `","type":"hash","confidence":95},
      {"indicator":"","type":"domain","confidence":50},
      {"indicator":"skip.example","type":"bogus","confidence":50}
    ]`)
	iocs, err := JSONParser{DefaultConfidence: 0.5}.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(iocs) != 3 {
		t.Fatalf("expected 3 iocs, got %d (%#v)", len(iocs), iocs)
	}
	by := indexByKey(iocs)
	if d := by[string(IOCTypeDomain)+"\x00"+"evil.example.io"]; d.Confidence != 0.85 {
		t.Errorf("domain confidence: got %v want 0.85", d.Confidence)
	}
	if ip := by[string(IOCTypeIP)+"\x00"+"203.0.113.7"]; ip.Confidence != 0.6 {
		t.Errorf("ip confidence (already 0-1): got %v", ip.Confidence)
	}
}

func TestJSONParser_WrappedArrayCustomKeys(t *testing.T) {
	t.Parallel()
	raw := []byte(`{"data":[
      {"ioc":"bad.example.com","category":"domain","score":"70","group":"FIN7","op":"CarbonSpider"}
    ]}`)
	p := JSONParser{
		ArrayKey:      "data",
		IndicatorKey:  "ioc",
		TypeKey:       "category",
		ConfidenceKey: "score",
		ActorKey:      "group",
		CampaignKey:   "op",
	}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(iocs) != 1 {
		t.Fatalf("expected 1 ioc, got %d", len(iocs))
	}
	got := iocs[0]
	if got.Type != IOCTypeDomain || got.Value != "bad.example.com" {
		t.Errorf("indicator: %#v", got)
	}
	if got.Confidence != 0.7 { // "70" string -> 0.70
		t.Errorf("string percent confidence: got %v want 0.7", got.Confidence)
	}
	if got.ThreatActor != "FIN7" || got.Campaign != "CarbonSpider" {
		t.Errorf("attribution: actor=%q campaign=%q", got.ThreatActor, got.Campaign)
	}
}

// --- OTX ---

func TestOTXParser_ResultsEnvelope(t *testing.T) {
	t.Parallel()
	raw := []byte(`{
      "results": [
        {
          "name": "FancyBear Infrastructure",
          "adversary": "APT28",
          "tags": ["apt", "espionage"],
          "indicators": [
            {"indicator":"203.0.113.20","type":"IPv4"},
            {"indicator":"sofacy.example.com","type":"domain"},
            {"indicator":"http://drop.example/x","type":"URL"},
            {"indicator":"` + sampleSHA256 + `","type":"FileHash-SHA256"},
            {"indicator":"someone@example.com","type":"email"}
          ]
        }
      ]
    }`)
	p := OTXParser{DefaultConfidence: 0.5}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	counts := countByType(iocs)
	if counts[IOCTypeIP] != 1 || counts[IOCTypeDomain] != 1 || counts[IOCTypeURL] != 1 || counts[IOCTypeHash] != 1 {
		t.Fatalf("otx counts %#v (email must be skipped)", counts)
	}
	for _, ioc := range iocs {
		if ioc.ThreatActor != "APT28" || ioc.Campaign != "FancyBear Infrastructure" {
			t.Errorf("pulse attribution not lifted onto indicator: %#v", ioc)
		}
		if ioc.Confidence != 0.5 {
			t.Errorf("default confidence: got %v", ioc.Confidence)
		}
	}
}

func TestOTXParser_BareArrayAndSinglePulse(t *testing.T) {
	t.Parallel()
	// Bare pulse array: actor falls back to the first tag when
	// adversary is absent.
	arr := []byte(`[
      {"name":"P1","tags":["trickbot"],"indicators":[{"indicator":"198.51.100.30","type":"IPv4"}]}
    ]`)
	iocs, err := OTXParser{DefaultConfidence: 0.4}.Parse(arr)
	if err != nil {
		t.Fatalf("array parse: %v", err)
	}
	if len(iocs) != 1 || iocs[0].ThreatActor != "trickbot" {
		t.Fatalf("bare array / tag-actor: %#v", iocs)
	}

	// Single pulse object.
	single := []byte(`{"name":"P2","adversary":"Wizard Spider","indicators":[{"indicator":"ryuk.example.net","type":"hostname"}]}`)
	iocs, err = OTXParser{DefaultConfidence: 0.4}.Parse(single)
	if err != nil {
		t.Fatalf("single parse: %v", err)
	}
	if len(iocs) != 1 || iocs[0].Type != IOCTypeDomain || iocs[0].ThreatActor != "Wizard Spider" {
		t.Fatalf("single pulse: %#v", iocs)
	}
}

// --- abuse.ch ---

func TestAbuseCHParser_URLhausCSV(t *testing.T) {
	t.Parallel()
	raw := []byte(`# URLhaus Database Dump (CSV)
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"123456","2023-01-01 10:00:00","http://malicious.example/payload.exe","online","2023-01-02 12:00:00","malware_download","emotet,heodo","https://urlhaus.abuse.ch/url/123456/","reporterX"
"123457","2023-01-03 08:30:00","https://bad2.example/dropper","offline","2023-01-04 09:00:00","malware_download","qakbot","https://urlhaus.abuse.ch/url/123457/","reporterY"
`)
	p := AbuseCHParser{Product: AbuseCHURLhaus}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(iocs) != 2 {
		t.Fatalf("expected 2 url iocs, got %d (%#v)", len(iocs), iocs)
	}
	by := indexByKey(iocs)
	u := by[string(IOCTypeURL)+"\x00"+"http://malicious.example/payload.exe"]
	if u.Confidence != 0.9 {
		t.Errorf("default abuse.ch confidence: got %v want 0.9", u.Confidence)
	}
	if u.Campaign != "malware_download" || u.ThreatActor != "emotet" {
		t.Errorf("urlhaus attribution: campaign=%q actor=%q", u.Campaign, u.ThreatActor)
	}
	if u.Source != "abuse.ch:urlhaus" {
		t.Errorf("source: got %q", u.Source)
	}
	if u.LastSeen.IsZero() {
		t.Errorf("last_online -> LastSeen not parsed")
	}
}

func TestAbuseCHParser_MalwareBazaarCSV(t *testing.T) {
	t.Parallel()
	raw := []byte(`# MalwareBazaar export
"2023-01-01 10:00:00","` + sampleSHA256 + `","` + sampleMD5 + `","` + sampleSHA1 + `","reporterZ","evil.exe","exe","application/x-dosexec","Emotet"
"2023-01-02 11:00:00","not-a-hash","x","y","r","f","exe","mime","n/a"
`)
	p := AbuseCHParser{Product: AbuseCHMalwareBazaar}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Second row's sha256 is invalid hex -> skipped (not fatal).
	if len(iocs) != 1 {
		t.Fatalf("expected 1 hash ioc, got %d (%#v)", len(iocs), iocs)
	}
	got := iocs[0]
	if got.Type != IOCTypeHash || got.Value != sampleSHA256 || got.HashAlgo != HashAlgoSHA256 {
		t.Errorf("hash ioc: %#v", got)
	}
	if got.ThreatActor != "Emotet" || got.Campaign != "Emotet" {
		t.Errorf("malwarebazaar signature -> actor/campaign: %#v", got)
	}
}

func TestAbuseCHParser_FeodoTrackerJSON(t *testing.T) {
	t.Parallel()
	raw := []byte(`[
      {"ip_address":"198.51.100.20","port":443,"status":"online","malware":"Emotet","first_seen":"2023-01-01 10:00:00","last_online":"2023-01-02 12:00:00"},
      {"ip_address":"bogus-ip","port":80,"status":"online","malware":"Dridex","first_seen":"2023-01-01 10:00:00"}
    ]`)
	p := AbuseCHParser{Product: AbuseCHFeodoTracker}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(iocs) != 1 {
		t.Fatalf("expected 1 ip ioc (bogus skipped), got %d", len(iocs))
	}
	got := iocs[0]
	if got.Type != IOCTypeIP || got.Value != "198.51.100.20" {
		t.Errorf("feodo ip: %#v", got)
	}
	if got.ThreatActor != "Emotet" || got.Campaign != "Emotet C2" {
		t.Errorf("feodo attribution: actor=%q campaign=%q", got.ThreatActor, got.Campaign)
	}
}

func TestAbuseCHParser_UnknownProduct(t *testing.T) {
	t.Parallel()
	_, err := AbuseCHParser{Product: "nope"}.Parse([]byte("x"))
	if err == nil {
		t.Fatal("expected error for unknown abuse.ch product")
	}
}

// applyFeedDefaults stamps a DefaultTTL onto undated IOCs — verify
// the manager-level TTL knob the scheduled aggregator relies on.
func TestFeedDefaultTTLAppliedToUndatedIOC(t *testing.T) {
	t.Parallel()
	now := time.Date(2023, 6, 1, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store := NewIOCStore(withStoreClock(clock))
	mgr := NewFeedManager(store, nil, withManagerClock(clock))
	feed := Feed{
		Name:       "csv-feed",
		DefaultTTL: 24 * time.Hour,
		Parser:     CSVParser{IndicatorColumn: "0", DefaultConfidence: 0.9},
		Fetcher:    StaticFetcher{Data: []byte("evil.example.com\n")},
	}
	if _, err := mgr.RunFeedOnce(context.Background(), feed); err != nil {
		t.Fatalf("run feed: %v", err)
	}
	snap := store.Snapshot()
	if len(snap.Domains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(snap.Domains))
	}
	want := now.Add(24 * time.Hour)
	if !snap.Domains[0].ExpiresAt.Equal(want) {
		t.Errorf("DefaultTTL not applied: got %v want %v", snap.Domains[0].ExpiresAt, want)
	}
	if !snap.Domains[0].LastSeen.Equal(now) {
		t.Errorf("LastSeen not stamped to ingest time: got %v", snap.Domains[0].LastSeen)
	}
}
