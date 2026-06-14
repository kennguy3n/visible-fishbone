package ai

import (
	"context"
	"testing"
)

// --- MISP ---

// A realistic MISP events REST-search response: one event carrying
// one attribute of each enforceable type, two composite attributes
// (domain|ip → domain + ip, filename|sha256 → hash only), an
// attribute inside a MISP "object", a non-to_ids contextual
// attribute (must be dropped by default), and event-level
// attribution via a threat-actor galaxy.
var mispEventsResponse = `{
  "response": [
    {
      "Event": {
        "info": "Emotet delivery infrastructure",
        "Tag": [{"name": "tlp:white"}],
        "Galaxy": [
          {
            "type": "threat-actor",
            "GalaxyCluster": [{"value": "Mealybug"}]
          }
        ],
        "Attribute": [
          {"type": "domain", "value": "evil.example.com", "to_ids": true, "timestamp": "1700000000"},
          {"type": "ip-dst", "value": "203.0.113.10", "to_ids": true},
          {"type": "url", "value": "http://malware.example/path", "to_ids": true},
          {"type": "sha256", "value": "` + sampleSHA256 + `", "to_ids": true},
          {"type": "domain|ip", "value": "c2.example.net|198.51.100.7", "to_ids": true},
          {"type": "comment", "value": "delivered via phishing", "to_ids": false},
          {"type": "domain", "value": "context.example.org", "to_ids": false}
        ],
        "Object": [
          {
            "Attribute": [
              {"type": "filename|sha256", "value": "dropper.exe|` + sampleSHA1 + sampleSHA1[:24] + `", "to_ids": true}
            ]
          }
        ]
      }
    }
  ]
}`

func TestMISPParser_EventsResponse(t *testing.T) {
	t.Parallel()
	p := MISPParser{Source: "misp", DefaultConfidence: 0.5}
	iocs, err := p.Parse([]byte(mispEventsResponse))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	counts := countByType(iocs)
	// domain (evil) + domain (c2 from composite) = 2 domains;
	// ip-dst + ip from composite = 2 IPs; 1 url; 1 sha256 +
	// 1 filename|sha256 hash = 2 hashes. The two to_ids:false
	// attributes (comment, context.example.org) are dropped.
	if counts[IOCTypeDomain] != 2 || counts[IOCTypeIP] != 2 || counts[IOCTypeURL] != 1 || counts[IOCTypeHash] != 2 {
		t.Fatalf("unexpected type counts: %#v (iocs=%d)", counts, len(iocs))
	}
	by := indexByKey(iocs)

	dom := by[string(IOCTypeDomain)+"\x00"+"evil.example.com"]
	if dom.Confidence != 0.5 {
		t.Errorf("domain confidence: got %v want 0.5", dom.Confidence)
	}
	if dom.Source != "misp" {
		t.Errorf("source: got %q", dom.Source)
	}
	if dom.Campaign != "Emotet delivery infrastructure" {
		t.Errorf("campaign (event info): got %q", dom.Campaign)
	}
	if dom.ThreatActor != "Mealybug" {
		t.Errorf("actor (galaxy cluster): got %q", dom.ThreatActor)
	}
	if dom.LastSeen.IsZero() || dom.LastSeen.Unix() != 1700000000 {
		t.Errorf("timestamp -> LastSeen not propagated: %v", dom.LastSeen)
	}

	// Composite domain|ip split into both halves.
	if _, ok := by[string(IOCTypeDomain)+"\x00"+"c2.example.net"]; !ok {
		t.Errorf("composite domain|ip: domain half missing")
	}
	if _, ok := by[string(IOCTypeIP)+"\x00"+"198.51.100.7"]; !ok {
		t.Errorf("composite domain|ip: ip half missing")
	}

	// Dropped contextual (to_ids:false) attributes.
	if _, ok := by[string(IOCTypeDomain)+"\x00"+"context.example.org"]; ok {
		t.Errorf("to_ids:false domain should have been dropped")
	}

	// Object attribute: filename|sha256 yields the hash, drops the filename.
	hashKey := string(IOCTypeHash) + "\x00" + (sampleSHA1 + sampleSHA1[:24])
	if h := by[hashKey]; h.HashAlgo != HashAlgoSHA256 {
		t.Errorf("object filename|sha256 hash missing/wrong algo: %q", h.HashAlgo)
	}
}

func TestMISPParser_IncludeNonIDs(t *testing.T) {
	t.Parallel()
	// With IncludeNonIDs, the two to_ids:false attributes are also
	// ingested (the comment is not a valid indicator and still
	// drops out; the context.example.org domain now lands).
	p := MISPParser{Source: "misp", DefaultConfidence: 0.5, IncludeNonIDs: true}
	iocs, err := p.Parse([]byte(mispEventsResponse))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	by := indexByKey(iocs)
	if _, ok := by[string(IOCTypeDomain)+"\x00"+"context.example.org"]; !ok {
		t.Errorf("IncludeNonIDs: to_ids:false domain should be ingested")
	}
}

func TestMISPParser_AttributesResponse(t *testing.T) {
	t.Parallel()
	// The attributes REST-search shape: {"response":{"Attribute":[…]}}
	// with no enclosing event.
	raw := []byte(`{
      "response": {
        "Attribute": [
          {"type": "ip-src", "value": "192.0.2.55", "to_ids": true},
          {"type": "hostname", "value": "bad.host.example", "to_ids": true},
          {"type": "md5", "value": "` + sampleMD5 + `", "to_ids": true}
        ]
      }
    }`)
	p := MISPParser{Source: "misp", DefaultConfidence: 0.7}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	counts := countByType(iocs)
	if counts[IOCTypeIP] != 1 || counts[IOCTypeDomain] != 1 || counts[IOCTypeHash] != 1 {
		t.Fatalf("unexpected counts: %#v", counts)
	}
	by := indexByKey(iocs)
	if h := by[string(IOCTypeHash)+"\x00"+sampleMD5]; h.HashAlgo != HashAlgoMD5 || h.Confidence != 0.7 {
		t.Errorf("md5: algo=%q conf=%v", h.HashAlgo, h.Confidence)
	}
}

func TestMISPParser_SingleEventAndBareArray(t *testing.T) {
	t.Parallel()
	single := []byte(`{"Event":{"info":"single","Attribute":[
      {"type":"domain","value":"single.example.com","to_ids":true}
    ]}}`)
	bare := []byte(`[{"Event":{"info":"arr","Attribute":[
      {"type":"ip-dst","value":"203.0.113.99","to_ids":true}
    ]}}]`)

	p := MISPParser{Source: "misp", DefaultConfidence: 0.5}

	iocs, err := p.Parse(single)
	if err != nil {
		t.Fatalf("parse single: %v", err)
	}
	if len(iocs) != 1 || iocs[0].Type != IOCTypeDomain || iocs[0].Value != "single.example.com" {
		t.Fatalf("single event: got %#v", iocs)
	}
	if iocs[0].Campaign != "single" {
		t.Errorf("single event campaign: got %q", iocs[0].Campaign)
	}

	iocs, err = p.Parse(bare)
	if err != nil {
		t.Fatalf("parse bare array: %v", err)
	}
	if len(iocs) != 1 || iocs[0].Type != IOCTypeIP || iocs[0].Value != "203.0.113.99" {
		t.Fatalf("bare array: got %#v", iocs)
	}
}

func TestMISPParser_ThreatActorFromTag(t *testing.T) {
	t.Parallel()
	// No galaxy; actor lifted from a misp-galaxy:threat-actor tag.
	raw := []byte(`{"Event":{
      "info":"tagged",
      "Tag":[{"name":"tlp:amber"},{"name":"misp-galaxy:threat-actor=\"APT28\""}],
      "Attribute":[{"type":"domain","value":"apt.example.com","to_ids":true}]
    }}`)
	p := MISPParser{Source: "misp", DefaultConfidence: 0.5}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(iocs) != 1 || iocs[0].ThreatActor != "APT28" {
		t.Fatalf("actor from tag: got %#v", iocs)
	}
}

func TestMISPParser_MalformedRowsSkipped(t *testing.T) {
	t.Parallel()
	// A batch with junk values and unsupported types must not fail;
	// only the valid indicators survive.
	raw := []byte(`{"Event":{"Attribute":[
      {"type":"domain","value":"not a domain","to_ids":true},
      {"type":"ip-dst","value":"999.999.999.999","to_ids":true},
      {"type":"btc","value":"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa","to_ids":true},
      {"type":"sha256","value":"tooshort","to_ids":true},
      {"type":"url","value":"http://ok.example/p","to_ids":true}
    ]}}`)
	p := MISPParser{Source: "misp", DefaultConfidence: 0.5}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(iocs) != 1 || iocs[0].Type != IOCTypeURL {
		t.Fatalf("only the valid URL should survive: got %#v", iocs)
	}
}

func TestMISPParser_SingleTypeValueWithPipeNotTruncated(t *testing.T) {
	t.Parallel()
	// A single-type `url` attribute whose value legitimately contains a
	// "|" must be taken whole, not split on the pipe. A composite type
	// in the same batch must still split.
	raw := []byte(`{"Event":{"Attribute":[
      {"type":"url","value":"http://evil.example/shell?cmd=a|b|c","to_ids":true},
      {"type":"domain|ip","value":"c2.example.net|198.51.100.7","to_ids":true}
    ]}}`)
	p := MISPParser{Source: "misp", DefaultConfidence: 0.5}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	by := indexByKey(iocs)
	if _, ok := by[string(IOCTypeURL)+"\x00"+"http://evil.example/shell?cmd=a|b|c"]; !ok {
		t.Errorf("single-type url value should be preserved whole; got %#v", iocs)
	}
	// Composite still decomposes into both halves.
	if _, ok := by[string(IOCTypeDomain)+"\x00"+"c2.example.net"]; !ok {
		t.Errorf("composite domain half missing")
	}
	if _, ok := by[string(IOCTypeIP)+"\x00"+"198.51.100.7"]; !ok {
		t.Errorf("composite ip half missing")
	}
}

func TestMISPParser_ToIDsEncodings(t *testing.T) {
	t.Parallel()
	// MISP has serialized to_ids as a bool, the strings "0"/"1" and
	// "true"/"false", and the numbers 0/1 across versions. None of
	// these may fail the document parse, and each must gate correctly.
	raw := []byte(`{"Event":{"Attribute":[
      {"type":"domain","value":"bool-true.example","to_ids":true},
      {"type":"domain","value":"str-one.example","to_ids":"1"},
      {"type":"domain","value":"str-true.example","to_ids":"true"},
      {"type":"domain","value":"num-one.example","to_ids":1},
      {"type":"domain","value":"str-zero.example","to_ids":"0"},
      {"type":"domain","value":"num-zero.example","to_ids":0},
      {"type":"domain","value":"junk.example","to_ids":2},
      {"type":"domain","value":"absent.example"}
    ]}}`)
	p := MISPParser{Source: "misp", DefaultConfidence: 0.5}
	iocs, err := p.Parse(raw)
	if err != nil {
		t.Fatalf("parse must tolerate mixed to_ids encodings: %v", err)
	}
	by := indexByKey(iocs)
	for _, want := range []string{"bool-true.example", "str-one.example", "str-true.example", "num-one.example"} {
		if _, ok := by[string(IOCTypeDomain)+"\x00"+want]; !ok {
			t.Errorf("actionable to_ids %q should be ingested", want)
		}
	}
	// "0", 0, an unrecognised token (2), and an absent flag are all
	// treated as non-actionable and dropped — never fatal to the batch.
	for _, drop := range []string{"str-zero.example", "num-zero.example", "junk.example", "absent.example"} {
		if _, ok := by[string(IOCTypeDomain)+"\x00"+drop]; ok {
			t.Errorf("non-actionable to_ids %q should be dropped", drop)
		}
	}
}

func TestMISPParser_EmptyAndGarbage(t *testing.T) {
	t.Parallel()
	p := MISPParser{Source: "misp"}
	if iocs, err := p.Parse(nil); err != nil || iocs != nil {
		t.Errorf("nil: got %v err %v", iocs, err)
	}
	if iocs, err := p.Parse([]byte("   ")); err != nil || iocs != nil {
		t.Errorf("blank: got %v err %v", iocs, err)
	}
	if _, err := p.Parse([]byte("not json")); err == nil {
		t.Errorf("garbage should error")
	}
}

// TestMISPParser_Efficacy is the parser-level efficacy check the
// workstream asks for: a fixed corpus of MISP attributes (each
// labelled bad/benign) is run through the parser and we assert it
// recovers every enforceable indicator (true positives) and emits
// nothing for the non-enforceable / non-actionable rows (no false
// positives). It complements the Rust bench/efficacy DNS/IPS rows,
// which exercise the edge matchers downstream of this feed.
func TestMISPParser_Efficacy(t *testing.T) {
	t.Parallel()
	type row struct {
		attrType string
		value    string
		toIDs    bool
		// want is the indicator the parser MUST recover, or "" when
		// the row must produce no IOC.
		wantType  IOCType
		wantValue string
	}
	corpus := []row{
		{"domain", "c2.malware.example", true, IOCTypeDomain, "c2.malware.example"},
		{"hostname", "drop.host.example", true, IOCTypeDomain, "drop.host.example"},
		{"ip-dst", "203.0.113.200", true, IOCTypeIP, "203.0.113.200"},
		{"ip-src", "198.51.100.200", true, IOCTypeIP, "198.51.100.200"},
		{"url", "https://phish.example/login", true, IOCTypeURL, "https://phish.example/login"},
		{"sha256", sampleSHA256, true, IOCTypeHash, sampleSHA256},
		{"md5", sampleMD5, true, IOCTypeHash, sampleMD5},
		// Non-actionable / non-enforceable rows: MUST yield nothing.
		{"domain", "benign.example.com", false, "", ""}, // to_ids:false
		{"btc", "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", true, "", ""},
		{"email-src", "attacker@evil.example", true, "", ""},
		{"comment", "see report", true, "", ""},
	}

	// Build one event carrying the whole corpus.
	var attrs []mispAttribute
	for _, r := range corpus {
		attrs = append(attrs, mispAttribute{Type: r.attrType, Value: r.value, ToIDs: mispBool(r.toIDs)})
	}
	ev := mispEvent{Info: "efficacy", Attribute: attrs}
	p := MISPParser{Source: "misp", DefaultConfidence: 0.5}
	iocs := p.iocsFromEvent(ev, p.Name())
	by := indexByKey(iocs)

	var wantTP int
	for _, r := range corpus {
		if r.wantType == "" {
			continue
		}
		wantTP++
		key := string(r.wantType) + "\x00" + r.wantValue
		if _, ok := by[key]; !ok {
			t.Errorf("missing true positive: %s %s", r.wantType, r.wantValue)
		}
	}
	// No false positives: total recovered == expected true positives.
	if len(iocs) != wantTP {
		t.Errorf("false positives: recovered %d IOCs, want exactly %d (%#v)", len(iocs), wantTP, iocs)
	}
}

// Ensure the MISP feed integrates with the manager exactly like the
// other parsers (parse → store → snapshot), with no parser-specific
// wiring.
func TestMISPParser_FeedManagerIntegration(t *testing.T) {
	t.Parallel()
	feed := Feed{
		Name:    "misp",
		Parser:  MISPParser{Source: "misp", DefaultConfidence: 0.9},
		Fetcher: StaticFetcher{Data: []byte(mispEventsResponse)},
	}
	store := NewIOCStore()
	mgr := NewFeedManager(store, []Feed{feed})
	if _, err := mgr.RunFeedOnce(context.Background(), feed); err != nil {
		t.Fatalf("RunFeedOnce: %v", err)
	}
	counts := store.SizeByType()
	if counts.Total == 0 {
		t.Fatalf("store empty after MISP ingest")
	}
	if counts.Domains < 1 || counts.IPs < 1 || counts.URLs < 1 || counts.Hashes < 1 {
		t.Errorf("expected all four IOC types in store: %#v", counts)
	}
}
